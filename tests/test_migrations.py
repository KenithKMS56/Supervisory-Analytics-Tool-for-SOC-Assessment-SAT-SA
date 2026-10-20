"""Versioned migrations, legacy Parquet adoption, crash recovery and atomic publication
(docs/migrations.md). Every test works on its own temporary copy; no deployment data is touched."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import polars as pl
import pytest

from satsa.store.catalog import Catalog, PublicationError
from satsa.store.duckdb import DuckDBStore
from satsa.store.migrations import Migration, MigrationError, apply_migrations
from satsa.store.sqlite import SQLiteStore

# ------------------------------------------------------------------ satsa.db from version 0


def _version0_database(path: Path) -> None:
    """A satsa.db as commit 47f10c9 left it (no numbered migrations), with one run of results."""
    store = SQLiteStore(path)
    conn = store.conn
    for table in ("rule_results", "run_config_snapshots", "applicability_decisions", "schema_migrations"):
        conn.execute(f"DROP TABLE {table}")
    conn.execute("DROP TABLE domain_scores")
    conn.execute(
        "CREATE TABLE domain_scores (run_id TEXT NOT NULL, entity_id TEXT NOT NULL, domain TEXT NOT NULL, "
        "score REAL NOT NULL, PRIMARY KEY (run_id, entity_id, domain), FOREIGN KEY (run_id) REFERENCES runs (run_id))"
    )
    for column in (
        "classification_status", "rules_applicable", "rules_assessed", "rules_degraded", "rules_insufficient",
        "rules_not_applicable", "coverage", "data_request_priority", "missing_inputs_json",
    ):  # fmt: skip
        conn.execute(f"ALTER TABLE entity_scores DROP COLUMN {column}")
    for column in ("fingerprint", "selection_json", "source_snapshot", "data_fingerprint_json", "environment_json",
                   "published_at"):  # fmt: skip
        conn.execute(f"ALTER TABLE runs DROP COLUMN {column}")
    conn.execute(
        "INSERT INTO runs (run_id, period, created_at, config_hash, code_version, status, manifest_json) "
        "VALUES ('RUN-OLD', '2026-Q1', '2026-04-02T00:00:00', 'abc', '0.1.0', 'completed', '{}')"
    )
    conn.execute(
        "INSERT INTO entity_scores (run_id, entity_id, risk_index, risk_band, distinct_rules_triggered, "
        "domain_scores_json) VALUES ('RUN-OLD', 'CSE-01', 42.5, 'High Supervisory Concern', 3, '{}')"
    )
    conn.executemany(
        "INSERT INTO domain_scores (run_id, entity_id, domain, score) VALUES ('RUN-OLD', 'CSE-01', ?, ?)",
        [("Escalation", 61.0), ("Investigation", 0.0)],
    )
    store.close()


def test_a_version0_database_is_backed_up_migrated_and_keeps_every_row(tmp_path):
    db = tmp_path / "satsa.db"
    _version0_database(db)
    store = SQLiteStore(db)
    applied = store.schema_versions_applied
    runs = [dict(r) for r in store.conn.execute("SELECT run_id, config_hash, fingerprint FROM runs")]
    scores = store.conn.execute(
        "SELECT risk_index, risk_band, classification_status, coverage FROM entity_scores WHERE run_id = 'RUN-OLD'"
    ).fetchone()
    domains = dict(store.conn.execute("SELECT domain, score FROM domain_scores WHERE run_id = 'RUN-OLD'").fetchall())
    recorded = store.conn.execute("SELECT version, backup_path FROM schema_migrations ORDER BY version").fetchall()
    store.close()

    assert applied == [1, 2]
    assert runs == [{"run_id": "RUN-OLD", "config_hash": "abc", "fingerprint": None}]
    # Legacy values unchanged; what legacy runs never recorded is NULL, never a made-up value.
    assert (scores["risk_index"], scores["risk_band"]) == (42.5, "High Supervisory Concern")
    assert scores["classification_status"] is None and scores["coverage"] is None
    assert domains == {"Escalation": 61.0, "Investigation": 0.0}
    backup = Path(recorded[0]["backup_path"])
    assert [r["version"] for r in recorded] == [1, 2] and backup.exists()
    with sqlite3.connect(backup) as old:  # the backup is the database exactly as it was
        assert old.execute("SELECT count(*) FROM domain_scores").fetchone()[0] == 2
        assert "rule_results" not in {r[0] for r in old.execute("SELECT name FROM sqlite_master")}


def test_reopening_a_migrated_database_applies_nothing_and_takes_no_backup(tmp_path):
    db = tmp_path / "satsa.db"
    SQLiteStore(db).close()
    store = SQLiteStore(db)
    assert store.schema_versions_applied == []
    store.close()
    assert not (tmp_path / "backups").exists()  # a database created moments ago needs none


def _fresh(tmp_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "t.db", isolation_level=None)
    conn.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, v TEXT)")
    conn.executemany("INSERT INTO evidence (v) VALUES (?)", [("a",), ("b",)])
    return conn


def test_a_failing_migration_is_rolled_back_and_not_recorded(tmp_path):
    conn = _fresh(tmp_path)

    def broken(c: sqlite3.Connection) -> None:
        c.execute("ALTER TABLE evidence ADD COLUMN extra TEXT")
        raise RuntimeError("boom")

    with pytest.raises(MigrationError, match="rolled back"):
        apply_migrations(conn, [Migration(1, "broken", broken)], tmp_path / "t.db")
    assert "extra" not in {r[1] for r in conn.execute("PRAGMA table_info(evidence)")}
    assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 0
    assert list((tmp_path / "backups").glob("t-pre-v1-*.db"))  # the backup was taken first


def test_a_migration_that_loses_rows_is_refused(tmp_path):
    conn = _fresh(tmp_path)
    with pytest.raises(MigrationError, match="lost rows"):
        apply_migrations(
            conn, [Migration(1, "lossy", lambda c: c.execute("DELETE FROM evidence WHERE v = 'a'"))], None
        )
    assert conn.execute("SELECT count(*) FROM evidence").fetchone()[0] == 2


def test_an_old_dangling_reference_does_not_block_an_upgrade_but_a_new_one_does(tmp_path):
    conn = sqlite3.connect(tmp_path / "fk.db", isolation_level=None)
    conn.execute("CREATE TABLE parent (id TEXT PRIMARY KEY)")
    conn.execute("CREATE TABLE child (pid TEXT REFERENCES parent (id))")
    conn.execute("INSERT INTO child VALUES ('missing')")  # legacy violation (FKs were not enforced)
    assert apply_migrations(conn, [Migration(1, "add", lambda c: c.execute("CREATE TABLE x (a)"))], None) == [1]
    with pytest.raises(MigrationError, match="foreign_key_check"):
        apply_migrations(
            conn, [Migration(2, "dangling", lambda c: c.execute("INSERT INTO child VALUES ('also missing')"))], None
        )


# ------------------------------------------------------------------ Parquet adoption and recovery


def test_parquet_files_from_before_the_catalog_are_adopted_with_a_backup(tmp_path):
    legacy = tmp_path / "parquet" / "alert" / "entity_id=CSE-01" / "data.parquet"
    legacy.parent.mkdir(parents=True)
    pl.DataFrame({"entity_id": ["CSE-01"] * 3, "alert_id": ["A1", "A2", "A3"]}).write_parquet(legacy)

    store = DuckDBStore(tmp_path)
    store.load_all_tables()
    ids = store.query("SELECT alert_id FROM alert ORDER BY alert_id")["alert_id"].to_list()
    batches = store.catalog.batches()
    problems = store.catalog.verify()
    store.close()

    assert ids == ["A1", "A2", "A3"]
    assert not legacy.exists()
    assert [(b["provenance"], b["state"]) for b in batches] == [("legacy-unknown", "published")]
    assert problems == []
    backups = list((tmp_path / "backups").glob("legacy-parquet-*/alert/entity_id=CSE-01/data.parquet"))
    assert len(backups) == 1 and pl.read_parquet(backups[0]).height == 3


def test_files_left_by_an_interrupted_writer_are_quarantined_and_never_read(tmp_path):
    store = DuckDBStore(tmp_path)
    store.write_partitioned_parquet("alert", pl.DataFrame({"entity_id": ["CSE-01"], "alert_id": ["A1"]}))
    # A crash between moving a batch's file into place and committing it leaves an orphan.
    orphan = tmp_path / "parquet" / "alert" / "entity_id=CSE-01" / "b-BATCH-CRASHED-0.parquet"
    pl.DataFrame({"entity_id": ["CSE-01"], "alert_id": ["GHOST"]}).write_parquet(orphan)
    stale_staging = tmp_path / "staging" / "BATCH-CRASHED2" / "alert"
    stale_staging.mkdir(parents=True)
    store.load_all_tables()
    assert store.query("SELECT alert_id FROM alert")["alert_id"].to_list() == ["A1"]  # readers ignore it

    report = store.catalog.recover()
    store.close()
    assert report == {"staging_discarded": 1, "orphans_quarantined": 1}
    assert not orphan.exists()
    assert list((tmp_path / "quarantine").rglob("b-BATCH-CRASHED-0.parquet"))
    assert not stale_staging.exists()


def test_a_batch_is_published_whole_or_not_at_all(tmp_path):
    store = DuckDBStore(tmp_path)
    with pytest.raises(RuntimeError), store.publication(transport="test") as batch:
        store.write_partitioned_parquet("alert", pl.DataFrame({"entity_id": ["E1"], "alert_id": ["A1"]}))
        store.write_partitioned_parquet("case", pl.DataFrame({"entity_id": ["E1"], "case_id": ["C1"]}))
        raise RuntimeError("the writer died before publishing")
    store.load_all_tables()
    assert store.query("SELECT count(*) AS n FROM alert")["n"][0] == 0
    assert store.query('SELECT count(*) AS n FROM "case"')["n"][0] == 0
    assert store.catalog.batch(batch.batch_id)["state"] == "failed"
    assert not (tmp_path / "staging" / batch.batch_id).exists()

    with store.publication(transport="test") as batch:
        store.write_partitioned_parquet("alert", pl.DataFrame({"entity_id": ["E1"], "alert_id": ["A1"]}))
        store.write_partitioned_parquet("case", pl.DataFrame({"entity_id": ["E1"], "case_id": ["C1"]}))
        batch.publish()
    store.load_all_tables()
    assert store.query("SELECT count(*) AS n FROM alert")["n"][0] == 1
    assert store.query('SELECT count(*) AS n FROM "case"')["n"][0] == 1
    store.close()


def test_a_published_file_is_never_overwritten(tmp_path):
    catalog = Catalog(tmp_path)
    with catalog.open_batch(transport="test", batch_id="FIXED") as writer:
        writer.add_table("alert", pl.DataFrame({"entity_id": ["E1"], "alert_id": ["A1"]}))
        writer.publish()
    # A second batch can never reuse a published batch's id (so its file names).
    with pytest.raises(sqlite3.IntegrityError), catalog.open_batch(transport="test", batch_id="FIXED"):
        pass
    catalog.close()


def test_a_held_batch_is_invisible_until_published_and_can_be_discarded(tmp_path):
    store = DuckDBStore(tmp_path)
    with store.publication(transport="upload") as batch:
        store.write_partitioned_parquet("alert", pl.DataFrame({"entity_id": ["E1"], "alert_id": ["A1"]}))
        batch.hold("held for review")
    store.load_all_tables()
    assert store.query("SELECT count(*) AS n FROM alert")["n"][0] == 0
    store.catalog.recover()  # recovery leaves a held batch alone
    store.catalog.publish_held(batch.batch_id, actor="analyst")
    store.load_all_tables()
    assert store.query("SELECT count(*) AS n FROM alert")["n"][0] == 1

    with store.publication(transport="upload") as second:
        store.write_partitioned_parquet("alert", pl.DataFrame({"entity_id": ["E1"], "alert_id": ["A2"]}))
        second.hold("held for review")
    store.catalog.discard_held(second.batch_id, actor="analyst")
    with pytest.raises(PublicationError):
        store.catalog.publish_held(second.batch_id, actor="analyst")
    store.load_all_tables()
    assert store.query("SELECT alert_id FROM alert")["alert_id"].to_list() == ["A1"]
    store.close()


def test_a_reader_can_load_an_earlier_source_snapshot(tmp_path):
    store = DuckDBStore(tmp_path)
    store.write_partitioned_parquet("alert", pl.DataFrame({"entity_id": ["E1"], "alert_id": ["A1"], "status": ["open"]}))
    first = store.catalog.max_pub_seq()
    store.write_partitioned_parquet(
        "alert", pl.DataFrame({"entity_id": ["E1"], "alert_id": ["A1"], "status": ["closed"]})
    )
    store.load_all_tables(max_pub_seq=first)
    assert store.query("SELECT status FROM alert").rows() == [("open",)]
    store.load_all_tables()
    assert store.query("SELECT status FROM alert").rows() == [("closed",)]
    store.close()
