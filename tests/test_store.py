"""Test storage layer: DuckDB and SQLite with hash chaining."""

import tempfile
from pathlib import Path

import polars as pl

from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def test_duckdb_store_initialization():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = DuckDBStore(tmpdir)
        df = pl.DataFrame(
            {
                "entity_id": ["CSE-01", "CSE-02"],
                "name": ["Entity One", "Entity Two"],
                "sector": ["power", "banking"],
                "size_band": ["large", "medium"],
                "soc_model": ["inhouse", "hybrid"],
                "timezone": ["UTC", "UTC"],
                "declared_shift_hours": ["09:00-18:00", "09:00-18:00"],
            }
        )
        store.write_partitioned_parquet("entity", df)
        res = store.query("SELECT count(*) as cnt FROM entity")
        assert res["cnt"][0] == 2
        store.close()


def test_sqlite_audit_hashchain():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        store = SQLiteStore(db_path)

        # Add 3 audit entries
        store.append_audit("ingest", "system", {"files": 3})
        store.append_audit("run", "supervisor", {"run_id": "run-101"})
        store.append_audit("feedback", "examiner", {"queue_id": "q-1", "status": "confirmed"})

        ok, msg = store.verify_audit_chain()
        assert ok is True
        assert "verified successfully" in msg

        # Test tamper detection
        cursor = store.conn.cursor()
        cursor.execute("UPDATE audit_log SET details_json = '{\"tampered\": true}' WHERE rowid = 2")
        store.conn.commit()

        ok, msg = store.verify_audit_chain()
        assert ok is False
        assert "Tampered record" in msg
        store.close()


def test_stray_unpartitioned_file_does_not_empty_table(tmp_path):
    """An unpartitioned file beside the entity_id= partitions, or a file with
    pass-through source columns, must not wipe every other row on load."""
    store = DuckDBStore(tmp_path)
    store.write_partitioned_parquet(
        "alert",
        pl.DataFrame(
            {
                "entity_id": ["CSE-01"],
                "alert_id": ["A1"],
                "created_at": ["2026-04-01T10:00:00"],
                "system": ["Host1"],  # not an alert column
            }
        ),
    )
    pl.DataFrame({"alert_id": ["A2"], "created_at": ["not-a-date"]}).write_parquet(
        tmp_path / "parquet" / "alert" / "data.parquet"
    )
    store.load_all_tables()
    rows = store.query("SELECT entity_id, alert_id, created_at FROM alert ORDER BY alert_id").rows()
    assert rows[0][:2] == ("CSE-01", "A1") and rows[0][2] is not None
    assert rows[1] == (None, "A2", None)
    store.close()


def test_rewritten_parquet_reloads_from_disk_not_a_file_cache(tmp_path):
    """A re-ingest rewrites data.parquet at the same path and reloads it on the same
    connection. DuckDB's external file cache could serve the old file's bytes (on Linux CI
    the golden test's double ingest failed with "ZSTD Decompression failure" and loaded an
    empty table), so the store turns it off; the reload must see exactly the new rows."""
    store = DuckDBStore(tmp_path)
    assert store.conn.execute("SELECT current_setting('enable_external_file_cache')").fetchone()[0] is False
    for version in range(1, 6):
        frame = pl.DataFrame({"entity_id": ["CSE-01"] * 50, "alert_id": [f"A{version}-{i}" for i in range(50)]})
        file_path = tmp_path / "parquet" / "alert" / "entity_id=CSE-01" / "data.parquet"
        if file_path.exists():
            file_path.unlink()  # a rewrite at the same path, as re-ingest does
        store.write_partitioned_parquet("alert", frame)
        ids = store.query("SELECT alert_id FROM alert ORDER BY alert_id")["alert_id"].to_list()
        assert ids == sorted(frame["alert_id"].to_list())
    store.close()


def _legacy_db(tmp_path, supervisor_passphrase):
    """A database as it looked before `supervisor` was renamed to `analyst`."""
    db = tmp_path / "legacy.db"
    store = SQLiteStore(db)
    store.conn.execute("DELETE FROM identities WHERE username = 'analyst'")
    store.upsert_identity("supervisor", "supervisor", supervisor_passphrase)
    store.upsert_identity("portal_sup", "NCIIPC Supervisor", "Passphrase#12345")
    store.append_audit("login", "supervisor", {"role": "supervisor"})
    store.close()
    return db


def test_migration_renames_default_supervisor_account(tmp_path):
    from satsa.auth.identities import verify_passphrase

    store = SQLiteStore(_legacy_db(tmp_path, "ChangeMe-Supervisor#2026"))
    assert store.get_identity("supervisor") is None
    analyst = store.get_identity("analyst")
    assert analyst is not None and analyst["role"] == "analyst"
    assert verify_passphrase("ChangeMe-Analyst#2026", analyst["pass_salt"], analyst["pass_hash"])
    assert store.get_identity("portal_sup")["role"] == "NCIIPC Analyst"
    # History is left alone, so the hash chain still verifies.
    assert store.verify_audit_chain()[0] is True
    store.close()


def test_migration_keeps_username_of_rotated_supervisor_account(tmp_path):
    store = SQLiteStore(_legacy_db(tmp_path, "Rotated-Passphrase#2026"))
    rotated = store.get_identity("supervisor")
    assert rotated is not None and rotated["role"] == "analyst"
    assert store.get_identity("analyst") is None
    store.close()
