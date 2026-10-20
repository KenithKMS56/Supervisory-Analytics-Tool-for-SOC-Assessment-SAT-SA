"""A recorded run replays to the same results after corrections arrive and the configuration
changes (brief §6): it reads its own source snapshot and its own configuration snapshot."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from satsa.scoring.replay import ReplayError, replay_run
from satsa.scoring.runner import AssessmentRunner
from satsa.store.catalog import CATALOG_FILE, Catalog
from satsa.store.duckdb import DuckDBStore
from satsa.store.migrations import backup_database
from satsa.store.sqlite import SQLiteStore


def _copy_shared_data(tmp_path: Path) -> Path:
    dest = tmp_path / "data"
    shutil.copytree("data/parquet", dest / "parquet")
    catalog = Catalog("data")
    try:
        backup_database(catalog.conn, dest / CATALOG_FILE)
    finally:
        catalog.close()
    return dest


def _runner(duck: DuckDBStore, sql: SQLiteStore, cfg: Path) -> AssessmentRunner:
    return AssessmentRunner(
        duck,
        sql,
        rules_config_path=cfg / "rules.yaml",
        scoring_config_path=cfg / "scoring.yaml",
        peers_config_path=cfg / "peers.yaml",
        systemic_config_path=cfg / "systemic.yaml",
        anomaly_config_path=cfg / "anomaly.yaml",
    )


def test_a_run_replays_after_a_correction_and_a_configuration_change(tmp_path):
    data = _copy_shared_data(tmp_path)
    cfg = tmp_path / "config"
    shutil.copytree("config", cfg)
    sql = SQLiteStore(tmp_path / "s.db")
    duck = DuckDBStore(data)
    run = _runner(duck, sql, cfg).run_assessment(period="2026-Q1", actor="test")
    assert run["status"] == "success"

    # Afterwards: a correction closes every alert of one entity, and the scoring changes.
    duck.load_all_tables()
    entity = duck.query("SELECT entity_id FROM alert GROUP BY entity_id ORDER BY count(*) DESC LIMIT 1").item()
    corrected = duck.query(
        "SELECT * REPLACE ('2026-01-01 00:00:00'::TIMESTAMP AS closed_at, 'false_positive' AS disposition) "
        "FROM alert WHERE entity_id = ?",
        [entity],
    )
    duck.write_partitioned_parquet("alert", corrected)
    scoring = yaml.safe_load((cfg / "scoring.yaml").read_text(encoding="utf-8"))
    scoring["scoring"]["breadth_weight"] = 0.5
    (cfg / "scoring.yaml").write_text(yaml.safe_dump(scoring), encoding="utf-8")
    fresh = _runner(duck, sql, cfg).run_assessment(period="2026-Q1", actor="test", dry_run=True)
    duck.close()
    assert fresh["fingerprint"] != run["fingerprint"]  # the live inputs did change

    report = replay_run(run["run_id"], data, sql)
    sql.close()
    assert report["results_match"], report
    assert report["fingerprint_match"], report["differences"]


def test_a_run_without_a_snapshot_says_it_cannot_be_replayed(tmp_path):
    sql = SQLiteStore(tmp_path / "s.db")
    sql.conn.execute(
        "INSERT INTO runs (run_id, period, created_at, config_hash, code_version, status) "
        "VALUES ('RUN-LEGACY', '2026-Q1', '2026-01-01', 'abc', '0.1.0', 'completed')"
    )
    with pytest.raises(ReplayError, match="cannot be replayed"):
        replay_run("RUN-LEGACY", tmp_path / "d", sql)
    sql.close()
