"""Regression tests for the confirmed defects B01-B06 of docs/product_brief.md (section 2).

Each test was written against commit 47f10c9 first and failed there (docs/baseline_product_brief.md
records the failing run); the fixes make them pass. They assert the required result from the
brief's defect register, not an implementation detail.
"""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

import polars as pl
import pytest
import yaml
from fastapi.testclient import TestClient

from satsa.ingest.pipeline import IngestionPipeline
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

ALERT_HEADER = "entity_id,alert_id,created_at,closed_at,severity_final,disposition,closed_by,rule_id,asset_id,category"


def _write(path: Path, header: str, rows: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")


def _stores(tmp_path: Path) -> tuple[DuckDBStore, SQLiteStore]:
    return DuckDBStore(tmp_path / "d"), SQLiteStore(tmp_path / "s.db")


def _copy_shared_data(tmp_path: Path) -> Path:
    """A private copy of the session's published data, so a test's runs never become the latest
    run that other tests read. The catalog is copied with SQLite's backup API (WAL-safe)."""
    from satsa.store.catalog import CATALOG_FILE, Catalog
    from satsa.store.migrations import backup_database

    dest = tmp_path / "data"
    shutil.copytree("data/parquet", dest / "parquet")
    catalog = Catalog("data")
    try:
        backup_database(catalog.conn, dest / CATALOG_FILE)
    finally:
        catalog.close()
    return dest


def _copy_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "config"
    shutil.copytree("config", cfg)
    return cfg


def _runner(duck: DuckDBStore, sql: SQLiteStore, cfg: Path = Path("config")) -> AssessmentRunner:
    return AssessmentRunner(
        duck,
        sql,
        rules_config_path=cfg / "rules.yaml",
        scoring_config_path=cfg / "scoring.yaml",
        peers_config_path=cfg / "peers.yaml",
        systemic_config_path=cfg / "systemic.yaml",
        anomaly_config_path=cfg / "anomaly.yaml",
    )


# ------------------------------------------------------------------------------------- B01


def test_b01_asset_only_entity_is_insufficient_evidence_not_low_concern(tmp_path):
    """One asset and no supporting SOC tables: 0/20 rules assessed, insufficient evidence, and no
    reassuring 'Low Supervisory Concern' band."""
    src = tmp_path / "in"
    _write(src / "asset.csv", "entity_id,asset_id,asset_type,criticality,monitored_flag", ["B01-ENT,H-1,server,5,true"])
    duck, sql = _stores(tmp_path)
    IngestionPipeline(duck, sql, salt_file=tmp_path / "salt").ingest_directory(src)
    res = AssessmentRunner(duck, sql).run_assessment(period="2026-Q1", actor="test")
    run_id = res["run_id"]

    score = sql.conn.execute(
        "SELECT risk_band, classification_status, rules_assessed, rules_applicable FROM entity_scores "
        "WHERE run_id = ? AND entity_id = 'B01-ENT'",
        (run_id,),
    ).fetchone()
    states = dict(
        sql.conn.execute(
            "SELECT rule_id, state FROM rule_results WHERE run_id = ? AND entity_id = 'B01-ENT'", (run_id,)
        ).fetchall()
    )
    domains = sql.conn.execute(
        "SELECT domain, score FROM domain_scores WHERE run_id = ? AND entity_id = 'B01-ENT'", (run_id,)
    ).fetchall()
    duck.close()
    sql.close()

    assert score["classification_status"] == "insufficient_evidence"
    assert score["risk_band"] != "Low Supervisory Concern"
    assert (score["rules_assessed"], score["rules_applicable"]) == (0, 20)
    assert len(states) == 20 and set(states.values()) == {"insufficient_evidence"}
    # An unassessable domain is unknown, not zero.
    assert domains and all(d["score"] is None for d in domains)


def test_b01_missing_escalation_table_is_not_a_clean_escalation_result(tmp_path):
    """Alerts only: EG03 (critical without escalation) must be insufficient evidence, not assessed
    clear; an independently supported finding elsewhere must survive."""
    src = tmp_path / "in"
    rows = [
        f"B01B,A-{i},2026-01-{(i % 27) + 1:02d}T09:00:00,2026-01-{(i % 27) + 1:02d}T09:30:00,critical,true_positive,u{i % 3},R1,H1,malware"
        for i in range(40)
    ]
    _write(src / "alert.csv", ALERT_HEADER, rows)
    duck, sql = _stores(tmp_path)
    IngestionPipeline(duck, sql, salt_file=tmp_path / "salt").ingest_directory(src)
    run_id = AssessmentRunner(duck, sql).run_assessment(period="2026-Q1", actor="test")["run_id"]
    states = dict(
        sql.conn.execute("SELECT rule_id, state FROM rule_results WHERE run_id = ? AND entity_id = 'B01B'", (run_id,))
    )
    missing = json.loads(
        sql.conn.execute(
            "SELECT missing_inputs_json FROM rule_results WHERE run_id = ? AND entity_id = 'B01B' AND rule_id = 'EG03'",
            (run_id,),
        ).fetchone()[0]
    )
    duck.close()
    sql.close()
    assert states["EG03"] == "insufficient_evidence"
    assert "escalation" in missing
    assert any(s in ("finding", "assessed_clear") for s in states.values())


# ------------------------------------------------------------------------------------- B02


@pytest.fixture
def analyst():
    c = TestClient(__import__("satsa.api.routes", fromlist=["app"]).app)
    r = c.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"}, follow_redirects=False)
    assert r.status_code == 303
    return c


@pytest.fixture
def fresh_entity():
    eid = f"ZZB-{uuid.uuid4().hex[:8].upper()}"
    yield eid
    # Leave the shared session dataset as it was for the tests that follow.
    for part in Path("data/parquet").glob(f"*/entity_id={eid}"):
        shutil.rmtree(part, ignore_errors=True)


def _parquet_text(entity_id: str) -> str:
    return "\n".join(
        json.dumps(pl.read_parquet(f).to_dicts(), default=str)
        for f in Path("data/parquet").rglob("*.parquet")
        if f"entity_id={entity_id}" in f.as_posix()
    )


def test_b02_json_submission_applies_the_same_privacy_processing_as_files(analyst, fresh_entity):
    payload = {
        "entity_id": fresh_entity,
        "period": "2026-Q1",
        "alerts": [
            {
                "alert_id": f"{fresh_entity}-A1",
                "created_at": "2026-02-01T10:00:00Z",
                "closed_at": "2026-02-01T11:00:00Z",
                "severity_final": "high",
                "closed_by": "Alice Analyst alice@example.org",
                "closed_by_type": "human",
                "analyst_phone": "+91 98765 43210",
            }
        ],
        "run_assessment_now": False,
    }
    r = analyst.post("/api/v1/submissions", json=payload)
    assert r.status_code == 200, r.text
    stored = _parquet_text(fresh_entity)
    assert f"{fresh_entity}-A1" in stored
    assert "alice@example.org" not in stored and "Alice Analyst" not in stored
    assert "98765" not in stored


def test_b02_malformed_timestamps_are_rejected_with_details(analyst, fresh_entity):
    payload = {
        "entity_id": fresh_entity,
        "period": "2026-Q1",
        "alerts": [{"alert_id": f"{fresh_entity}-A1", "created_at": "31/31/2026 99:99", "severity_final": "high"}],
        "run_assessment_now": False,
    }
    r = analyst.post("/api/v1/submissions", json=payload)
    assert r.status_code == 422, r.text
    errors = r.json()["detail"]["errors"]
    assert any(e["table"] == "alert" and e["field"] == "created_at" and e["row"] == 1 for e in errors)
    assert _parquet_text(fresh_entity) == ""


# ------------------------------------------------------------------------------------- B03


def test_b03_row_entity_must_match_the_batch_entity(analyst, fresh_entity):
    other = f"ZZO-{uuid.uuid4().hex[:8].upper()}"
    payload = {
        "entity_id": fresh_entity,
        "period": "2026-Q1",
        "alerts": [{"entity_id": other, "alert_id": "X-1", "created_at": "2026-02-01T10:00:00Z", "severity_final": "high"}],
        "run_assessment_now": False,
    }
    r = analyst.post("/api/v1/submissions", json=payload)
    assert r.status_code == 422, r.text
    assert _parquet_text(other) == "" and _parquet_text(fresh_entity) == ""


def test_b03_alternate_period_labels_cannot_evade_the_duplicate_rule(analyst, fresh_entity):
    def batch(period: str, alert_suffix: str) -> dict:
        return {
            "entity_id": fresh_entity,
            "period": period,
            "alerts": [
                {"alert_id": f"{fresh_entity}-{alert_suffix}", "created_at": "2026-02-01T10:00:00Z", "severity_final": "high"}
            ],
            "run_assessment_now": False,
        }

    assert analyst.post("/api/v1/submissions", json=batch("2026-Q1", "A1")).status_code == 200
    # February is inside Q1: a monthly label for the same entity is an overlapping submission.
    overlap = analyst.post("/api/v1/submissions", json=batch("2026-02", "A2"))
    assert overlap.status_code == 409, overlap.text
    # Exactly the same submission again is an idempotent retry, not a second batch.
    again = analyst.post("/api/v1/submissions", json=batch("2026-Q1", "A1"))
    assert again.status_code == 200 and again.json().get("idempotent_replay") is True


# ------------------------------------------------------------------------------------- B04


def test_b04_q1_and_q2_assessments_read_their_own_period(tmp_path):
    duck, sql = DuckDBStore(_copy_shared_data(tmp_path)), SQLiteStore(tmp_path / "s.db")
    runner = AssessmentRunner(duck, sql)
    q1 = runner.run_assessment(period="2026-Q1", actor="test")
    q2 = runner.run_assessment(period="2026-Q2", actor="test")
    assert q1["status"] == q2["status"] == "success"
    assert q1["entity_scores"] != q2["entity_scores"]
    # No alert cited as evidence by a Q1 finding was created outside Q1.
    ids = [
        r[0]
        for r in sql.conn.execute(
            "SELECT e.record_id FROM finding_evidences e JOIN findings f USING (finding_id) "
            "WHERE f.run_id = ? AND e.record_type = 'alert'",
            (q1["run_id"],),
        )
    ]
    duck.load_all_tables()
    if ids:
        placeholders = ", ".join("?" for _ in ids)
        outside = duck.query(
            f"SELECT count(*) FROM alert WHERE alert_id IN ({placeholders}) "
            "AND (created_at < '2026-01-01' OR created_at >= '2026-04-01')",
            ids,
        ).row(0)[0]
        assert outside == 0
    selection = json.loads(
        sql.conn.execute("SELECT manifest_json FROM runs WHERE run_id = ?", (q1["run_id"],)).fetchone()[0]
    )["selection"]
    assert selection["start"].startswith("2026-01-01") and selection["end_exclusive"].startswith("2026-04-01")
    duck.close()
    sql.close()


# ------------------------------------------------------------------------------------- B05


def test_b05_an_updated_alert_replaces_its_earlier_version(tmp_path):
    duck, sql = _stores(tmp_path)
    pipe = IngestionPipeline(duck, sql, salt_file=tmp_path / "salt")
    first, second = tmp_path / "v1", tmp_path / "v2"
    _write(first / "alert.csv", ALERT_HEADER, ["B05,A-1,2026-01-05T09:00:00,,high,,,R1,H1,malware"])
    _write(second / "alert.csv", ALERT_HEADER, ["B05,A-1,2026-01-05T09:00:00,2026-01-05T12:00:00,high,true_positive,u1,R1,H1,malware"])
    pipe.ingest_directory(first)
    pipe.ingest_directory(second)
    duck.load_all_tables()
    rows = duck.query("SELECT alert_id, closed_at, disposition FROM alert WHERE entity_id = 'B05'").rows()
    duck.close()
    sql.close()
    assert len(rows) == 1
    assert rows[0][1] is not None and rows[0][2] == "true_positive"


# ------------------------------------------------------------------------------------- B06


def test_b06_changing_the_scoring_breadth_weight_changes_the_reported_config_identity(tmp_path):
    cfg = _copy_config(tmp_path)
    duck, sql = DuckDBStore(_copy_shared_data(tmp_path)), SQLiteStore(tmp_path / "s.db")
    before = _runner(duck, sql, cfg).run_assessment(period="2026-H1", actor="test", dry_run=True)
    scoring = yaml.safe_load((cfg / "scoring.yaml").read_text(encoding="utf-8"))
    scoring["scoring"]["breadth_weight"] = 0.30
    (cfg / "scoring.yaml").write_text(yaml.safe_dump(scoring), encoding="utf-8")
    after = _runner(duck, sql, cfg).run_assessment(period="2026-H1", actor="test", dry_run=True)
    duck.close()
    sql.close()
    assert before["entity_scores"] != after["entity_scores"]
    assert before["config_hash"] != after["config_hash"]
    assert before["fingerprint"] != after["fingerprint"]


# ------------------------------------------------------- defects found at baseline (not in the brief)


def test_declared_kpis_are_compared_whatever_their_case(tmp_path):
    """The registration form wrote `mttr`, EG10 read only `MTTR`: a declared KPI was never compared."""
    from satsa.rules.registry import RuleRegistry

    duck = DuckDBStore(tmp_path)
    duck.write_partitioned_parquet(
        "alert",
        pl.DataFrame(
            {
                "entity_id": ["KPI-ENT"] * 20,
                "alert_id": [f"A{i}" for i in range(20)],
                "severity_final": ["high"] * 20,
                "created_at": ["2026-01-05T09:00:00"] * 20,
                "closed_at": ["2026-01-05T19:00:00"] * 20,  # 600 minutes each
            }
        ),
    )
    duck.write_partitioned_parquet(
        "declared_kpi",
        pl.DataFrame({"entity_id": ["KPI-ENT"], "period": ["2026-Q1"], "metric": ["mttr"], "severity": ["HIGH"],
                      "value": [60.0]}),
    )
    findings, _ = RuleRegistry().get_rule("EG10").evaluate("KPI-ENT", duck, [], "RUN-T")
    duck.close()
    assert len(findings) == 1 and findings[0].peer_comparison["declared_mttr_mins"] == 60.0
