"""Exploratory anomaly scan, control/process prioritisation, and database/API ingest.

These close the gaps the requirement table recorded as partial: F7 (anomalies and outliers,
including indicators no rule was written for), F8 (peer benchmarking), F10 (controls and
processes prioritised, not only entities and alerts) and F2 (database exports and APIs
reachable from `satsa ingest`).
"""

import json
import sqlite3
from pathlib import Path

import polars as pl
import pytest
import yaml
from fastapi.testclient import TestClient

from satsa import FINDING_NOTICE
from satsa.ingest.adapters import SourceAdapter, stage_api_submission
from satsa.ingest.pipeline import IngestionPipeline
from satsa.models.canonical import Entity
from satsa.peers.anomaly_scan import METRICS, AnomalyScanner
from satsa.peers.grouping import PeerResolver
from satsa.peers.spc import SPCDetector
from satsa.scoring.control_priorities import rank_controls, rank_processes
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.synth.generator import SyntheticDataGenerator

CLEAN_ENTITIES = ("CSE-01", "CSE-04", "CSE-06")  # no defect injected (satsa.synth.defects)


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    root = tmp_path_factory.mktemp("anomaly")
    csv_dir, _ = SyntheticDataGenerator(seed=42).save_dataset(root / "gen")
    duck, lite = DuckDBStore(root), SQLiteStore(root / "satsa.db")
    assert IngestionPipeline(duck, lite).ingest_directory(csv_dir)["status"] == "success"
    duck.load_all_tables()
    yield {"root": root, "csv_dir": csv_dir, "duck": duck, "lite": lite}
    duck.close()
    lite.close()


def _entities(duck: DuckDBStore) -> list[Entity]:
    return [Entity(**r) for r in duck.query("SELECT * FROM entity").iter_rows(named=True)]


def _scan(generated) -> dict:
    duck, lite = generated["duck"], generated["lite"]
    return AnomalyScanner().scan("RUN-T", _entities(duck), duck, PeerResolver(), lite.get_submitted_tables())


def test_clean_entities_raise_no_lead(generated):
    signals = _scan(generated)["signals"]
    assert signals, "the injected defects should surface at least one lead"
    assert not [s for s in signals if s["entity_id"] in CLEAN_ENTITIES]


def test_volume_collapse_is_found_as_a_time_shift(generated):
    """CSE-10's alert volume collapses mid-period (inject_cse10_volume_collapse_and_night_flatline)."""
    shifts = [s for s in _scan(generated)["signals"] if s["entity_id"] == "CSE-10" and s["kind"] == "time_shift"]
    volume = [s for s in shifts if s["metric"] == "monthly:alerts_per_day"]
    assert volume and volume[0]["direction"] == "below"
    assert volume[0]["value"] < volume[0]["baseline"]
    assert volume[0]["detail"]["shift_from"] in volume[0]["detail"]["months"]


def test_template_comments_are_found_as_a_peer_outlier(generated):
    """CSE-07 closes with templated comments (inject_cse07_metric_gaming_and_templates)."""
    hit = [
        s
        for s in _scan(generated)["signals"]
        if s["entity_id"] == "CSE-07" and s["metric"] == "comment_distinct_ratio"
    ]
    assert hit and hit[0]["direction"] == "below" and hit[0]["related_rule"] == "EG04"


def test_every_signal_is_explained_and_reproducible(generated):
    first, second = _scan(generated), _scan(generated)
    assert first == second  # deterministic
    stored = {(m["entity_id"], m["period"], m["metric"]): m["value"] for m in first["metric_values"]}
    for s in first["signals"]:
        assert s["entity_id"] in s["rationale"] and "lead, not a finding" in s["rationale"]
        if s["kind"] == "peer_outlier":
            assert abs(s["z"]) >= 3.5
            assert s["n_peers"] >= 3
            # The flagged value is one of the stored metric values, so it can be re-derived.
            assert stored[(s["entity_id"], "run", s["metric"])] == s["value"]
        else:
            assert len(s["detail"]["months"]) >= 5
            assert s["detail"]["shift_from"] not in s["detail"]["reference_months"]


def test_catalogue_covers_every_capability_domain():
    domains = {m.domain for m in METRICS.values()}
    assert domains == {
        "Threat Detection",
        "Investigation",
        "Escalation",
        "Incident Response",
        "Security Operations",
        "Governance and Oversight",
        "Operational Discipline",
        "Cyber Resilience",
    }


def test_peer_outlier_needs_enough_peers_and_records():
    scanner = AnomalyScanner()
    values = {
        "A": {"tp_share": (0.50, 500)},
        "B": {"tp_share": (0.10, 500)},
        "C": {"tp_share": (0.11, 500)},
        "D": {"tp_share": (0.09, 500)},
    }
    assert scanner._peer_outliers("R", "A", ["B", "C", "D"], "cohort", values)
    assert not scanner._peer_outliers("R", "A", ["B", "C"], "cohort", values)  # 2 peers < min_peers
    values["A"]["tp_share"] = (0.50, 10)  # population below min_population
    assert not scanner._peer_outliers("R", "A", ["B", "C", "D"], "cohort", values)


def test_metric_from_a_table_never_submitted_is_not_compared(generated):
    duck = generated["duck"]
    manifest = {e.entity_id: {"alert", "entity"} for e in _entities(duck)}
    values = AnomalyScanner().compute_metrics(duck, manifest)
    for metrics in values.values():
        assert "escalation_per_tp" not in metrics  # needs the escalation table
        assert "tp_share" in metrics


def test_cusum_spread_floor_keeps_flat_series_finite():
    flat = [1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
    assert SPCDetector.cusum(flat, min_scale=0.1)[2] == []
    # A shift lasting half the series is absorbed by a self-referenced median, which is why
    # the scan tests later months against a reference period instead.
    step = [2.0, 2.0, 2.0, 1.2, 1.2, 1.2]
    assert SPCDetector.cusum(step, min_scale=0.1)[2] == []
    _hi, lo, alarms = SPCDetector.cusum(step[3:], threshold_h=4.0, min_scale=0.1, reference=step[:3])
    assert alarms == [0, 1, 2] and all(v < float("inf") for v in lo)


def test_leads_do_not_change_scores_and_are_persisted(generated, tmp_path):
    duck, lite = generated["duck"], generated["lite"]
    off = tmp_path / "anomaly_off.yaml"
    off.write_text(yaml.safe_dump({"anomaly_scan": {"enabled": False}}), encoding="utf-8")
    with_scan = AssessmentRunner(duck, lite).run_assessment(refresh_tables=False, dry_run=True)
    without = AssessmentRunner(duck, lite, anomaly_config_path=off).run_assessment(
        refresh_tables=False, dry_run=True
    )
    assert with_scan["entity_scores"] == without["entity_scores"]
    assert with_scan["anomaly_signals_count"] > 0 and without["anomaly_signals_count"] == 0

    res = AssessmentRunner(duck, lite).run_assessment(refresh_tables=False)
    run_id = res["run_id"]
    assert len(lite.get_anomaly_signals(run_id)) == res["anomaly_signals_count"]
    n_values = lite.conn.execute("SELECT count(*) FROM metric_values WHERE run_id = ?", (run_id,)).fetchone()[0]
    assert n_values > 0
    manifest = json.loads(lite.conn.execute("SELECT manifest_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0])
    assert manifest["anomaly_signals"] == res["anomaly_signals_count"]
    assert manifest["anomaly_config_hash"]

    controls = rank_controls(lite.conn, run_id)
    processes = rank_processes(lite.conn, run_id)
    assert controls and processes
    failing = [c["entities_failing"] for c in controls]
    assert failing == sorted(failing, reverse=True)
    findings = lite.conn.execute(
        "SELECT count(DISTINCT rule_id) FROM findings WHERE run_id = ?", (run_id,)
    ).fetchone()[0]
    assert len(controls) == findings
    assert sum(p["anomaly_leads"] for p in processes) == res["anomaly_signals_count"]


def test_control_ranking_orders_by_breadth_then_severity():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE findings (run_id, rule_id, domain, entity_id, severity, score, title);
        CREATE TABLE dq_issues (issue_id, check_name);
        CREATE TABLE domain_scores (run_id, domain, entity_id, score);
        INSERT INTO findings VALUES ('R','EG01','Investigation','CSE-01','critical',80,'t'),
                                    ('R','EG04','Investigation','CSE-01','medium',30,'t'),
                                    ('R','EG04','Investigation','CSE-02','medium',30,'t'),
                                    ('R','NS07','Incident Response','CSE-02','critical',60,'t');
        INSERT INTO dq_issues VALUES ('DQ-NOT-ASSESSED-CSE-03-EG04','rule_not_assessed');
        INSERT INTO domain_scores VALUES ('R','Investigation','CSE-01',70),('R','Investigation','CSE-02',55),
                                         ('R','Escalation','CSE-01',90),('R','Escalation','CSE-02',0);
        """
    )
    controls = rank_controls(conn, "R")
    assert [c["rule_id"] for c in controls] == ["EG04", "EG01", "NS07"]
    assert controls[0]["entities_not_assessed"] == 1
    processes = rank_processes(conn, "R")
    assert [p["domain"] for p in processes] == ["Investigation", "Escalation"]
    assert processes[0]["entities_of_concern"] == 2


def test_sqlite_database_export_ingests_like_the_csv_files(generated, tmp_path):
    db = tmp_path / "submission.sqlite"
    conn = sqlite3.connect(db)
    for csv in sorted(generated["csv_dir"].glob("*.csv")):
        frame = pl.read_csv(csv, infer_schema_length=0)  # every column as text, like a DB dump
        if frame.is_empty():
            continue
        cols = ", ".join(f'"{c}"' for c in frame.columns)
        conn.execute(f'CREATE TABLE "{csv.stem}" ({cols})')
        conn.executemany(
            f'INSERT INTO "{csv.stem}" VALUES ({", ".join("?" for _ in frame.columns)})', frame.rows()
        )
    conn.commit()
    conn.close()
    assert SourceAdapter.list_sqlite_tables(db)

    from_db = IngestionPipeline(DuckDBStore(tmp_path / "db"), SQLiteStore(tmp_path / "db.meta")).ingest_directory(
        _only(db, tmp_path / "in")
    )
    from_csv = IngestionPipeline(DuckDBStore(tmp_path / "csv"), SQLiteStore(tmp_path / "csv.meta")).ingest_directory(
        generated["csv_dir"]
    )
    assert from_db["status"] == "success"
    assert from_db["row_counts"] == from_csv["row_counts"]


def _only(path: Path, folder: Path) -> Path:
    folder.mkdir()
    target = folder / path.name
    target.write_bytes(path.read_bytes())
    return folder


def test_a_file_named_db_that_is_not_a_database_is_reported(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "export.db").write_text("not a database", encoding="utf-8")
    res = IngestionPipeline(DuckDBStore(tmp_path), SQLiteStore(tmp_path / "meta.db")).ingest_directory(tmp_path / "in")
    assert res["status"] == "error"


def test_api_submission_is_staged_and_ingested(generated, tmp_path):
    fixtures = tmp_path / "api"
    fixtures.mkdir()
    for table in ("entity", "alert"):
        rows = pl.read_csv(generated["csv_dir"] / f"{table}.csv", infer_schema_length=0)
        rows = rows.filter(pl.col("entity_id") == "CSE-01")
        (fixtures / f"{table}.json").write_text(json.dumps({"items": rows.to_dicts()}), encoding="utf-8")
    cfg = tmp_path / "api.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "endpoints": {
                    t: {"fixture_path": str(fixtures / f"{t}.json"), "records_key": "items"}
                    for t in ("entity", "alert")
                }
            }
        ),
        encoding="utf-8",
    )
    staged = tmp_path / "staged"
    counts = stage_api_submission(cfg, staged)
    assert counts["alert"] > 0 and counts["entity"] == 1
    res = IngestionPipeline(DuckDBStore(tmp_path / "pq"), SQLiteStore(tmp_path / "m.db")).ingest_directory(staged)
    assert res["status"] == "success"
    assert res["entities"] == ["CSE-01"]


def test_api_submission_refuses_a_non_loopback_endpoint(tmp_path):
    cfg = tmp_path / "api.yaml"
    cfg.write_text(yaml.safe_dump({"endpoints": {"alert": {"url": "https://example.com/alerts"}}}), encoding="utf-8")
    with pytest.raises(ValueError, match="non-loopback"):
        stage_api_submission(cfg, tmp_path / "out")


def test_routes_show_leads_and_priorities_with_the_notice():
    from satsa.api.routes import app

    duck, lite = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    try:
        if duck.query("SELECT count(*) AS n FROM entity").is_empty():
            pytest.skip("shared data store not bootstrapped")
        res = AssessmentRunner(duck, lite).run_assessment(actor="test-suite")
        assert res["status"] == "success"
        run_id = res["run_id"]
        client = TestClient(app)
        r = client.post("/login", data={"username": "examiner", "password": "ChangeMe-Examiner#2026"}, follow_redirects=False)
        assert r.status_code == 303

        leads = client.get("/api/v1/anomalies").json()
        assert len(leads) == res["anomaly_signals_count"]
        assert all(s["supervisory_notice"] == FINDING_NOTICE and s["run_id"] == run_id for s in leads)
        prio = client.get("/api/v1/priorities").json()
        assert prio["run_id"] == run_id and prio["processes"]
        assert all(c["supervisory_notice"] == FINDING_NOTICE for c in prio["controls"])

        page = client.get("/portfolio").text
        assert "Controls &amp; Processes to Prioritise" in page and 'id="processPriorityTable"' in page
        if leads:
            ent = leads[0]["entity_id"]
            profile = client.get(f"/entity/{ent}").text
            assert 'id="anomalyLeadsTable"' in profile and leads[0]["label"] in profile
    finally:
        if "run_id" in locals():
            with lite.conn:
                lite.conn.execute(
                    "DELETE FROM finding_evidences WHERE finding_id IN (SELECT finding_id FROM findings WHERE run_id = ?)",
                    (run_id,),
                )
                for table in (
                    "runs", "entity_scores", "domain_scores", "findings", "review_queue",
                    "systemic_findings", "anomaly_signals", "metric_values",
                ):
                    lite.conn.execute(f"DELETE FROM {table} WHERE run_id = ?", (run_id,))
        duck.close()
        lite.close()
