"""Check only: a submission is read, mapped and validated and the report shown, with nothing
published or recorded (docs/data_contract.md, "Publication policy"; docs/product_brief.md
section 4, "mapping preview"). On a private copy of the deployment.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from deploy_utils import copy_deployment
from fastapi.testclient import TestClient

from satsa.api import routes
from satsa.ingest.pipeline import IngestionPipeline
from satsa.jobs.worker import run_jobs
from satsa.store.catalog import published_sequence
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

ALERTS = (
    "alert_id,rule_id,category,severity_orig,severity_final,asset_id,created_at\n"
    "PV-1,R-1,malware,high,high,A-1,2026-05-02T10:00:00Z\n"
    "PV-2,R-1,malware,high,high,A-1,not a time\n"
    "PV-3,R-2,phishing,low,low,A-2,2026-05-03T11:00:00Z\n"
)


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    return root


def _state() -> dict:
    """Everything a publication or a recorded submission would change."""
    conn = sqlite3.connect("data/satsa.db")
    try:
        counts = {t: conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                  for t in ("dq_issues", "submitted_tables", "runs")}
    finally:
        conn.close()
    files = sorted(str(p) for p in Path("data/parquet").rglob("*.parquet"))
    return {**counts, "pub_seq": published_sequence("data"), "parquet": files}


def test_a_preview_reports_everything_and_changes_nothing(deployment, tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    (src / "alerts.csv").write_text(ALERTS, encoding="utf-8")
    before = _state()
    duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    try:
        res = IngestionPipeline(duck, sql).ingest_directory(
            src, bound_entity="CSE-01", period="2026-Q2", transport="upload", policy="preview",
            batch_id="BATCH-PREVIEW-TEST-1")
        audit = sql.conn.execute("SELECT action FROM audit_log ORDER BY rowid DESC LIMIT 1").fetchone()[0]
    finally:
        duck.close()
        sql.close()
    assert res["status"] == "preview" and res["batch_state"] == "preview"
    assert _state() == before, "a preview must not publish, record or store anything"
    assert audit == "ingest_preview"
    # The report is the full one: per file, rule coverage and the DQ issues it did not store.
    (f,) = res["file_coverage"]
    assert f["rows_read"] == 3
    assert res["invalid_timestamps"] and any(i["check_name"] for i in res["dq_issue_list"])
    coverage = res["rule_coverage"]["CSE-01"]
    assert set(coverage["assessed"]) | set(coverage["not_assessed"]) | set(coverage["degraded"])
    catalog = sqlite3.connect("data/catalog.db")
    try:
        state, note = catalog.execute("SELECT state, note FROM batches WHERE batch_id = 'BATCH-PREVIEW-TEST-1'").fetchone()
    finally:
        catalog.close()
    assert state == "discarded" and "preview" in note
    assert not (deployment / "data" / "staging" / "BATCH-PREVIEW-TEST-1").exists()


def test_check_only_on_the_upload_page_shows_the_report_and_publishes_nothing(deployment):
    client = TestClient(routes.app)
    assert client.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                       follow_redirects=False).status_code == 303
    before = _state()
    r = client.post("/upload", data={"target_entity": "CSE-01", "period": "2026-Q2", "preview": "1"},
                    files={"files": ("alerts.csv", ALERTS.encode(), "text/csv")}, follow_redirects=False)
    job_id = r.headers["location"].rsplit("/", 1)[1]
    (done,) = run_jobs(job_id)
    assert done["state"] == "succeeded", done
    assert done["result"]["ingestion_status"] == "preview" and "run_id" not in done["result"]
    assert _state() == before
    page = client.get(f"/jobs/{job_id}").text
    assert "Checked only: nothing was published" in page
    assert "What these files would give (not published)" in page and "Rules the entity could be assessed on" in page
    assert "Unreadable timestamps" in page

    # The same files submitted for real are a new job, not a repeat of the check.
    r2 = client.post("/upload", data={"target_entity": "CSE-01", "period": "2026-Q2"},
                     files={"files": ("alerts.csv", ALERTS.encode(), "text/csv")}, follow_redirects=False)
    job2 = r2.headers["location"].rsplit("/", 1)[1]
    assert job2 != job_id
    (real,) = run_jobs(job2)
    assert real["result"]["ingestion_status"] == "held"  # the unreadable timestamp holds it, as always


def test_the_cli_checks_without_publishing(deployment, tmp_path):
    from typer.testing import CliRunner

    from satsa.cli import app

    src = tmp_path / "cli-in"
    src.mkdir()
    (src / "alerts.csv").write_text(ALERTS, encoding="utf-8")
    before = _state()
    out = CliRunner().invoke(app, ["ingest", "--data-dir", str(src), "--entity", "CSE-01", "--period", "2026-Q2",
                                   "--check-only", "--parquet-dir", "data", "--db-path", "data/satsa.db"])
    assert out.exit_code == 0, out.output
    assert "Checked only: nothing was published" in out.output and "alerts.csv" in out.output
    assert _state() == before
