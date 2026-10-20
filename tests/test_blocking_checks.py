"""Blocking data-quality checks (config/data_quality.yaml; docs/data_contract.md, "Blocking
checks"): format errors stop publication like a rejected row; problems that are also supervisory
signals are reported and published as evidence.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from deploy_utils import copy_deployment
from fastapi.testclient import TestClient

from satsa.api import routes
from satsa.ingest.pipeline import DEFAULT_BLOCKING_CHECKS, IngestionPipeline, load_blocking_checks
from satsa.jobs.worker import run_jobs
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

HEADER = "alert_id,rule_id,severity_orig,severity_final,status,disposition,asset_id,created_at,closed_at\n"
CLEAN = [
    "BC-1,R-1,high,high,closed,true_positive,A-1,2026-05-02T10:00:00Z,2026-05-02T11:00:00Z",
    "BC-2,R-1,low,low,closed,false_positive,A-1,2026-05-03T10:00:00Z,2026-05-03T10:30:00Z",
    "BC-3,R-2,medium,medium,open,unknown,A-2,2026-05-04T10:00:00Z,",
]
ASSETS = "asset_id,hostname,criticality\nA-1,host-1,high\nA-2,host-2,low\n"

# One format error each, and the check that must find it.
FORMAT_ERRORS = {
    "unrecognised severity": (
        "BC-4,R-1,high,catastrophic,closed,true_positive,A-1,2026-05-05T10:00:00Z,2026-05-05T11:00:00Z",
        "unrecognised_value", "severity_final"),
    "unrecognised status": (
        "BC-4,R-1,high,high,parked,true_positive,A-1,2026-05-05T10:00:00Z,2026-05-05T11:00:00Z",
        "unrecognised_value", "status"),
    "unrecognised disposition": (
        "BC-4,R-1,high,high,closed,probably fine,A-1,2026-05-05T10:00:00Z,2026-05-05T11:00:00Z",
        "unrecognised_value", "disposition"),
    "duplicate alert id": (
        "BC-1,R-1,high,high,closed,true_positive,A-1,2026-05-05T10:00:00Z,2026-05-05T11:00:00Z",
        "duplicate_primary_keys", None),
    "missing severity": (
        "BC-4,R-1,,,closed,true_positive,A-1,2026-05-05T10:00:00Z,2026-05-05T11:00:00Z",
        "missing_required_field", "severity_final"),
}
# Problems that are also what the rules look for: reported, never blocking by default.
EVIDENCE = {
    "closed before created": (
        "BC-4,R-1,high,high,closed,true_positive,A-1,2026-05-05T10:00:00Z,2026-05-05T09:00:00Z",
        "close_before_create"),
    "alert on an asset the submission lacks": (
        "BC-4,R-1,high,high,closed,true_positive,A-9,2026-05-05T10:00:00Z,2026-05-05T11:00:00Z",
        "orphan_foreign_keys"),
}


def _submission(directory: Path, extra_row: str | None) -> Path:
    directory.mkdir(parents=True)
    rows = CLEAN + ([extra_row] if extra_row else [])
    (directory / "alerts.csv").write_text(HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    (directory / "assets.csv").write_text(ASSETS, encoding="utf-8")
    return directory


def _ingest(tmp_path: Path, extra_row: str | None, policy: str, data_quality: Path | None = None) -> tuple[dict, dict]:
    """The pipeline's result, and what it left behind: DQ checks stored, Parquet files, batches."""
    src = _submission(tmp_path / f"in-{policy}", extra_row)
    (tmp_path / "salt").write_bytes(b"blocking-check-test-salt-32bytes")
    data = tmp_path / f"data-{policy}"
    duck, sql = DuckDBStore(data), SQLiteStore(data / "satsa.db")
    try:
        res = IngestionPipeline(duck, sql, salt_file=tmp_path / "salt", data_quality_path=data_quality).ingest_directory(
            src, bound_entity="CSE-BC", period="2026-Q2", transport="upload", policy=policy)
        checks = [r[0] for r in sql.conn.execute("SELECT check_name FROM dq_issues")]
    finally:
        duck.close()
        sql.close()
    conn = sqlite3.connect(data / "catalog.db")
    try:
        batches = dict(conn.execute("SELECT state, note FROM batches").fetchall())
    finally:
        conn.close()
    left = {"checks": checks, "parquet": sorted(p.name for p in (data / "parquet").rglob("*.parquet")
                                                if "staging" not in p.parts), "batches": batches}
    return res, left


def test_a_clean_submission_is_published_with_nothing_blocking(tmp_path):
    res, left = _ingest(tmp_path, None, "if_clean")
    assert res["status"] == "success" and res["batch_state"] == "published"
    assert res["blocking_issues"] == []
    assert "published" in left["batches"]


@pytest.mark.parametrize("case", sorted(FORMAT_ERRORS))
def test_a_format_error_holds_a_web_upload(tmp_path, case):
    row, check, field = FORMAT_ERRORS[case]
    res, left = _ingest(tmp_path, row, "if_clean")
    assert res["status"] == "held" and res["batch_state"] == "held", res
    assert [(b["check"], b["field"], b["entity_id"]) for b in res["blocking_issues"]] == [(check, field, "CSE-BC")]
    assert check in left["batches"]["held"], "the hold reason names the check"
    assert check in left["checks"], "the issue is stored for the Data Quality page"
    assert left["parquet"] == [], "nothing of a held batch is visible to readers"


@pytest.mark.parametrize("case", sorted(FORMAT_ERRORS))
def test_a_format_error_rejects_an_api_submission_and_stores_nothing(tmp_path, case):
    row, check, field = FORMAT_ERRORS[case]
    res, left = _ingest(tmp_path, row, "strict")
    assert res["status"] == "rejected"
    assert res["error_count"] == 1
    (error,) = res["errors"]
    assert (error["check"], error["field"], error["table"], error["count"]) == (check, field, "alert", 1)
    assert error["records"] and error["reason"]
    assert left == {"checks": [], "parquet": [], "batches": {}}, "a rejected submission leaves no trace"


@pytest.mark.parametrize("case", sorted(FORMAT_ERRORS))
def test_the_cli_policy_publishes_and_reports_a_format_error(tmp_path, case):
    row, check, _field = FORMAT_ERRORS[case]
    res, left = _ingest(tmp_path, row, "auto")
    assert res["status"] == "success" and res["batch_state"] == "published"
    assert [b["check"] for b in res["blocking_issues"]] == [check]
    assert check in left["checks"]


@pytest.mark.parametrize("policy", ["if_clean", "strict"])
@pytest.mark.parametrize("case", sorted(EVIDENCE))
def test_a_supervisory_signal_is_published_as_evidence(tmp_path, case, policy):
    row, check = EVIDENCE[case]
    res, left = _ingest(tmp_path, row, policy)
    assert res["status"] == "success" and res["batch_state"] == "published", res
    assert res["blocking_issues"] == []
    assert check in left["checks"], "still reported"
    assert left["parquet"], "and published for the rules to read"


def test_check_only_says_the_upload_would_be_held(tmp_path):
    row, check, field = FORMAT_ERRORS["unrecognised severity"]
    res, left = _ingest(tmp_path, row, "preview")
    assert res["status"] == "preview"
    assert [(b["check"], b["field"]) for b in res["blocking_issues"]] == [(check, field)]
    assert left["checks"] == [] and left["parquet"] == []


def test_the_policy_is_read_from_config(tmp_path):
    none = tmp_path / "none.yaml"
    none.write_text("blocking_checks: []\n", encoding="utf-8")
    res, _ = _ingest(tmp_path, FORMAT_ERRORS["duplicate alert id"][0], "if_clean", data_quality=none)
    assert res["batch_state"] == "published" and res["blocking_issues"] == []

    stricter = tmp_path / "stricter.yaml"
    stricter.write_text("blocking_checks: [close_before_create]\n", encoding="utf-8")
    res, _ = _ingest(tmp_path / "b", EVIDENCE["closed before created"][0], "if_clean", data_quality=stricter)
    assert res["batch_state"] == "held"


def test_the_shipped_policy_blocks_format_errors_only():
    assert load_blocking_checks("config/data_quality.yaml") == DEFAULT_BLOCKING_CHECKS == {
        "missing_required_field", "duplicate_primary_keys", "unrecognised_value"}
    assert load_blocking_checks("config/no-such-file.yaml") == DEFAULT_BLOCKING_CHECKS


@pytest.mark.parametrize("content", ["blocking_checks: [duplicate_primary_key]\n", "blocking_checks: duplicate\n",
                                     "blocking_checks: [table_write_failed]\n"])
def test_a_misconfigured_policy_is_refused_not_ignored(tmp_path, content):
    bad = tmp_path / "data_quality.yaml"
    bad.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="blocking_checks"):
        load_blocking_checks(bad)


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    return root


def _analyst() -> TestClient:
    client = TestClient(routes.app)
    assert client.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                       follow_redirects=False).status_code == 303
    return client


def test_the_upload_page_holds_and_says_which_check(deployment):
    client = _analyst()
    body = HEADER + "\n".join(CLEAN + [FORMAT_ERRORS["duplicate alert id"][0]]) + "\n"
    r = client.post("/upload", data={"target_entity": "CSE-01", "period": "2026-Q2"},
                    files={"files": ("alerts.csv", body.encode(), "text/csv")}, follow_redirects=False)
    job_id = r.headers["location"].rsplit("/", 1)[1]
    (done,) = run_jobs(job_id)
    assert done["result"]["ingestion_status"] == "held"
    assert "blocking data-quality checks: duplicate_primary_keys: 1 (CSE-01)" in done["result"]["message"]
    assert "duplicate_primary_keys" in client.get("/upload").text, "the held list says why"

    preview = client.post("/upload", data={"target_entity": "CSE-01", "period": "2026-Q2", "preview": "1"},
                          files={"files": ("alerts.csv", body.encode(), "text/csv")}, follow_redirects=False)
    preview_job = preview.headers["location"].rsplit("/", 1)[1]
    run_jobs(preview_job)
    page = client.get(f"/jobs/{preview_job}").text
    assert 'id="previewBlocking"' in page and "Would be held for review" in page


def test_the_api_rejects_with_the_check_and_field(deployment):
    client = _analyst()
    r = client.post("/api/v1/submissions", json={
        "entity_id": "CSE-01", "period": "2026-Q2", "run_assessment_now": False,
        "alerts": [{"alert_id": "API-BC-1", "created_at": "2026-05-02T10:00:00Z", "severity_final": "catastrophic",
                    "closed_by_type": "human"}]})
    assert r.status_code == 422, r.text
    (error,) = r.json()["detail"]["errors"]
    assert (error["check"], error["field"], error["count"]) == ("unrecognised_value", "severity_final", 1)


def test_the_cli_publishes_but_says_a_web_upload_would_be_held(deployment, tmp_path):
    from typer.testing import CliRunner

    from satsa.cli import app

    src = _submission(tmp_path / "cli-in", FORMAT_ERRORS["unrecognised status"][0])
    out = CliRunner().invoke(app, ["ingest", "--data-dir", str(src), "--entity", "CSE-01", "--period", "2026-Q2",
                                   "--parquet-dir", "data", "--db-path", "data/satsa.db"])
    assert out.exit_code == 0, out.output
    assert "Ingestion completed successfully" in out.output
    assert "a web upload would have been held" in out.output and "unrecognised_value" in out.output
