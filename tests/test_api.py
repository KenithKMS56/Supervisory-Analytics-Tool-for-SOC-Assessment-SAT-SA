"""Test offline UI views and REST API endpoints."""

import re

import pytest
from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.jobs.worker import run_jobs

client = TestClient(app)


def _login(c: TestClient, username: str = "analyst", password: str = "ChangeMe-Analyst#2026") -> None:
    resp = c.post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )
    assert resp.status_code == 303, f"login failed: {resp.text}"


# Most tests in this module exercise gated routes (see tests/test_auth.py and
# tests/test_rbac_matrix.py for the dedicated RBAC tests). The analyst may open
# every page these tests touch; review decisions (queue feedback, blind-review
# verdicts) are the examiner's only, so those go through examiner_client.
examiner_client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def _signed_in():
    """Sign in when this module's tests start (a session opened at import can time out first)."""
    _login(client)
    _login(examiner_client, "examiner", "ChangeMe-Examiner#2026")


def test_ui_portfolio_view():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Supervisory Entity Risk Portfolio" in resp.text
    assert "8-Domain Supervisory Heatmap" in resp.text
    assert "CSE-01" in resp.text


def test_ui_entity_profile_view():
    resp = client.get("/entity/CSE-03")
    assert resp.status_code == 200
    assert "CSE-03" in resp.text
    assert "8-Domain Radar vs Peer Median" in resp.text
    assert "KPI Reconciliation Panel" in resp.text


def test_ui_review_queue_view():
    resp = client.get("/queue")
    assert resp.status_code == 200
    assert "Prioritised Supervisory Review Queue" in resp.text
    assert "Top-Risk" in resp.text


def test_ui_dq_coverage_view():
    resp = client.get("/dq")
    assert resp.status_code == 200
    assert "Data Quality & Submission Completeness" in resp.text


def test_ui_runs_audit_view():
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert "Supervisory Runs & Cryptographic Audit Trail" in resp.text
    assert "prev_hash" in resp.text


def test_rest_api_endpoints():
    # 1. Runs
    r_runs = client.get("/api/v1/runs")
    assert r_runs.status_code == 200
    assert isinstance(r_runs.json(), list)

    # 2. Entities
    r_ent = client.get("/api/v1/entities")
    assert r_ent.status_code == 200
    assert len(r_ent.json()) > 0

    # 3. Findings
    r_fnd = client.get("/api/v1/findings")
    assert r_fnd.status_code == 200
    assert len(r_fnd.json()) > 0

    # 4. Queue
    r_q = client.get("/api/v1/queue")
    assert r_q.status_code == 200
    assert len(r_q.json()) > 0

    # 5. Audit verify
    r_aud = client.get("/api/v1/audit/verify")
    assert r_aud.status_code == 200
    assert r_aud.json()["verified"] is True

    # 6. Export CSV
    r_csv = client.get("/api/v1/export/queue.csv")
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]
    assert "queue_id" in r_csv.text


def test_feedback_submission():
    # Fetch an item from queue
    r_q = client.get("/api/v1/queue")
    q_items = r_q.json()
    if q_items:
        first_id = q_items[0]["queue_id"]
        resp = examiner_client.post(
            "/api/v1/feedback",
            data={
                "queue_id": first_id,
                "status": "confirmed",
                "notes": "Verified malicious true positive",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303

        # Verify feedback did not corrupt audit chain
        r_aud = client.get("/api/v1/audit/verify")
        assert r_aud.json()["verified"] is True


def test_ui_alerts_view():
    resp = client.get("/alerts")
    assert resp.status_code == 200
    assert "National SOC Alert Explorer" in resp.text
    assert "CSE-" in resp.text


def test_ui_upload_view():
    resp = client.get("/upload")
    assert resp.status_code == 200
    assert "Periodic Submission & Ingestion Wizard" in resp.text
    assert "Quick Demo Launcher" in resp.text
    assert "Load Demonstration Data" in resp.text  # the suite runs as a demo deployment


def test_ui_blind_review():
    """The analyst draws a sample for the examiner, who judges, submits and then reveals
    (the full blinding checks are in tests/test_blind_tasks.py)."""
    resp = client.get("/blind-review")
    assert resp.status_code == 200
    assert "Draw a blind sample" in resp.text

    run_id = re.search(r'<option value="(RUN-[^"]+)"', resp.text).group(1)
    made = client.post("/blind-review/samples", data={"run_id": run_id, "assignee": "examiner",
                                                       "flagged": 1, "random_n": 0, "control": 0},
                       follow_redirects=False)
    assert made.status_code == 303
    tasks = examiner_client.get("/blind-review").text
    task_url = re.search(r'href="(/blind-review/tasks/BLT-[0-9A-F]{12})"', tasks).group(1)
    assert "Your independent judgement" in examiner_client.get(task_url).text

    sub_resp = examiner_client.post(
        f"{task_url}/submit",
        data={
            "examiner_concern": "Elevated",
            "examiner_priority": "P2",
            "examiner_recommendation": "Formal Audit",
            "examiner_notes": "Evidence shows systematic escalation bottleneck on high severity alerts.",
        },
        follow_redirects=True,
    )
    assert sub_resp.status_code == 200
    assert "Evidence shows systematic escalation bottleneck" in sub_resp.text
    assert "Agreement" not in sub_resp.text  # hidden until revealed
    revealed = examiner_client.post(f"{task_url}/reveal", follow_redirects=True)
    assert "Agreement" in revealed.text and "System assessment" in revealed.text


def test_ui_tuning_view_and_save():
    resp = client.get("/tuning")
    assert resp.status_code == 200
    assert "Supervisory Rule Calibration & Rule-Pack Studio" in resp.text
    assert "Active Config Hash" in resp.text

    from pathlib import Path

    config_path = Path("config/rules.yaml")
    orig_content = config_path.read_text(encoding="utf-8")
    try:
        save_resp = client.post(
            "/tuning/save",
            data={
                "EG01__fast_share_threshold": "0.2",
                "EG04__max_comment_hash_share": "0.45",
            },
            follow_redirects=True,
        )
        assert save_resp.status_code == 200
        assert "Parameters updated!" in save_resp.text
        # The re-assessment is a job (satsa.jobs): it runs in the worker with the saved values.
        job_id = re.search(r"queued as job (JOB-[A-Za-z0-9_-]+)", save_resp.text).group(1)
        (job,) = run_jobs(job_id)
        assert job["state"] == "succeeded", job
        assert job["result"]["run_id"] == f"RUN-{job_id}" and job["result"]["findings_count"] > 0
    finally:
        config_path.write_text(orig_content, encoding="utf-8")


def test_report_downloads():
    # HTML dossier
    r_html = client.get("/reports/entity/CSE-03/html")
    assert r_html.status_code == 200
    assert "CSE-03" in r_html.text

    # Portfolio HTML
    r_port = client.get("/reports/portfolio/html")
    assert r_port.status_code == 200
    assert "SAT-SA Portfolio Supervisory Assessment Report" in r_port.text

    # Findings CSV
    r_fnd_csv = client.get("/reports/export/findings-csv")
    assert r_fnd_csv.status_code == 200
    assert "text/csv" in r_fnd_csv.headers["content-type"]
    assert "rule_id" in r_fnd_csv.text

    # Queue CSV
    r_q_csv = client.get("/reports/export/queue-csv")
    assert r_q_csv.status_code == 200
    assert "text/csv" in r_q_csv.headers["content-type"]

    # PDF Dossier
    r_pdf = client.get("/reports/entity/CSE-03/pdf")
    assert r_pdf.status_code == 200
    assert r_pdf.headers["content-type"] == "application/pdf"
    assert len(r_pdf.content) > 1000
