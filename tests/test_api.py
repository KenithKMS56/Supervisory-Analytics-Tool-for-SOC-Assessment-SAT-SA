"""Test offline UI views and REST API endpoints."""

from fastapi.testclient import TestClient

from satsa.api.routes import app

client = TestClient(app)


def _login(c: TestClient, username: str = "admin", password: str = "ChangeMe-Admin#2026") -> None:
    resp = c.post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )
    assert resp.status_code == 303, f"login failed: {resp.text}"


# Most tests in this module exercise formerly-open routes that now require an
# authenticated admin/supervisor/examiner session (see tests/test_auth.py for
# the dedicated unauthenticated/wrong-role/audit-actor RBAC tests). Logging in
# once as admin here keeps this module's existing coverage green since admin
# is permitted on every gated route these tests touch.
_login(client)


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
        resp = client.post(
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
    assert "National SOC Alert Telemetry Explorer" in resp.text
    assert "CSE-" in resp.text


def test_ui_upload_view():
    resp = client.get("/upload")
    assert resp.status_code == 200
    assert "Telemetric Submission & Ingestion Wizard" in resp.text
    assert "Quick Demo Launcher" in resp.text
    assert "Run Full Assessment Pipeline" in resp.text


def test_ui_blind_review():
    resp = client.get("/blind-review?entity_id=CSE-03")
    assert resp.status_code == 200
    assert "Blinded Supervisory Review Studio" in resp.text
    assert "Cognitive bias mitigation" in resp.text

    # Submit a blind review
    sub_resp = client.post(
        "/blind-review/submit",
        data={
            "entity_id": "CSE-03",
            "examiner_concern": "Elevated",
            "examiner_priority": "High Priority",
            "examiner_recommendation": "On-Site Review",
            "examiner_notes": "Evidence shows systematic escalation bottleneck on high severity alerts.",
        },
        follow_redirects=True,
    )
    assert sub_resp.status_code == 200
    assert "Inter-Rater Concordance" in sub_resp.text
    assert "Evidence shows systematic escalation bottleneck" in sub_resp.text


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
                "eg01_threshold": "150",
                "eg04_share": "0.45",
            },
            follow_redirects=True,
        )
        assert save_resp.status_code == 200
        assert "Parameters updated and re-calibrated!" in save_resp.text
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
