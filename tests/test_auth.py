"""Tests for local RBAC: authentication, role gating, and real-actor audit trail."""

from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.auth.identities import hash_passphrase, verify_passphrase
from satsa.store.sqlite import SQLiteStore

client = TestClient(app)


def _login(c: TestClient, username: str, password: str) -> None:
    resp = c.post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )
    assert resp.status_code == 303, f"login failed for {username}: {resp.text}"


def test_passphrase_hash_roundtrip():
    from satsa.auth.identities import generate_salt

    salt = generate_salt()
    h = hash_passphrase("correct horse battery staple", salt)
    assert verify_passphrase("correct horse battery staple", salt.hex(), h)
    assert not verify_passphrase("wrong password", salt.hex(), h)


def test_default_identities_seeded():
    store = SQLiteStore("data/satsa.db")
    admin = store.get_identity("admin")
    supervisor = store.get_identity("supervisor")
    examiner = store.get_identity("examiner")
    store.close()
    assert admin is not None and admin["role"] == "admin"
    assert supervisor is not None and supervisor["role"] == "supervisor"
    assert examiner is not None and examiner["role"] == "examiner"


def test_unauthenticated_access_rejected_on_protected_routes():
    anon = TestClient(app)
    # Tuning save (admin/supervisor only)
    r1 = anon.post("/tuning/save", data={"EG01__fast_share_threshold": "0.2"}, follow_redirects=False)
    assert r1.status_code == 401

    # Rule pack export (admin/supervisor only)
    r2 = anon.get("/tuning/export-pack", follow_redirects=False)
    assert r2.status_code == 401

    # Feedback submission (examiner/supervisor/admin only)
    r3 = anon.post(
        "/api/v1/feedback",
        data={"queue_id": "does-not-matter", "status": "confirmed"},
        follow_redirects=False,
    )
    assert r3.status_code == 401

    # Telemetry ingest API (admin/supervisor only)
    r4 = anon.post(
        "/api/v1/telemetry/ingest",
        json={"entity_id": "CSE-01", "alerts": []},
        follow_redirects=False,
    )
    assert r4.status_code == 401


def test_wrong_role_rejected():
    # Examiner is not permitted to trigger tuning changes (admin/supervisor only).
    exam_client = TestClient(app)
    _login(exam_client, "examiner", "ChangeMe-Examiner#2026")
    resp = exam_client.post(
        "/tuning/save", data={"EG01__fast_share_threshold": "0.2"}, follow_redirects=False
    )
    assert resp.status_code == 403


def test_role_appropriate_access_succeeds():
    from pathlib import Path

    config_path = Path("config/rules.yaml")
    orig_content = config_path.read_text(encoding="utf-8")
    try:
        sup_client = TestClient(app)
        _login(sup_client, "supervisor", "ChangeMe-Supervisor#2026")
        resp = sup_client.post(
            "/tuning/save", data={"EG01__fast_share_threshold": "0.18"}, follow_redirects=True
        )
        assert resp.status_code == 200
        assert "Parameters updated and re-calibrated!" in resp.text
    finally:
        # Restore the exact original config content, not a guessed default --
        # /tuning/save's Form defaults would otherwise silently overwrite
        # every unspecified threshold too.
        config_path.write_text(orig_content, encoding="utf-8")


def test_examiner_can_submit_feedback_and_blind_review():
    exam_client = TestClient(app)
    _login(exam_client, "examiner", "ChangeMe-Examiner#2026")

    r_q = exam_client.get("/api/v1/queue")
    q_items = r_q.json()
    assert q_items, "expected a non-empty review queue from fixture data"
    first_id = q_items[0]["queue_id"]

    resp = exam_client.post(
        "/api/v1/feedback",
        data={"queue_id": first_id, "status": "confirmed", "notes": "auth-test confirm"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_audit_log_records_real_actor_not_caller_supplied_string():
    exam_client = TestClient(app)
    _login(exam_client, "examiner", "ChangeMe-Examiner#2026")

    r_q = exam_client.get("/api/v1/queue")
    q_items = r_q.json()
    assert q_items
    first_id = q_items[0]["queue_id"]

    # Even though no examiner_id field is accepted anymore, attempt to smuggle
    # a spoofed identity via an unexpected form field: it must be ignored.
    exam_client.post(
        "/api/v1/feedback",
        data={
            "queue_id": first_id,
            "status": "confirmed",
            "notes": "spoof-attempt",
            "examiner_id": "SPOOFED_IDENTITY",
        },
        follow_redirects=False,
    )

    store = SQLiteStore("data/satsa.db")
    cur = store.conn.cursor()
    cur.execute(
        "SELECT actor FROM audit_log WHERE action = 'feedback' ORDER BY rowid DESC LIMIT 1"
    )
    row = cur.fetchone()
    store.close()
    assert row is not None
    assert row["actor"] == "examiner"
    assert row["actor"] != "SPOOFED_IDENTITY"


def test_login_failure_is_audited_and_rejected():
    anon = TestClient(app)
    resp = anon.post(
        "/login",
        data={"username": "admin", "password": "definitely-wrong-password"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error" in resp.headers["location"]

    store = SQLiteStore("data/satsa.db")
    cur = store.conn.cursor()
    cur.execute("SELECT actor FROM audit_log WHERE action = 'login_failed' ORDER BY rowid DESC LIMIT 1")
    row = cur.fetchone()
    store.close()
    assert row is not None
    assert row["actor"] == "admin"


def test_logout_clears_session():
    c = TestClient(app)
    _login(c, "admin", "ChangeMe-Admin#2026")
    resp = c.post("/logout", follow_redirects=False)
    assert resp.status_code == 303

    # Now protected actions should be rejected again.
    r = c.post("/tuning/save", data={"EG01__fast_share_threshold": "0.2"}, follow_redirects=False)
    assert r.status_code == 401
