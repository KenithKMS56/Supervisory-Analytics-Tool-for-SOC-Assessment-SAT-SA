"""Offline MFA for administrators (docs/product_brief.md section 10; satsa.auth.mfa). Runs as a
production deployment, where MFA is required, with the real seeding behaviour."""

from __future__ import annotations

import base64
import re

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from satsa import deployment
from satsa.auth import mfa
from satsa.store.sqlite import SQLiteStore

PASSPHRASE = "Admin-Passphrase#2026"


def test_totp_matches_the_rfc_6238_test_vector():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa.totp(secret, 59 // 30) == "287082"  # RFC 6238 appendix B, T=59 (8 digits: 94287082)
    assert mfa.totp(secret, 1111111109 // 30) == "081804"


@pytest.fixture
def portal(tmp_path, monkeypatch, first_login_enforced):
    monkeypatch.delenv("SATSA_DEMO", raising=False)
    monkeypatch.delenv("SATSA_ADMIN_MFA", raising=False)
    monkeypatch.chdir(tmp_path)
    store = SQLiteStore("data/satsa.db")
    deployment.complete_setup(store, "data", token=None, admin_username="ops-admin", passphrase=PASSPHRASE,
                              confirm=PASSPHRASE, deployment_name="MFA test", timezone="UTC", require_token=False)
    store.create_user("second-admin", deployment.SETUP_ADMIN_ROLE, PASSPHRASE, org_id="ORG-NCIIPC")
    from satsa.admin.app import app

    app.state.store = store
    yield store, app
    store.close()


def _login(app, username: str = "ops-admin") -> tuple[TestClient, str]:
    client = TestClient(app)
    r = client.post("/login", data={"username": username, "password": PASSPHRASE}, follow_redirects=False)
    assert r.status_code == 303
    return client, r.headers["location"]


def _secret(store: SQLiteStore, username: str) -> str:
    return store.conn.execute("SELECT secret_b32 FROM mfa_factors WHERE username = ?", (username,)).fetchone()[0]


def _enrol(store: SQLiteStore, app, username: str = "ops-admin") -> tuple[TestClient, list[str]]:
    client, location = _login(app, username)
    assert location == "/mfa/setup"
    page = client.get("/mfa/setup")
    assert page.status_code == 200 and _secret(store, username) in page.text
    code = mfa.totp(_secret(store, username), mfa.current_step())
    done = client.post("/mfa/setup", data={"code": code})
    assert done.status_code == 200 and "shown <strong>once</strong>" in done.text
    codes = re.findall(r"<li>([0-9A-F]{5}-[0-9A-F]{5})</li>", done.text)
    return client, codes


def test_an_administrator_must_enrol_before_using_the_portal(portal):
    store, app = portal
    client, location = _login(app)
    assert location == "/mfa/setup"
    assert client.get("/users", follow_redirects=False).headers["location"] == "/mfa/setup"
    assert client.post("/users/create", data={}).status_code == 403
    with pytest.raises(WebSocketDisconnect), client.websocket_connect("/ws/activity"):
        pass
    wrong = client.post("/mfa/setup", data={"code": "000000"})
    assert wrong.status_code == 400 and not mfa.enrolled(store, "ops-admin")

    enrolled_client, codes = _enrol(store, app)
    assert len(codes) == mfa.RECOVERY_CODES
    assert enrolled_client.get("/users").status_code == 200, "the enrolling session is verified"
    stored = [r[0] for r in store.conn.execute("SELECT code_hash FROM mfa_recovery_codes")]
    assert not set(codes) & set(stored), "recovery codes are stored hashed"


def test_every_new_session_must_prove_the_factor_and_codes_do_not_replay(portal):
    store, app = portal
    _enrol(store, app)
    client, location = _login(app)
    assert location == "/login/mfa"
    assert client.get("/", follow_redirects=False).headers["location"] == "/login/mfa"
    assert client.post("/users/create", data={}).status_code == 403
    assert client.post("/login/mfa", data={"code": "123456"}).status_code == 401
    code = mfa.totp(_secret(store, "ops-admin"), mfa.current_step() + 1)
    ok = client.post("/login/mfa", data={"code": code}, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/"
    assert client.get("/users").status_code == 200

    other, _ = _login(app)
    replay = other.post("/login/mfa", data={"code": code})
    assert replay.status_code == 401, "a used code must not work again"


def test_a_recovery_code_works_once(portal):
    store, app = portal
    _, codes = _enrol(store, app)
    first, _ = _login(app)
    assert first.post("/login/mfa", data={"code": codes[0]}, follow_redirects=False).status_code == 303
    again, _ = _login(app)
    assert again.post("/login/mfa", data={"code": codes[0]}).status_code == 401
    assert mfa.remaining_recovery_codes(store, "ops-admin") == mfa.RECOVERY_CODES - 1


def test_repeated_wrong_codes_end_the_session(portal):
    store, app = portal
    _enrol(store, app)
    client, _ = _login(app)
    for _ in range(5):
        r = client.post("/login/mfa", data={"code": "000000"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/users", follow_redirects=False).headers["location"] == "/login"


def test_another_administrator_resets_a_lost_factor_and_it_is_audited(portal):
    store, app = portal
    owner, _ = _enrol(store, app)
    helper, _ = _enrol(store, app, "second-admin")
    assert helper.post("/users/second-admin/mfa-reset", follow_redirects=False).headers["location"].startswith(
        "/users?error="), "nobody resets their own factor"
    r = helper.post("/users/ops-admin/mfa-reset", follow_redirects=False)
    assert r.status_code == 303 and "removed" in r.headers["location"]
    assert not mfa.enrolled(store, "ops-admin")
    actions = [row[0] for row in store.conn.execute("SELECT action FROM admin_audit_log")]
    assert "MFA_RESET" in actions and actions.count("MFA_ENROLLED") == 2
    assert owner.get("/users", follow_redirects=False).headers["location"] == "/mfa/setup"


def test_demo_deployments_keep_mfa_optional(tmp_path, monkeypatch, first_login_enforced):
    monkeypatch.setenv("SATSA_DEMO", "1")
    monkeypatch.delenv("SATSA_ADMIN_MFA", raising=False)
    store = SQLiteStore(tmp_path / "demo.db")
    try:
        assert mfa.policy(store) == "optional"
        monkeypatch.setenv("SATSA_ADMIN_MFA", "required")
        assert mfa.policy(store) == "required"
    finally:
        store.close()
