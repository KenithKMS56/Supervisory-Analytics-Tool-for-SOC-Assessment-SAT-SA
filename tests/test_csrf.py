"""Cross-site request forgery (docs/product_brief.md section 10): a request that changes state
and carries a session cookie must come from the portal's own origin. Browsers send `Origin`
(and `Sec-Fetch-Site`) on every such request, so a forged one from another site is identified
and refused; non-browser clients that send neither are unaffected. Same for the Admin Portal's
WebSocket handshake."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from satsa.admin.routes import ADMIN_COOKIE_NAME
from satsa.api.routes import app as satsa_app
from satsa.store.sqlite import SQLiteStore

SELF = "http://testserver"
EVIL = "https://evil.example"


@pytest.fixture(scope="module")
def analyst() -> TestClient:
    client = TestClient(satsa_app)
    r = client.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                    follow_redirects=False)
    assert r.status_code == 303
    return client


def _cancel_unknown_job(client: TestClient, headers: dict[str, str]) -> int:
    # A harmless state-changing route: cancelling a job that does not exist (404 when allowed).
    return client.post("/jobs/JOB-CSRF-NO-SUCH-JOB/cancel", headers=headers, follow_redirects=False).status_code


def test_a_cross_site_form_post_with_the_session_cookie_is_refused(analyst):
    assert _cancel_unknown_job(analyst, {"Origin": EVIL}) == 403
    assert _cancel_unknown_job(analyst, {"Sec-Fetch-Site": "cross-site"}) == 403
    assert _cancel_unknown_job(analyst, {"Referer": f"{EVIL}/attack.html"}) == 403
    assert _cancel_unknown_job(analyst, {"Origin": "null"}) == 403  # sandboxed frame / data: URL


def test_same_origin_and_non_browser_requests_still_work(analyst):
    assert _cancel_unknown_job(analyst, {"Origin": SELF}) == 404
    assert _cancel_unknown_job(analyst, {"Origin": SELF, "Sec-Fetch-Site": "same-origin"}) == 404
    assert _cancel_unknown_job(analyst, {"Referer": f"{SELF}/jobs"}) == 404
    assert _cancel_unknown_job(analyst, {}) == 404  # curl or a script: no Origin, no Referer


def test_a_cross_site_login_attempt_is_refused():
    """Login CSRF: another site must not sign a victim's browser into an attacker's account."""
    client = TestClient(satsa_app)
    r = client.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                    headers={"Origin": EVIL}, follow_redirects=False)
    assert r.status_code == 403


def test_the_admin_portal_refuses_cross_site_posts_too(tmp_path):
    from satsa.admin.app import app as admin_app

    store = SQLiteStore(tmp_path / "admin.db")
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    admin_app.state.store = store
    client = TestClient(admin_app)
    client.cookies.set(ADMIN_COOKIE_NAME, store.create_admin_session("nciipc_admin", "NCIIPC Super Administrator"))
    try:
        assert client.post("/users/nciipc_admin/block", headers={"Origin": EVIL}).status_code == 403
        assert store.get_user("nciipc_admin")["is_blocked"] in (0, None)
    finally:
        store.close()


def test_the_activity_websocket_refuses_a_foreign_origin(tmp_path):
    from satsa.admin.app import app as admin_app

    store = SQLiteStore(tmp_path / "admin.db")
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    with store.transaction():
        store.conn.execute("UPDATE identities SET force_password_change = 0 WHERE username = 'nciipc_admin'")
    admin_app.state.store = store
    client = TestClient(admin_app)
    client.cookies.set(ADMIN_COOKIE_NAME, store.create_admin_session("nciipc_admin", "NCIIPC Super Administrator"))
    try:
        with pytest.raises(WebSocketDisconnect) as exc, client.websocket_connect(
            "/ws/activity", headers={"Origin": EVIL}
        ):
            pass
        assert exc.value.code == 1008
        with client.websocket_connect("/ws/activity", headers={"Origin": SELF}):
            pass  # accepted: the handshake from the portal's own page still works
    finally:
        store.close()
