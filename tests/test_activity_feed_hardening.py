"""Admin activity feed (live_events) hardening -- see DECISIONS.md ADR-006.

- get_live_events validates since_id and caps limit; the polling endpoints reject
  out-of-range parameters with 422.
- The feed is non-authoritative and not hash-chained, so every security-relevant
  event it records must have a counterpart in a hash-chained audit log.
"""

import pytest
from fastapi.testclient import TestClient

from satsa.admin.app import app as admin_app
from satsa.admin.routes import ADMIN_COOKIE_NAME
from satsa.store.sqlite import LIVE_EVENTS_MAX_LIMIT, SQLiteStore


@pytest.fixture
def store(tmp_path):
    s = SQLiteStore(tmp_path / "feed.db")
    s.seed_default_organisations_and_cses()
    s.seed_default_admin()
    yield s
    s.close()


def test_limit_is_capped(store):
    for i in range(LIVE_EVENTS_MAX_LIMIT + 50):
        store.record_live_event("FINDING_VIEWED", actor="examiner", details={"i": i})
    assert len(store.get_live_events(limit=10_000)) == LIVE_EVENTS_MAX_LIMIT
    assert len(store.get_live_events(since_id=0, limit=0)) == 1  # clamped up to 1
    assert len(store.get_live_events(since_id=5, limit=3)) == 3


@pytest.mark.parametrize("bad", [-1, "5", "1 OR 1=1", 1.5, True, None])
def test_since_id_must_be_non_negative_int(store, bad):
    with pytest.raises(ValueError):
        store.get_live_events(since_id=bad)


@pytest.mark.parametrize("bad", ["50", None, 2.0])
def test_limit_must_be_int(store, bad):
    with pytest.raises(ValueError):
        store.get_live_events(limit=bad)


def _admin_client(store) -> TestClient:
    admin_app.state.store = store
    c = TestClient(admin_app)
    c.cookies.set(ADMIN_COOKIE_NAME, store.create_admin_session("nciipc_admin", "NCIIPC Super Administrator"))
    return c


@pytest.mark.parametrize(
    "params",
    [{"since_id": -1}, {"since_id": "abc"}, {"since_id": "1 OR 1=1"}, {"limit": 0},
     {"limit": LIVE_EVENTS_MAX_LIMIT + 1}, {"limit": "x"}],
)
def test_stream_endpoint_rejects_bad_params(store, params):
    assert _admin_client(store).get("/api/activity/stream", params=params).status_code == 422


def test_recent_endpoint_rejects_bad_limit(store):
    c = _admin_client(store)
    assert c.get("/api/activity/recent", params={"limit": 10_000}).status_code == 422
    assert c.get("/api/activity/recent", params={"limit": 5}).status_code == 200


def test_stream_endpoint_valid_polling(store):
    ids = [store.record_live_event("USER_LOGIN", actor=f"u{i}") for i in range(5)]
    c = _admin_client(store)
    r = c.get("/api/activity/stream", params={"since_id": ids[1], "limit": 2})
    assert r.status_code == 200
    body = r.json()
    assert [e["event_id"] for e in body["events"]] == ids[2:4]
    assert body["max_id"] == ids[3]


def _audit_actions(store, table: str, actor: str) -> list[str]:
    return [r[0] for r in store.conn.execute(f"SELECT action FROM {table} WHERE actor = ?", (actor,))]


def test_login_and_logout_events_have_chained_counterparts(tmp_path, monkeypatch):
    """USER_LOGIN / USER_LOGOUT in the feed are mirrored by audit_log login / logout."""
    from satsa.api.routes import app as satsa_app

    store = SQLiteStore("data/satsa.db")
    before = store.conn.execute("SELECT max(event_id) FROM live_events").fetchone()[0] or 0
    c = TestClient(satsa_app)
    assert c.post("/login", data={"username": "examiner", "password": "ChangeMe-Examiner#2026"},
                  follow_redirects=False).status_code == 303
    c.post("/logout", follow_redirects=False)
    events = [e for e in store.get_live_events(since_id=before, limit=200) if e["actor"] == "examiner"]
    kinds = [e["event_type"] for e in events]
    assert "USER_LOGIN" in kinds and "USER_LOGOUT" in kinds
    recent = [r[0] for r in store.conn.execute(
        "SELECT action FROM audit_log WHERE actor = 'examiner' ORDER BY rowid DESC LIMIT 5")]
    assert "login" in recent and "logout" in recent
    assert store.verify_audit_chain()[0]
    store.close()


def test_admin_account_events_have_chained_counterparts(store):
    """ACCOUNT_BLOCKED / ROLE_CHANGED / CSE_CHANGED are mirrored in admin_audit_log."""
    store.create_user("feed_target", "SOC Analyst", "Passphrase#12345", "ORG-POWER", "CSE-01")
    c = _admin_client(store)
    assert c.post("/users/feed_target/block", follow_redirects=False).status_code == 303
    assert c.post("/users/feed_target/unblock", follow_redirects=False).status_code == 303
    r = c.post(
        "/users/feed_target/edit",
        data={"role": "SOC Manager", "status": "ACTIVE", "org_id": "ORG-POWER", "cse_id": "CSE-06"},
        follow_redirects=False,
    )
    assert r.status_code == 303

    feed = {e["event_type"] for e in store.get_live_events(limit=200) if e["entity_id"] == "feed_target"}
    assert {"ACCOUNT_BLOCKED", "ROLE_CHANGED", "CSE_CHANGED"} <= feed
    chained = [r[0] for r in store.conn.execute(
        "SELECT action FROM admin_audit_log WHERE target = 'feed_target'")]
    for counterpart in ("USER_BLOCKED", "ROLE_CHANGED", "CSE_CHANGED"):
        assert counterpart in chained
    assert store.verify_admin_audit_chain()[0]
