"""Login lockout: LOGIN_MAX_FAILURES failures within LOGIN_LOCKOUT_MINUTES lock a username.

Uses throwaway identities only -- never the shared seeded accounts other tests
depend on.
"""

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.auth.identities import LOGIN_LOCKOUT_MINUTES, LOGIN_MAX_FAILURES
from satsa.store.sqlite import SQLiteStore

PASSWORD = "Throwaway-Passphrase#2026"


def test_constants():
    assert LOGIN_MAX_FAILURES == 5
    assert LOGIN_LOCKOUT_MINUTES == 15


@pytest.fixture
def throwaway_user():
    username = f"lockout-{uuid.uuid4().hex[:10]}"
    store = SQLiteStore("data/satsa.db")
    store.upsert_identity(username, "examiner", PASSWORD)
    store.close()
    return username


def _attempt(username: str, password: str):
    return TestClient(app).post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )


def _succeeded(resp) -> bool:
    return resp.status_code == 303 and "error=" not in resp.headers["location"]


def test_five_failures_lock_even_the_correct_password(throwaway_user):
    for _ in range(LOGIN_MAX_FAILURES):
        assert not _succeeded(_attempt(throwaway_user, "wrong-passphrase"))

    locked = _attempt(throwaway_user, PASSWORD)
    assert not _succeeded(locked)
    assert "satsa_session" not in locked.cookies

    # Same generic response as an unknown username: no enumeration via error text.
    unknown = _attempt(f"nobody-{uuid.uuid4().hex[:8]}", "whatever")
    assert locked.status_code == unknown.status_code == 303
    assert locked.headers["location"] == unknown.headers["location"]

    store = SQLiteStore("data/satsa.db")
    row = store.conn.execute(
        "SELECT action FROM audit_log WHERE actor = ? ORDER BY rowid DESC LIMIT 1", (throwaway_user,)
    ).fetchone()
    store.close()
    assert row["action"] == "login_locked"


def test_successful_login_before_threshold_resets_count(throwaway_user):
    for _ in range(LOGIN_MAX_FAILURES - 1):
        assert not _succeeded(_attempt(throwaway_user, "wrong-passphrase"))
    assert _succeeded(_attempt(throwaway_user, PASSWORD))  # resets
    for _ in range(LOGIN_MAX_FAILURES - 1):
        assert not _succeeded(_attempt(throwaway_user, "wrong-passphrase"))
    # 8 failures in the window, but only 4 since the last success: not locked.
    assert _succeeded(_attempt(throwaway_user, PASSWORD))


def test_lock_expires_after_window(tmp_path):
    store = SQLiteStore(tmp_path / "t.db")
    for _ in range(LOGIN_MAX_FAILURES):
        store.append_audit("login_failed", "expiring-user", {})
    assert store.count_recent_login_failures("expiring-user", LOGIN_LOCKOUT_MINUTES) == 5
    later = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=LOGIN_LOCKOUT_MINUTES + 1)
    assert store.count_recent_login_failures("expiring-user", LOGIN_LOCKOUT_MINUTES, now=later) == 0
    store.close()


def _insert_raw(store: SQLiteStore, ts: str, action: str, actor: str = "mixed") -> None:
    store.conn.execute(
        "INSERT INTO audit_log (log_id, ts, action, actor, details_json, prev_hash, curr_hash) "
        "VALUES (?, ?, ?, ?, '{}', '', '')",
        (uuid.uuid4().hex[:16], ts, action, actor),
    )


def test_mixed_timestamp_precision_and_formats(tmp_path):
    """String comparison would get these wrong; datetime comparison must not.

    now = 12:15:00.000000 UTC -> cutoff = 12:00:00.000000 UTC (15-minute window).
    """
    store = SQLiteStore(tmp_path / "t.db")
    now = dt.datetime(2026, 9, 28, 12, 15, 0, tzinfo=dt.UTC)
    inside = [
        "2026-09-28T12:00:00+00:00",         # exactly at cutoff, no fraction (lexically < ".000000")
        "2026-09-28T12:00:00.000001+00:00",  # just inside, with fraction
        "2026-09-28 12:14:00",               # naive, space separator (' ' < 'T' lexically)
        "2026-09-28T12:10:00Z",              # 'Z' suffix
        "2026-09-28T17:44:00+05:30",         # 12:14 UTC expressed in IST
    ]
    outside = [
        "2026-09-28T11:59:59.999999+00:00",
        "2026-09-28T11:59:59+00:00",
        "2026-09-28T17:29:59+05:30",         # 11:59:59 UTC in IST (lexically > cutoff!)
    ]
    for ts in outside + inside:  # oldest-ish first, as they'd be appended
        _insert_raw(store, ts, "login_failed")
    assert store.count_recent_login_failures("mixed", 15, now=now) == len(inside)
    store.close()


def test_new_audit_timestamps_have_fixed_precision(tmp_path):
    store = SQLiteStore(tmp_path / "t.db")
    for _ in range(20):
        store.append_audit("login_failed", "precision", {})
    lengths = {len(r[0]) for r in store.conn.execute("SELECT ts FROM audit_log")}
    store.close()
    assert lengths == {len("2026-09-28T12:00:00.000000+00:00")}


def test_admin_portal_lockout(tmp_path):
    from satsa.admin.app import app as admin_app

    store = SQLiteStore(tmp_path / "admin.db")
    store.seed_default_organisations_and_cses()
    store.create_user("lock_admin", "admin", PASSWORD)
    admin_app.state.store = store
    c = TestClient(admin_app)
    for _ in range(LOGIN_MAX_FAILURES):
        assert c.post("/login", data={"username": "lock_admin", "password": "nope"}).status_code == 401
    locked = c.post("/login", data={"username": "lock_admin", "password": PASSWORD}, follow_redirects=False)
    assert locked.status_code == 401
    assert "Invalid administrative credentials" in locked.text
    assert store.list_admin_audit_logs(action="ADMIN_LOGIN_LOCKED", actor="lock_admin")
    store.close()
