"""Seeded default accounts (and admin-issued passphrases) must be replaced at first login.

A session opened with such a passphrase can reach the change-password page and nothing
else, on both portals. conftest.py lifts the requirement for the rest of the suite; the
`first_login_enforced` fixture puts the real seeding and start-up behaviour back here.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from satsa.admin.app import app as admin_app
from satsa.api.routes import app as satsa_app
from satsa.auth.identities import (
    LOGIN_MAX_FAILURES,
    MIN_PASSPHRASE_LENGTH,
    SEEDED_DEFAULT_PASSPHRASES,
    passphrase_policy_error,
    verify_passphrase,
)
from satsa.store.sqlite import SQLiteStore

NEW = "A-Fresh-Passphrase#7431"
ISSUED = "Issued-By-Admin#2026"


def _flag(store: SQLiteStore, username: str) -> int:
    return store.conn.execute(
        "SELECT force_password_change FROM identities WHERE username = ?", (username,)
    ).fetchone()[0]


def _change(client: TestClient, current: str, new: str = NEW, confirm: str | None = None):
    return client.post(
        "/change-password",
        data={"current_password": current, "new_password": new, "confirm_password": confirm or new},
        follow_redirects=False,
    )


# ------------------------------------------------------------------ seeding and start-up


def test_every_seeded_account_is_created_owing_a_passphrase_change(tmp_path, first_login_enforced):
    store = SQLiteStore(tmp_path / "fresh.db")
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    try:
        assert set(SEEDED_DEFAULT_PASSPHRASES) == {"admin", "analyst", "examiner", "nciipc_admin"}
        for username in SEEDED_DEFAULT_PASSPHRASES:
            assert _flag(store, username) == 1, username
    finally:
        store.close()


def test_start_up_flags_a_database_seeded_before_rotation_was_enforced(tmp_path, first_login_enforced):
    store = SQLiteStore(tmp_path / "old.db")
    store.seed_default_admin()
    try:
        # An older database: the seeded accounts exist with their defaults and no flag.
        store.conn.execute("UPDATE identities SET force_password_change = 0")
        store.conn.commit()
        assert sorted(store.flag_unrotated_default_accounts()) == sorted(SEEDED_DEFAULT_PASSPHRASES)
        assert all(_flag(store, u) == 1 for u in SEEDED_DEFAULT_PASSPHRASES)

        # Once an account has its own passphrase, start-up leaves it alone.
        store.change_own_password("analyst", NEW)
        assert _flag(store, "analyst") == 0
        assert store.flag_unrotated_default_accounts() == []
        assert _flag(store, "analyst") == 0
    finally:
        store.close()


def test_passphrase_policy():
    assert passphrase_policy_error(NEW, NEW, "old-one") is None
    assert "do not match" in passphrase_policy_error(NEW, NEW + "x", "old-one")
    assert str(MIN_PASSPHRASE_LENGTH) in passphrase_policy_error("short#1", "short#1", "old-one")
    assert "must differ" in passphrase_policy_error(NEW, NEW, NEW)
    for default in SEEDED_DEFAULT_PASSPHRASES.values():
        assert "published default" in passphrase_policy_error(default, default, "old-one")


# ------------------------------------------------------------------ SAT-SA (:8001)


def test_satsa_seeded_default_login_can_only_set_a_new_passphrase(
    tmp_path, monkeypatch, first_login_enforced
):
    """A fresh install, end to end, with the real seeded `analyst` account."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    default = SEEDED_DEFAULT_PASSPHRASES["analyst"]
    c = TestClient(satsa_app)

    login = c.post("/login", data={"username": "analyst", "password": default}, follow_redirects=False)
    assert login.status_code == 303 and login.headers["location"] == "/change-password"

    # Pages bounce to the change form; APIs, downloads and every mutation are refused.
    for page in ("/portfolio", "/queue", "/tuning", "/upload", "/audit"):
        r = c.get(page, follow_redirects=False)
        assert (r.status_code, r.headers.get("location")) == (303, "/change-password"), page
    for api in ("/api/v1/runs", "/api/v1/findings", "/reports/portfolio/html", "/reports/export/findings-csv"):
        r = c.get(api, follow_redirects=False)
        assert r.status_code == 403 and "new passphrase must be set" in r.json()["detail"], api
    for method, path in (("POST", "/tuning/save"), ("POST", "/upload/trigger-demo"), ("POST", "/tuning/preview")):
        assert c.request(method, path, follow_redirects=False).status_code == 403, path

    form = c.get("/change-password")
    assert form.status_code == 200 and 'id="forcedChangeNotice"' in form.text

    # Refused changes leave the requirement in place.
    assert "current passphrase is not correct" in _change(c, "not-the-passphrase").text
    assert _change(c, default, "short#1").status_code == 400
    assert "do not match" in _change(c, default, NEW, NEW + "x").text
    assert "must differ" in _change(c, default, default).text
    assert "published default" in _change(c, default, SEEDED_DEFAULT_PASSPHRASES["examiner"]).text
    assert c.get("/api/v1/runs").status_code == 403

    done = _change(c, default)
    assert done.status_code == 303 and done.headers["location"] == "/portfolio"
    assert c.get("/api/v1/runs").status_code == 200  # the same session now works

    store = SQLiteStore("data/satsa.db")
    try:
        assert _flag(store, "analyst") == 0
        row = store.get_identity("analyst")
        assert verify_passphrase(NEW, row["pass_salt"], row["pass_hash"])
        actions = [
            r["action"]
            for r in store.conn.execute("SELECT action FROM audit_log WHERE actor = 'analyst' ORDER BY rowid")
        ]
        assert actions[0] == "login" and actions[-1] == "password_changed"
        assert store.verify_audit_chain()[0]
    finally:
        store.close()

    old = TestClient(satsa_app).post(
        "/login", data={"username": "analyst", "password": default}, follow_redirects=False
    )
    assert "error=" in old.headers["location"]
    fresh = TestClient(satsa_app).post(
        "/login", data={"username": "analyst", "password": NEW}, follow_redirects=False
    )
    assert fresh.headers["location"] == "/portfolio"


@pytest.fixture
def issued_examiner():
    """An account whose passphrase an administrator issued with 'force change' ticked."""
    username = f"issued-{uuid.uuid4().hex[:10]}"
    store = SQLiteStore("data/satsa.db")
    store.create_user(username, "examiner", ISSUED, force_password_change=1)
    store.close()
    yield username
    store = SQLiteStore("data/satsa.db")
    store.conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
    store.conn.execute("DELETE FROM identities WHERE username = ?", (username,))
    store.conn.commit()
    store.close()


def _satsa_login(username: str, password: str) -> TestClient:
    c = TestClient(satsa_app)
    r = c.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    assert r.status_code == 303 and "error=" not in r.headers["location"]
    return c


def test_admin_issued_passphrase_is_held_to_the_same_rule(issued_examiner):
    c = _satsa_login(issued_examiner, ISSUED)
    assert c.get("/queue", follow_redirects=False).headers["location"] == "/change-password"
    assert c.post("/api/v1/feedback", data={}, follow_redirects=False).status_code == 403
    assert _change(c, ISSUED).status_code == 303
    assert c.get("/queue", follow_redirects=False).status_code == 200


def test_changing_the_passphrase_ends_the_users_other_sessions(issued_examiner):
    first = _satsa_login(issued_examiner, ISSUED)
    second = _satsa_login(issued_examiner, ISSUED)
    assert _change(first, ISSUED).status_code == 303
    assert first.get("/api/v1/runs").status_code == 200
    assert second.get("/api/v1/runs").status_code == 401


def test_wrong_current_passphrase_counts_towards_the_lockout(issued_examiner):
    c = _satsa_login(issued_examiner, ISSUED)
    for _ in range(LOGIN_MAX_FAILURES):
        assert "current passphrase is not correct" in _change(c, "a-wrong-guess").text
    # Locked: even the right current passphrase is refused now.
    locked = _change(c, ISSUED)
    assert locked.status_code == 400 and "Too many failed attempts" in locked.text
    store = SQLiteStore("data/satsa.db")
    try:
        assert _flag(store, issued_examiner) == 1
    finally:
        store.close()


def test_change_password_needs_a_session():
    c = TestClient(satsa_app)
    assert c.get("/change-password", follow_redirects=False).headers["location"].startswith("/login")
    assert _change(c, "x").status_code == 401


# ------------------------------------------------------------------ Admin Portal (:8000)


@pytest.fixture
def fresh_admin_portal(tmp_path, first_login_enforced):
    store = SQLiteStore(tmp_path / "admin.db")
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    admin_app.state.store = store
    yield store
    store.close()


@pytest.mark.parametrize("username", ["nciipc_admin", "admin"])
def test_admin_seeded_default_login_can_only_set_a_new_passphrase(fresh_admin_portal, username):
    store = fresh_admin_portal
    default = SEEDED_DEFAULT_PASSPHRASES[username]
    c = TestClient(admin_app)

    login = c.post("/login", data={"username": username, "password": default}, follow_redirects=False)
    assert login.status_code == 303 and login.headers["location"] == "/change-password"

    for page in ("/", "/overview", "/users", "/users/create", "/audit", "/login", "/splash"):
        r = c.get(page, follow_redirects=False)
        assert (r.status_code, r.headers.get("location")) == (303, "/change-password"), page
    created = c.post(
        "/users/create",
        data={"username": "should-not-exist", "role": "examiner", "password": "Whatever#123456"},
        follow_redirects=False,
    )
    assert created.status_code == 403 and store.get_user("should-not-exist") is None
    with pytest.raises(WebSocketDisconnect) as exc, c.websocket_connect("/ws/activity"):
        pass
    assert exc.value.code == 1008

    assert 'id="forcedChangeNotice"' in c.get("/change-password").text
    assert "current passphrase is not correct" in _change(c, "not-the-passphrase").text
    assert "published default" in _change(c, default, SEEDED_DEFAULT_PASSPHRASES["analyst"]).text
    assert _flag(store, username) == 1

    done = _change(c, default)
    assert done.status_code == 303 and done.headers["location"] == "/"
    assert _flag(store, username) == 0
    assert c.get("/users", follow_redirects=False).status_code == 200
    actions = [
        r["action"]
        for r in store.conn.execute(
            "SELECT action FROM admin_audit_log WHERE actor = ? ORDER BY rowid", (username,)
        )
    ]
    assert actions[0] == "ADMIN_LOGIN" and actions[-1] == "PASSWORD_CHANGED"

    assert TestClient(admin_app).post("/login", data={"username": username, "password": default}).status_code == 401
    again = TestClient(admin_app).post(
        "/login", data={"username": username, "password": NEW}, follow_redirects=False
    )
    assert again.status_code == 303 and again.headers["location"] == "/"


def test_admin_change_password_needs_a_session(fresh_admin_portal):
    c = TestClient(admin_app)
    assert c.get("/change-password", follow_redirects=False).headers["location"] == "/login"
    assert _change(c, "x").status_code == 401
