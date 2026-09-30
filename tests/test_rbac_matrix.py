"""RBAC permission matrix for BOTH apps (SAT-SA and the NCIIPC Admin Portal).

Every route either app serves (minus /static, /docs, /openapi.json) must appear in
an explicit {(method, path): allowed_roles} table below; a completeness check
fails if a route is added without being classified, so nothing can slip in
ungated by accident.

For every route x role in {anonymous, examiner, analyst, admin}:
  - anonymous on a gated route -> 401 (or a 303 to /login for browser page GETs)
  - a role not in the table's allowed set -> 403
  - an allowed role -> anything except 401/403
Mutating routes are sent an empty body so only the auth layer is exercised (an
allowed role then gets 422 from validation), or are pointed at harmless targets;
config/rules.yaml is snapshotted and restored around /tuning/save.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from route_utils import served_http_routes, served_websocket_paths
from starlette.websockets import WebSocketDisconnect

import satsa.api.routes as satsa_routes
from satsa.admin.app import app as admin_app
from satsa.admin.routes import ADMIN_COOKIE_NAME
from satsa.api.routes import app as satsa_app
from satsa.store.sqlite import SQLiteStore

ROLES = ("anonymous", "examiner", "analyst", "admin")
PUBLIC = "PUBLIC"
# SAT-SA's two operators. `admin` works the Admin Portal only and is refused on
# every gated SAT-SA route.
ALL = frozenset({"examiner", "analyst"})
SUP_READ = ALL
ANALYST = frozenset({"analyst"})  # engine room: ingest, runs, tuning, raw telemetry, audit
REVIEW = frozenset({"examiner"})  # review decisions (separation of duties)
INGEST = ANALYST
TUNING = ANALYST
RULEPACK = ANALYST
ADMIN_ONLY = frozenset({"admin"})

# (method, path) -> (allowed roles or PUBLIC, is_browser_page)
SATSA_MATRIX: dict[tuple[str, str], tuple[object, bool]] = {
    ("GET", "/login"): (PUBLIC, True),
    ("POST", "/login"): (PUBLIC, False),
    ("POST", "/logout"): (PUBLIC, False),
    ("GET", "/change-password"): (ALL, True),
    ("POST", "/change-password"): (ALL, False),
    ("GET", "/api/session/status"): (PUBLIC, False),
    ("GET", "/splash"): (PUBLIC, True),
    ("GET", "/"): (PUBLIC, True),
    ("GET", "/portfolio"): (ALL, True),
    ("GET", "/entity/{entity_id}"): (ALL, True),
    ("GET", "/finding/{finding_id}"): (ALL, True),
    ("GET", "/queue"): (ALL, True),
    ("GET", "/dq"): (ANALYST, True),
    ("GET", "/audit"): (ANALYST, True),
    ("GET", "/runs"): (ANALYST, True),
    ("GET", "/alerts"): (ANALYST, True),
    ("GET", "/upload"): (ANALYST, True),
    ("GET", "/blind-review"): (ALL, True),
    ("GET", "/rules"): (ANALYST, True),
    ("GET", "/tuning"): (ANALYST, True),
    ("GET", "/shadow-pilot"): (ANALYST, True),
    ("POST", "/shadow-pilot"): (ANALYST, False),
    ("GET", "/templates/{template_name}"): (ANALYST, False),
    ("GET", "/reports/entity/{entity_id}/pdf"): (ALL, False),
    ("GET", "/reports/entity/{entity_id}/html"): (ALL, False),
    ("GET", "/api/v1/runs"): (SUP_READ, False),
    ("GET", "/api/v1/entities"): (SUP_READ, False),
    ("GET", "/api/v1/findings"): (SUP_READ, False),
    ("GET", "/api/v1/queue"): (SUP_READ, False),
    ("GET", "/api/v1/audit/verify"): (ANALYST, False),
    ("GET", "/api/v1/export/queue.csv"): (ANALYST, False),
    ("GET", "/reports/portfolio/html"): (SUP_READ, False),
    ("GET", "/reports/portfolio/pdf"): (SUP_READ, False),
    ("GET", "/reports/finding/{finding_id}/pdf"): (SUP_READ, False),
    ("GET", "/reports/export/findings-csv"): (ANALYST, False),
    ("GET", "/reports/export/queue-csv"): (ANALYST, False),
    ("POST", "/api/v1/feedback"): (REVIEW, False),
    ("POST", "/blind-review/submit"): (REVIEW, False),
    ("POST", "/upload"): (INGEST, False),
    ("POST", "/upload/add-entity"): (INGEST, False),
    ("POST", "/upload/delete-entity/{entity_id}"): (INGEST, False),
    ("POST", "/upload/trigger-demo"): (INGEST, False),
    ("POST", "/api/v1/submissions"): (INGEST, False),
    ("POST", "/tuning/save"): (TUNING, False),
    ("POST", "/tuning/preview"): (TUNING, False),
    ("GET", "/tuning/export-pack"): (RULEPACK, False),
    ("POST", "/tuning/import-pack"): (RULEPACK, False),
}

ADMIN_MATRIX: dict[tuple[str, str], tuple[object, bool]] = {
    ("GET", "/login"): (PUBLIC, True),
    ("POST", "/login"): (PUBLIC, False),
    ("POST", "/logout"): (PUBLIC, False),
    ("GET", "/change-password"): (ADMIN_ONLY, True),
    ("POST", "/change-password"): (ADMIN_ONLY, False),
    ("GET", "/splash"): (PUBLIC, True),
    ("GET", "/"): (PUBLIC, True),  # splash for guests, overview for admins
    ("GET", "/overview"): (ADMIN_ONLY, True),
    ("GET", "/users"): (ADMIN_ONLY, True),
    ("GET", "/users/create"): (ADMIN_ONLY, True),
    ("POST", "/users/create"): (ADMIN_ONLY, False),
    ("GET", "/users/{username}/edit"): (ADMIN_ONLY, True),
    ("POST", "/users/{username}/edit"): (ADMIN_ONLY, False),
    ("POST", "/users/{username}/block"): (ADMIN_ONLY, False),
    ("POST", "/users/{username}/unblock"): (ADMIN_ONLY, False),
    ("GET", "/users/{username}/reset"): (ADMIN_ONLY, True),
    ("POST", "/users/{username}/reset"): (ADMIN_ONLY, False),
    ("GET", "/organisations"): (ADMIN_ONLY, True),
    ("POST", "/organisations/create"): (ADMIN_ONLY, False),
    ("GET", "/cses"): (ADMIN_ONLY, True),
    ("POST", "/cses/create"): (ADMIN_ONLY, False),
    ("GET", "/audit"): (ADMIN_ONLY, True),
    ("GET", "/api/activity/stream"): (ADMIN_ONLY, False),
    ("GET", "/api/activity/recent"): (ADMIN_ONLY, False),
}
ADMIN_WEBSOCKETS = {"/ws/activity"}

def test_satsa_matrix_is_complete():
    served = served_http_routes(satsa_app)
    assert served - set(SATSA_MATRIX) == set(), "unclassified SAT-SA routes"
    assert set(SATSA_MATRIX) - served == set(), "stale SAT-SA matrix entries"


def test_admin_matrix_is_complete():
    served = served_http_routes(admin_app)
    assert served - set(ADMIN_MATRIX) == set(), "unclassified admin routes"
    assert set(ADMIN_MATRIX) - served == set(), "stale admin matrix entries"
    assert served_websocket_paths(admin_app) == ADMIN_WEBSOCKETS


def _check(resp, allowed, is_page, role):
    if allowed is PUBLIC:
        assert resp.status_code < 500
        return
    if role == "anonymous":
        if is_page:
            assert resp.status_code == 303, resp.status_code
            assert resp.headers["location"].startswith("/login")
        else:
            assert resp.status_code == 401, resp.status_code
    elif role in allowed:
        assert resp.status_code not in (401, 403), (resp.status_code, resp.text[:200])
    else:
        assert resp.status_code == 403, (resp.status_code, resp.text[:200])


# ---------------------------------------------------------------- SAT-SA app

SATSA_PASSWORDS = {
    "examiner": "ChangeMe-Examiner#2026",
    "analyst": "ChangeMe-Analyst#2026",
}


@pytest.fixture(scope="module")
def satsa_clients():
    clients = {"anonymous": TestClient(satsa_app)}
    for role, pw in SATSA_PASSWORDS.items():
        c = TestClient(satsa_app)
        r = c.post("/login", data={"username": role, "password": pw}, follow_redirects=False)
        assert r.status_code == 303 and "error" not in r.headers["location"]
        clients[role] = c
    # Admins are refused at SAT-SA's /login, so the admin client carries a
    # directly created session: a stale or forged one must still be refused.
    store = SQLiteStore("data/satsa.db")
    token = store.create_session("admin", "admin")
    store.close()
    admin = TestClient(satsa_app)
    admin.cookies.set(satsa_routes.SESSION_COOKIE_NAME, token)
    clients["admin"] = admin
    return clients


@pytest.fixture(scope="module")
def real_finding_id():
    store = SQLiteStore("data/satsa.db")
    row = store.conn.execute("SELECT finding_id FROM findings ORDER BY rowid DESC LIMIT 1").fetchone()
    store.close()
    assert row, "bootstrapped data required"
    return row[0]


def _satsa_url(path: str, finding_id: str) -> str:
    return (
        path.replace("{entity_id}", "CSE-03")
        .replace("{finding_id}", finding_id)
        .replace("{template_name}", "alerts.csv")
    )


class _Stub:
    """No-op stand-in for heavy collaborators so trigger-demo only exercises auth."""

    def __init__(self, *a, **k):
        pass

    def save_dataset(self, path):
        return path, path

    def ingest_directory(self, *a, **k):
        return {"status": "empty"}

    def run_assessment(self, *a, **k):
        return {"findings_count": 0}


@pytest.fixture
def rules_yaml_guard():
    path = Path("config/rules.yaml")
    original = path.read_bytes()
    yield
    path.write_bytes(original)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("route", sorted(SATSA_MATRIX), ids=lambda r: f"{r[0]} {r[1]}")
def test_satsa_rbac(route, role, satsa_clients, real_finding_id, rules_yaml_guard, monkeypatch):
    method, path = route
    allowed, is_page = SATSA_MATRIX[route]
    if allowed is PUBLIC and role != "anonymous":
        pytest.skip("public route: exercised once anonymously")
    client = satsa_clients[role]
    url = _satsa_url(path, real_finding_id)
    if path == "/upload/delete-entity/{entity_id}":
        url = "/upload/delete-entity/ZZ-RBAC-NO-SUCH-ENTITY"  # never deletes real data
    if path == "/upload/trigger-demo":
        for name in ("SyntheticDataGenerator", "IngestionPipeline", "AssessmentRunner"):
            monkeypatch.setattr(satsa_routes, name, _Stub)
        monkeypatch.setattr(satsa_routes, "seed_historical_periods", lambda *a, **k: [])
    if path == "/tuning/export-pack":
        monkeypatch.setenv("SATSA_RULEPACK_SECRET", "rbac-test-secret-" + "x" * 32)
    if path == "/logout":
        client = TestClient(satsa_app)  # don't log the shared role clients out

    if method == "GET":
        resp = client.get(url, follow_redirects=False)
    else:
        resp = client.request(method, url, follow_redirects=False)
    _check(resp, allowed, is_page, role)


# ---------------------------------------------------------------- Admin portal


@pytest.fixture(scope="module")
def admin_env(tmp_path_factory):
    db = tmp_path_factory.mktemp("rbac_admin") / "admin.db"
    store = SQLiteStore(db)
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    store.create_user("rbac_examiner", "examiner", "Passphrase#12345")
    store.create_user("rbac_analyst", "analyst", "Passphrase#12345")
    store.create_user("rbac_target", "examiner", "Passphrase#12345")
    tokens = {
        # Sessions are created directly: examiners/analysts can't log in to
        # the portal, but a stale or forged session must still be refused.
        "examiner": store.create_admin_session("rbac_examiner", "examiner"),
        "analyst": store.create_admin_session("rbac_analyst", "analyst"),
        "admin": store.create_admin_session("nciipc_admin", "NCIIPC Super Administrator"),
    }
    yield store, tokens
    store.close()


def _admin_client(admin_env, role):
    store, tokens = admin_env
    admin_app.state.store = store
    c = TestClient(admin_app)
    if role != "anonymous":
        c.cookies.set(ADMIN_COOKIE_NAME, tokens[role])
    return c


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("route", sorted(ADMIN_MATRIX), ids=lambda r: f"{r[0]} {r[1]}")
def test_admin_rbac(route, role, admin_env):
    method, path = route
    allowed, is_page = ADMIN_MATRIX[route]
    if allowed is PUBLIC and role != "anonymous":
        pytest.skip("public route: exercised once anonymously")
    client = _admin_client(admin_env, role)
    url = path.replace("{username}", "rbac_target")
    resp = client.request(method, url, follow_redirects=False)
    _check(resp, allowed, is_page, role)


@pytest.mark.parametrize("role", ["anonymous", "examiner", "analyst"])
def test_admin_websocket_refuses_non_admin(role, admin_env):
    client = _admin_client(admin_env, role)
    with pytest.raises(WebSocketDisconnect) as exc, client.websocket_connect("/ws/activity"):
        pass
    assert exc.value.code == 1008


def test_admin_websocket_accepts_admin(admin_env):
    client = _admin_client(admin_env, "admin")
    with client.websocket_connect("/ws/activity") as ws:
        assert ws is not None


def test_analyst_cannot_log_in_to_admin_portal(admin_env):
    store, _ = admin_env
    admin_app.state.store = store
    resp = TestClient(admin_app).post(
        "/login", data={"username": "rbac_analyst", "password": "Passphrase#12345"}
    )
    assert resp.status_code == 401
    assert "Invalid administrative credentials" in resp.text


def test_is_admin_user_flag_no_longer_grants_portal_access(admin_env):
    store, _ = admin_env
    store.create_user("flagged_examiner", "examiner", "Passphrase#12345", is_admin_user=1)
    admin_app.state.store = store
    c = TestClient(admin_app)
    resp = c.post("/login", data={"username": "flagged_examiner", "password": "Passphrase#12345"})
    assert resp.status_code == 401
    token = store.create_admin_session("flagged_examiner", "examiner")
    c.cookies.set(ADMIN_COOKIE_NAME, token)
    assert c.get("/users", follow_redirects=False).status_code == 403


def test_fresh_install_admins_can_still_reach_portal(tmp_path):
    """Dropping the is_admin_user bypass must not lock admins out of a fresh install."""
    store = SQLiteStore(tmp_path / "fresh.db")
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    admin_app.state.store = store
    for username, pw in (("nciipc_admin", "ChangeMe-NCIIPC#2026"), ("admin", "ChangeMe-Admin#2026")):
        c = TestClient(admin_app)
        r = c.post("/login", data={"username": username, "password": pw}, follow_redirects=False)
        assert r.status_code == 303, (username, r.status_code)
        assert c.get("/users").status_code == 200
    store.close()


def test_blocked_and_unknown_admin_logins_are_indistinguishable(admin_env):
    store, _ = admin_env
    store.create_user("frozen_admin_x", "admin", "Passphrase#12345", status="BLOCKED")
    admin_app.state.store = store
    c = TestClient(admin_app)
    blocked = c.post("/login", data={"username": "frozen_admin_x", "password": "wrong-pass"})
    unknown = c.post("/login", data={"username": "no_such_user_x", "password": "wrong-pass"})
    blocked_ok_pw = c.post("/login", data={"username": "frozen_admin_x", "password": "Passphrase#12345"})
    assert blocked.status_code == unknown.status_code == blocked_ok_pw.status_code == 401
    for r in (blocked, unknown, blocked_ok_pw):
        assert "Invalid administrative credentials" in r.text
        assert "blocked" not in r.text.lower()


def test_anonymous_api_v1_findings_is_401():
    assert TestClient(satsa_app).get("/api/v1/findings").status_code == 401
