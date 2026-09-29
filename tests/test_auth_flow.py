"""Tests for Part 1/5: SAT-SA Authentication Flow and UI-Only Changes.

Verifies:
1. Splash screen as entry point at / and /splash with 'Login' action.
2. Direct navigation to /login.
3. Route protection: unauthenticated direct access to protected pages (/portfolio, /alerts, /queue, etc.) redirects to /login.
4. Failed authentication displays clear error message.
5. Blocked account attempts display clear access-denied message and cannot authenticate.
6. Successful authentication sets session and navigates to /portfolio.
7. Authenticated users visiting / or /portfolio view the portfolio dashboard.
8. Authenticated users visiting /login are redirected to /portfolio.
9. Logout terminates session and redirects to /login.
"""

import uuid

from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.store.sqlite import SQLiteStore


def test_splash_screen_rendered_at_root_for_unauthenticated_users():
    client = TestClient(app)
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 200
    assert "Supervisory Analytics Tool" in resp.text
    assert "0xZenith" in resp.text
    assert "btnLandingLogin" in resp.text
    assert 'href="/login"' in resp.text
    # "Continue" button should no longer be present
    assert "btnLandingContinue" not in resp.text
    assert "satsaEnterDashboard" not in resp.text


def test_splash_screen_rendered_at_splash_route():
    client = TestClient(app)
    resp = client.get("/splash", follow_redirects=False)
    assert resp.status_code == 200
    assert "btnLandingLogin" in resp.text
    assert 'href="/login"' in resp.text


def test_login_page_renders_cleanly():
    client = TestClient(app)
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "SAT-SA Supervisory Login" in resp.text
    assert 'name="username"' in resp.text
    assert 'name="password"' in resp.text
    assert "btnLoginSubmit" in resp.text
    assert "Back to Splash" in resp.text


def test_unauthenticated_protected_routes_redirect_to_login():
    client = TestClient(app)
    protected_paths = [
        "/portfolio",
        "/alerts",
        "/queue",
        "/upload",
        "/entity/CSE-01",
        "/blind-review",
        "/rules",
        "/dq",
        "/tuning",
        "/runs",
    ]
    for path in protected_paths:
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code == 303, f"Expected 303 redirect for {path}, got {resp.status_code}"
        assert "/login?next=" in resp.headers["location"]


def test_failed_login_displays_error():
    # Uses an unknown username rather than the shared seeded "admin" account:
    # failed attempts count toward login lockout, and other tests depend on
    # "admin" staying usable no matter how often this suite runs.
    client = TestClient(app)
    resp = client.post(
        "/login",
        data={"username": f"nobody-{uuid.uuid4().hex[:8]}", "password": "WrongPassword#9999"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]

    # Follow redirect to login page
    page_resp = client.get(resp.headers["location"])
    assert page_resp.status_code == 200
    assert "Invalid username or passphrase" in page_resp.text


def test_blocked_account_denied_access():
    store = SQLiteStore("data/satsa.db")
    # Temporarily mark examiner as blocked
    store.set_blocked("examiner", True)
    try:
        client = TestClient(app)
        resp = client.post(
            "/login",
            data={"username": "examiner", "password": "ChangeMe-Examiner#2026"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "blocked=1" in resp.headers["location"]

        # Follow redirect to login page
        page_resp = client.get(resp.headers["location"])
        assert page_resp.status_code == 200
        assert "Access Denied" in page_resp.text
        assert "blocked" in page_resp.text.lower()
    finally:
        # Restore unblocked state
        store.set_blocked("examiner", False)
        store.close()


def test_blocked_account_session_invalidated_immediately():
    store = SQLiteStore("data/satsa.db")
    client = TestClient(app)

    # First login successfully
    resp = client.post(
        "/login",
        data={"username": "examiner", "password": "ChangeMe-Examiner#2026"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    # Verify session works
    assert client.get("/portfolio", follow_redirects=False).status_code == 200

    # Now block the account
    store.set_blocked("examiner", True)
    try:
        # Next request should be rejected and redirected to /login
        subsequent_resp = client.get("/portfolio", follow_redirects=False)
        assert subsequent_resp.status_code == 303
        assert "/login?next=" in subsequent_resp.headers["location"]
    finally:
        store.set_blocked("examiner", False)
        store.close()


def test_successful_login_and_full_navigation_flow():
    client = TestClient(app)

    # 1. Start at Splash
    splash_resp = client.get("/")
    assert splash_resp.status_code == 200
    assert "btnLandingLogin" in splash_resp.text

    # 2. Navigate to Login
    login_resp = client.get("/login")
    assert login_resp.status_code == 200

    # 3. Submit valid credentials
    auth_resp = client.post(
        "/login",
        data={"username": "analyst", "password": "ChangeMe-Analyst#2026", "next": "/portfolio"},
        follow_redirects=False,
    )
    assert auth_resp.status_code == 303
    assert auth_resp.headers["location"] == "/portfolio"
    assert "satsa_session" in auth_resp.cookies

    # 4. View Portfolio
    portfolio_resp = client.get("/portfolio")
    assert portfolio_resp.status_code == 200
    assert "Supervisory Entity Risk Portfolio" in portfolio_resp.text

    # 5. Accessing root / also renders Portfolio when authenticated
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert "Supervisory Entity Risk Portfolio" in root_resp.text

    # 6. Accessing /login when authenticated redirects to /portfolio
    relogin_resp = client.get("/login", follow_redirects=False)
    assert relogin_resp.status_code == 303
    assert relogin_resp.headers["location"] == "/portfolio"

    # 7. Logout
    logout_resp = client.post("/logout", follow_redirects=False)
    assert logout_resp.status_code == 303
    assert logout_resp.headers["location"] == "/login"

    # 8. Subsequent visit to /portfolio redirects to /login
    after_logout = client.get("/portfolio", follow_redirects=False)
    assert after_logout.status_code == 303
    assert "/login?next=" in after_logout.headers["location"]
