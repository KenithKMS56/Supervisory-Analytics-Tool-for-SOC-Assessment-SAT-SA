"""End-to-End integration tests connecting NCIIPC Admin Portal (:8000) to SAT-SA (:8001).

Tests:
1. Admin Portal provisions an authoritative identity (NCIIPC Analyst, org, status=ACTIVE).
2. User authenticates into SAT-SA (:8001) and gets the analyst's workspace.
3. Admin changes the role to NCIIPC Examiner -> the live session switches to the
   examiner's workspace immediately (engine-room pages 403, review decisions open).
4. Admin changes the role to a CSE-scoped role (SOC Analyst) -> SAT-SA refuses the
   live session, and a fresh login is refused too: only analyst and examiner may use SAT-SA.
5. Admin blocks the user (status = BLOCKED) -> SAT-SA access revoked immediately,
   sessions terminated, new logins denied.
"""

from fastapi.testclient import TestClient

from satsa.admin.app import app as admin_app
from satsa.api.routes import app as satsa_app
from satsa.store.sqlite import SQLiteStore


def test_end_to_end_admin_to_satsa_flow():
    # Use real shared application database "data/satsa.db"
    store = SQLiteStore("data/satsa.db")
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()

    test_username = "nciipc_analyst01"

    # Clean up test user if previously left
    with store.conn:
        store.conn.execute("DELETE FROM sessions WHERE username = ?", (test_username,))
        store.conn.execute("DELETE FROM admin_sessions WHERE username = ?", (test_username,))
        store.conn.execute("DELETE FROM identities WHERE username = ?", (test_username,))

    admin_app.state.store = store
    admin_client = TestClient(admin_app)
    satsa_client = TestClient(satsa_app)

    def edit_role(role: str, org_id: str = "ORG-NCIIPC", cse_id: str = "") -> None:
        resp = admin_client.post(
            f"/users/{test_username}/edit",
            data={
                "role": role,
                "status": "ACTIVE",
                "org_id": org_id,
                "cse_id": cse_id,
                "force_password_change": "false",
                "is_admin_user": "false",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert store.get_user(test_username)["role"] == role

    try:
        # -----------------------------------------------------------------
        # STEP 1: Log in to Admin Portal as NCIIPC Super Administrator
        # -----------------------------------------------------------------
        admin_login = admin_client.post(
            "/login",
            data={"username": "nciipc_admin", "password": "ChangeMe-NCIIPC#2026"},
            follow_redirects=False,
        )
        assert admin_login.status_code == 303
        assert admin_login.cookies.get("nciipc_admin_session") is not None

        # -----------------------------------------------------------------
        # STEP 2: NCIIPC Admin provisions a new NCIIPC Analyst
        # -----------------------------------------------------------------
        create_user_resp = admin_client.post(
            "/users/create",
            data={
                "username": test_username,
                "role": "NCIIPC Analyst",
                "password": "SecurePass#2026",
                "org_id": "ORG-NCIIPC",
                "cse_id": "",
                "force_password_change": "false",
                "is_admin_user": "false",
            },
            follow_redirects=True,
        )
        assert create_user_resp.status_code == 200
        assert test_username in create_user_resp.text

        user_record = store.get_user(test_username)
        assert user_record is not None
        assert user_record["role"] == "NCIIPC Analyst"
        assert user_record["status"] == "ACTIVE"

        # -----------------------------------------------------------------
        # STEP 3: User logs into SAT-SA (:8001) and gets the analyst workspace
        # -----------------------------------------------------------------
        satsa_login = satsa_client.post(
            "/login",
            data={"username": test_username, "password": "SecurePass#2026", "next": "/portfolio"},
            follow_redirects=False,
        )
        assert satsa_login.status_code == 303
        satsa_token = satsa_login.cookies.get("satsa_session")
        assert satsa_token is not None
        cookies = {"satsa_session": satsa_token}

        portfolio_resp = satsa_client.get("/portfolio", cookies=cookies)
        assert portfolio_resp.status_code == 200
        assert test_username in portfolio_resp.text
        assert "NCIIPC Analyst" in portfolio_resp.text
        assert 'href="/upload"' in portfolio_resp.text
        assert satsa_client.get("/upload", cookies=cookies).status_code == 200
        assert satsa_client.get("/entity/CSE-02", cookies=cookies).status_code == 200

        # -----------------------------------------------------------------
        # STEP 4: Admin makes the user an Examiner -> live session follows
        # -----------------------------------------------------------------
        edit_role("NCIIPC Examiner")
        examiner_portfolio = satsa_client.get("/portfolio", cookies=cookies)
        assert examiner_portfolio.status_code == 200
        assert "NCIIPC Examiner" in examiner_portfolio.text
        assert 'href="/upload"' not in examiner_portfolio.text
        assert satsa_client.get("/upload", cookies=cookies, follow_redirects=False).status_code == 403
        assert 'action="/api/v1/feedback"' in satsa_client.get("/queue", cookies=cookies).text

        # -----------------------------------------------------------------
        # STEP 5: Admin moves the user to a CSE-scoped role -> SAT-SA refuses it
        # -----------------------------------------------------------------
        edit_role("SOC Analyst", org_id="ORG-POWER", cse_id="CSE-01")
        refused = satsa_client.get("/portfolio", cookies=cookies, follow_redirects=False)
        assert refused.status_code == 403
        assert "not a SAT-SA operator" in refused.text
        fresh = TestClient(satsa_app).post(
            "/login",
            data={"username": test_username, "password": "SecurePass#2026"},
            follow_redirects=False,
        )
        assert fresh.status_code == 303
        assert "not+a+SAT-SA+operator" in fresh.headers["location"]

        # -----------------------------------------------------------------
        # STEP 6: Admin blocks user account (status = BLOCKED)
        # -----------------------------------------------------------------
        edit_role("NCIIPC Analyst")
        block_resp = admin_client.post(f"/users/{test_username}/block", follow_redirects=True)
        assert block_resp.status_code == 200

        # Verify active session is revoked immediately in SAT-SA
        post_block_resp = satsa_client.get("/portfolio", cookies=cookies, follow_redirects=False)
        # Unauthenticated / session deleted -> redirected to /login
        assert post_block_resp.status_code == 303
        assert "/login" in post_block_resp.headers["location"]

        # Attempting new login with blocked user credentials -> rejected at perimeter
        blocked_login_resp = satsa_client.post(
            "/login",
            data={"username": test_username, "password": "SecurePass#2026"},
            follow_redirects=False,
        )
        assert blocked_login_resp.status_code == 303
        assert "blocked=1" in blocked_login_resp.headers["location"]

    finally:
        # Cleanup
        with store.conn:
            store.conn.execute("DELETE FROM sessions WHERE username = ?", (test_username,))
            store.conn.execute("DELETE FROM admin_sessions WHERE username = ?", (test_username,))
            store.conn.execute("DELETE FROM identities WHERE username = ?", (test_username,))
        store.close()
