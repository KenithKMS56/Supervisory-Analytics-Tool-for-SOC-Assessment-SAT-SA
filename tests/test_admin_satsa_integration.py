"""End-to-End integration tests connecting NCIIPC Admin Portal (:8000) to SAT-SA (:8001).

Tests:
1. Admin Portal provisions authoritative identity (username, org, cse, role, status=ACTIVE).
2. User authenticates into SAT-SA (:8001).
3. SAT-SA correctly resolves role, organisation, and CSE scope from the shared database.
4. User accesses their assigned CSE profile -> 200 OK.
5. User attempts to access a different CSE profile -> 403 Forbidden.
6. Admin updates user's CSE scope (e.g. CSE-01 -> CSE-06) -> scope updates dynamically on active session.
7. Admin updates user's role (e.g. SOC Analyst -> CSE Administrator) -> role updates dynamically.
8. Admin blocks user (status = BLOCKED) -> SAT-SA access revoked immediately, sessions terminated, new logins denied.
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

    test_username = "cse01_analyst01"

    # Clean up test user if previously left
    with store.conn:
        store.conn.execute("DELETE FROM sessions WHERE username = ?", (test_username,))
        store.conn.execute("DELETE FROM admin_sessions WHERE username = ?", (test_username,))
        store.conn.execute("DELETE FROM identities WHERE username = ?", (test_username,))

    admin_app.state.store = store
    admin_client = TestClient(admin_app)
    satsa_client = TestClient(satsa_app)

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
        admin_token = admin_login.cookies.get("nciipc_admin_session")
        assert admin_token is not None

        # -----------------------------------------------------------------
        # STEP 2: NCIIPC Admin provisions a new user: cse01_analyst01
        # Organisation: ORG-POWER, CSE: CSE-01, Role: SOC Analyst
        # -----------------------------------------------------------------
        create_user_resp = admin_client.post(
            "/users/create",
            data={
                "username": test_username,
                "role": "SOC Analyst",
                "password": "SecurePass#2026",
                "org_id": "ORG-POWER",
                "cse_id": "CSE-01",
                "force_password_change": "false",
                "is_admin_user": "false",
            },
            follow_redirects=True,
        )
        assert create_user_resp.status_code == 200
        assert test_username in create_user_resp.text

        # Verify user record in SQLite store
        user_record = store.get_user(test_username)
        assert user_record is not None
        assert user_record["role"] == "SOC Analyst"
        assert user_record["org_id"] == "ORG-POWER"
        assert user_record["cse_id"] == "CSE-01"
        assert user_record["status"] == "ACTIVE"

        # -----------------------------------------------------------------
        # STEP 3: User logs into SAT-SA (:8001) with provisioned credentials
        # -----------------------------------------------------------------
        satsa_login = satsa_client.post(
            "/login",
            data={"username": test_username, "password": "SecurePass#2026", "next": "/portfolio"},
            follow_redirects=False,
        )
        assert satsa_login.status_code == 303
        satsa_token = satsa_login.cookies.get("satsa_session")
        assert satsa_token is not None

        # -----------------------------------------------------------------
        # STEP 4: Verify SAT-SA loads user scope (Role, Org, CSE)
        # -----------------------------------------------------------------
        portfolio_resp = satsa_client.get("/portfolio", cookies={"satsa_session": satsa_token})
        assert portfolio_resp.status_code == 200
        # Check UI shows user identity and assigned CSE
        assert test_username in portfolio_resp.text
        assert "CSE-01" in portfolio_resp.text

        # -----------------------------------------------------------------
        # STEP 5: Verify Authorized CSE access (CSE-01) succeeds
        # -----------------------------------------------------------------
        cse01_resp = satsa_client.get("/entity/CSE-01", cookies={"satsa_session": satsa_token})
        assert cse01_resp.status_code == 200
        assert "CSE-01" in cse01_resp.text

        # -----------------------------------------------------------------
        # STEP 6: Verify Unauthorized CSE access (CSE-02) is rejected (403)
        # -----------------------------------------------------------------
        cse02_resp = satsa_client.get("/entity/CSE-02", cookies={"satsa_session": satsa_token})
        assert cse02_resp.status_code == 403
        assert "Access Denied: Your account is restricted to CSE-01" in cse02_resp.text

        # -----------------------------------------------------------------
        # STEP 7: Admin updates user's CSE scope (CSE-01 -> CSE-06)
        # (Both belong to ORG-POWER)
        # -----------------------------------------------------------------
        edit_cse_resp = admin_client.post(
            f"/users/{test_username}/edit",
            data={
                "role": "SOC Analyst",
                "status": "ACTIVE",
                "org_id": "ORG-POWER",
                "cse_id": "CSE-06",
                "force_password_change": "false",
                "is_admin_user": "false",
            },
            follow_redirects=True,
        )
        assert edit_cse_resp.status_code == 200

        # Now verify user's session reflects CSE-06 scope immediately
        cse06_resp = satsa_client.get("/entity/CSE-06", cookies={"satsa_session": satsa_token})
        assert cse06_resp.status_code == 200

        # And old CSE-01 is now forbidden
        old_cse_resp = satsa_client.get("/entity/CSE-01", cookies={"satsa_session": satsa_token})
        assert old_cse_resp.status_code == 403
        assert "Access Denied: Your account is restricted to CSE-06" in old_cse_resp.text

        # -----------------------------------------------------------------
        # STEP 8: Admin updates user's Role (SOC Analyst -> CSE Administrator)
        # -----------------------------------------------------------------
        edit_role_resp = admin_client.post(
            f"/users/{test_username}/edit",
            data={
                "role": "CSE Administrator",
                "status": "ACTIVE",
                "org_id": "ORG-POWER",
                "cse_id": "CSE-06",
                "force_password_change": "false",
                "is_admin_user": "false",
            },
            follow_redirects=True,
        )
        assert edit_role_resp.status_code == 200

        updated_user = store.get_user(test_username)
        assert updated_user["role"] == "CSE Administrator"

        # -----------------------------------------------------------------
        # STEP 9: Admin blocks user account (status = BLOCKED)
        # -----------------------------------------------------------------
        block_resp = admin_client.post(
            f"/users/{test_username}/block",
            follow_redirects=True,
        )
        assert block_resp.status_code == 200

        # Verify active session is revoked immediately in SAT-SA
        post_block_resp = satsa_client.get(
            "/portfolio",
            cookies={"satsa_session": satsa_token},
            follow_redirects=False,
        )
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
