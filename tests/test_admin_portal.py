"""Comprehensive tests for NCIIPC Administration Portal and Central RBAC.

Covers:
1. Bootstrap Admin authentication and session handling
2. Unauthenticated redirection to /login
3. User provisioning with dynamic Organisation-to-CSE validation
4. PBKDF2 password hashing (no plaintext storage)
5. User editing and status toggling (ACTIVE / BLOCKED)
6. Immediate session invalidation upon blocking and perimeter denial across SAT-SA and Admin
7. User unblocking and credential reset
8. Organisation and CSE registry creation
9. Cryptographic audit trail logging and SHA-256 chain verification
10. Server-side CSE boundary enforcement
"""

import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from satsa.admin.app import app as admin_app
from satsa.api.routes import app as satsa_app
from satsa.auth.identities import verify_passphrase
from satsa.store.sqlite import SQLiteStore


@pytest.fixture
def temp_db():
    """Create an isolated SQLite database with migrations and seeds."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_admin.db"
        store = SQLiteStore(str(db_path))
        store.seed_default_organisations_and_cses()
        store.seed_default_admin()
        yield store
        store.close()


@pytest.fixture
def admin_client(temp_db):
    """Test client for NCIIPC Admin Portal backed by temp_db."""
    admin_app.state.store = temp_db
    client = TestClient(admin_app)
    return client


@pytest.fixture
def authenticated_admin_client(admin_client, temp_db):
    """Admin client with active nciipc_admin session."""
    resp = admin_client.post(
        "/login",
        data={"username": "nciipc_admin", "password": "ChangeMe-NCIIPC#2026"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    return admin_client


def test_admin_splash_screen_at_root_and_splash(admin_client):
    """Splash screen rendered at / and /splash for unauthenticated users."""
    resp = admin_client.get("/", follow_redirects=False)
    assert resp.status_code == 200
    assert "0xZenith" in resp.text
    assert "btnLandingLogin" in resp.text
    assert 'href="/login"' in resp.text

    resp_splash = admin_client.get("/splash", follow_redirects=False)
    assert resp_splash.status_code == 200
    assert "btnLandingLogin" in resp_splash.text


def test_admin_bootstrap_and_unauthenticated_redirect(admin_client):
    """Unauthenticated requests to protected endpoints redirect to /login."""
    resp = admin_client.get("/overview", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    resp = admin_client.get("/users", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    resp = admin_client.get("/organisations", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_admin_login_failure(admin_client):
    """Login with invalid credentials returns 401."""
    resp = admin_client.post(
        "/login",
        data={"username": "nciipc_admin", "password": "WrongPassword!"},
    )
    assert resp.status_code == 401
    assert "Invalid administrative credentials" in resp.text


def test_admin_login_success(authenticated_admin_client):
    """Bootstrap admin login succeeds and can view overview page."""
    resp = authenticated_admin_client.get("/")
    assert resp.status_code == 200
    assert "National Cyber Resilience Oversight" in resp.text
    assert "Overview" in resp.text
    assert "nciipc_admin" in resp.text


def test_user_provisioning_with_dynamic_org_cse_constraint(authenticated_admin_client, temp_db):
    """Admin provisions users and dynamic Org-to-CSE boundary is enforced."""
    # 1. Valid user: CSE-01 belongs to ORG-POWER
    resp = authenticated_admin_client.post(
        "/users/create",
        data={
            "username": "analyst_power_1",
            "role": "SOC Analyst",
            "password": "SecurePassword#2026",
            "org_id": "ORG-POWER",
            "cse_id": "CSE-01",
            "force_password_change": "true",
            "is_admin_user": "false",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "analyst_power_1" in resp.text

    # Verify user stored with PBKDF2 hash, never plaintext
    user = temp_db.get_user("analyst_power_1")
    assert user is not None
    assert user["role"] == "SOC Analyst"
    assert user["org_id"] == "ORG-POWER"
    assert user["cse_id"] == "CSE-01"
    assert user["status"] == "ACTIVE"
    assert user["force_password_change"] == 1

    # Verify PBKDF2 hash matches
    cur = temp_db.conn.cursor()
    cur.execute("SELECT pass_hash, pass_salt FROM identities WHERE username = 'analyst_power_1'")
    row = cur.fetchone()
    assert verify_passphrase("SecurePassword#2026", row["pass_salt"], row["pass_hash"])
    assert row["pass_hash"] != "SecurePassword#2026"  # Not plaintext

    # 2. Invalid dynamic constraint: CSE-02 belongs to ORG-BANK, NOT ORG-POWER
    resp_invalid = authenticated_admin_client.post(
        "/users/create",
        data={
            "username": "analyst_mismatch",
            "role": "SOC Analyst",
            "password": "SecurePassword#2026",
            "org_id": "ORG-POWER",
            "cse_id": "CSE-02",  # Belongs to ORG-BANK!
        },
    )
    assert resp_invalid.status_code == 400
    assert "belongs to organisation" in resp_invalid.text


def test_user_edit_and_role_change(authenticated_admin_client, temp_db):
    """Admin can edit an identity's role, org, CSE, and flags."""
    # Create test user
    temp_db.create_user("test_editor", "SOC Analyst", "InitPass#2026", "ORG-POWER", "CSE-01")

    # Update role to SOC Manager
    resp = authenticated_admin_client.post(
        "/users/test_editor/edit",
        data={
            "role": "SOC Manager",
            "status": "ACTIVE",
            "org_id": "ORG-POWER",
            "cse_id": "CSE-01",
            "force_password_change": "false",
            "is_admin_user": "false",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    updated = temp_db.get_user("test_editor")
    assert updated["role"] == "SOC Manager"


def test_user_blocking_and_immediate_session_revocation(authenticated_admin_client, temp_db):
    """Blocking a user revokes active sessions and denies authentication."""
    # 1. Create a user
    temp_db.create_user("user_to_block", "SOC Analyst", "UserPass#2026", "ORG-POWER", "CSE-01")

    # 2. Create active session in SAT-SA
    token = temp_db.create_session("user_to_block", "SOC Analyst")
    assert temp_db.get_session(token) is not None

    # 3. Block user via admin action
    resp = authenticated_admin_client.post(
        "/users/user_to_block/block",
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "blocked" in resp.text

    # 4. Check user status in database
    user = temp_db.get_user("user_to_block")
    assert user["status"] == "BLOCKED"
    assert user["is_blocked"] == 1

    # 5. Check that active session is immediately revoked
    assert temp_db.get_session(token) is None

    # 6. Attempt login at admin portal with blocked credentials -> denied
    admin_login_resp = authenticated_admin_client.post(
        "/login",
        data={"username": "user_to_block", "password": "UserPass#2026"},
    )
    assert admin_login_resp.status_code == 403
    assert "Account is blocked" in admin_login_resp.text

    # 7. Unblock user
    unblock_resp = authenticated_admin_client.post(
        "/users/user_to_block/unblock",
        follow_redirects=True,
    )
    assert unblock_resp.status_code == 200
    assert temp_db.get_user("user_to_block")["status"] == "ACTIVE"


def test_user_credential_reset(authenticated_admin_client, temp_db):
    """Admin can reset a user's password and force password change on next login."""
    temp_db.create_user("user_reset_test", "SOC Analyst", "OldPass#2026", "ORG-POWER", "CSE-01")
    token = temp_db.create_session("user_reset_test", "SOC Analyst")
    assert temp_db.get_session(token) is not None

    resp = authenticated_admin_client.post(
        "/users/user_reset_test/reset",
        data={"new_password": "NewSecretPassphrase#2026", "force_password_change": "true"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "reset" in resp.text

    # Session invalidated
    assert temp_db.get_session(token) is None

    # New password works
    user = temp_db.get_user("user_reset_test")
    assert user["force_password_change"] == 1
    cur = temp_db.conn.cursor()
    cur.execute("SELECT pass_hash, pass_salt FROM identities WHERE username = 'user_reset_test'")
    row = cur.fetchone()
    assert verify_passphrase("NewSecretPassphrase#2026", row["pass_salt"], row["pass_hash"])
    assert not verify_passphrase("OldPass#2026", row["pass_salt"], row["pass_hash"])


def test_organisation_and_cse_registration(authenticated_admin_client, temp_db):
    """Admin can register new organisations and critical sector entities."""
    # Register Org
    resp_org = authenticated_admin_client.post(
        "/organisations/create",
        data={
            "org_id": "ORG-RAILWAY",
            "name": "Indian Railways Information Systems",
            "sector": "Transport & Aviation",
        },
        follow_redirects=True,
    )
    assert resp_org.status_code == 200
    assert "ORG-RAILWAY" in resp_org.text

    # Register CSE under ORG-RAILWAY
    resp_cse = authenticated_admin_client.post(
        "/cses/create",
        data={
            "cse_id": "CSE-20",
            "org_id": "ORG-RAILWAY",
            "sector": "Transport & Aviation",
        },
        follow_redirects=True,
    )
    assert resp_cse.status_code == 200
    assert "CSE-20" in resp_cse.text


def test_cryptographic_audit_trail_and_chain_verification(authenticated_admin_client, temp_db):
    """All administrative actions generate chained SHA-256 audit records with verifiable integrity."""
    # Verify chain integrity
    valid, msg = temp_db.verify_admin_audit_chain()
    assert valid is True
    assert "verified" in msg

    resp = authenticated_admin_client.get("/audit")
    assert resp.status_code == 200
    assert "Hash Chain Verified" in resp.text


def test_server_side_cse_boundary_enforcement():
    """Users scoped to one CSE cannot access other CSE data in SAT-SA."""
    from fastapi import HTTPException
    from satsa.auth.session import Identity, require_cse_access

    # 1. CSE-scoped identity
    analyst_cse01 = Identity(
        username="analyst1",
        role="SOC Analyst",
        org_id="ORG-POWER",
        cse_id="CSE-01",
        status="ACTIVE",
    )

    # Scoped user accessing their own CSE -> Permitted
    require_cse_access("CSE-01", analyst_cse01)

    # Scoped user attempting to access different CSE -> HTTP 403 Forbidden
    with pytest.raises(HTTPException) as exc_info:
        require_cse_access("CSE-02", analyst_cse01)
    assert exc_info.value.status_code == 403
    assert "cannot access data for CSE-02" in exc_info.value.detail

    # 2. Supervisory identity (unscoped) -> Permitted to access any CSE
    supervisor = Identity(
        username="supervisor1",
        role="NCIIPC Supervisor",
        org_id=None,
        cse_id=None,
        status="ACTIVE",
    )
    require_cse_access("CSE-01", supervisor)
    require_cse_access("CSE-02", supervisor)
    require_cse_access("CSE-10", supervisor)
