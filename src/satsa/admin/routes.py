"""NCIIPC Administration Portal Routes and HTTP Handlers.

Provides dedicated web control interfaces for:
- Super Administrator & Supervisory authentication
- Authoritative user provisioning and lifecycle management
- Critical sector organisation and CSE registries
- Cryptographic administrative audit log exploration and chain verification
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from satsa.admin.rbac import can_access_admin_portal
from satsa.auth.identities import LOGIN_LOCKOUT_MINUTES, LOGIN_MAX_FAILURES, verify_passphrase
from satsa.security import is_valid_username
from satsa.store.sqlite import LIVE_EVENTS_MAX_LIMIT, SQLiteStore

# Setup Jinja2 template environment for admin portal
_ADMIN_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_ADMIN_DIR / "templates"))

router = APIRouter()

ADMIN_COOKIE_NAME = "nciipc_admin_session"


def get_store(request: Request) -> SQLiteStore:
    """Retrieve SQLiteStore instance attached to app state."""
    return request.app.state.store


class AdminAuthRequired(Exception):
    """Raised when an admin-portal route is hit without a valid admin session.

    Handled in satsa.admin.app: HTML GET pages redirect to /login (browser
    flow); API paths and mutating requests get HTTP 401.
    """


def get_session_user(request: Request) -> dict[str, Any] | None:
    """Resolve the identity behind the admin session cookie (any role), or None."""
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not token:
        return None
    store = get_store(request)
    session = store.get_admin_session(token)  # also rejects expired / blocked sessions
    if not session:
        return None
    user = store.get_user(session["username"])
    if not user or user.get("is_blocked") or user.get("status") == "BLOCKED":
        store.delete_admin_session(token)
        return None
    return user


def get_current_operator(request: Request) -> dict[str, Any] | None:
    """Return the session user only if their role may use the admin portal."""
    user = get_session_user(request)
    if user and can_access_admin_portal(user.get("role", "")):
        return user
    return None


def require_admin_operator(request: Request) -> dict[str, Any]:
    """FastAPI dependency: require an authenticated administrator.

    Runs before form/body validation, so an anonymous POST gets 401 (not 422).
    No session -> AdminAuthRequired (303 to /login for pages, 401 otherwise);
    authenticated but not an administrator role -> 403.
    """
    user = get_session_user(request)
    if user is None:
        raise AdminAuthRequired()
    if not can_access_admin_portal(user.get("role", "")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The NCIIPC Administration Portal requires an administrator role.",
        )
    return user


def require_valid_username(username: str) -> None:
    """Reject a {username} path parameter that fails satsa.security.USERNAME_RE (HTTP 400)."""
    if not is_valid_username(username):
        raise HTTPException(status_code=400, detail="Invalid username.")


# =========================================================================
# Authentication Endpoints
# =========================================================================


@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, error: str | None = None) -> Any:
    """Render the admin login page or redirect if already authenticated."""
    operator = get_current_operator(request)
    if operator:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request=request,
        name="admin_login.html",
        context={"request": request, "error": error},
    )


ADMIN_LOGIN_FAILED_MESSAGE = "Invalid administrative credentials."
# Burned on unknown usernames so a miss costs the same PBKDF2 work as a hit.
_DUMMY_SALT_HEX = "00" * 16
_DUMMY_HASH = "0" * 64


@router.post("/login")
async def admin_login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> Any:
    """Process admin authentication and issue secure session cookie.

    The passphrase is verified FIRST. Unknown user, wrong passphrase, blocked
    account and non-administrator role all return the same generic 401, so the
    response never reveals whether a username exists or is blocked. The
    distinct reasons are still recorded in the hash-chained admin audit log.
    """
    store = get_store(request)
    username_clean = username.strip()

    def _deny(action: str, reason: str) -> Any:
        store.append_admin_audit(action, username_clean, target=username_clean, details={"reason": reason})
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={"request": request, "error": ADMIN_LOGIN_FAILED_MESSAGE, "username": username_clean},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    recent_failures = store.count_recent_login_failures(
        username_clean,
        LOGIN_LOCKOUT_MINUTES,
        table="admin_audit_log",
        fail_action="ADMIN_LOGIN_FAIL",
        success_action="ADMIN_LOGIN",
    )
    if recent_failures >= LOGIN_MAX_FAILURES:
        # Locked: rejected even with the correct passphrase, same generic response.
        return _deny("ADMIN_LOGIN_LOCKED", "Too many recent failed attempts")

    cur = store.conn.cursor()
    cur.execute(
        "SELECT username, role, pass_hash, pass_salt, is_blocked, status FROM identities WHERE username = ?",
        (username_clean,),
    )
    user_row = cur.fetchone()

    if not user_row:
        verify_passphrase(password, _DUMMY_SALT_HEX, _DUMMY_HASH)
        return _deny("ADMIN_LOGIN_FAIL", "User not found")
    if not verify_passphrase(password, user_row["pass_salt"], user_row["pass_hash"]):
        return _deny("ADMIN_LOGIN_FAIL", "Bad passphrase")
    if user_row["is_blocked"] or user_row["status"] == "BLOCKED":
        return _deny("ADMIN_LOGIN_BLOCKED", "Account is blocked")
    role = user_row["role"]
    if not can_access_admin_portal(role):
        return _deny("ADMIN_LOGIN_DENIED", "Insufficient role for admin portal")

    # Create session
    token = store.create_admin_session(username_clean, role)
    store.update_user_last_login(username_clean)
    store.append_admin_audit("ADMIN_LOGIN", username_clean, target=username_clean, details={"role": role})

    resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        key=ADMIN_COOKIE_NAME,
        value=token,
        httponly=True,
        # Strict: no admin flow starts from another site, so the session cookie is
        # never sent on cross-site requests (partial mitigation for missing CSRF tokens).
        samesite="strict",
        # Off by default for plain-HTTP localhost; set SATSA_COOKIE_SECURE=1 behind TLS.
        secure=os.environ.get("SATSA_COOKIE_SECURE", "").lower() in ("1", "true", "yes"),
        max_age=8 * 3600,
    )
    return resp


@router.post("/logout")
async def admin_logout_post(request: Request) -> Any:
    """Invalidate administrative session and clear cookie."""
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    operator = get_current_operator(request)
    store = get_store(request)

    if token:
        store.delete_admin_session(token)
    if operator:
        store.append_admin_audit("ADMIN_LOGOUT", operator["username"], target=operator["username"])

    resp = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(ADMIN_COOKIE_NAME)
    return resp


# =========================================================================
# Splash Screen & Dashboard Overview
# =========================================================================


@router.get("/splash", response_class=HTMLResponse)
async def admin_splash_page(request: Request) -> Any:
    """Render NCIIPC Control Console splash/welcome screen like SAT-SA."""
    operator = get_current_operator(request)
    if operator:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request=request,
        name="admin_splash.html",
        context={"request": request, "active_tab": "splash", "hide_nav": True},
    )


@router.get("/overview", response_class=HTMLResponse)
async def admin_overview_direct(request: Request, operator: dict[str, Any] = Depends(require_admin_operator)) -> Any:
    """Protected direct route for Administration Overview."""
    store = get_store(request)
    stats = store.get_admin_overview_stats()
    return templates.TemplateResponse(
        request=request,
        name="admin_overview.html",
        context={
            "request": request,
            "operator": operator,
            "active_tab": "overview",
            "stats": stats,
            "recent_admin_activity": stats["recent_admin_activity"],
            "recent_user_activity": stats["recent_user_activity"],
        },
    )


@router.get("/", response_class=HTMLResponse)
async def admin_overview(request: Request) -> Any:
    """NCIIPC Administration entry point: splash screen for guests, overview for authenticated operators."""
    operator = get_current_operator(request)
    if not operator:
        return templates.TemplateResponse(
            request=request,
            name="admin_splash.html",
            context={"request": request, "active_tab": "splash", "hide_nav": True},
        )

    store = get_store(request)
    stats = store.get_admin_overview_stats()

    return templates.TemplateResponse(
        request=request,
        name="admin_overview.html",
        context={
            "request": request,
            "operator": operator,
            "active_tab": "overview",
            "stats": stats,
            "recent_admin_activity": stats["recent_admin_activity"],
            "recent_user_activity": stats["recent_user_activity"],
        },
    )


# =========================================================================
# User Management
# =========================================================================


@router.get("/users", response_class=HTMLResponse)
async def admin_users_list(request: Request, message: str | None = None, error: str | None = None, operator: dict[str, Any] = Depends(require_admin_operator)) -> Any:
    """Authoritative user directory with online state, role, and operational actions."""

    store = get_store(request)
    users = store.list_admin_users()

    return templates.TemplateResponse(
        request=request,
        name="admin_users.html",
        context={
            "request": request,
            "operator": operator,
            "active_tab": "users",
            "users": users,
            "message": message,
            "error": error,
        },
    )


@router.get("/users/create", response_class=HTMLResponse)
async def admin_user_create_get(request: Request, error: str | None = None, operator: dict[str, Any] = Depends(require_admin_operator)) -> Any:
    """Render user provisioning form with dynamic org/CSE dataset."""

    store = get_store(request)
    organisations = store.list_organisations()
    cses = store.list_cses()

    return templates.TemplateResponse(
        request=request,
        name="admin_user_create.html",
        context={
            "request": request,
            "operator": operator,
            "active_tab": "users",
            "organisations": organisations,
            "cses": cses,
            "error": error,
        },
    )


@router.post("/users/create")
async def admin_user_create_post(
    request: Request,
    username: str = Form(...),
    role: str = Form(...),
    password: str = Form(...),
    org_id: str | None = Form(None),
    cse_id: str | None = Form(None),
    force_password_change: str | None = Form(None),
    operator: dict[str, Any] = Depends(require_admin_operator),
) -> Any:
    """Provision a new authoritative identity with PBKDF2 hashed credentials."""

    store = get_store(request)
    username_clean = username.strip()
    role_clean = role.strip()
    org_clean = org_id.strip() if org_id and org_id.strip() else None
    cse_clean = cse_id.strip() if cse_id and cse_id.strip() else None
    fpc = 1 if force_password_change in ("true", "1", "on") else 0

    # Validation
    if not re.match(r"^[a-zA-Z0-9_\-\.]{3,32}$", username_clean):
        return templates.TemplateResponse(
            request=request,
            name="admin_user_create.html",
            context={
                "request": request,
                "operator": operator,
                "active_tab": "users",
                "organisations": store.list_organisations(),
                "cses": store.list_cses(),
                "error": "Username must be 3-32 characters and contain only alphanumeric, dash, dot, or underscore.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="admin_user_create.html",
            context={
                "request": request,
                "operator": operator,
                "active_tab": "users",
                "organisations": store.list_organisations(),
                "cses": store.list_cses(),
                "error": "Passphrase must be at least 8 characters.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Check if username exists
    existing = store.get_user(username_clean)
    if existing:
        return templates.TemplateResponse(
            request=request,
            name="admin_user_create.html",
            context={
                "request": request,
                "operator": operator,
                "active_tab": "users",
                "organisations": store.list_organisations(),
                "cses": store.list_cses(),
                "error": f"Identity '{username_clean}' already exists.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Dynamic constraint check: if org_id is provided and cse_id is provided, CSE must belong to Org
    if org_clean and cse_clean:
        cur = store.conn.cursor()
        cur.execute("SELECT org_id FROM cses WHERE cse_id = ?", (cse_clean,))
        cse_row = cur.fetchone()
        if cse_row and cse_row["org_id"] != org_clean:
            return templates.TemplateResponse(
                request=request,
                name="admin_user_create.html",
                context={
                    "request": request,
                    "operator": operator,
                    "active_tab": "users",
                    "organisations": store.list_organisations(),
                    "cses": store.list_cses(),
                    "error": f"Selected CSE '{cse_clean}' belongs to organisation '{cse_row['org_id']}', not '{org_clean}'.",
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    # Create user
    store.create_user(
        username=username_clean,
        role=role_clean,
        passphrase=password,
        org_id=org_clean,
        cse_id=cse_clean,
        status="ACTIVE",
        force_password_change=fpc,
    )

    # Append cryptographic audit event (password is never logged)
    store.append_admin_audit(
        action="USER_CREATED",
        actor=operator["username"],
        target=username_clean,
        details={
            "role": role_clean,
            "org_id": org_clean,
            "cse_id": cse_clean,
            "force_password_change": fpc,
        },
    )

    return RedirectResponse(
        url=f"/users?message=Identity+'{username_clean}'+provisioned+successfully",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/users/{username}/edit", response_class=HTMLResponse)
async def admin_user_edit_get(request: Request, username: str, error: str | None = None, operator: dict[str, Any] = Depends(require_admin_operator)) -> Any:
    """Render user editing form."""
    require_valid_username(username)

    store = get_store(request)
    user = store.get_user(username)
    if not user:
        return RedirectResponse(url="/users?error=User+not+found", status_code=status.HTTP_303_SEE_OTHER)

    organisations = store.list_organisations()
    cses = store.list_cses()

    return templates.TemplateResponse(
        request=request,
        name="admin_user_edit.html",
        context={
            "request": request,
            "operator": operator,
            "active_tab": "users",
            "user": user,
            "organisations": organisations,
            "cses": cses,
            "error": error,
        },
    )


@router.post("/users/{username}/edit")
async def admin_user_edit_post(
    request: Request,
    username: str,
    role: str = Form(...),
    status_val: str = Form(..., alias="status"),
    org_id: str | None = Form(None),
    cse_id: str | None = Form(None),
    force_password_change: str | None = Form(None),
    operator: dict[str, Any] = Depends(require_admin_operator),
) -> Any:
    """Update user identity parameters and enforce audit logging for mutations."""
    require_valid_username(username)

    store = get_store(request)
    prev_user = store.get_user(username)
    if not prev_user:
        return RedirectResponse(url="/users?error=User+not+found", status_code=status.HTTP_303_SEE_OTHER)

    role_clean = role.strip()
    status_clean = "BLOCKED" if status_val == "BLOCKED" else "ACTIVE"
    org_clean = org_id.strip() if org_id and org_id.strip() else None
    cse_clean = cse_id.strip() if cse_id and cse_id.strip() else None
    fpc = 1 if force_password_change in ("true", "1", "on") else 0

    # Dynamic constraint check: if org_id is provided and cse_id is provided, CSE must belong to Org
    if org_clean and cse_clean:
        cur = store.conn.cursor()
        cur.execute("SELECT org_id FROM cses WHERE cse_id = ?", (cse_clean,))
        cse_row = cur.fetchone()
        if cse_row and cse_row["org_id"] != org_clean:
            return templates.TemplateResponse(
                request=request,
                name="admin_user_edit.html",
                context={
                    "request": request,
                    "operator": operator,
                    "active_tab": "users",
                    "user": prev_user,
                    "organisations": store.list_organisations(),
                    "cses": store.list_cses(),
                    "error": f"Selected CSE '{cse_clean}' belongs to organisation '{cse_row['org_id']}', not '{org_clean}'.",
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    store.update_user(
        username=username,
        role=role_clean,
        org_id=org_clean,
        cse_id=cse_clean,
        status=status_clean,
        force_password_change=fpc,
    )

    # Audit individual mutations
    if prev_user["status"] != status_clean:
        audit_action = "USER_BLOCKED" if status_clean == "BLOCKED" else "USER_UNBLOCKED"
        store.append_admin_audit(audit_action, operator["username"], target=username)
        if status_clean == "BLOCKED":
            store.record_live_event(
                "ACCOUNT_BLOCKED",
                actor=operator["username"],
                role=operator.get("role", "admin"),
                entity_id=username,
                details={"target_user": username, "action": "blocked"},
                is_admin=True,
            )

    if prev_user["role"] != role_clean:
        store.append_admin_audit(
            "ROLE_CHANGED",
            operator["username"],
            target=username,
            details={"old_role": prev_user["role"], "new_role": role_clean},
        )
        store.record_live_event(
            "ROLE_CHANGED",
            actor=operator["username"],
            role=operator.get("role", "admin"),
            entity_id=username,
            details={"target_user": username, "old_role": prev_user["role"], "new_role": role_clean},
            is_admin=True,
        )

    if prev_user["org_id"] != org_clean:
        store.append_admin_audit(
            "ORGANISATION_CHANGED",
            operator["username"],
            target=username,
            details={"old_org": prev_user["org_id"], "new_org": org_clean},
        )

    if prev_user["cse_id"] != cse_clean:
        store.append_admin_audit(
            "CSE_CHANGED",
            operator["username"],
            target=username,
            details={"old_cse": prev_user["cse_id"], "new_cse": cse_clean},
        )
        store.record_live_event(
            "CSE_CHANGED",
            actor=operator["username"],
            role=operator.get("role", "admin"),
            entity_id=username,
            details={"target_user": username, "old_cse": prev_user["cse_id"], "new_cse": cse_clean},
            is_admin=True,
        )

    store.append_admin_audit(
        "USER_UPDATED",
        operator["username"],
        target=username,
        details={"status": status_clean, "role": role_clean, "org": org_clean, "cse": cse_clean},
    )

    return RedirectResponse(
        url=f"/users?message=Identity+'{username}'+updated+successfully",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/users/{username}/block")
async def admin_user_block(request: Request, username: str, operator: dict[str, Any] = Depends(require_admin_operator)) -> Any:
    """Immediately block user and revoke active sessions."""
    require_valid_username(username)

    store = get_store(request)
    store.set_user_status(username, "BLOCKED")
    store.append_admin_audit("USER_BLOCKED", operator["username"], target=username)
    store.record_live_event(
        "ACCOUNT_BLOCKED",
        actor=operator["username"],
        role=operator.get("role", "admin"),
        entity_id=username,
        details={"target_user": username, "action": "blocked"},
        is_admin=True,
    )

    return RedirectResponse(
        url=f"/users?message=User+'{username}'+has+been+blocked+and+sessions+revoked",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/users/{username}/unblock")
async def admin_user_unblock(request: Request, username: str, operator: dict[str, Any] = Depends(require_admin_operator)) -> Any:
    """Restore active status to a previously blocked user."""
    require_valid_username(username)

    store = get_store(request)
    store.set_user_status(username, "ACTIVE")
    store.append_admin_audit("USER_UNBLOCKED", operator["username"], target=username)

    return RedirectResponse(
        url=f"/users?message=User+'{username}'+has+been+unblocked",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/users/{username}/reset", response_class=HTMLResponse)
async def admin_user_reset_get(request: Request, username: str, error: str | None = None, operator: dict[str, Any] = Depends(require_admin_operator)) -> Any:
    """Render password reset form."""
    require_valid_username(username)

    store = get_store(request)
    user = store.get_user(username)
    if not user:
        return RedirectResponse(url="/users?error=User+not+found", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request=request,
        name="admin_user_reset.html",
        context={
            "request": request,
            "operator": operator,
            "active_tab": "users",
            "user": user,
            "error": error,
        },
    )


@router.post("/users/{username}/reset")
async def admin_user_reset_post(
    request: Request,
    username: str,
    new_password: str = Form(...),
    force_password_change: str | None = Form(None),
    operator: dict[str, Any] = Depends(require_admin_operator),
) -> Any:
    """Issue new credentials, invalidate current sessions, and append audit record."""
    require_valid_username(username)

    store = get_store(request)
    user = store.get_user(username)
    if not user:
        return RedirectResponse(url="/users?error=User+not+found", status_code=status.HTTP_303_SEE_OTHER)

    if len(new_password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="admin_user_reset.html",
            context={
                "request": request,
                "operator": operator,
                "active_tab": "users",
                "user": user,
                "error": "Passphrase must be at least 8 characters.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    fpc = 1 if force_password_change in ("true", "1", "on") else 0
    store.reset_user_password(username, new_password, force_password_change=fpc)
    store.append_admin_audit("CREDENTIAL_RESET", operator["username"], target=username, details={"force_password_change": fpc})

    return RedirectResponse(
        url=f"/users?message=Credentials+for+'{username}'+have+been+reset",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# =========================================================================
# Organisation Management
# =========================================================================


@router.get("/organisations", response_class=HTMLResponse)
async def admin_organisations_list(
    request: Request, message: str | None = None, error: str | None = None, operator: dict[str, Any] = Depends(require_admin_operator)
) -> Any:
    """View critical sector organisations."""

    store = get_store(request)
    organisations = store.list_organisations()

    return templates.TemplateResponse(
        request=request,
        name="admin_organisations.html",
        context={
            "request": request,
            "operator": operator,
            "active_tab": "organisations",
            "organisations": organisations,
            "message": message,
            "error": error,
        },
    )


@router.post("/organisations/create")
async def admin_organisation_create(
    request: Request,
    org_id: str = Form(...),
    name: str = Form(...),
    sector: str = Form(...),
    operator: dict[str, Any] = Depends(require_admin_operator),
) -> Any:
    """Register a new critical sector organisation."""

    store = get_store(request)
    org_clean = org_id.strip().upper()
    name_clean = name.strip()
    sector_clean = sector.strip()

    if not re.match(r"^[A-Z0-9_\-]{3,32}$", org_clean):
        return RedirectResponse(
            url="/organisations?error=Invalid+Organisation+ID.+Must+be+3-32+uppercase+alphanumeric+or+hyphens.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        store.create_organisation(org_clean, name_clean, sector_clean)
        store.append_admin_audit(
            "ORGANISATION_CREATED",
            operator["username"],
            target=org_clean,
            details={"name": name_clean, "sector": sector_clean},
        )
        return RedirectResponse(
            url=f"/organisations?message=Organisation+'{org_clean}'+registered+successfully",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url=f"/organisations?error=Failed+to+register+organisation:+{str(exc)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )


# =========================================================================
# CSE Management
# =========================================================================


@router.get("/cses", response_class=HTMLResponse)
async def admin_cses_list(request: Request, message: str | None = None, error: str | None = None, operator: dict[str, Any] = Depends(require_admin_operator)) -> Any:
    """View registered Critical Sector Entities."""

    store = get_store(request)
    cses = store.list_cses()
    organisations = store.list_organisations()

    return templates.TemplateResponse(
        request=request,
        name="admin_cses.html",
        context={
            "request": request,
            "operator": operator,
            "active_tab": "cses",
            "cses": cses,
            "organisations": organisations,
            "message": message,
            "error": error,
        },
    )


@router.post("/cses/create")
async def admin_cse_create(
    request: Request,
    cse_id: str = Form(...),
    org_id: str = Form(...),
    sector: str = Form(...),
    operator: dict[str, Any] = Depends(require_admin_operator),
) -> Any:
    """Register a new Critical Sector Entity."""

    store = get_store(request)
    cse_clean = cse_id.strip().upper()
    org_clean = org_id.strip()
    sector_clean = sector.strip()

    if not re.match(r"^[A-Z0-9_\-]{3,16}$", cse_clean):
        return RedirectResponse(
            url="/cses?error=Invalid+CSE+ID.+Must+be+3-16+uppercase+alphanumeric+or+hyphens.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        store.create_cse(cse_clean, org_clean, sector_clean)
        store.append_admin_audit(
            "CSE_CREATED",
            operator["username"],
            target=cse_clean,
            details={"org_id": org_clean, "sector": sector_clean},
        )
        return RedirectResponse(
            url=f"/cses?message=Critical+Sector+Entity+'{cse_clean}'+registered+successfully",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url=f"/cses?error=Failed+to+register+CSE:+{str(exc)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )


# =========================================================================
# Administrative Audit Trail
# =========================================================================


@router.get("/audit", response_class=HTMLResponse)
async def admin_audit_view(request: Request, operator: dict[str, Any] = Depends(require_admin_operator)) -> Any:
    """Cryptographic audit trail viewer with live SHA-256 chain verification."""

    store = get_store(request)
    logs = store.list_admin_audit_logs(limit=250)
    chain_valid, chain_msg = store.verify_admin_audit_chain()

    return templates.TemplateResponse(
        request=request,
        name="admin_audit.html",
        context={
            "request": request,
            "operator": operator,
            "active_tab": "audit",
            "audit_logs": logs,
            "chain_valid": chain_valid,
            "chain_message": chain_msg,
        },
    )


# =========================================================================
# Admin Activity Feed (operator session monitor) Endpoints
# =========================================================================


@router.get("/api/activity/stream")
async def admin_activity_stream(
    request: Request,
    since_id: int = Query(0, ge=0, description="Return events with event_id > since_id"),
    limit: int = Query(50, ge=1, le=LIVE_EVENTS_MAX_LIMIT),
    operator: dict[str, Any] = Depends(require_admin_operator),
) -> JSONResponse:
    """Admin activity feed polling endpoint: SAT-SA operator events newer than since_id.

    Monitors SAT-SA's own operators (logins, report downloads, account actions),
    not CSE security data. Parameters are range-checked (422 on bad input).
    """
    store = get_store(request)
    events = store.get_live_events(since_id=since_id, limit=limit)
    online_users = store.get_online_operators()
    max_id = max([e["event_id"] for e in events], default=since_id)
    return JSONResponse(
        {
            "events": events,
            "online_users": online_users,
            "max_id": max_id,
        }
    )


@router.get("/api/activity/recent")
async def admin_activity_recent(
    request: Request,
    limit: int = Query(30, ge=1, le=LIVE_EVENTS_MAX_LIMIT),
    operator: dict[str, Any] = Depends(require_admin_operator),
) -> JSONResponse:
    """Most recent admin activity feed events and currently signed-in operators."""
    store = get_store(request)
    events = store.get_live_events(since_id=0, limit=limit)
    online_users = store.get_online_operators()
    return JSONResponse({"events": events, "online_users": online_users})


@router.websocket("/ws/activity")
async def admin_activity_websocket(websocket: WebSocket) -> None:
    """Admin activity feed over WebSocket: pushes new SAT-SA operator events (admin session required)."""
    store: SQLiteStore = websocket.app.state.store
    # Same authorization as every other admin route: a valid, unblocked admin
    # session with an administrator role. Otherwise refuse the handshake
    # (policy violation, 1008) before any event is sent.
    token = websocket.cookies.get(ADMIN_COOKIE_NAME)
    session = store.get_admin_session(token) if token else None
    user = store.get_user(session["username"]) if session else None
    if (
        not user
        or user.get("is_blocked")
        or user.get("status") == "BLOCKED"
        or not can_access_admin_portal(user.get("role", ""))
    ):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    last_id = 0
    initial_events = store.get_live_events(since_id=0, limit=25)
    if initial_events:
        last_id = max(e["event_id"] for e in initial_events)
    try:
        import asyncio

        while True:
            new_events = store.get_live_events(since_id=last_id, limit=50)
            if new_events:
                last_id = max(e["event_id"] for e in new_events)
                online_users = store.get_online_operators()
                await websocket.send_json({"events": new_events, "online_users": online_users})
            await asyncio.sleep(1.0)
    except (WebSocketDisconnect, Exception):
        pass
