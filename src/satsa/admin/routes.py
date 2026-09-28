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

from fastapi import APIRouter, Form, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from satsa.admin.rbac import can_access_admin_portal
from satsa.auth.identities import verify_passphrase
from satsa.security import is_valid_username
from satsa.store.sqlite import SQLiteStore

# Setup Jinja2 template environment for admin portal
_ADMIN_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_ADMIN_DIR / "templates"))

router = APIRouter()

ADMIN_COOKIE_NAME = "nciipc_admin_session"


def get_store(request: Request) -> SQLiteStore:
    """Retrieve SQLiteStore instance attached to app state."""
    return request.app.state.store


def get_current_operator(request: Request) -> dict[str, Any] | None:
    """Validate admin session token from cookie and return active operator identity."""
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not token:
        return None
    store = get_store(request)
    session = store.get_admin_session(token)
    if not session:
        return None

    # Check account status & admin privileges
    if session.get("is_blocked") or session.get("status") == "BLOCKED":
        store.delete_admin_session(token)
        return None

    user = store.get_user(session["username"])
    if not user:
        return None

    role = user.get("role", "")
    is_admin = bool(user.get("is_admin_user"))
    if not can_access_admin_portal(role, is_admin):
        store.delete_admin_session(token)
        return None

    return user


def require_valid_username(username: str) -> None:
    """Reject a {username} path parameter that fails satsa.security.USERNAME_RE (HTTP 400)."""
    if not is_valid_username(username):
        raise HTTPException(status_code=400, detail="Invalid username.")


def require_operator(request: Request) -> tuple[dict[str, Any] | None, RedirectResponse | None]:
    """Helper to require authenticated operator or return a redirect to /login."""
    operator = get_current_operator(request)
    if not operator:
        return None, RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return operator, None


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


@router.post("/login")
async def admin_login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> Any:
    """Process admin authentication and issue secure session cookie."""
    store = get_store(request)
    username_clean = username.strip()

    # Look up user
    cur = store.conn.cursor()
    cur.execute(
        "SELECT username, role, pass_hash, pass_salt, is_blocked, status, is_admin_user FROM identities WHERE username = ?",
        (username_clean,),
    )
    user_row = cur.fetchone()

    if not user_row:
        store.append_admin_audit("ADMIN_LOGIN_FAIL", username_clean, target=username_clean, details={"reason": "User not found"})
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={"request": request, "error": "Invalid administrative credentials.", "username": username_clean},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Check status
    if user_row["is_blocked"] or user_row["status"] == "BLOCKED":
        store.append_admin_audit("ADMIN_LOGIN_BLOCKED", username_clean, target=username_clean, details={"reason": "Account is blocked"})
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={"request": request, "error": "Account is blocked. Access denied.", "username": username_clean},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    # Check passphrase
    if not verify_passphrase(password, user_row["pass_salt"], user_row["pass_hash"]):
        store.append_admin_audit("ADMIN_LOGIN_FAIL", username_clean, target=username_clean, details={"reason": "Bad passphrase"})
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={"request": request, "error": "Invalid administrative credentials.", "username": username_clean},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Check administrative portal authorization
    role = user_row["role"]
    is_admin = bool(user_row["is_admin_user"])
    if not can_access_admin_portal(role, is_admin):
        store.append_admin_audit("ADMIN_LOGIN_DENIED", username_clean, target=username_clean, details={"reason": "Insufficient role for admin portal"})
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={"request": request, "error": "Identity is not authorized to access NCIIPC Administration Portal.", "username": username_clean},
            status_code=status.HTTP_403_FORBIDDEN,
        )

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
async def admin_overview_direct(request: Request) -> Any:
    """Protected direct route for Administration Overview."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect
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
async def admin_users_list(request: Request, message: str | None = None, error: str | None = None) -> Any:
    """Authoritative user directory with online state, role, and operational actions."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect

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
async def admin_user_create_get(request: Request, error: str | None = None) -> Any:
    """Render user provisioning form with dynamic org/CSE dataset."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect

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
    is_admin_user: str | None = Form(None),
) -> Any:
    """Provision a new authoritative identity with PBKDF2 hashed credentials."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect

    store = get_store(request)
    username_clean = username.strip()
    role_clean = role.strip()
    org_clean = org_id.strip() if org_id and org_id.strip() else None
    cse_clean = cse_id.strip() if cse_id and cse_id.strip() else None
    fpc = 1 if force_password_change in ("true", "1", "on") else 0
    admin_access = 1 if is_admin_user in ("true", "1", "on") else 0

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
        is_admin_user=admin_access,
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
            "is_admin_user": admin_access,
        },
    )

    return RedirectResponse(
        url=f"/users?message=Identity+'{username_clean}'+provisioned+successfully",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/users/{username}/edit", response_class=HTMLResponse)
async def admin_user_edit_get(request: Request, username: str, error: str | None = None) -> Any:
    """Render user editing form."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect
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
    is_admin_user: str | None = Form(None),
) -> Any:
    """Update user identity parameters and enforce audit logging for mutations."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect
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
    admin_access = 1 if is_admin_user in ("true", "1", "on") else 0

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
        is_admin_user=admin_access,
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
async def admin_user_block(request: Request, username: str) -> Any:
    """Immediately block user and revoke active sessions."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect
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
async def admin_user_unblock(request: Request, username: str) -> Any:
    """Restore active status to a previously blocked user."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect
    require_valid_username(username)

    store = get_store(request)
    store.set_user_status(username, "ACTIVE")
    store.append_admin_audit("USER_UNBLOCKED", operator["username"], target=username)

    return RedirectResponse(
        url=f"/users?message=User+'{username}'+has+been+unblocked",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/users/{username}/reset", response_class=HTMLResponse)
async def admin_user_reset_get(request: Request, username: str, error: str | None = None) -> Any:
    """Render password reset form."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect
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
) -> Any:
    """Issue new credentials, invalidate current sessions, and append audit record."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect
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
    request: Request, message: str | None = None, error: str | None = None
) -> Any:
    """View critical sector organisations."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect

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
) -> Any:
    """Register a new critical sector organisation."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect

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
async def admin_cses_list(request: Request, message: str | None = None, error: str | None = None) -> Any:
    """View registered Critical Sector Entities."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect

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
) -> Any:
    """Register a new Critical Sector Entity."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect

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
async def admin_audit_view(request: Request) -> Any:
    """Cryptographic audit trail viewer with live SHA-256 chain verification."""
    operator, redirect = require_operator(request)
    if redirect:
        return redirect

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
# Live Activity & Telemetry Endpoints
# =========================================================================


@router.get("/api/activity/stream")
async def admin_activity_stream(request: Request, since_id: int = 0, limit: int = 50) -> JSONResponse:
    """Telemetry stream endpoint providing real-time SAT-SA operational events and online operators."""
    operator = get_current_operator(request)
    if not operator:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

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
async def admin_activity_recent(request: Request, limit: int = 30) -> JSONResponse:
    """Fetch the most recent operational events."""
    operator = get_current_operator(request)
    if not operator:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    store = get_store(request)
    events = store.get_live_events(since_id=0, limit=limit)
    online_users = store.get_online_operators()
    return JSONResponse({"events": events, "online_users": online_users})


@router.websocket("/ws/activity")
async def admin_activity_websocket(websocket: WebSocket) -> None:
    """WebSocket endpoint pushing near-real-time operational telemetry to Admin Dashboard."""
    await websocket.accept()
    store: SQLiteStore = websocket.app.state.store
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
