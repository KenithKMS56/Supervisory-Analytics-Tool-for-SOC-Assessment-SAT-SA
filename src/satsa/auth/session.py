"""FastAPI session dependencies backed by the local SQLite session table."""

from collections.abc import Callable

from fastapi import HTTPException, Request
from pydantic import BaseModel

from satsa.store.sqlite import SQLiteStore

SESSION_COOKIE_NAME = "satsa_session"


class Identity(BaseModel):
    """The real, authenticated actor behind a request."""

    username: str
    role: str
    org_id: str | None = None
    org_name: str | None = None
    cse_id: str | None = None
    cse_name: str | None = None
    status: str = "ACTIVE"
    is_admin_user: bool = False


# Role equivalence mapping to ensure backward and forward compatibility
ROLE_ALIASES: dict[str, set[str]] = {
    "admin": {"admin", "NCIIPC Super Administrator", "NCIIPC_SUPER_ADMINISTRATOR"},
    "NCIIPC Super Administrator": {"admin", "NCIIPC Super Administrator", "NCIIPC_SUPER_ADMINISTRATOR"},
    "NCIIPC_SUPER_ADMINISTRATOR": {"admin", "NCIIPC Super Administrator", "NCIIPC_SUPER_ADMINISTRATOR"},
    "supervisor": {"supervisor", "NCIIPC Supervisor", "NCIIPC_SUPERVISOR"},
    "NCIIPC Supervisor": {"supervisor", "NCIIPC Supervisor", "NCIIPC_SUPERVISOR"},
    "NCIIPC_SUPERVISOR": {"supervisor", "NCIIPC Supervisor", "NCIIPC_SUPERVISOR"},
    "examiner": {"examiner", "NCIIPC Examiner", "NCIIPC_EXAMINER"},
    "NCIIPC Examiner": {"examiner", "NCIIPC Examiner", "NCIIPC_EXAMINER"},
    "NCIIPC_EXAMINER": {"examiner", "NCIIPC Examiner", "NCIIPC_EXAMINER"},
    "CSE Administrator": {"CSE Administrator", "CSE_ADMIN", "CSE_ADMINISTRATOR"},
    "CSE_ADMIN": {"CSE Administrator", "CSE_ADMIN", "CSE_ADMINISTRATOR"},
    "CSE_ADMINISTRATOR": {"CSE Administrator", "CSE_ADMIN", "CSE_ADMINISTRATOR"},
    "SOC Manager": {"SOC Manager", "SOC_MANAGER"},
    "SOC_MANAGER": {"SOC Manager", "SOC_MANAGER"},
    "SOC Analyst": {"SOC Analyst", "SOC_ANALYST"},
    "SOC_ANALYST": {"SOC Analyst", "SOC_ANALYST"},
    "CSE Viewer": {"CSE Viewer", "CSE_VIEWER"},
    "CSE_VIEWER": {"CSE Viewer", "CSE_VIEWER"},
}


def get_current_identity(request: Request, db_path: str = "data/satsa.db") -> Identity | None:
    """Resolve the authenticated identity from the session cookie, or None."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    store = SQLiteStore(db_path)
    try:
        session = store.get_session(token)
    finally:
        store.close()
    if not session:
        return None
    return Identity(
        username=session["username"],
        role=session["role"],
        org_id=session.get("org_id"),
        org_name=session.get("org_name"),
        cse_id=session.get("cse_id"),
        cse_name=session.get("cse_name"),
        status=session.get("status") or "ACTIVE",
        is_admin_user=bool(session.get("is_admin_user")),
    )


def require_role(*allowed_roles: str) -> Callable[[Request], Identity]:
    """FastAPI dependency factory: require an authenticated identity with one of the given roles.

    Raises 401 if there is no valid session, 403 if the session's role is
    not in `allowed_roles`. Route handlers receive the real `Identity` and
    should use `identity.username` for the audit log's `actor` field
    instead of any caller-supplied form value.
    """
    expanded_allowed: set[str] = set()
    for r in allowed_roles:
        expanded_allowed.update(ROLE_ALIASES.get(r, {r}))

    def _dependency(request: Request) -> Identity:
        identity = get_current_identity(request)
        if identity is None:
            raise HTTPException(
                status_code=401,
                detail="Authentication required. Please log in at /login.",
            )
        if identity.role not in expanded_allowed:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Role '{identity.role}' is not permitted for this action; "
                    f"requires one of {list(allowed_roles)}."
                ),
            )
        return identity

    return _dependency


def require_cse_access(target_cse_id: str, identity: Identity) -> None:
    """Enforce server-side boundary: a user assigned to a specific CSE cannot access another CSE.

    NCIIPC Supervisory roles (NCIIPC Super Administrator, NCIIPC Supervisor,
    NCIIPC Examiner, admin, supervisor, examiner) possess multi-entity supervisory
    oversight. Entity-scoped roles (CSE Administrator, SOC Manager, SOC Analyst,
    CSE Viewer) are strictly constrained to their designated identity.cse_id.
    """
    SUPERVISORY_ROLES = {
        "NCIIPC Super Administrator",
        "NCIIPC Supervisor",
        "NCIIPC Examiner",
        "admin",
        "supervisor",
        "examiner",
        "NCIIPC_SUPER_ADMINISTRATOR",
        "NCIIPC_SUPERVISOR",
        "NCIIPC_EXAMINER",
    }
    if identity.role in SUPERVISORY_ROLES:
        return
    if identity.cse_id and identity.cse_id.upper() != target_cse_id.upper():
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Your account is restricted to {identity.cse_id} and cannot access data for {target_cse_id}.",
        )
