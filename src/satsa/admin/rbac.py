"""Centralized Role-Based Access Control (RBAC) and permissions for NCIIPC Admin Portal and SAT-SA."""

from enum import Enum


class Role:
    NCIIPC_SUPER_ADMIN = "NCIIPC Super Administrator"
    NCIIPC_ANALYST = "NCIIPC Analyst"
    NCIIPC_EXAMINER = "NCIIPC Examiner"
    CSE_ADMIN = "CSE Administrator"
    SOC_MANAGER = "SOC Manager"
    SOC_ANALYST = "SOC Analyst"
    CSE_VIEWER = "CSE Viewer"

    # Legacy aliases. "supervisor" is the pre-rename name of the analyst role;
    # SQLiteStore._ensure_migrations rewrites stored rows to "analyst".
    LEGACY_ADMIN = "admin"
    LEGACY_ANALYST = "analyst"
    LEGACY_SUPERVISOR = "supervisor"
    LEGACY_EXAMINER = "examiner"


# Every spelling of the two SAT-SA operator roles. Deliberately disjoint from
# the CSE-side "SOC Analyst" role.
ANALYST_ROLE_NAMES: frozenset[str] = frozenset(
    {
        Role.NCIIPC_ANALYST,
        Role.LEGACY_ANALYST,
        "NCIIPC_ANALYST",
        Role.LEGACY_SUPERVISOR,
        "NCIIPC Supervisor",
        "NCIIPC_SUPERVISOR",
    }
)
EXAMINER_ROLE_NAMES: frozenset[str] = frozenset(
    {Role.NCIIPC_EXAMINER, Role.LEGACY_EXAMINER, "NCIIPC_EXAMINER"}
)
# SAT-SA (:8001) admits only these: the analyst operates the pipeline, the
# examiner decides. Administrators work the Admin Portal (:8000) only.
SATSA_OPERATOR_ROLES: frozenset[str] = ANALYST_ROLE_NAMES | EXAMINER_ROLE_NAMES


def is_analyst(role: str | None) -> bool:
    return role in ANALYST_ROLE_NAMES


def is_examiner(role: str | None) -> bool:
    return role in EXAMINER_ROLE_NAMES


# List of official authoritative roles for administrative assignment
ALL_ASSIGNABLE_ROLES: tuple[str, ...] = (
    Role.NCIIPC_SUPER_ADMIN,
    Role.NCIIPC_ANALYST,
    Role.NCIIPC_EXAMINER,
    Role.CSE_ADMIN,
    Role.SOC_MANAGER,
    Role.SOC_ANALYST,
    Role.CSE_VIEWER,
)

SUPERVISORY_ROLES: set[str] = {
    Role.NCIIPC_SUPER_ADMIN,
    Role.LEGACY_ADMIN,
    *SATSA_OPERATOR_ROLES,
}

# Only administrator roles may use the Admin Portal: every portal route can
# create/modify identities (including new administrators), block accounts or
# reset credentials, so read-only supervisory roles are deliberately excluded.
ADMIN_PORTAL_ROLES: set[str] = {
    Role.NCIIPC_SUPER_ADMIN,
    Role.LEGACY_ADMIN,
    "NCIIPC_SUPER_ADMINISTRATOR",
}


class Permission(str, Enum):
    ACCESS_ADMIN_PORTAL = "access_admin_portal"
    MANAGE_ORGANISATIONS = "manage_organisations"
    MANAGE_CSES = "manage_cses"
    MANAGE_USERS = "manage_users"
    RESET_CREDENTIALS = "reset_credentials"
    BLOCK_USERS = "block_users"
    VIEW_ADMIN_AUDIT = "view_admin_audit"
    SUPERVISORY_OVERSIGHT = "supervisory_oversight"
    VIEW_ALL_CSES = "view_all_cses"


ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    Role.NCIIPC_SUPER_ADMIN: {
        Permission.ACCESS_ADMIN_PORTAL,
        Permission.MANAGE_ORGANISATIONS,
        Permission.MANAGE_CSES,
        Permission.MANAGE_USERS,
        Permission.RESET_CREDENTIALS,
        Permission.BLOCK_USERS,
        Permission.VIEW_ADMIN_AUDIT,
        Permission.SUPERVISORY_OVERSIGHT,
        Permission.VIEW_ALL_CSES,
    },
    Role.LEGACY_ADMIN: {
        Permission.ACCESS_ADMIN_PORTAL,
        Permission.MANAGE_ORGANISATIONS,
        Permission.MANAGE_CSES,
        Permission.MANAGE_USERS,
        Permission.RESET_CREDENTIALS,
        Permission.BLOCK_USERS,
        Permission.VIEW_ADMIN_AUDIT,
        Permission.SUPERVISORY_OVERSIGHT,
        Permission.VIEW_ALL_CSES,
    },
    **{
        name: {
            Permission.ACCESS_ADMIN_PORTAL,
            Permission.VIEW_ADMIN_AUDIT,
            Permission.SUPERVISORY_OVERSIGHT,
            Permission.VIEW_ALL_CSES,
        }
        for name in ANALYST_ROLE_NAMES
    },
    Role.NCIIPC_EXAMINER: {
        Permission.VIEW_ALL_CSES,
    },
    Role.LEGACY_EXAMINER: {
        Permission.VIEW_ALL_CSES,
    },
    Role.CSE_ADMIN: {
        Permission.MANAGE_USERS,
        Permission.RESET_CREDENTIALS,
    },
    Role.SOC_MANAGER: set(),
    Role.SOC_ANALYST: set(),
    Role.CSE_VIEWER: set(),
}


def has_permission(role: str, permission: Permission) -> bool:
    """Check if a given role has a specific permission."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms


def can_access_admin_portal(role: str) -> bool:
    """Determine whether an actor is authorized to use the NCIIPC Admin Portal.

    Authorization is derived from the role alone. The legacy `is_admin_user`
    identity flag is ignored: it let any role (e.g. an examiner) be granted
    full user-management power outside the role model.
    """
    return role in ADMIN_PORTAL_ROLES
