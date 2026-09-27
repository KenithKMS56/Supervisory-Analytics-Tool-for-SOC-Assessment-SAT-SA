"""Centralized Role-Based Access Control (RBAC) and permissions for NCIIPC Admin Portal and SAT-SA."""

from enum import Enum


class Role:
    NCIIPC_SUPER_ADMIN = "NCIIPC Super Administrator"
    NCIIPC_SUPERVISOR = "NCIIPC Supervisor"
    NCIIPC_EXAMINER = "NCIIPC Examiner"
    CSE_ADMIN = "CSE Administrator"
    SOC_MANAGER = "SOC Manager"
    SOC_ANALYST = "SOC Analyst"
    CSE_VIEWER = "CSE Viewer"
    
    # Legacy aliases
    LEGACY_ADMIN = "admin"
    LEGACY_SUPERVISOR = "supervisor"
    LEGACY_EXAMINER = "examiner"


# List of official authoritative roles for administrative assignment
ALL_ASSIGNABLE_ROLES: tuple[str, ...] = (
    Role.NCIIPC_SUPER_ADMIN,
    Role.NCIIPC_SUPERVISOR,
    Role.NCIIPC_EXAMINER,
    Role.CSE_ADMIN,
    Role.SOC_MANAGER,
    Role.SOC_ANALYST,
    Role.CSE_VIEWER,
)

SUPERVISORY_ROLES: set[str] = {
    Role.NCIIPC_SUPER_ADMIN,
    Role.NCIIPC_SUPERVISOR,
    Role.NCIIPC_EXAMINER,
    Role.LEGACY_ADMIN,
    Role.LEGACY_SUPERVISOR,
    Role.LEGACY_EXAMINER,
}

ADMIN_PORTAL_ROLES: set[str] = {
    Role.NCIIPC_SUPER_ADMIN,
    Role.NCIIPC_SUPERVISOR,
    Role.LEGACY_ADMIN,
    Role.LEGACY_SUPERVISOR,
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
    Role.NCIIPC_SUPERVISOR: {
        Permission.ACCESS_ADMIN_PORTAL,
        Permission.VIEW_ADMIN_AUDIT,
        Permission.SUPERVISORY_OVERSIGHT,
        Permission.VIEW_ALL_CSES,
    },
    Role.LEGACY_SUPERVISOR: {
        Permission.ACCESS_ADMIN_PORTAL,
        Permission.VIEW_ADMIN_AUDIT,
        Permission.SUPERVISORY_OVERSIGHT,
        Permission.VIEW_ALL_CSES,
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


def can_access_admin_portal(role: str, is_admin_user: bool = False) -> bool:
    """Determine whether an actor is authorized to authenticate into the NCIIPC Admin Portal."""
    if is_admin_user:
        return True
    return role in ADMIN_PORTAL_ROLES
