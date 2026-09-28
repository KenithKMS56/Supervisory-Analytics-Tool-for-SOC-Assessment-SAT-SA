"""Local, offline role-based access control (RBAC) for SAT-SA.

Three roles -- admin, supervisor, examiner -- backed by a local SQLite
identity table (PBKDF2-HMAC-SHA256 hashed passphrases, no plaintext
storage) and signed-cookie sessions. Nothing here makes a network call;
all verification happens against the local `data/satsa.db` file, keeping
the air-gapped guarantee intact.
"""

from satsa.auth.identities import (
    ROLES,
    generate_salt,
    hash_passphrase,
    verify_passphrase,
)
from satsa.auth.session import (
    SESSION_COOKIE_NAME,
    Identity,
    get_current_identity,
    require_role,
)

__all__ = [
    "ROLES",
    "SESSION_COOKIE_NAME",
    "Identity",
    "generate_salt",
    "get_current_identity",
    "hash_passphrase",
    "require_role",
    "verify_passphrase",
]
