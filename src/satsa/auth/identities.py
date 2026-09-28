"""Local passphrase hashing and default demo identities.

Uses hashlib.pbkdf2_hmac (Python standard library, no network-dependent
auth provider, no new third-party dependency) with a per-user random salt
and 200,000 iterations of SHA-256, consistent with OWASP's current PBKDF2
guidance for offline-verifiable credentials.
"""

import hashlib
import os
import secrets

ROLES: tuple[str, ...] = ("admin", "supervisor", "examiner")

PBKDF2_ITERATIONS = 200_000
PBKDF2_ALGO = "sha256"

# Login lockout: after LOGIN_MAX_FAILURES failed attempts for a username within
# LOGIN_LOCKOUT_MINUTES (and since its last successful login), further attempts
# are rejected -- even with the correct passphrase -- until the window passes.
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_MINUTES = 15

# Demo/default identities seeded into a fresh database so the offline demo
# is usable out of the box. These are intentionally documented (see
# docs/functional_design.md, Section 2) as CHANGE-ME credentials: a real
# NCIIPC deployment MUST rotate these before use, e.g. via:
#   satsa users set-password <username>
DEFAULT_IDENTITIES: tuple[tuple[str, str, str], ...] = (
    ("admin", "admin", "ChangeMe-Admin#2026"),
    ("supervisor", "supervisor", "ChangeMe-Supervisor#2026"),
    ("examiner", "examiner", "ChangeMe-Examiner#2026"),
)


def generate_salt() -> bytes:
    """Generate a cryptographically random 16-byte salt."""
    return os.urandom(16)


def hash_passphrase(passphrase: str, salt: bytes) -> str:
    """Derive a PBKDF2-HMAC-SHA256 hash of a passphrase, hex-encoded."""
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_ALGO, passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return derived.hex()


def verify_passphrase(passphrase: str, salt_hex: str, expected_hash_hex: str) -> bool:
    """Constant-time verification of a passphrase against a stored hash+salt."""
    salt = bytes.fromhex(salt_hex)
    candidate = hash_passphrase(passphrase, salt)
    return secrets.compare_digest(candidate, expected_hash_hex)
