"""Local passphrase hashing and default demo identities.

Uses hashlib.pbkdf2_hmac (Python standard library, no network-dependent
auth provider, no new third-party dependency) with a per-user random salt
and 200,000 iterations of SHA-256, consistent with OWASP's current PBKDF2
guidance for offline-verifiable credentials.
"""

import hashlib
import os
import secrets

# `admin` works the NCIIPC Admin Portal (:8000) only; SAT-SA (:8001) accepts
# just the two operator roles, `analyst` and `examiner` (see
# satsa.admin.rbac.SATSA_OPERATOR_ROLES).
ROLES: tuple[str, ...] = ("admin", "analyst", "examiner")

PBKDF2_ITERATIONS = 200_000
PBKDF2_ALGO = "sha256"

# Login lockout: after LOGIN_MAX_FAILURES failed attempts for a username within
# LOGIN_LOCKOUT_MINUTES (and since its last successful login), further attempts
# are rejected -- even with the correct passphrase -- until the window passes.
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_MINUTES = 15

# Default identities seeded into a fresh database so a new install can be opened
# at all. Their passphrases are published (README, login pages), so every seeded
# account is created with force_password_change set: the first login gets a
# session that can do nothing except choose a new passphrase.
DEFAULT_IDENTITIES: tuple[tuple[str, str, str], ...] = (
    ("admin", "admin", "ChangeMe-Admin#2026"),
    ("analyst", "analyst", "ChangeMe-Analyst#2026"),
    ("examiner", "examiner", "ChangeMe-Examiner#2026"),
)
# Bootstrap administrator of the NCIIPC Admin Portal (seeded by seed_default_admin).
BOOTSTRAP_ADMIN_IDENTITY: tuple[str, str, str] = (
    "nciipc_admin",
    "NCIIPC Super Administrator",
    "ChangeMe-NCIIPC#2026",
)
# username -> published default passphrase, for every seeded account.
SEEDED_DEFAULT_PASSPHRASES: dict[str, str] = {
    username: passphrase for username, _, passphrase in (*DEFAULT_IDENTITIES, BOOTSTRAP_ADMIN_IDENTITY)
}

MIN_PASSPHRASE_LENGTH = 12


def passphrase_policy_error(new: str, confirm: str, current: str) -> str | None:
    """Why a self-chosen passphrase is not acceptable, or None when it is."""
    if new != confirm:
        return "The new passphrase and its confirmation do not match."
    if len(new) < MIN_PASSPHRASE_LENGTH:
        return f"The new passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters long."
    if new == current:
        return "The new passphrase must differ from the current one."
    if new in SEEDED_DEFAULT_PASSPHRASES.values():
        return "That is a published default passphrase. Choose a different one."
    return None


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
