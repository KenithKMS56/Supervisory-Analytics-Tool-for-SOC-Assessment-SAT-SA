"""Offline multi-factor authentication for privileged accounts (docs/security/mfa.md).

Administrators of the Admin Portal prove a second factor with a time-based one-time password
(TOTP, RFC 6238: HMAC-SHA1, 30-second steps, 6 digits). Any authenticator app can produce it
without a network connection. Nothing here contacts a server.

- **Enrolment** shows the shared secret (base32 and an `otpauth://` URI to type or paste) and is
  confirmed by entering one valid code. Ten one-time **recovery codes** are then shown once and
  stored only as SHA-256 hashes (each has 50 random bits).
- **Verification** accepts the current step and one step either side, for clock drift. A code is
  never accepted twice: each account records the last step it used.
- **Policy** (`SATSA_ADMIN_MFA`): `required` (the default in production) or `optional` (the default
  in a demo deployment). When it is required, an administrator without a factor can only enrol.
- **Reset** (device lost): another administrator removes the factor; the reset is audited and the
  account must enrol again.

The TOTP secret has to be stored in a form the server can use, so it is readable by anyone who can
read the database. That is the usual TOTP trade-off; disk encryption and host custody cover it.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote

from satsa.store.sqlite import SQLiteStore

STEP_SECONDS = 30
DIGITS = 6
WINDOW = 1
RECOVERY_CODES = 10
ISSUER = "SAT-SA Admin Portal"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def policy(store: SQLiteStore) -> str:
    """`required` or `optional`."""
    from satsa.deployment import is_demo

    configured = os.environ.get("SATSA_ADMIN_MFA", "").strip().lower()
    if configured in ("required", "optional"):
        return configured
    return "optional" if is_demo(store) else "required"


def totp(secret_b32: str, step: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(code).zfill(DIGITS)


def current_step(at: float | None = None) -> int:
    return int((time.time() if at is None else at) // STEP_SECONDS)


def enrolled(store: SQLiteStore, username: str) -> bool:
    row = store.conn.execute(
        "SELECT 1 FROM mfa_factors WHERE username = ? AND confirmed_at IS NOT NULL", (username,)
    ).fetchone()
    return row is not None


def begin_enrolment(store: SQLiteStore, username: str) -> tuple[str, str]:
    """A new, unconfirmed secret (replacing any earlier unconfirmed one) and its otpauth URI."""
    if enrolled(store, username):
        raise ValueError("This account already has a second factor; an administrator must reset it first.")
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    with store.transaction():
        store.conn.execute(
            "INSERT INTO mfa_factors (username, secret_b32, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT (username) DO UPDATE SET secret_b32 = excluded.secret_b32, created_at = excluded.created_at, "
            "confirmed_at = NULL, last_step = NULL",
            (username, secret, _now_iso()),
        )
    uri = (f"otpauth://totp/{quote(ISSUER)}:{quote(username)}?secret={secret}&issuer={quote(ISSUER)}"
           f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}")
    return secret, uri


def _check_code(store: SQLiteStore, username: str, code: str, *, confirmed: bool) -> bool:
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == DIGITS):
        return False
    row = store.conn.execute(
        "SELECT secret_b32, last_step FROM mfa_factors WHERE username = ? AND (confirmed_at IS NOT NULL) = ?",
        (username, confirmed),
    ).fetchone()
    if row is None:
        return False
    now = current_step()
    for step in range(now - WINDOW, now + WINDOW + 1):
        if row["last_step"] is not None and step <= row["last_step"]:
            continue  # this code (or an earlier one) was already used
        if hmac.compare_digest(totp(row["secret_b32"], step), code):
            with store.transaction():
                store.conn.execute("UPDATE mfa_factors SET last_step = ? WHERE username = ?", (step, username))
            return True
    return False


def _recovery_hash(code: str) -> str:
    return hashlib.sha256(code.strip().upper().replace("-", "").encode()).hexdigest()


def confirm_enrolment(store: SQLiteStore, username: str, code: str) -> list[str] | None:
    """Confirm with one valid code. Returns the recovery codes (show them once), or None."""
    if not _check_code(store, username, code, confirmed=False):
        return None
    codes = ["-".join(secrets.token_hex(5).upper()[i:i + 5] for i in (0, 5)) for _ in range(RECOVERY_CODES)]
    now = _now_iso()
    with store.audited_transaction():
        store.conn.execute("UPDATE mfa_factors SET confirmed_at = ? WHERE username = ?", (now, username))
        store.conn.execute("DELETE FROM mfa_recovery_codes WHERE username = ?", (username,))
        store.conn.executemany(
            "INSERT INTO mfa_recovery_codes (username, code_hash, created_at) VALUES (?, ?, ?)",
            [(username, _recovery_hash(c), now) for c in codes],
        )
        store.append_admin_audit("MFA_ENROLLED", username, target=username, details={"recovery_codes": len(codes)})
    return codes


def verify(store: SQLiteStore, username: str, code: str) -> str | None:
    """`totp` or `recovery` when the code is valid (a recovery code is used up), else None."""
    if _check_code(store, username, code, confirmed=True):
        return "totp"
    with store.transaction():
        cur = store.conn.execute(
            "UPDATE mfa_recovery_codes SET used_at = ? WHERE username = ? AND code_hash = ? AND used_at IS NULL",
            (_now_iso(), username, _recovery_hash(code)),
        )
    return "recovery" if cur.rowcount == 1 else None


def remaining_recovery_codes(store: SQLiteStore, username: str) -> int:
    return int(store.conn.execute(
        "SELECT count(*) FROM mfa_recovery_codes WHERE username = ? AND used_at IS NULL", (username,)
    ).fetchone()[0])


def reset(store: SQLiteStore, username: str, actor: str) -> bool:
    with store.audited_transaction():
        cur = store.conn.execute("DELETE FROM mfa_factors WHERE username = ?", (username,))
        store.conn.execute("DELETE FROM mfa_recovery_codes WHERE username = ?", (username,))
        store.conn.execute("UPDATE admin_sessions SET mfa_verified_at = NULL WHERE username = ?", (username,))
        if cur.rowcount:
            store.append_admin_audit("MFA_RESET", actor, target=username, details={})
    return bool(cur.rowcount)


def mark_session_verified(store: SQLiteStore, raw_token: str) -> None:
    with store.transaction():
        store.conn.execute(
            "UPDATE admin_sessions SET mfa_verified_at = ? WHERE session_hash = ?",
            (_now_iso(), hashlib.sha256(raw_token.encode()).hexdigest()),
        )
