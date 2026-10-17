"""Service credentials for machine integration with the submission API (docs/api_credentials.md).

A browser session cookie is not a machine integration contract. A connector or script that
submits batches (`POST /api/v1/submissions`) instead presents

    Authorization: Bearer satsa_sc_<credential id>_<secret>

Each credential:
- **is scoped.** It grants the `submit` scope only, for an explicit list of entities. A batch for
  any other entity is refused (403).
- **expires.** Every credential has an expiry, at most 365 days after it is issued.
- **is revocable.** A revoked or expired credential stops working on its next request; nothing is
  cached.
- **is never stored.** The secret is 256 random bits and is shown once, when issued. Only its
  SHA-256 verifier is kept; a fast hash suffices for a secret with that much entropy, unlike a
  passphrase. Comparison is constant-time.
- **is audited.** Issue, revocation and every use are written to the audit chain, with the
  credential id and name, never the secret.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any

from satsa.security import is_valid_entity_id
from satsa.store.sqlite import SQLiteStore

PREFIX = "satsa_sc_"
SCOPES = frozenset({"submit"})
MAX_LIFETIME_DAYS = 365
TOKEN_RE = re.compile(r"^satsa_sc_([a-f0-9]{16})_([A-Za-z0-9_-]{43})$")


class CredentialError(ValueError):
    """Issuing or revoking was refused; the message is safe to show."""


@dataclass(frozen=True)
class ServicePrincipal:
    credential_id: str
    name: str
    scopes: frozenset[str]
    entities: frozenset[str]

    @property
    def actor(self) -> str:
        return f"service:{self.name}"

    def may_submit_for(self, entity_id: str) -> bool:
        return "submit" in self.scopes and entity_id.upper() in self.entities


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _verifier(secret: str) -> str:
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


def issue(
    store: SQLiteStore, *, name: str, entities: list[str], expires_days: int, created_by: str,
    scopes: tuple[str, ...] = ("submit",),
) -> tuple[str, dict[str, Any]]:
    """Create a credential. Returns the token (show it once) and the stored record."""
    name = name.strip()
    if not re.match(r"^[A-Za-z0-9 _.-]{3,64}$", name):
        raise CredentialError("The name must be 3-64 letters, digits, spaces, '.', '_' or '-'.")
    clean = sorted({e.strip().upper() for e in entities if e.strip()})
    if not clean or not all(is_valid_entity_id(e) for e in clean):
        raise CredentialError("Give at least one valid entity id the credential may submit for.")
    if set(scopes) - SCOPES or not scopes:
        raise CredentialError(f"Unknown scope; the only scope is {sorted(SCOPES)}.")
    if not 1 <= expires_days <= MAX_LIFETIME_DAYS:
        raise CredentialError(f"A credential must expire within 1-{MAX_LIFETIME_DAYS} days.")
    credential_id = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    now = _now()
    record = {
        "credential_id": credential_id, "name": name, "scopes": sorted(scopes), "entities": clean,
        "created_by": created_by, "created_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + _dt.timedelta(days=expires_days)).isoformat(timespec="seconds"),
    }
    with store.audited_transaction():
        store.conn.execute(
            "INSERT INTO service_credentials (credential_id, name, verifier, scopes_json, entity_scope_json, "
            "created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (credential_id, name, _verifier(secret), json.dumps(record["scopes"]), json.dumps(clean),
             created_by, record["created_at"], record["expires_at"]),
        )
        store.append_audit(action="service_credential_issued", actor=created_by,
                           details={k: v for k, v in record.items() if k != "created_by"})
    return f"{PREFIX}{credential_id}_{secret}", record


def revoke(store: SQLiteStore, credential_id: str, actor: str) -> bool:
    now = _now().isoformat(timespec="seconds")
    with store.audited_transaction():
        cur = store.conn.execute(
            "UPDATE service_credentials SET revoked_at = ?, revoked_by = ? WHERE credential_id = ? AND revoked_at IS NULL",
            (now, actor, credential_id),
        )
        if cur.rowcount != 1:
            return False
        store.append_audit(action="service_credential_revoked", actor=actor, details={"credential_id": credential_id})
    return True


def listing(store: SQLiteStore) -> list[dict[str, Any]]:
    rows = store.conn.execute(
        "SELECT credential_id, name, scopes_json, entity_scope_json, created_by, created_at, expires_at, "
        "revoked_at, last_used_at, use_count FROM service_credentials ORDER BY created_at DESC"
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["scopes"] = json.loads(item.pop("scopes_json"))
        item["entities"] = json.loads(item.pop("entity_scope_json"))
        out.append(item)
    return out


def authenticate(store: SQLiteStore, authorization: str | None) -> ServicePrincipal | None:
    """The principal behind an `Authorization: Bearer` header, or None if it is not a valid,
    unrevoked, unexpired service credential. Records the use."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    match = TOKEN_RE.match(authorization[len("Bearer "):].strip())
    if match is None:
        return None
    credential_id, secret = match.groups()
    row = store.conn.execute("SELECT * FROM service_credentials WHERE credential_id = ?", (credential_id,)).fetchone()
    if row is None or not secrets.compare_digest(row["verifier"], _verifier(secret)):
        return None
    now = _now()
    if row["revoked_at"] or _dt.datetime.fromisoformat(row["expires_at"]) <= now:
        return None
    with store.transaction():
        store.conn.execute(
            "UPDATE service_credentials SET last_used_at = ?, use_count = use_count + 1 WHERE credential_id = ?",
            (now.isoformat(timespec="seconds"), credential_id),
        )
    return ServicePrincipal(credential_id, row["name"], frozenset(json.loads(row["scopes_json"])),
                            frozenset(json.loads(row["entity_scope_json"])))
