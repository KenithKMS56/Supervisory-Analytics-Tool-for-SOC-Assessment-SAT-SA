"""The deployment's pseudonymisation keys, kept with its data (docs/key_management.md).

Ingestion replaces analyst names, host names and other identifiers with HMAC-SHA256 pseudonyms.
The key must outlive any one process or container: the same person must get the same pseudonym
in every period, or longitudinal analysis silently breaks. Until Phase 2 the key was a file
named `.satsa_salt` in whatever directory the process started in -- outside the container's
data volume, so recreating the container generated a new key without a word.

The keys now live in `data/secrets/pseudonym_keys.json`, inside the data volume and outside every
directory served over HTTP. Each key has a version. The current one pseudonymises new
submissions, and every batch records the id of the key it used (`batches.pseudonym_key_id` in
the catalog), so a linkage break is visible instead of silent.

Rules:
- A legacy `.satsa_salt` is imported as version 1, byte for byte, and left where it was.
- No key is ever generated while published data exists that an earlier key pseudonymised:
  that would silently break linkage. Restore `data/secrets/` from a backup instead, or rotate
  explicitly.
- `rotate` adds a new version and keeps the old ones, which are needed to explain old batches.
  Pseudonyms made after a rotation do not match those made before it.

Protection is the file system's: the directory and file are created owner-only where the
platform supports it (POSIX modes; on Windows they inherit the folder's ACL). A host
administrator can read them; volume encryption and backup custody are deployment controls.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SECRETS_DIR = "secrets"
KEYRING_FILE = "pseudonym_keys.json"
LEGACY_SALT_FILE = ".satsa_salt"
KEY_BYTES = 32


class PseudonymKeyMissing(RuntimeError):
    """Published data was pseudonymised with a key that is not here; refusing to make a new one."""


@dataclass(frozen=True)
class PseudonymKey:
    version: int
    key: bytes

    @property
    def key_id(self) -> str:
        """Names the key without revealing it: version and a fingerprint of the key."""
        return f"v{self.version}:{hashlib.sha256(b'satsa-pseudonym-key-id' + self.key).hexdigest()[:12]}"


def secrets_dir(data_dir: Path | str) -> Path:
    return Path(data_dir) / SECRETS_DIR


def keyring_path(data_dir: Path | str) -> Path:
    return secrets_dir(data_dir) / KEYRING_FILE


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def write_private(path: Path, content: bytes) -> None:
    """Write a secret file atomically, owner-only where the platform supports it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _read(data_dir: Path | str) -> dict[str, Any] | None:
    path = keyring_path(data_dir)
    if not path.exists():
        return None
    doc: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return doc


def _save(data_dir: Path | str, doc: dict[str, Any]) -> None:
    write_private(keyring_path(data_dir), json.dumps(doc, indent=2, sort_keys=True).encode("utf-8"))


def _key(doc: dict[str, Any], version: int) -> PseudonymKey:
    return PseudonymKey(version, bytes.fromhex(doc["keys"][str(version)]["key_hex"]))


def _pseudonymised_data_exists(data_dir: Path | str) -> bool:
    """Whether the catalog holds submitted data (anything but `direct` profile writes)."""
    from satsa.store.catalog import CATALOG_FILE, Catalog

    if not (Path(data_dir) / CATALOG_FILE).exists():
        return False
    catalog = Catalog(data_dir)
    try:
        row = catalog.conn.execute(
            "SELECT 1 FROM batches WHERE state IN ('published', 'held') AND transport != 'direct' LIMIT 1"
        ).fetchone()
    finally:
        catalog.close()
    return row is not None


def current_key(data_dir: Path | str, legacy_salt: Path | str | None = LEGACY_SALT_FILE) -> PseudonymKey:
    """The key new submissions are pseudonymised with, creating the keyring if it is safe to.

    `legacy_salt` is the pre-Phase-2 salt file (relative to the working directory by default).
    """
    doc = _read(data_dir)
    if doc is not None:
        return _key(doc, int(doc["current"]))
    legacy = Path(legacy_salt) if legacy_salt else None
    if legacy is not None and legacy.is_file():
        key = legacy.read_bytes()
        origin = f"imported from legacy salt file {legacy.resolve()}"
    elif _pseudonymised_data_exists(data_dir):
        raise PseudonymKeyMissing(
            f"{keyring_path(data_dir)} is missing, but this deployment holds data pseudonymised with an "
            "earlier key. A new key would make every pseudonym from now on unlinkable to the old ones. "
            "Restore data/secrets/ from a backup, or put the old .satsa_salt file back in the working "
            "directory. Only if the old key is truly lost, run `satsa keys init --new-key-breaks-linkage`."
        )
    else:
        key = secrets.token_bytes(KEY_BYTES)
        origin = "generated"
    doc = {"current": 1, "keys": {"1": {"key_hex": key.hex(), "created_at": _now(), "origin": origin}}}
    _save(data_dir, doc)
    return _key(doc, 1)


def init_new_key_breaking_linkage(data_dir: Path | str) -> PseudonymKey:
    """Create a keyring with a fresh key although pseudonymised data exists (the old key is lost)."""
    if _read(data_dir) is not None:
        raise FileExistsError(f"{keyring_path(data_dir)} already exists; use rotate")
    key = secrets.token_bytes(KEY_BYTES)
    doc = {
        "current": 1,
        "keys": {"1": {"key_hex": key.hex(), "created_at": _now(),
                       "origin": "generated although earlier pseudonymised data exists (old key lost)"}},
    }
    _save(data_dir, doc)
    return _key(doc, 1)


def rotate(data_dir: Path | str) -> PseudonymKey:
    """Add a new key version and make it current. Earlier versions are kept."""
    doc = _read(data_dir)
    if doc is None:
        raise FileNotFoundError(f"{keyring_path(data_dir)} does not exist yet")
    version = max(int(v) for v in doc["keys"]) + 1
    doc["keys"][str(version)] = {"key_hex": secrets.token_bytes(KEY_BYTES).hex(), "created_at": _now(),
                                 "origin": "rotation"}
    doc["current"] = version
    _save(data_dir, doc)
    return _key(doc, version)


def status(data_dir: Path | str) -> dict[str, Any]:
    """What the keyring holds, without any key material."""
    doc = _read(data_dir)
    if doc is None:
        return {"keyring": str(keyring_path(data_dir)), "exists": False}
    return {
        "keyring": str(keyring_path(data_dir)),
        "exists": True,
        "current": _key(doc, int(doc["current"])).key_id,
        "versions": [
            {"key_id": _key(doc, int(v)).key_id, "created_at": e["created_at"], "origin": e["origin"]}
            for v, e in sorted(doc["keys"].items(), key=lambda kv: int(kv[0]))
        ],
    }
