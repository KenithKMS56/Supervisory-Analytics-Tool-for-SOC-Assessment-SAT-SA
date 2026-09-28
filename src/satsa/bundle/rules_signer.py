"""Signed rule-pack packaging and cryptographic verification.

Signing key: the HMAC key MUST come from the SATSA_RULEPACK_SECRET environment
variable (or an explicit argument). There is deliberately NO built-in default:
the key that used to be embedded in this repository is public to anyone with
repo access and must be treated as permanently compromised, so it is also
explicitly rejected. Without a configured key, signing and importing refuse to
run (RulePackKeyError) instead of silently falling back.

Import order: every archive member is validated (no absolute paths, no '..',
no links/devices, size caps) and the manifest signature is verified from memory
BEFORE anything is written to disk; files are then checksum-verified and
written only inside the target directory.
"""

import hashlib
import hmac
import io
import json
import os
import shutil
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from satsa.security import safe_archive_member, safe_join
from satsa.store.sqlite import SQLiteStore

SECRET_ENV_VAR = "SATSA_RULEPACK_SECRET"
MIN_SECRET_LENGTH = 32
# Formerly hardcoded in this repo (and in the CLI's --secret default): burned.
_COMPROMISED_SECRETS = frozenset({"SATSA_RULEPACK_NCIIPC_2026"})

PACK_ROOT = "rule_pack"
MAX_MEMBER_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_MEMBERS = 500


class RulePackKeyError(RuntimeError):
    """No usable rule-pack signing key is configured."""


def resolve_secret(explicit: str | None = None) -> bytes:
    """Return the signing key from `explicit` or SATSA_RULEPACK_SECRET, or fail loudly."""
    secret = explicit if explicit is not None else os.environ.get(SECRET_ENV_VAR)
    if not secret:
        raise RulePackKeyError(
            f"Rule-pack signing is disabled: set {SECRET_ENV_VAR} to a secret of at least "
            f"{MIN_SECRET_LENGTH} characters. There is no built-in default key."
        )
    if secret in _COMPROMISED_SECRETS:
        raise RulePackKeyError(
            "Refusing to use the rule-pack key that was previously committed to this repository; "
            f"it is compromised. Configure a new {SECRET_ENV_VAR}."
        )
    if len(secret) < MIN_SECRET_LENGTH:
        raise RulePackKeyError(
            f"{SECRET_ENV_VAR} is too short ({len(secret)} chars); use at least {MIN_SECRET_LENGTH}."
        )
    return secret.encode("utf-8")


def _validate_rel_path(rel: str) -> PurePosixPath:
    """A manifest file path: relative, no '..', no backslashes/drive letters."""
    p = safe_archive_member(rel)
    if not p.parts:
        raise ValueError(f"Unsafe path in rule pack: {rel!r}")
    return p


class RulePackSigner:
    """Exports and imports tamper-evident, versioned supervisory rule packs."""

    def __init__(self, secret: str | None = None):
        # Resolved eagerly so a misconfigured deployment fails at the first use.
        self._secret = resolve_secret(secret)

    def _compute_sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def export_rule_pack(
        self,
        config_dir: Path | str = "config",
        output_path: Path | str = "dist/rule_pack_v1.tar.gz",
        version: str = "1.0.0",
    ) -> Path:
        """Package config directory into a signed, tamper-evident tar.gz archive."""
        cfg_dir = Path(config_dir).resolve()
        out_path = Path(output_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Compute checksums of all config files
        file_hashes: dict[str, str] = {}
        for p in sorted(cfg_dir.glob("**/*")):
            if p.is_file() and not p.name.startswith("."):
                rel = str(p.relative_to(cfg_dir)).replace("\\", "/")
                file_hashes[rel] = self._compute_sha256(p.read_bytes())

        manifest = {
            "pack_version": version,
            "created_at": datetime.now(UTC).isoformat(),
            "file_count": len(file_hashes),
            "files": file_hashes,
        }

        manifest_json = json.dumps(manifest, sort_keys=True, indent=2)
        # Compute HMAC signature over the manifest
        signature = hmac.new(self._secret, manifest_json.encode("utf-8"), hashlib.sha256).hexdigest()

        with tempfile.TemporaryDirectory() as tmp_str:
            pack_root = Path(tmp_str) / PACK_ROOT
            pack_root.mkdir()
            for rel in file_hashes:
                dst_f = pack_root / rel
                dst_f.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(cfg_dir / rel, dst_f)

            # Written as exact bytes (write_text would turn "\n" into "\r\n" on
            # Windows, so the archived manifest would no longer match what was signed).
            (pack_root / "manifest.json").write_bytes(manifest_json.encode("utf-8"))
            (pack_root / "signature.sig").write_bytes(signature.encode("utf-8"))

            with tarfile.open(out_path, "w:gz") as tar:
                tar.add(pack_root, arcname=PACK_ROOT)

        return out_path

    @staticmethod
    def _read_members(tar: tarfile.TarFile) -> dict[str, bytes]:
        """Validate every member and read regular files into memory (nothing touches disk)."""
        members = tar.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ValueError("Rule pack rejected: too many archive members.")
        contents: dict[str, bytes] = {}
        total = 0
        for m in members:
            name = safe_archive_member(m.name)  # rejects absolute paths and '..'
            if not name.parts or name.parts[0] != PACK_ROOT:
                raise ValueError(f"Rule pack rejected: member outside '{PACK_ROOT}/': {m.name!r}")
            if m.isdir():
                continue
            if not m.isfile():  # symlinks, hardlinks, devices, fifos
                raise ValueError(f"Rule pack rejected: non-regular member {m.name!r}")
            if m.size > MAX_MEMBER_BYTES:
                raise ValueError(f"Rule pack rejected: member too large: {m.name!r}")
            total += m.size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("Rule pack rejected: archive too large.")
            fobj = tar.extractfile(m)
            if fobj is None:
                raise ValueError(f"Rule pack rejected: unreadable member {m.name!r}")
            contents[str(PurePosixPath(*name.parts[1:]))] = fobj.read()
        return contents

    def import_rule_pack(
        self,
        archive_path: Path | str,
        target_config_dir: Path | str = "config",
        sqlite_store: SQLiteStore | None = None,
        actor: str = "unknown",
    ) -> dict[str, Any]:
        """Verify member paths, signature and checksums (in memory) before writing anything."""
        arc_p = Path(archive_path).resolve()
        if not arc_p.exists():
            raise FileNotFoundError(f"Rule pack archive not found: {arc_p}")

        with open(arc_p, "rb") as fh:
            raw = fh.read(MAX_TOTAL_BYTES + 1)
        if len(raw) > MAX_TOTAL_BYTES:
            raise ValueError("Rule pack rejected: archive too large.")
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                contents = self._read_members(tar)
        except tarfile.TarError as e:
            raise ValueError(f"Corrupt rule pack archive: {e}") from e

        manifest_bytes = contents.get("manifest.json")
        sig_bytes = contents.get("signature.sig")
        if manifest_bytes is None or sig_bytes is None:
            raise ValueError("Tamper check failed: manifest.json or signature.sig missing.")

        # 1. Verify the HMAC signature before trusting anything in the manifest.
        expected_sig = hmac.new(self._secret, manifest_bytes, hashlib.sha256).hexdigest()
        recorded_sig = sig_bytes.decode("utf-8", errors="replace").strip()
        if not hmac.compare_digest(recorded_sig, expected_sig):
            raise PermissionError(
                "Rule pack cryptographic signature verification FAILED! Import rejected."
            )

        manifest = json.loads(manifest_bytes.decode("utf-8"))
        file_hashes: dict[str, str] = manifest.get("files", {})

        # 2. Validate every listed path and verify its SHA-256 from memory.
        target_dir = Path(target_config_dir).resolve()
        planned: list[tuple[Path, bytes]] = []
        for rel, expected_hash in file_hashes.items():
            rel_p = _validate_rel_path(rel)
            data = contents.get(str(rel_p))
            if data is None:
                raise ValueError(f"Integrity check failed: expected file missing: {rel}")
            if self._compute_sha256(data) != expected_hash:
                raise ValueError(f"Tamper check failed: SHA-256 mismatch for {rel}")
            planned.append((safe_join(target_dir, rel_p), data))

        # 3. All checks passed: write into the target config directory only.
        target_dir.mkdir(parents=True, exist_ok=True)
        for dst_f, data in planned:
            dst_f.parent.mkdir(parents=True, exist_ok=True)
            dst_f.write_bytes(data)

        if sqlite_store:
            sqlite_store.append_audit(
                action="rule_pack_imported",
                actor=actor,
                details={
                    "archive": arc_p.name,
                    "pack_version": manifest.get("pack_version"),
                    "files_verified": len(planned),
                    "signature": recorded_sig[:12] + "...",
                },
            )

        return {
            "status": "success",
            "version": manifest.get("pack_version"),
            "files_imported": len(planned),
            "verified": True,
        }
