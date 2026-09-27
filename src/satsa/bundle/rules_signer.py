"""Signed rule-pack packaging and cryptographic verification."""

import hashlib
import hmac
import json
import shutil
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from satsa.store.sqlite import SQLiteStore


class RulePackSigner:
    """Exports and imports tamper-evident, versioned supervisory rule packs."""

    def __init__(self, default_secret: str = "SATSA_RULEPACK_NCIIPC_2026"):
        self.default_secret = default_secret

    def _compute_file_sha256(self, path: Path) -> str:
        """Compute SHA-256 hex digest of a file."""
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def export_rule_pack(
        self,
        config_dir: Path | str = "config",
        output_path: Path | str = "dist/rule_pack_v1.tar.gz",
        version: str = "1.0.0",
        secret_key: str | None = None,
    ) -> Path:
        """Package config directory into a signed, tamper-evident tar.gz archive."""
        cfg_dir = Path(config_dir).resolve()
        out_path = Path(output_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        secret = (secret_key or self.default_secret).encode("utf-8")

        # 1. Compute checksums of all config files
        file_hashes: dict[str, str] = {}
        for p in sorted(cfg_dir.glob("**/*")):
            if p.is_file() and not p.name.startswith("."):
                rel = str(p.relative_to(cfg_dir)).replace("\\", "/")
                file_hashes[rel] = self._compute_file_sha256(p)

        manifest = {
            "pack_version": version,
            "created_at": datetime.now(UTC).isoformat(),
            "file_count": len(file_hashes),
            "files": file_hashes,
        }

        manifest_json = json.dumps(manifest, sort_keys=True, indent=2)
        # Compute HMAC signature over the manifest
        signature = hmac.new(secret, manifest_json.encode("utf-8"), hashlib.sha256).hexdigest()

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            # Copy all files preserving relative path
            pack_root = tmp / "pack"
            pack_root.mkdir()
            for rel in file_hashes:
                src_f = cfg_dir / rel
                dst_f = pack_root / rel
                dst_f.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_f, dst_f)

            (pack_root / "manifest.json").write_text(manifest_json, encoding="utf-8")
            (pack_root / "signature.sig").write_text(signature, encoding="utf-8")

            # Create tar.gz
            with tarfile.open(out_path, "w:gz") as tar:
                tar.add(pack_root, arcname="rule_pack")

        return out_path

    def import_rule_pack(
        self,
        archive_path: Path | str,
        target_config_dir: Path | str = "config",
        secret_key: str | None = None,
        sqlite_store: SQLiteStore | None = None,
    ) -> dict[str, Any]:
        """Verify signature and file integrity before importing rule pack."""
        arc_p = Path(archive_path).resolve()
        if not arc_p.exists():
            raise FileNotFoundError(f"Rule pack archive not found: {arc_p}")

        secret = (secret_key or self.default_secret).encode("utf-8")
        target_dir = Path(target_config_dir).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            with tarfile.open(arc_p, "r:gz") as tar:
                tar.extractall(tmp)

            pack_root = tmp / "rule_pack"
            if not pack_root.exists():
                raise ValueError("Corrupt archive: 'rule_pack' directory missing.")

            manifest_f = pack_root / "manifest.json"
            sig_f = pack_root / "signature.sig"
            if not manifest_f.exists() or not sig_f.exists():
                raise ValueError("Tamper check failed: manifest.json or signature.sig missing.")

            manifest_json = manifest_f.read_text(encoding="utf-8")
            recorded_sig = sig_f.read_text(encoding="utf-8").strip()

            # Verify HMAC signature
            expected_sig = hmac.new(
                secret, manifest_json.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(recorded_sig, expected_sig):
                raise PermissionError(
                    "Rule pack cryptographic signature verification FAILED! Import rejected."
                )

            manifest = json.loads(manifest_json)
            file_hashes: dict[str, str] = manifest.get("files", {})

            # Verify SHA-256 checksum of every single file
            for rel, expected_hash in file_hashes.items():
                p = pack_root / rel
                if not p.exists():
                    raise ValueError(f"Integrity check failed: expected file missing: {rel}")
                actual_hash = self._compute_file_sha256(p)
                if actual_hash != expected_hash:
                    raise ValueError(f"Tamper check failed: SHA-256 mismatch for {rel}")

            # All checks passed: copy into target config directory
            imported_count = 0
            for rel in file_hashes:
                src_f = pack_root / rel
                dst_f = target_dir / rel
                dst_f.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_f, dst_f)
                imported_count += 1

            # Log audit event if store is provided
            if sqlite_store:
                sqlite_store.append_audit(
                    action="rule_pack_imported",
                    actor="supervisor",
                    details={
                        "archive": arc_p.name,
                        "pack_version": manifest.get("pack_version"),
                        "files_verified": imported_count,
                        "signature": recorded_sig[:12] + "...",
                    },
                )

            return {
                "status": "success",
                "version": manifest.get("pack_version"),
                "files_imported": imported_count,
                "verified": True,
            }
