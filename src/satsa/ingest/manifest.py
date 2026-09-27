"""Submission manifest and integrity digest generator."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from satsa.models.canonical import SubmissionBatch


class ManifestBuilder:
    """Calculates cryptographic hashes, row totals, and mapping metadata for ingestion batches."""

    @staticmethod
    def hash_file(file_path: Path | str) -> str:
        """Compute SHA-256 of file contents."""
        path = Path(file_path)
        if not path.exists():
            return ""
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def build_manifest(
        entity_id: str,
        files: list[Path],
        row_counts: dict[str, int],
        mapping_version: str = "1.0.0",
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> tuple[SubmissionBatch, dict[str, Any]]:
        """Build SubmissionBatch model and full manifest dictionary."""
        file_hashes = {f.name: ManifestBuilder.hash_file(f) for f in files}
        combined_payload = "".join(sorted(f"{k}:{v}" for k, v in file_hashes.items())).encode()
        batch_hash = hashlib.sha256(combined_payload).hexdigest()
        batch_id = f"BATCH-{entity_id}-{batch_hash[:12]}"

        now = datetime.now(UTC)
        p_start = period_start or now
        p_end = period_end or now

        batch = SubmissionBatch(
            batch_id=batch_id,
            entity_id=entity_id,
            period_start=p_start,
            period_end=p_end,
            file_name=",".join([f.name for f in files]),
            sha256=batch_hash,
            row_counts=row_counts,
        )

        manifest_dict = {
            "batch_id": batch_id,
            "entity_id": entity_id,
            "mapping_version": mapping_version,
            "batch_sha256": batch_hash,
            "file_hashes": file_hashes,
            "row_counts": row_counts,
            "timestamp": now.isoformat(),
        }

        return batch, manifest_dict
