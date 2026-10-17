"""Limits on uploaded files and archives (docs/data_contract.md, "Limits").

Checked when an upload arrives (size, archive members) and again by the import job before it
extracts anything, so a job queued under older limits cannot get past newer ones.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Any

from satsa.security import safe_archive_member

# Upload limits (docs/data_contract.md, "Limits"). Configurable for large deployments.
MAX_UPLOAD_BYTES = int(os.environ.get("SATSA_MAX_UPLOAD_MB", "1024")) * 1024 * 1024
MAX_ZIP_ENTRIES = int(os.environ.get("SATSA_MAX_ZIP_ENTRIES", "2000"))
MAX_ZIP_UNCOMPRESSED_BYTES = int(os.environ.get("SATSA_MAX_ZIP_UNCOMPRESSED_MB", "4096")) * 1024 * 1024
MAX_ZIP_RATIO = 200  # a member compressed more than this is treated as a decompression bomb


def check_zip_limits(z: zipfile.ZipFile) -> None:
    """Refuse an archive that is too large, has too many members or a suspicious compression ratio
    before anything is extracted (ValueError explains which limit)."""
    infos = z.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ValueError(f"the archive has {len(infos)} members; the limit is {MAX_ZIP_ENTRIES}")
    total = 0
    for info in infos:
        safe_archive_member(info.filename)
        total += info.file_size
        if info.compress_size and info.file_size / info.compress_size > MAX_ZIP_RATIO and info.file_size > 1024 * 1024:
            raise ValueError(f"archive member {info.filename!r} expands more than {MAX_ZIP_RATIO}x; refused")
    if total > MAX_ZIP_UNCOMPRESSED_BYTES:
        raise ValueError(
            f"the archive expands to {total // (1024 * 1024)} MiB; the limit is "
            f"{MAX_ZIP_UNCOMPRESSED_BYTES // (1024 * 1024)} MiB"
        )


def _copy_limited(source: Any, dest: Path, budget: int) -> int:
    """Copy an upload to disk, refusing it once the request's byte budget is spent."""
    written = 0
    with open(dest, "wb") as out:
        while chunk := source.read(1024 * 1024):
            written += len(chunk)
            if written > budget:
                raise ValueError(f"the upload is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB")
            out.write(chunk)
    return written
