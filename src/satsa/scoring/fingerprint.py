"""Complete identity of an assessment's inputs: configuration snapshot and analytical fingerprint.

`run_id` names one execution (it contains the time it ran). The *analytical fingerprint* names
what the result depends on, so two executions with the same fingerprint must produce the same
normalised results in the pinned environment:

- every configuration file the assessment read (rules, scoring, peers, systemic, anomaly) and
  the ingest-time transforms that shaped the data (taxonomy, source mappings) -- the full text
  of each is stored with the run, not only its hash;
- the selected data: per table, the row count and an order-independent hash of every row as
  loaded (after version selection and the assessment window);
- the selection itself (mode, window, source snapshot);
- code revision, the dependency lock file and the runtime versions of the engines that compute
  results (Python, DuckDB, Polars).

The row hash uses DuckDB's `hash()`; it is stable for a pinned DuckDB version (uv.lock), which
is why the DuckDB version is part of the fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from importlib import metadata
from pathlib import Path
from typing import Any

from satsa.store.duckdb import CANONICAL_TABLES, DuckDBStore

# Files under config/ that change assessment results, and those that change what ingestion
# stores (recorded so a replay can say whether the transforms differ).
ASSESSMENT_CONFIG_KEYS = ("rules", "scoring", "peers", "systemic", "anomaly")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def config_snapshot(paths: dict[str, Path], extra_dirs: tuple[Path, ...] = ()) -> list[dict[str, Any]]:
    """[{key, path, sha256, content}] for each named config file and each YAML file in extra_dirs."""
    entries: list[dict[str, Any]] = []
    for key, path in sorted(paths.items()):
        p = Path(path)
        content = p.read_bytes() if p.exists() else None
        entries.append(
            {
                "key": key,
                "path": p.as_posix(),
                "sha256": _sha256_bytes(content) if content is not None else None,
                "content": content.decode("utf-8", errors="replace") if content is not None else None,
            }
        )
    for folder in extra_dirs:
        for p in sorted(Path(folder).glob("*.yaml")):
            content = p.read_bytes()
            entries.append(
                {
                    "key": f"mapping:{p.stem}",
                    "path": p.as_posix(),
                    "sha256": _sha256_bytes(content),
                    "content": content.decode("utf-8", errors="replace"),
                }
            )
    return entries


def config_hash(snapshot: list[dict[str, Any]], keys: tuple[str, ...] = ASSESSMENT_CONFIG_KEYS) -> str:
    """Hash over the result-affecting configuration (16 hex chars, as runs have always shown)."""
    digest = hashlib.sha256()
    for entry in sorted(snapshot, key=lambda e: e["key"]):
        if entry["key"] in keys:
            digest.update(f"{entry['key']}\x1f{entry['sha256']}\x1e".encode())
    return digest.hexdigest()[:16]


def data_fingerprint(store: DuckDBStore) -> dict[str, dict[str, Any]]:
    """Per canonical table: row count and an order-independent hash of the rows as loaded."""
    out: dict[str, dict[str, Any]] = {}
    for table in CANONICAL_TABLES:
        q = f'"{table}"'
        row = store.conn.execute(f"SELECT count(*), coalesce(bit_xor(hash(t)), 0) FROM {q} t").fetchone()
        n, h = (int(row[0]), int(row[1])) if row else (0, 0)
        out[table] = {"rows": n, "hash": f"{h:016x}"}
    return out


def code_revision(repo_dir: Path | None = None) -> str:
    """The git commit of the running code (with `-dirty` for local edits), else the package version."""
    root = repo_dir or Path(__file__).resolve().parents[3]
    try:
        rev = subprocess.run(
            ["git", "-C", str(root), "describe", "--always", "--dirty", "--abbrev=12"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        ).stdout.strip()
        if rev:
            return rev
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        return f"satsa-{metadata.version('satsa')}"
    except metadata.PackageNotFoundError:
        return "unknown"


def lockfile_hash(repo_dir: Path | None = None) -> str | None:
    root = repo_dir or Path(__file__).resolve().parents[3]
    for candidate in (root / "uv.lock", Path("uv.lock")):
        if candidate.exists():
            return _sha256_bytes(candidate.read_bytes())
    return None


def runtime_versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for pkg in ("duckdb", "polars"):
        try:
            versions[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            versions[pkg] = "unknown"
    return versions


_CODE_REVISION: str | None = None


def environment_identity() -> dict[str, Any]:
    global _CODE_REVISION
    if _CODE_REVISION is None:
        _CODE_REVISION = code_revision()
    return {"code_revision": _CODE_REVISION, "lockfile_sha256": lockfile_hash(), "runtime": runtime_versions()}


def analytical_fingerprint(
    snapshot: list[dict[str, Any]],
    data: dict[str, dict[str, Any]],
    selection: dict[str, Any],
    environment: dict[str, Any],
) -> str:
    payload = {
        "config": {e["key"]: e["sha256"] for e in snapshot},
        "data": data,
        "selection": {k: v for k, v in selection.items() if k != "description"},
        "environment": environment,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
