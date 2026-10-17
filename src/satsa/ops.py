"""Operational checks and housekeeping (docs/deployment_ops.md, SOP-06 to SOP-09).

- `readiness()`: whether this process can serve. It checks the operational database (open, at the
  latest schema version, integrity), the catalog, free disk and the worker's heartbeat. A missing
  worker does not make the portal unready, since reads still work; it is reported so that queued
  jobs are not a surprise.
- `apply_retention()`: deletes only what the retention settings allow: inputs of finished jobs
  older than N days, and local backups beyond the newest N. Assessment evidence (published
  batches, runs, findings, decisions, audit) is never touched. Every deletion is audited.
- `diagnostics_bundle()`: a support package with versions, schema, counts, job states and errors,
  disk, and configuration hashes. It contains **no** submitted data, no secrets, no tokens and no
  usernames (actors are replaced by a salted hash that is stable within the package). Nothing is
  sent anywhere: the operator reviews it and hands it over.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import secrets
import shutil
import zipfile
from pathlib import Path
from typing import Any

from satsa.store.sqlite import SQLiteStore

MIN_FREE_DISK_BYTES = int(os.environ.get("SATSA_MIN_FREE_DISK_MB", "512")) * 1024 * 1024
WORKER_WINDOW_SECONDS = 60


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def readiness(data_dir: Path | str = "data") -> dict[str, Any]:
    """{"ready": bool, "checks": {name: {"ok": bool, "detail": str}}, "worker": ...}."""
    from satsa.jobs.queue import JobQueue
    from satsa.store.catalog import CATALOG_FILE, published_sequence
    from satsa.store.sqlite_migrations import OPERATIONAL_MIGRATIONS

    data = Path(data_dir)
    checks: dict[str, dict[str, Any]] = {}
    worker: dict[str, Any] = {"alive": False}
    try:
        store = SQLiteStore(data / "satsa.db")
        try:
            versions = [r[0] for r in store.conn.execute("SELECT version FROM schema_migrations")]
            head = max(m.version for m in OPERATIONAL_MIGRATIONS)
            checks["database"] = {"ok": store.conn.execute("PRAGMA quick_check").fetchone()[0] == "ok",
                                  "detail": "quick_check"}
            checks["schema"] = {"ok": max(versions or [0]) == head, "detail": f"version {max(versions or [0])} of {head}"}
            live = JobQueue(store).live_workers(WORKER_WINDOW_SECONDS)
            queued = store.conn.execute("SELECT count(*) FROM jobs WHERE state = 'queued'").fetchone()[0]
            worker = {"alive": bool(live), "queued_jobs": queued,
                      "last_heartbeat": live[0]["heartbeat_at"] if live else None}
        finally:
            store.close()
    except Exception as exc:  # noqa: BLE001 - reported, not raised: readiness must answer
        checks["database"] = {"ok": False, "detail": type(exc).__name__}
    seq = published_sequence(data) if (data / CATALOG_FILE).exists() else 0
    checks["catalog"] = {"ok": seq >= 0, "detail": f"publication sequence {seq}"}
    free = shutil.disk_usage(data if data.exists() else Path(".")).free
    checks["disk"] = {"ok": free >= MIN_FREE_DISK_BYTES,
                      "detail": f"{free // (1024 * 1024)} MiB free, threshold {MIN_FREE_DISK_BYTES // (1024 * 1024)} MiB"}
    return {"ready": all(c["ok"] for c in checks.values()), "checks": checks, "worker": worker}


def apply_retention(
    data_dir: Path | str = "data",
    *,
    backups_dir: Path | str | None = None,
    actor: str = "system",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Delete what the deployment's retention settings allow. Returns what was (or would be) removed."""
    from satsa.backup import prune_backups
    from satsa.deployment import DEFAULT_RETENTION_DAYS, settings

    data = Path(data_dir)
    store = SQLiteStore(data / "satsa.db")
    try:
        values = settings(store)
        days = int(values.get("retention_job_inputs_days", DEFAULT_RETENTION_DAYS["job_inputs_days"]))
        keep = int(values.get("retention_backups_keep", DEFAULT_RETENTION_DAYS["backups_keep"]))
        cutoff = (_now() - _dt.timedelta(days=days)).isoformat()
        finished = [r[0] for r in store.conn.execute(
            "SELECT job_id FROM jobs WHERE state IN ('succeeded', 'failed', 'cancelled') AND finished_at < ?",
            (cutoff,))]
        job_dirs = [data / "jobs" / j for j in finished if (data / "jobs" / j).is_dir()]
        report: dict[str, Any] = {
            "job_input_days": days, "backups_keep": keep, "dry_run": dry_run,
            "job_inputs_removed": [p.name for p in job_dirs], "backups_removed": [],
        }
        if backups_dir is not None:
            candidates = sorted(p for p in Path(backups_dir).iterdir() if p.name.startswith("satsa-backup-")) \
                if Path(backups_dir).is_dir() else []
            report["backups_removed"] = [p.name for p in candidates[:-keep]] if len(candidates) > keep else []
        if not dry_run:
            for p in job_dirs:
                shutil.rmtree(p, ignore_errors=True)
            if backups_dir is not None:
                prune_backups(backups_dir, keep)
            if report["job_inputs_removed"] or report["backups_removed"]:
                store.append_audit(action="retention_applied", actor=actor,
                                   details={k: v for k, v in report.items() if k != "dry_run"})
    finally:
        store.close()
    return report


def diagnostics_bundle(out_path: Path | str, data_dir: Path | str = "data", config_dir: Path | str = "config") -> Path:
    """Write the redacted support package (a zip of JSON files) and return its path."""
    from satsa.deployment import settings
    from satsa.jobs.queue import JobQueue
    from satsa.scoring.fingerprint import environment_identity
    from satsa.store.catalog import Catalog

    data = Path(data_dir)
    pepper = secrets.token_bytes(16)  # pseudonyms valid only inside this one package

    def who(name: str | None) -> str | None:
        return None if name is None else "actor-" + hashlib.sha256(pepper + name.encode()).hexdigest()[:10]

    store = SQLiteStore(data / "satsa.db")
    try:
        tables = [r[0] for r in store.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        counts = {t: store.conn.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0] for t in tables}
        jobs = [{
            "job_id": j["job_id"], "kind": j["kind"], "state": j["state"], "stage": j["stage"],
            "attempts": j["attempts"], "created_at": j["created_at"], "finished_at": j["finished_at"],
            "created_by": who(j["created_by"]),
            "error": {"type": (j["error"] or {}).get("type"), "stage": (j["error"] or {}).get("stage")} if j["error"] else None,
        } for j in JobQueue(store).recent(100)]
        workers = [{"heartbeat_at": w["heartbeat_at"], "stopped_at": w["stopped_at"]}
                   for w in store.conn.execute("SELECT heartbeat_at, stopped_at FROM worker_heartbeats")]
        schema = [dict(r) for r in store.conn.execute("SELECT version, name, applied_at FROM schema_migrations")]
        deployment = {k: v for k, v in settings(store).items()
                      if k in ("mode", "mode_origin", "timezone", "retention_job_inputs_days",
                               "retention_backups_keep", "setup_completed_at", "created_at")}
        runs = [{"run_id": r["run_id"], "period": r["period"], "created_at": r["created_at"],
                 "config_hash": r["config_hash"], "fingerprint": r["fingerprint"]}
                for r in store.conn.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT 20")]
    finally:
        store.close()
    catalog = Catalog(data)
    try:
        catalog_summary = {
            "publication_sequence": catalog.max_pub_seq(),
            "batches_by_state": dict(catalog.conn.execute("SELECT state, count(*) FROM batches GROUP BY state").fetchall()),
            "verify_problems": len(catalog.verify()),
        }
    finally:
        catalog.close()
    config_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(Path(config_dir).glob("*.yaml"))} if Path(config_dir).is_dir() else {}
    disk = shutil.disk_usage(data)
    package = {
        "README.txt": ("SAT-SA diagnostics package. Contains no submitted data, secrets, tokens or usernames;\n"
                       "actors are replaced by hashes valid only inside this package. Review before sharing.\n"),
        "environment.json": environment_identity(),
        "deployment.json": deployment,
        "schema.json": schema,
        "table_counts.json": counts,
        "catalog.json": catalog_summary,
        "jobs.json": jobs,
        "workers.json": workers,
        "runs.json": runs,
        "config_hashes.json": config_hashes,
        "disk.json": {"total_mib": disk.total // (1 << 20), "free_mib": disk.free // (1 << 20)},
        "readiness.json": readiness(data),
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in package.items():
            z.writestr(name, body if isinstance(body, str) else json.dumps(body, indent=2, sort_keys=True, default=str))
    return out
