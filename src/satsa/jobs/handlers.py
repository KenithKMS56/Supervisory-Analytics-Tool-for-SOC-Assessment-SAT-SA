"""What each kind of job does. A handler gets a JobContext and returns a JSON-able result.

Retry safety (a retried attempt must not duplicate anything):
- `assessment`: the run id is derived from the job id. A retry after the run was published finds
  it and returns it, and the run is published in one transaction, so there is never a partial
  one.
- `import`: each attempt uses its own batch id derived from the job id. A retry first looks for
  a batch an earlier attempt already published or held and continues from it instead of
  ingesting the files again. It then assesses, under the job's run id.
- `demo_seed`: not retried automatically (it publishes several batches and runs).
"""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from satsa.jobs.worker import JobContext

IMPORT_INPUT = "input"


class JobFailed(RuntimeError):
    """The job ran but could not do its work; `details` is shown to the user."""

    def __init__(self, message: str, **details: Any):
        super().__init__(message)
        self.details = details


def job_dir(data_dir: Path | str, job_id: str) -> Path:
    return Path(data_dir) / "jobs" / job_id


def run_id_for(job_id: str) -> str:
    return f"RUN-{job_id}"


def _assess(ctx: JobContext, period: str | None, entity_label: str) -> dict[str, Any]:
    from satsa.jobs.worker import ASSESS_BYTES_PER_ROW, MEMORY_BASE_BYTES
    from satsa.scoring.runner import AssessmentRunner
    from satsa.store.catalog import published_rows
    from satsa.store.duckdb import DuckDBStore

    actor, role = ctx.job["created_by"], ctx.job["params"].get("role", "")
    rows = published_rows(ctx.data_dir)
    ctx.preflight_memory(MEMORY_BASE_BYTES + ASSESS_BYTES_PER_ROW * rows,
                         f"an assessment of {rows:,} stored rows")
    ctx.stage("assessing")
    ctx.store.record_live_event(
        "ASSESSMENT_STARTED", actor=actor, role=role, entity_id=entity_label,
        details={"period": period, "job_id": ctx.job["job_id"]},
    )
    duck = DuckDBStore(ctx.data_dir)
    try:
        res = AssessmentRunner(duck, ctx.store).run_assessment(
            period=period, actor=actor, run_id=run_id_for(ctx.job["job_id"])
        )
    finally:
        duck.close()
    if res.get("status") != "success":
        raise JobFailed(f"the assessment could not run: {res.get('message')}")
    ctx.store.record_live_event(
        "ASSESSMENT_COMPLETED", actor=actor, role=role, entity_id=entity_label,
        details={"period": period, "findings_count": res.get("findings_count", 0), "job_id": ctx.job["job_id"]},
    )
    return {"run_id": res["run_id"], "findings_count": res.get("findings_count", 0), "period": period}


def assessment(ctx: JobContext) -> dict[str, Any]:
    params = ctx.job["params"]
    result = _assess(ctx, params.get("period"), params.get("entity_label") or "PORTFOLIO")
    reason = params.get("reason")
    result["message"] = (
        (f"{reason}: " if reason else "")
        + f"assessment {result['run_id']} for {result['period'] or 'all submitted data'} published, "
        f"{result['findings_count']} findings flagged."
    )
    return result


def _blocking_summary(res: dict[str, Any]) -> str:
    """'unrecognised_value: 3 in alert.severity_final (CSE-01); ...' for what blocking checks found."""
    return "; ".join(
        f"{b['check']}: {b['count']}"
        + (f" in {b['table']}.{b['field']}" if b.get("table") and b.get("field") else "")
        + f" ({b['entity_id']})"
        for b in res.get("blocking_issues") or []
    )


def describe_ingestion(res: dict[str, Any], target_entity: str | None) -> str:
    """The message an analyst sees for an ingestion result (kept from the synchronous upload)."""
    status = res.get("status")
    if status == "empty":
        return "Warning: No supported CSV, TSV, Excel (.xlsx) or JSON files could be parsed from upload."
    if status == "preview":
        rows = sum(res.get("row_counts", {}).values())
        return (
            f"Checked only: nothing was published or recorded. {rows} row(s) would be stored; "
            f"{len(res.get('dq_issue_list') or [])} data-quality issue(s). The tables below say what each file "
            "would give and which rules the entity could then be assessed on. Upload again without "
            "\"Check only\" to submit it."
        )
    if status == "held":
        held_why = "; ".join(
            f["summary"] for f in res.get("file_coverage") or [] if f["status"] not in ("ingested", "empty")
        )
        bad_ts = ", ".join(f"{k}: {n}" for k, n in (res.get("invalid_timestamps") or {}).items())
        blocked = _blocking_summary(res)
        return (
            f"Held for review: batch {res.get('batch_id')} was NOT published because part of it could not be "
            "accepted"
            + (f" ({held_why[:500]})" if held_why else "")
            + (f" (unreadable timestamps: {bad_ts})" if bad_ts else "")
            + (f" (blocking data-quality checks: {blocked[:500]})" if blocked else "")
            + ". See Data Quality, then publish it as it is or discard it and upload a corrected file "
            "(Held submissions, on the upload page). No assessment was run."
        )
    if status == "error":
        reason = str(res.get("message", "Failed to ingest batch"))
        return f"Error: {reason[:800]}{'...' if len(reason) > 800 else ''}"
    if status == "partial":
        return (
            "Error: these tables could not be stored: "
            f"{', '.join(res.get('failed_tables', []))}. No assessment was run; see Data Quality, "
            "fix the files and upload again."
        )
    detected = ", ".join(res.get("entities", [])) or target_entity or "Auto"
    row_str = " | ".join(f"{k}: {v}" for k, v in res.get("row_counts", {}).items())
    msg = f"Batch ingested successfully! [{row_str}] | Entities: {detected}"
    if res.get("detected_source"):
        msg += f" | Recognised as a {res['detected_source']} export by its columns."
    tidied = res.get("file_sanitising") or []
    if tidied:
        notes = "; ".join(f"{f['file']}: {', '.join(f['notes'])}" for f in tidied)
        msg += f" | Read notes: {notes[:400]}{'...' if len(notes) > 400 else ''}"
    not_whole = [f["summary"] for f in res.get("file_coverage") or [] if f["status"] not in ("ingested", "empty")]
    if not_whole:
        notes = "; ".join(not_whole)
        msg += f" | Not fully ingested (see Data Quality): {notes[:600]}{'...' if len(notes) > 600 else ''}"
    skipped = res.get("unattributed_rows") or {}
    if skipped:
        counts = ", ".join(f"{t}: {n}" for t, n in sorted(skipped.items()))
        msg += (
            f" | Warning: rows with no entity_id were not stored [{counts}]; "
            "add an entity_id column or choose a target entity."
        )
    return msg


def _earlier_attempt_batch(ctx: JobContext) -> dict[str, Any] | None:
    from satsa.store.catalog import Catalog

    catalog = Catalog(ctx.data_dir)
    try:
        for attempt in range(1, int(ctx.job["attempts"])):
            if ctx.job["params"].get("preview"):
                break  # a check-only import publishes nothing; it simply runs again
            batch = catalog.batch(f"BATCH-{ctx.job['job_id']}-a{attempt}")
            if batch is not None and batch["state"] in ("published", "held"):
                return batch
    finally:
        catalog.close()
    return None


def import_files(ctx: JobContext) -> dict[str, Any]:
    """Ingest an uploaded submission (saved under data/jobs/<job>/input) and assess it."""
    from satsa.ingest.pipeline import IngestionPipeline, detect_source_mapping
    from satsa.ingest.uploads import check_zip_limits
    from satsa.store.duckdb import DuckDBStore

    params = ctx.job["params"]
    target = params.get("target_entity")
    period = params.get("period")
    source = job_dir(ctx.data_dir, ctx.job["job_id"]) / IMPORT_INPUT

    preview = bool(params.get("preview"))
    earlier = _earlier_attempt_batch(ctx)
    if earlier is not None:
        ctx.stage(f"continuing from batch {earlier['batch_id']} of an earlier attempt")
        res: dict[str, Any] = {"status": "success" if earlier["state"] == "published" else "held",
                               "batch_id": earlier["batch_id"], "row_counts": {}, "entities": []}
    else:
        if not source.is_dir():
            raise JobFailed("the uploaded files are no longer on disk (data/jobs/<job>/input was removed)")
        from satsa.jobs.worker import IMPORT_BYTES_PER_INPUT_BYTE, MEMORY_BASE_BYTES

        input_bytes = sum(f.stat().st_size for f in source.rglob("*") if f.is_file())
        ctx.preflight_disk(input_bytes)
        ctx.preflight_memory(MEMORY_BASE_BYTES + IMPORT_BYTES_PER_INPUT_BYTE * input_bytes,
                             f"an import of {input_bytes // (1024 * 1024)} MiB")
        ctx.stage("reading and validating files")
        with tempfile.TemporaryDirectory(dir=job_dir(ctx.data_dir, ctx.job["job_id"])) as tmp:
            work = Path(tmp)
            for f in source.iterdir():
                if f.suffix.lower() == ".zip":
                    with zipfile.ZipFile(f, "r") as z:
                        check_zip_limits(z)
                        z.extractall(work)
                else:
                    shutil.copy2(f, work / f.name)
            mapping = detect_source_mapping(work, ctx.mappings_dir)
            if mapping is not None and not (target or mapping.entity_id):
                raise JobFailed(
                    f"This is a {mapping.source} export, which does not say which CSE it belongs to: "
                    "choose a target entity and upload it again."
                )
            duck = DuckDBStore(ctx.data_dir)
            try:
                ctx.stage("validating and publishing")
                res = IngestionPipeline(duck, ctx.store).ingest_directory(
                    work,
                    default_entity_id=target,
                    mapping=mapping,
                    bound_entity=target,
                    period=period,
                    transport="upload",
                    submitted_by=ctx.job["created_by"],
                    policy="preview" if preview else "if_clean",
                    batch_id=f"BATCH-{ctx.job['job_id']}-{'p' if preview else 'a'}{ctx.job['attempts']}",
                )
            finally:
                duck.close()
            if mapping is not None:
                res["detected_source"] = mapping.source

    message = describe_ingestion(res, target)
    result: dict[str, Any] = {
        "ingestion_status": res.get("status"),
        "batch_id": res.get("batch_id"),
        "row_counts": res.get("row_counts", {}),
        "entities": res.get("entities", []),
        "message": message,
    }
    if res.get("status") == "preview":
        coverage_by_entity: dict[str, Any] = res.get("rule_coverage") or {}
        cov: dict[str, Any] = coverage_by_entity.get(target or "") or next(iter(coverage_by_entity.values()), {})
        result["preview"] = {
            "files": res.get("file_coverage", []),
            "assessed": sorted(cov.get("assessed", {})),
            "not_assessed": cov.get("not_assessed", {}),
            "degraded": cov.get("degraded", {}),
            "issues": (res.get("dq_issue_list") or [])[:50],
            "issue_count": len(res.get("dq_issue_list") or []),
            # Problems that would hold the upload (config/data_quality.yaml).
            "blocking": res.get("blocking_issues") or [],
            "unmapped_files": res.get("unmapped_files", []),
            "invalid_timestamps": res.get("invalid_timestamps", {}),
        }
    elif res.get("status") == "success" and params.get("assess", True):
        assessed = _assess(ctx, period or params.get("default_period"), target or "PORTFOLIO")
        result.update(assessed)
        result["message"] = f"{message} | Assessment {assessed['run_id']}: {assessed['findings_count']} findings flagged."
    elif res.get("status") in ("error", "partial", "empty"):
        raise JobFailed(message, ingestion_status=res.get("status"), batch_id=res.get("batch_id"))
    shutil.rmtree(source, ignore_errors=True)
    return result


def demo_seed(ctx: JobContext) -> dict[str, Any]:
    """Synthetic demonstration data, its assessment and three historical periods (demo mode only)."""
    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.scoring.history import seed_historical_periods
    from satsa.store.duckdb import DuckDBStore
    from satsa.synth.generator import SyntheticDataGenerator

    ctx.stage("generating synthetic data")
    gen = SyntheticDataGenerator(seed=42, base_alerts_per_entity=1500)
    duck = DuckDBStore(ctx.data_dir)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            csv_dir, _ = gen.save_dataset(Path(tmp))
            ctx.stage("ingesting synthetic data")
            IngestionPipeline(duck, ctx.store).ingest_directory(csv_dir, transport="demo")
    finally:
        duck.close()
    assessed = _assess(ctx, "2026-Q1", "DEMO_PORTFOLIO")
    ctx.stage("seeding historical periods")
    seed_historical_periods(str(ctx.data_dir), ctx.store, n_periods=3, actor=ctx.job["created_by"])
    assessed["message"] = (
        f"Demo dataset seeded and assessed: {assessed['findings_count']} findings flagged "
        f"(run {assessed['run_id']}), plus 3 historical periods."
    )
    return assessed


HANDLERS: dict[str, Callable[[JobContext], dict[str, Any]]] = {
    "assessment": assessment,
    "import": import_files,
    "demo_seed": demo_seed,
}
RETRY_SAFE = {"assessment", "import"}
