"""FastAPI application providing offline server-rendered UI and REST endpoints."""

import copy
import csv
import hashlib
import io
import json
import logging
import os
import re
import shutil
import statistics
import tempfile
import urllib.parse
import zipfile
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode

import polars as pl
import yaml
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from satsa import FINDING_NOTICE, SUPERVISORY_NOTICE
from satsa.admin.rbac import SATSA_OPERATOR_ROLES, is_analyst, is_examiner
from satsa.auth.identities import MIN_PASSPHRASE_LENGTH, passphrase_policy_error
from satsa.auth.service_credentials import authenticate as authenticate_service
from satsa.auth.session import (
    SESSION_COOKIE_NAME,
    Identity,
    get_current_identity,
    require_authenticated,
    require_cse_access,
    require_role,
)
from satsa.bundle.rules_signer import RulePackKeyError, RulePackSigner
from satsa.cases.workflow import CaseError
from satsa.config_cache import load_yaml
from satsa.csv_safe import SafeWriter
from satsa.explain.finding_card import WHY_IT_MATTERS, FindingCard
from satsa.ingest.pipeline import IngestionPipeline
from satsa.ingest.uploads import MAX_UPLOAD_BYTES, _copy_limited, check_zip_limits
from satsa.jobs.handlers import IMPORT_INPUT, job_dir
from satsa.jobs.queue import JobQueue, fingerprint, new_job_id
from satsa.models.canonical import Entity
from satsa.models.outputs import EXAMINER_DECISIONS, ExaminerFeedback
from satsa.netguard import install_egress_guard, uninstall_egress_guard
from satsa.peers.anomaly_scan import format_value as format_metric_value
from satsa.peers.grouping import PeerResolver
from satsa.report.generator import ReportGenerator, ReportNotFoundError, coverage_sentence
from satsa.report.naming import entity_pdf_name, finding_pdf_name, portfolio_pdf_name
from satsa.rules import lifecycle
from satsa.rules.negative_space import REVIEW_PERIOD_MONTHS_RANGE
from satsa.rules.registry import RuleRegistry
from satsa.scoring.control_priorities import rank_controls, rank_processes
from satsa.scoring.runner import AssessmentRunner
from satsa.scoring.scorer import ScoringEngine, band_tier
from satsa.scoring.selection import period_bounds
from satsa.security import (
    is_valid_entity_id,
    is_valid_finding_id,
    is_valid_run_id,
    safe_join,
    safe_local_path,
)
from satsa.store.catalog import PublicationError
from satsa.store.duckdb import DuckDBStore, analytics_cache
from satsa.store.sqlite import SQLiteStore, utc_now_iso
from satsa.web_security import CROSS_SITE_REFUSED, SecurityMiddleware, cross_site_reason

# Roles permitted for each protected action category, matching
# docs/functional_design.md Section 2 (User Personas & Permissions). SAT-SA has
# two operators: the analyst runs the pipeline (ingest, runs, tuning, raw
# telemetry, audit ledger) and the examiner makes the review decisions. Keeping
# the two apart is deliberate separation of duties: whoever tunes the rules
# can't also sign off the findings. Administrators use the Admin Portal (:8000)
# and are refused here (see enforce_auth_middleware and handle_login).
ANALYST_ROLES = ("analyst",)
INGEST_RUN_ROLES = ANALYST_ROLES
TUNING_ROLES = ANALYST_ROLES
RULEPACK_ROLES = ANALYST_ROLES
REVIEW_ROLES = ("examiner",)
# Executive views, dossiers and read APIs, open to both operators.
SUPERVISORY_READ_ROLES = ("analyst", "examiner")

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """At start, install the egress guard and require a passphrase change on seeded accounts
    still using their default. The guard is removed again at shutdown."""
    guarded = install_egress_guard()
    try:
        store = SQLiteStore("data/satsa.db")
        try:
            for username in store.flag_unrotated_default_accounts():
                logger.warning("Account %r still uses its published default passphrase; "
                               "a new one must be set at first login.", username)
        finally:
            store.close()
        yield
    finally:
        if guarded:
            uninstall_egress_guard()


app = FastAPI(
    title="SAT-SA Supervisory API",
    description="Supervisory Analytics Tool for SOC Assessment",
    version="0.1.0",
    # /docs is served below from local Swagger UI assets (B07): FastAPI's default page loads them
    # from a CDN, which leaves it blank on an air-gapped network.
    docs_url=None,
    redoc_url=None,
    lifespan=_lifespan,
)

# Setup directories
STATIC_DIR = Path(__file__).resolve().parent.parent / "ui" / "static"
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "ui" / "templates"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
# Exposed as a Jinja global so base.html can render the logged-in identity
# (or lack thereof) in the nav bar without every route handler needing to
# thread it through its own context dict.
templates.env.globals["get_identity"] = get_current_identity
# Role-adaptive views: templates decide what to show from these, never from
# raw role strings, so every alias of a role (e.g. "NCIIPC Analyst") matches.
templates.env.globals["supervisory_notice"] = SUPERVISORY_NOTICE
templates.env.globals["band_tier"] = band_tier
templates.env.globals["is_analyst"] = is_analyst
templates.env.globals["is_examiner"] = is_examiner


def _deployment_settings(_request: Request | None = None) -> dict[str, str]:
    """The deployment's settings (mode, name ...) for page chrome such as the demo banner."""
    from satsa.deployment import settings

    store = SQLiteStore("data/satsa.db")
    try:
        return settings(store)
    finally:
        store.close()


templates.env.globals["deployment"] = _deployment_settings


def _brand() -> dict[str, str]:
    """The configured organisation wording for page chrome (satsa.deployment.branding)."""
    from satsa.deployment import branding

    return branding(values=_deployment_settings())


templates.env.globals["brand"] = _brand


# Paths anyone may reach without a session. Everything else requires one; the
# route's own dependency then enforces the specific role (see the RBAC table
# in tests/test_rbac_matrix.py, which must list every route).
PUBLIC_PATHS = {"/", "/login", "/logout", "/splash", "/api/session/status", "/healthz", "/readyz"}
# The only gated paths open to a session that still owes a passphrase change.
PASSWORD_CHANGE_PATH = "/change-password"
PASSWORD_CHANGE_REQUIRED = "A new passphrase must be set at /change-password before this account can be used."
PUBLIC_PREFIXES = ("/static/",)
# Non-page GET endpoints (JSON APIs and file downloads): an anonymous request
# gets 401 rather than a login redirect.
NON_PAGE_PREFIXES = ("/api/", "/reports/", "/templates/", "/tuning/export-pack", "/openapi.json")
NOT_SATSA_OPERATOR = (
    "This account is not a SAT-SA operator account (analyst or examiner). "
    "Administrators use the Admin Portal at :8000."
)


# Paths that accept a service credential instead of a session (docs/api_credentials.md), and the
# cap on their request bodies (SATSA_MAX_API_BODY_MB, default 64).
SERVICE_CREDENTIAL_PATHS = {"/api/v1/submissions"}
MAX_API_BODY_BYTES = int(os.environ.get("SATSA_MAX_API_BODY_MB", "64")) * 1024 * 1024


def require_submitter(request: Request) -> Identity:
    """An analyst session, or a service credential with the `submit` scope (set by the middleware)."""
    principal = getattr(request.state, "service_principal", None)
    if principal is not None:
        return Identity(username=principal.actor, role="service")
    return require_role(*INGEST_RUN_ROLES)(request)


def _is_public_path(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


@app.middleware("http")
async def enforce_auth_middleware(request: Request, call_next):
    """Reject anonymous requests to every non-public path.

    Anonymous browser page loads (GET on an HTML view) are redirected to
    /login; anonymous API calls, downloads and all mutating requests get 401.
    Authenticated requests pass through to the route, whose dependency
    (require_authenticated / require_role) enforces the allowed roles.
    """
    path = request.url.path
    if _is_public_path(path):
        return await call_next(request)

    # Machine integration (satsa.auth.service_credentials): a Bearer service credential on the
    # submission API, checked on every request so revocation and expiry apply at once.
    if path in SERVICE_CREDENTIAL_PATHS:
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_API_BODY_BYTES):
            return JSONResponse({"detail": f"The request body is larger than {MAX_API_BODY_BYTES // (1024 * 1024)} MiB."},
                                status_code=413)
        if request.headers.get("authorization"):
            store = SQLiteStore("data/satsa.db")
            try:
                principal = authenticate_service(store, request.headers.get("authorization"))
            finally:
                store.close()
            if principal is None:
                return JSONResponse({"detail": "Invalid, expired or revoked service credential."}, status_code=401)
            request.state.service_principal = principal
            return await call_next(request)

    identity = get_current_identity(request)
    if identity is None:
        if request.method == "GET" and not path.startswith(NON_PAGE_PREFIXES):
            import urllib.parse

            encoded_next = urllib.parse.quote_plus(path)
            return RedirectResponse(url=f"/login?next={encoded_next}", status_code=303)
        return JSONResponse(
            {"detail": "Authentication required. Please log in at /login."}, status_code=401
        )
    # Only the two SAT-SA operator roles get past here. A session held by any
    # other role (an administrator, a CSE-scoped account, or one opened before
    # it was refused at login) is denied on every gated path.
    if identity.role not in SATSA_OPERATOR_ROLES:
        return JSONResponse({"detail": NOT_SATSA_OPERATOR}, status_code=403)
    # A seeded default (or admin-reset) passphrase buys exactly one thing: replacing it.
    if identity.must_change_password and path != PASSWORD_CHANGE_PATH:
        if request.method == "GET" and not path.startswith(NON_PAGE_PREFIXES):
            return RedirectResponse(url=PASSWORD_CHANGE_PATH, status_code=303)
        return JSONResponse({"detail": PASSWORD_CHANGE_REQUIRED}, status_code=403)

    return await call_next(request)


WORKER_WINDOW_SECONDS = 60


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    """Liveness: the process answers. No dependencies are checked."""
    return {"status": "ok"}


@app.get("/readyz", include_in_schema=False)
def readyz() -> Response:
    """Readiness (satsa.ops.readiness): database, schema, catalog and disk; worker reported.
    503 when not ready. Holds no data and no secrets, so it is public, like /healthz."""
    from satsa.ops import readiness

    report = readiness("data")
    return JSONResponse(report, status_code=200 if report["ready"] else 503)


def enqueue_job(
    kind: str,
    params: dict[str, Any],
    identity: Identity,
    *,
    input_fingerprint: str | None = None,
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Queue a job (satsa.jobs) on behalf of `identity` and audit it. An identical job that is
    still queued or running is returned instead of a duplicate."""
    store = get_sqlite_store()
    try:
        job = JobQueue(store).enqueue(kind, {**params, "role": identity.role}, identity.username,
                                      input_fingerprint=input_fingerprint, max_attempts=max_attempts)
        if not job["deduplicated"]:
            store.append_audit(action="job_queued", actor=identity.username,
                               details={"job_id": job["job_id"], "kind": kind, **params})
    finally:
        store.close()
    return job


def enqueue_assessment(
    period: str | None, identity: Identity, reason: str, entity_label: str = "PORTFOLIO"
) -> dict[str, Any]:
    """Queue an assessment of `period`. Its fingerprint is the period, the current configuration
    and the published data, so the same request twice collapses while one is pending."""
    from satsa.store.catalog import published_sequence

    params = {"period": period, "reason": reason, "entity_label": entity_label}
    fp = fingerprint("assessment", {"period": period},
                     extra=f"{_current_config_hashes()[:1]}:{published_sequence('data')}")
    return enqueue_job("assessment", params, identity, input_fingerprint=fp)


SWAGGER_ASSETS = "/static/vendor/swagger-ui"


@app.get("/docs", include_in_schema=False)
def api_docs(identity: Identity = Depends(require_authenticated)) -> HTMLResponse:
    """Interactive API reference, rendered from vendored Swagger UI assets (see their VERSION file).

    The validator badge is switched off: Swagger UI would otherwise send the schema to
    validator.swagger.io from the browser."""
    return get_swagger_ui_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} - API reference",
        swagger_js_url=f"{SWAGGER_ASSETS}/swagger-ui-bundle.js",
        swagger_css_url=f"{SWAGGER_ASSETS}/swagger-ui.css",
        swagger_favicon_url="/static/0xzenith-logo.png",
        swagger_ui_parameters={"validatorUrl": None},
    )


JOB_ID_RE = re.compile(r"^JOB-[A-Za-z0-9_-]{1,64}$")
SHOWN_JOB_PARAMS = {"period": "Period", "target_entity": "Target entity", "files": "Files",
                    "reason": "Reason", "entity_label": "Entity"}


def _job_or_404(queue: JobQueue, job_id: str) -> dict[str, Any]:
    job = queue.get(job_id) if JOB_ID_RE.match(job_id) else None
    if job is None:
        raise HTTPException(status_code=404, detail="No such job.")
    return job


@app.get("/jobs", response_class=HTMLResponse)
def view_jobs(request: Request, identity: Identity = Depends(require_role(*SUPERVISORY_READ_ROLES))) -> Response:
    """Recent jobs of the deployment (portfolio-wide, like runs; examiners can read, not cancel)."""
    store = get_sqlite_store()
    try:
        queue = JobQueue(store)
        jobs = queue.recent(100)
        workers = queue.live_workers(WORKER_WINDOW_SECONDS)
    finally:
        store.close()
    return templates.TemplateResponse(
        request=request, name="jobs.html",
        context={"active_tab": "jobs", "jobs": jobs, "workers": workers, "worker_window": WORKER_WINDOW_SECONDS,
                 "any_active": any(j["state"] in ("queued", "running") for j in jobs)},
    )


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def view_job(request: Request, job_id: str,
             identity: Identity = Depends(require_role(*SUPERVISORY_READ_ROLES))) -> Response:
    store = get_sqlite_store()
    try:
        queue = JobQueue(store)
        job = _job_or_404(queue, job_id)
        workers = queue.live_workers(WORKER_WINDOW_SECONDS)
    finally:
        store.close()
    shown = [(label, ", ".join(v) if isinstance(v, list) else v)
             for key, label in SHOWN_JOB_PARAMS.items() if (v := job["params"].get(key))]
    return templates.TemplateResponse(
        request=request, name="job_detail.html",
        context={"active_tab": "jobs", "job": job, "workers": workers, "worker_window": WORKER_WINDOW_SECONDS,
                 "shown_params": shown, "can_cancel": is_analyst(identity.role)},
    )


@app.get("/api/v1/jobs/{job_id}")
def api_job(job_id: str, identity: Identity = Depends(require_role(*SUPERVISORY_READ_ROLES))) -> dict[str, Any]:
    """A job's state, stage, attempts, result or structured error."""
    store = get_sqlite_store()
    try:
        job = _job_or_404(JobQueue(store), job_id)
    finally:
        store.close()
    job["params"] = {k: v for k, v in job["params"].items() if k != "role"}
    return {k: v for k, v in job.items() if k not in ("lease_owner", "input_fingerprint")}


@app.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, identity: Identity = Depends(require_role(*INGEST_RUN_ROLES))) -> Response:
    """Cancel a queued job, or ask a running one to stop at its next stage."""
    store = get_sqlite_store()
    try:
        queue = JobQueue(store)
        _job_or_404(queue, job_id)
        job = queue.cancel(job_id)
        store.append_audit(action="job_cancel_requested", actor=identity.username,
                           details={"job_id": job_id, "state": (job or {}).get("state")})
    finally:
        store.close()
    return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)


@app.middleware("http")
async def refuse_cross_site_requests(request: Request, call_next):
    """CSRF defence (satsa.web_security): a state-changing request must come from this portal's
    own pages. Registered after the authentication middleware, so it runs before it."""
    reason = cross_site_reason(request.method, request.headers, str(request.base_url))
    if reason is not None:
        logger.warning("Refused cross-site %s %s: %s", request.method, request.url.path, reason)
        return JSONResponse({"detail": CROSS_SITE_REFUSED}, status_code=403)
    return await call_next(request)


# Characters an uploaded file's stored name may not contain.
UNSAFE_FILE_CHARS = re.compile(r"[^A-Za-z0-9._ -]")
WINDOWS_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                          *(f"LPT{i}" for i in range(1, 10))}

# Multipart framing around the uploaded files of one /upload request.
UPLOAD_FORM_SLACK_BYTES = 1024 * 1024


def _request_body_limit(path: str) -> int:
    """The most bytes a request to `path` may send: the upload limit for file uploads, the API
    body limit for everything else (read at request time, so the environment settings apply)."""
    return MAX_UPLOAD_BYTES + UPLOAD_FORM_SLACK_BYTES if path == "/upload" else MAX_API_BODY_BYTES


# Outermost: security headers on every response, and request bodies capped as they arrive.
app.add_middleware(SecurityMiddleware, limit_for=lambda path: _request_body_limit(path))


def require_valid_entity_id(entity_id: str) -> str:
    """Reject an externally supplied entity_id that fails satsa.security.ENTITY_ID_RE (HTTP 400)."""
    if not is_valid_entity_id(entity_id):
        raise HTTPException(status_code=400, detail="Invalid entity_id.")
    return entity_id


def session_cookie_secure() -> bool:
    """Whether to set the Secure cookie flag (off by default: the app serves plain-HTTP localhost)."""
    return os.environ.get("SATSA_COOKIE_SECURE", "").lower() in ("1", "true", "yes")


def get_sqlite_store() -> SQLiteStore:
    """State store only, for the many requests that never touch the analytics tables."""
    return SQLiteStore("data/satsa.db")


def get_stores() -> tuple[DuckDBStore, SQLiteStore]:
    """Stores for a request that only reads.

    The analytics store is a view on the process-wide cache (satsa.store.duckdb.AnalyticsCache):
    the Parquet tables are loaded once and reused until a new assessment run completes or the
    stored data changes, instead of being re-read on every request.
    """
    sqlite_store = SQLiteStore("data/satsa.db")
    row = sqlite_store.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
    return analytics_cache.view("data", row["run_id"] if row else None), sqlite_store


def get_write_stores() -> tuple[DuckDBStore, SQLiteStore]:
    """Stores for a request that ingests, deletes or re-assesses: a private analytics store,
    loaded fresh. What it writes changes the Parquet fingerprint, which retires the read cache."""
    duckdb_store = DuckDBStore("data")
    duckdb_store.load_all_tables()
    return duckdb_store, SQLiteStore("data/satsa.db")


def _build_real_trend_series(
    cur: Any, entity_ids: list[str], ranked_entities: list[dict[str, Any]], max_periods: int = 6
) -> tuple[list[str], list[dict[str, Any]], bool]:
    """Build the portfolio trend chart series from REAL persisted run history.

    Queries entity_scores joined to runs.period across the most recent
    distinct assessment runs and returns genuine risk_index values per
    period. An entity with fewer than 2 historical data points is marked
    with `insufficient_history=True` and an empty `data` list -- it is
    never padded with synthesized or interpolated values.
    """
    if not entity_ids:
        return [], [], False

    cur.execute(
        """
        SELECT DISTINCT r.run_id, r.period, r.created_at
        FROM runs r
        ORDER BY r.created_at ASC
        """
    )
    all_runs = cur.fetchall()
    if not all_runs:
        return [], [], False

    # Keep only the most recent `max_periods` runs (chronological order).
    recent_runs = all_runs[-max_periods:] if len(all_runs) > max_periods else all_runs
    run_ids = [r["run_id"] for r in recent_runs]
    trend_periods = [r["period"] for r in recent_runs]

    placeholders = ",".join("?" for _ in run_ids)
    cur.execute(
        f"""
        SELECT run_id, entity_id, risk_index
        FROM entity_scores
        WHERE entity_id IN ({",".join("?" for _ in entity_ids)}) AND run_id IN ({placeholders})
        """,
        (*entity_ids, *run_ids),
    )
    score_rows = cur.fetchall()
    by_entity: dict[str, dict[str, float]] = {}
    for r in score_rows:
        by_entity.setdefault(r["entity_id"], {})[r["run_id"]] = float(r["risk_index"])

    name_map = {e["entity_id"]: e["name"] for e in ranked_entities}

    trend_series = []
    any_real_data = False
    for eid in entity_ids:
        run_scores = by_entity.get(eid, {})
        real_points = [run_scores[rid] for rid in run_ids if rid in run_scores]
        if len(real_points) < 2:
            trend_series.append(
                {
                    "name": f"{eid} - {name_map.get(eid, eid)[:16]}",
                    "data": [],
                    "insufficient_history": True,
                }
            )
            continue
        any_real_data = True
        data_points = [run_scores.get(rid) for rid in run_ids]
        trend_series.append(
            {
                "name": f"{eid} - {name_map.get(eid, eid)[:16]}",
                "data": data_points,
                "insufficient_history": False,
            }
        )

    return trend_periods, trend_series, any_real_data


def _trend_comparability_warnings(cur: Any, entity_ids: list[str], max_periods: int = 6) -> list[str]:
    """Why points of the trend chart may not be comparable (docs/examiner_workflow.md, "Trends").

    Between consecutive runs of the chart: a change of rule parameters, of a rule's version or of
    the peer-group definition; and, per entity, a fall in risk index that comes with a fall in
    evidence coverage, which is missing data rather than improvement.
    """
    runs = cur.execute(
        "SELECT run_id, period FROM runs ORDER BY created_at DESC LIMIT ?", (max_periods,)
    ).fetchall()[::-1]
    warnings: list[str] = []
    shas: dict[str, dict[str, str]] = {}
    versions: dict[str, dict[str, str]] = {}
    for r in runs:
        shas[r["run_id"]] = {k: v for k, v in cur.execute(
            "SELECT key, sha256 FROM run_config_snapshots WHERE run_id = ?", (r["run_id"],))}
        versions[r["run_id"]] = {k: v for k, v in cur.execute(
            "SELECT DISTINCT rule_id, rule_version FROM rule_results WHERE run_id = ?", (r["run_id"],))}
    for a, b in pairwise(runs):
        between = f"between {a['period']} and {b['period']}"
        sa, sb = shas[a["run_id"]], shas[b["run_id"]]
        if not sa or not sb:
            warnings.append(f"A run {between} predates configuration snapshots: comparability cannot be checked.")
            continue
        if sa.get("rules") != sb.get("rules"):
            warnings.append(f"Rule parameters changed {between}: scores on either side are not directly comparable.")
        if sa.get("peers") != sb.get("peers"):
            warnings.append(f"The peer-group definition changed {between}: peer-based scores may shift.")
        for rule_id, version in sorted(versions[b["run_id"]].items()):
            before = versions[a["run_id"]].get(rule_id)
            if before and before != version:
                warnings.append(f"Rule {rule_id} changed version ({before} to {version}) {between}.")
    if entity_ids and len(runs) > 1:
        rows = cur.execute(
            f"SELECT run_id, entity_id, risk_index, coverage, classification_status FROM entity_scores "
            f"WHERE run_id IN ({','.join('?' for _ in runs)}) AND entity_id IN ({','.join('?' for _ in entity_ids)})",
            (*[r["run_id"] for r in runs], *entity_ids),
        ).fetchall()
        by = {(r["run_id"], r["entity_id"]): r for r in rows}
        for eid in entity_ids:
            for a, b in pairwise(runs):
                ra, rb = by.get((a["run_id"], eid)), by.get((b["run_id"], eid))
                if ra is None or rb is None or rb["risk_index"] >= ra["risk_index"]:
                    continue
                ca, cb = ra["coverage"], rb["coverage"]
                lower_coverage = ca is not None and cb is not None and cb < ca
                unclassified = (rb["classification_status"] or "assessable") != "assessable"
                if lower_coverage or unclassified:
                    cov = f" (coverage {ca:.0%} to {cb:.0%})" if lower_coverage else ""
                    warnings.append(
                        f"{eid}: the risk index fell {a['period']} to {b['period']} while less evidence could be "
                        f"assessed{cov}. A lower score from missing data is not improvement."
                    )
    return list(dict.fromkeys(warnings))


# --- Local Auth: Login / Logout ---


@app.get("/login", response_class=HTMLResponse)
async def view_login(
    request: Request, error: str = "", next: str = "/portfolio", blocked: str = ""
) -> Response:
    identity = get_current_identity(request)
    if identity:
        return RedirectResponse(url="/portfolio", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "active_tab": "login",
            "error": error,
            "blocked": bool(blocked),
            "next": next,
            "identity": None,
        },
    )


@app.post("/login")
async def handle_login(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/portfolio",
) -> Response:
    import urllib.parse

    from satsa.auth.identities import LOGIN_LOCKOUT_MINUTES, LOGIN_MAX_FAILURES, verify_passphrase

    uname = username.strip()
    safe_next = safe_local_path(next)
    # One generic message for unknown user, wrong passphrase AND lockout, so the
    # response never reveals whether a username exists or is locked.
    generic_error = RedirectResponse(
        url=f"/login?error={urllib.parse.quote_plus('Invalid username or passphrase.')}&next={safe_next}",
        status_code=303,
    )

    sqlite_store = get_sqlite_store()
    actor = uname or "unknown"
    if sqlite_store.count_recent_login_failures(actor, LOGIN_LOCKOUT_MINUTES) >= LOGIN_MAX_FAILURES:
        # Rejected even if the passphrase is correct; not counted as a new failure,
        # so the lock expires LOGIN_LOCKOUT_MINUTES after the last real failure.
        sqlite_store.append_audit(
            action="login_locked",
            actor=actor,
            details={"max_failures": LOGIN_MAX_FAILURES, "window_minutes": LOGIN_LOCKOUT_MINUTES},
        )
        sqlite_store.close()
        return generic_error

    identity_row = sqlite_store.get_identity(uname)
    if identity_row is None or not verify_passphrase(
        password, identity_row["pass_salt"], identity_row["pass_hash"]
    ):
        sqlite_store.append_audit(
            action="login_failed", actor=actor, details={"reason": "bad_credentials"}
        )
        sqlite_store.close()
        return generic_error

    if identity_row.get("is_blocked") or identity_row.get("status") == "BLOCKED":
        sqlite_store.append_audit(
            action="login_blocked", actor=uname, details={"reason": "account_blocked"}
        )
        sqlite_store.close()
        err_msg = urllib.parse.quote_plus(
            "Access Denied: This account has been blocked. Please contact your deployment administrator."
        )
        return RedirectResponse(
            url=f"/login?error={err_msg}&blocked=1&next={safe_next}", status_code=303
        )

    if identity_row["role"] not in SATSA_OPERATOR_ROLES:
        sqlite_store.append_audit(
            action="login_denied_role", actor=uname, details={"role": identity_row["role"]}
        )
        sqlite_store.close()
        return RedirectResponse(
            url=f"/login?error={urllib.parse.quote_plus(NOT_SATSA_OPERATOR)}&next={safe_next}",
            status_code=303,
        )

    token = sqlite_store.create_session(identity_row["username"], identity_row["role"])
    must_change = bool(identity_row.get("force_password_change"))
    sqlite_store.append_audit(
        action="login",
        actor=identity_row["username"],
        details={"role": identity_row["role"], "password_change_required": must_change},
    )
    sqlite_store.record_live_event(
        "USER_LOGIN",
        actor=identity_row["username"],
        role=identity_row["role"],
        entity_id=identity_row.get("cse_id"),
        details={"org_id": identity_row.get("org_id")},
    )
    sqlite_store.close()

    resp = RedirectResponse(url=PASSWORD_CHANGE_PATH if must_change else safe_next, status_code=303)
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=session_cookie_secure(),
        max_age=8 * 3600,
    )
    return resp


@app.get("/change-password", response_class=HTMLResponse)
async def view_change_password(
    request: Request, identity: Identity = Depends(require_authenticated)
) -> Response:
    return templates.TemplateResponse(
        request=request,
        name="change_password.html",
        context={
            "active_tab": "login",
            "error": "",
            "forced": identity.must_change_password,
            "min_length": MIN_PASSPHRASE_LENGTH,
        },
    )


@app.post("/change-password")
async def handle_change_password(
    request: Request,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    identity: Identity = Depends(require_authenticated),
) -> Response:
    """Replace the signed-in operator's own passphrase; lifts a forced change.

    The current passphrase is asked for again, and a wrong one counts towards the login
    lockout, so a borrowed session cannot be used to guess it.
    """
    from satsa.auth.identities import LOGIN_LOCKOUT_MINUTES, LOGIN_MAX_FAILURES, verify_passphrase

    def _refuse(message: str) -> Response:
        return templates.TemplateResponse(
            request=request,
            name="change_password.html",
            context={
                "active_tab": "login",
                "error": message,
                "forced": identity.must_change_password,
                "min_length": MIN_PASSPHRASE_LENGTH,
            },
            status_code=400,
        )

    sqlite_store = get_sqlite_store()
    try:
        username = identity.username
        if sqlite_store.count_recent_login_failures(username, LOGIN_LOCKOUT_MINUTES) >= LOGIN_MAX_FAILURES:
            return _refuse("Too many failed attempts. Try again later.")
        row = sqlite_store.get_identity(username)
        if row is None or not verify_passphrase(current_password, row["pass_salt"], row["pass_hash"]):
            sqlite_store.append_audit(
                action="login_failed", actor=username, details={"reason": "bad_current_passphrase"}
            )
            return _refuse("The current passphrase is not correct.")
        problem = passphrase_policy_error(new_password, confirm_password, current_password)
        if problem:
            return _refuse(problem)
        sqlite_store.change_own_password(
            username, new_password, keep_token=request.cookies.get(SESSION_COOKIE_NAME)
        )
        sqlite_store.append_audit(
            action="password_changed",
            actor=username,
            details={"forced": identity.must_change_password},
        )
    finally:
        sqlite_store.close()
    return RedirectResponse(url="/portfolio", status_code=303)


@app.post("/logout")
async def handle_logout(request: Request) -> Response:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        sqlite_store = get_sqlite_store()
        session = sqlite_store.get_session(token)
        sqlite_store.delete_session(token)
        if session:
            sqlite_store.append_audit(action="logout", actor=session["username"], details={})
            sqlite_store.record_live_event(
                "USER_LOGOUT",
                actor=session["username"],
                role=session.get("role"),
                entity_id=session.get("cse_id"),
                details={},
            )
        sqlite_store.close()
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


@app.get("/api/session/status")
async def api_session_status(request: Request) -> JSONResponse:
    """Session status endpoint polled by the SAT-SA frontend to detect administrative revocation of the session."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return JSONResponse({"authenticated": False, "revoked": False})

    sqlite_store = get_sqlite_store()
    try:
        session = sqlite_store.get_session(token)
        if not session:
            return JSONResponse({"authenticated": False, "revoked": True, "reason": "session_terminated"})

        user = sqlite_store.get_user(session["username"])
        if not user or user.get("status") == "BLOCKED" or user.get("is_blocked"):
            sqlite_store.delete_session(token)
            return JSONResponse(
                {"authenticated": False, "revoked": True, "blocked": True, "reason": "account_blocked"}
            )

        return JSONResponse(
            {
                "authenticated": True,
                "revoked": False,
                "username": session["username"],
                "role": session["role"],
                "cse_id": session.get("cse_id"),
                "org_id": session.get("org_id"),
            }
        )
    finally:
        sqlite_store.close()


# --- Web UI Routes ---


@app.get("/splash", response_class=HTMLResponse)
async def view_splash(request: Request) -> Response:
    return templates.TemplateResponse(
        request=request,
        name="splash.html",
        context={"active_tab": "splash"},
    )


@app.get("/", response_class=HTMLResponse)
@app.get("/portfolio", response_class=HTMLResponse, dependencies=[Depends(require_authenticated)])
async def view_portfolio(
    request: Request,
    run_id: str | None = None,
    q: str = "",
    band: str = "",
    evidence: str = "",
    sort: str = "risk",
) -> Response:
    identity = get_current_identity(request)
    if identity is None:
        if request.url.path == "/portfolio":
            return RedirectResponse(url="/login?next=/portfolio", status_code=303)
        return templates.TemplateResponse(
            request=request,
            name="splash.html",
            context={"active_tab": "splash"},
        )

    require_valid_run_id(run_id)
    filters = _portfolio_filters(q, band, evidence, sort)
    duckdb_store, sqlite_store = get_stores()

    # The selected run (default: the latest)
    cur = sqlite_store.conn.cursor()
    try:
        run_row = _selected_run(sqlite_store, run_id)
    except HTTPException:
        duckdb_store.close()
        sqlite_store.close()
        raise
    period = run_row["period"] if run_row else "no assessment run yet"
    run_id = run_row["run_id"] if run_row else ""

    # Fetch entities from DuckDB
    df_ent = duckdb_store.query("SELECT entity_id, name, sector, size_band FROM entity")
    ent_map = {row["entity_id"]: row for row in df_ent.iter_rows(named=True)}

    # Fetch entity scores from SQLite
    cur.execute(
        """
        SELECT *
        FROM entity_scores
        WHERE run_id = ?
        ORDER BY risk_index DESC
    """,
        (run_id,),
    )
    score_rows = cur.fetchall()

    ranked_entities = []
    for r in score_rows:
        eid = r["entity_id"]
        e_info = ent_map.get(eid, {"name": eid, "sector": "general", "size_band": "medium"})
        ranked_entities.append(
            {
                "entity_id": eid,
                "name": e_info["name"],
                "sector": e_info["sector"],
                "size_band": e_info["size_band"],
                "risk_index": r["risk_index"],
                "risk_band": r["risk_band"],
                "distinct_rules": r["distinct_rules_triggered"],
                "classification_status": r["classification_status"],
                "coverage": r["coverage"],
                "evidence": coverage_sentence(dict(r)),
                "missing_inputs": json.loads(r["missing_inputs_json"] or "[]"),
            }
        )

    # Fetch domain scores for heatmap
    cur.execute(
        """
        SELECT entity_id, domain, score
        FROM domain_scores
        WHERE run_id = ?
    """,
        (run_id,),
    )
    domain_rows = cur.fetchall()

    heatmap_entities = [e["entity_id"] for e in ranked_entities]
    domains = [
        "Threat Detection",
        "Investigation",
        "Escalation",
        "Incident Response",
        "Security Operations",
        "Governance and Oversight",
        "Operational Discipline",
        "Cyber Resilience",
    ]
    heatmap_data = []
    for r in domain_rows:
        # A domain no rule could assess for the entity has no score (not 0): its cell stays blank.
        if r["entity_id"] in heatmap_entities and r["domain"] in domains and r["score"] is not None:
            y_idx = heatmap_entities.index(r["entity_id"])
            x_idx = domains.index(r["domain"])
            heatmap_data.append([x_idx, y_idx, round(r["score"], 1)])
    # The same scores as a table, for screen readers and anyone who cannot read the colours.
    cells = {(x, y): v for x, y, v in heatmap_data}
    heatmap_table = [{"entity_id": eid, "scores": [cells.get((x, y)) for x in range(len(domains))]}
                     for y, eid in enumerate(heatmap_entities)]

    # Execution Gaps vs Negative Space breakdown
    cur.execute(
        """
        SELECT
            count(CASE WHEN rule_id LIKE 'EG%' THEN 1 END) as total_eg,
            count(CASE WHEN rule_id LIKE 'NS%' THEN 1 END) as total_ns
        FROM findings
        WHERE run_id = ?
    """,
        (run_id,),
    )
    gap_row = cur.fetchone()
    total_eg = gap_row["total_eg"] if gap_row else 0
    total_ns = gap_row["total_ns"] if gap_row else 0

    # Entity-level EG / NS counts
    cur.execute(
        """
        SELECT
            entity_id,
            count(CASE WHEN rule_id LIKE 'EG%' THEN 1 END) as eg_hits,
            count(CASE WHEN rule_id LIKE 'NS%' THEN 1 END) as ns_hits
        FROM findings
        WHERE run_id = ?
        GROUP BY entity_id
    """,
        (run_id,),
    )
    ent_gap_map = {
        r["entity_id"]: {"eg_hits": r["eg_hits"], "ns_hits": r["ns_hits"]} for r in cur.fetchall()
    }

    for e in ranked_entities:
        e["eg_count"] = ent_gap_map.get(e["entity_id"], {}).get("eg_hits", 0)
        e["ns_count"] = ent_gap_map.get(e["entity_id"], {}).get("ns_hits", 0)

    # Top Execution Gaps
    cur.execute(
        """
        SELECT rule_id, title, severity, count(*) as count
        FROM findings
        WHERE run_id = ? AND rule_id LIKE 'EG%'
        GROUP BY rule_id, title, severity
        ORDER BY count DESC
        LIMIT 3
    """,
        (run_id,),
    )
    top_eg_list = [dict(r) for r in cur.fetchall()]

    # Top Negative Space Anomalies
    cur.execute(
        """
        SELECT rule_id, title, severity, count(*) as count
        FROM findings
        WHERE run_id = ? AND rule_id LIKE 'NS%'
        GROUP BY rule_id, title, severity
        ORDER BY count DESC
        LIMIT 3
    """,
        (run_id,),
    )
    top_ns_list = [dict(r) for r in cur.fetchall()]

    # Multi-period historical risk trajectory for top entities, built from
    # REAL persisted run history (entity_scores joined to runs.period),
    # never synthesized. See docs/analytics_methodology.md for the method
    # used to seed genuine historical periods in demo environments.
    trend_periods, trend_series, trend_has_data = _build_real_trend_series(
        cur, [e["entity_id"] for e in ranked_entities[:5]], ranked_entities[:5]
    )
    trend_warnings = _trend_comparability_warnings(cur, [e["entity_id"] for e in ranked_entities[:5]])

    # Counts
    cur.execute("SELECT count(*) FROM findings WHERE run_id = ?", (run_id,))
    total_findings = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM review_queue WHERE run_id = ?", (run_id,))
    queue_count = cur.fetchone()[0]

    critical_count = sum(1 for e in ranked_entities if band_tier(e["risk_band"]) != "low")

    # Cross-entity ("systemic") findings for this run -- a distinct section,
    # not folded into any per-entity finding card. See satsa.rules.systemic.
    systemic_findings = sqlite_store.get_systemic_findings(run_id)

    # Controls (rules) and processes (domains) to prioritise, plus exploratory leads per
    # entity. See satsa.scoring.control_priorities and satsa.peers.anomaly_scan.
    priority_controls = rank_controls(sqlite_store.conn, run_id)
    priority_processes = rank_processes(sqlite_store.conn, run_id)
    lead_counts: dict[str, int] = {}
    for sig in sqlite_store.get_anomaly_signals(run_id):
        lead_counts[sig["entity_id"]] = lead_counts.get(sig["entity_id"], 0) + 1
    for e in ranked_entities:
        e["lead_count"] = lead_counts.get(e["entity_id"], 0)
    _attention(cur, run_id, ranked_entities)
    league = _filter_league(ranked_entities, filters)
    recent_runs = [dict(r) for r in cur.execute(
        "SELECT run_id, period, created_at FROM runs ORDER BY created_at DESC LIMIT 25"
    )]
    saved_views = [dict(r) for r in cur.execute(
        "SELECT view_id, name, query_json FROM saved_views WHERE owner = ? ORDER BY name", (identity.username,)
    )]
    for v in saved_views:
        v["href"] = "/portfolio?" + urlencode(json.loads(v.pop("query_json")))

    duckdb_store.close()
    sqlite_store.close()

    return templates.TemplateResponse(
        request=request,
        name="portfolio.html",
        context={
            "active_tab": "portfolio",
            "period": period,
            "ranked_entities": ranked_entities,
            "entities": ranked_entities,
            "critical_count": critical_count,
            "total_findings": total_findings,
            "total_eg": total_eg,
            "total_ns": total_ns,
            "top_eg_list": top_eg_list,
            "top_ns_list": top_ns_list,
            "trend_periods": trend_periods,
            "trend_series": trend_series,
            "trend_has_data": trend_has_data,
            "trend_warnings": trend_warnings,
            "queue_count": queue_count,
            "heatmap_entities": heatmap_entities,
            "heatmap_domains": domains,
            "heatmap_data": heatmap_data,
            "heatmap_table": heatmap_table,
            "systemic_findings": systemic_findings,
            "priority_controls": priority_controls,
            "priority_processes": priority_processes,
            "league": league,
            "filters": filters,
            "run": dict(run_row) if run_row else None,
            "recent_runs": recent_runs,
            "saved_views": saved_views,
            "portfolio_sorts": PORTFOLIO_SORTS,
        },
    )


PORTFOLIO_SORTS = {
    "risk": "Risk index (highest first)",
    "evidence": "Evidence coverage (lowest first)",
    "findings": "Rules triggered (most first)",
    "entity": "Entity ID",
}
PORTFOLIO_BANDS = ("critical", "moderate", "low", "insufficient")
PORTFOLIO_EVIDENCE = ("assessable", "partially_assessable", "insufficient_evidence")


def _portfolio_filters(q: str, band: str, evidence: str, sort: str) -> dict[str, str]:
    """The portfolio's filters, each reduced to a known value (anything else means "all")."""
    return {
        "q": q.strip()[:100],
        "band": band if band in PORTFOLIO_BANDS else "",
        "evidence": evidence if evidence in PORTFOLIO_EVIDENCE else "",
        "sort": sort if sort in PORTFOLIO_SORTS else "risk",
    }


def _attention(cur: Any, run_id: str, entities: list[dict[str, Any]]) -> None:
    """Why each entity needs attention and the next supervisory action, from this run's
    findings, evidence coverage and the entity's open supervisory cases."""
    top: dict[str, dict[str, Any]] = {}
    for r in cur.execute(
        "SELECT entity_id, rule_id, title, severity, score FROM findings WHERE run_id = ? AND exception_id IS NULL "
        "ORDER BY score DESC, finding_id", (run_id,)
    ):
        top.setdefault(r["entity_id"], dict(r))
    cases: dict[str, dict[str, Any]] = {}
    for r in cur.execute(
        "SELECT case_id, entity_id, rule_id, state FROM cases WHERE state <> 'closed' ORDER BY created_at, case_id"
    ):
        cases.setdefault(r["entity_id"], dict(r))
    for e in entities:
        tier = band_tier(e["risk_band"])
        missing = ", ".join(e["missing_inputs"][:4])
        finding = top.get(e["entity_id"])
        case = cases.get(e["entity_id"])
        if tier == "insufficient":
            e["why"] = "Too little evidence to classify" + (f" (missing: {missing})" if missing else "")
            e["next_action"] = "Request the missing data" + (f": {missing}" if missing else "")
        elif finding is None:
            e["why"] = "No finding in this run"
            e["next_action"] = "No action; reassess next period"
        else:
            e["why"] = f"{finding['rule_id']}: {finding['title']}"
            if case is not None:
                state = str(case["state"]).replace("_", " ")
                e["next_action"] = f"Continue case {case['case_id']} ({state})"
                e["case_id"] = case["case_id"]
            elif tier in ("critical", "moderate"):
                e["next_action"] = f"Review {finding['rule_id']} evidence and open a supervisory case if it holds"
            else:
                e["next_action"] = "Review the findings in the queue"
        if e.get("classification_status") == "partially_assessable" and missing and tier != "insufficient":
            e["next_action"] += f"; request {missing}"


def _filter_league(entities: list[dict[str, Any]], f: dict[str, str]) -> list[dict[str, Any]]:
    out = [
        e for e in entities
        if (not f["band"] or band_tier(e["risk_band"]) == f["band"])
        and (not f["evidence"] or e.get("classification_status") == f["evidence"])
        and (not f["q"] or f["q"].lower() in f"{e['entity_id']} {e['name']} {e['sector']}".lower())
    ]
    if f["sort"] == "evidence":
        out.sort(key=lambda e: (e["coverage"] if e["coverage"] is not None else -1.0, e["entity_id"]))
    elif f["sort"] == "findings":
        out.sort(key=lambda e: (-(e["distinct_rules"] or 0), e["entity_id"]))
    elif f["sort"] == "entity":
        out.sort(key=lambda e: e["entity_id"])
    return out


SAVED_VIEW_NAME_RE = re.compile(r"^[\w .,()-]{1,60}$")
SAVED_VIEW_ID_RE = re.compile(r"^VIEW-[A-F0-9]{12}$")


@app.post("/portfolio/views")
async def save_portfolio_view(
    name: Annotated[str, Form()],
    q: Annotated[str, Form()] = "",
    band: Annotated[str, Form()] = "",
    evidence: Annotated[str, Form()] = "",
    sort: Annotated[str, Form()] = "risk",
    run_id: Annotated[str, Form()] = "",
    identity: Identity = Depends(require_role(*SUPERVISORY_READ_ROLES)),
) -> Response:
    """Save the current portfolio filters under a name, for this user only."""
    name = name.strip()
    if not SAVED_VIEW_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="A view name is 1-60 letters, digits, spaces or .,()-")
    require_valid_run_id(run_id or None)
    query = {k: v for k, v in {**_portfolio_filters(q, band, evidence, sort), "run_id": run_id}.items() if v}
    store = get_sqlite_store()
    try:
        view_id = "VIEW-" + hashlib.sha256(f"{identity.username}:{name}".encode()).hexdigest()[:12].upper()
        with store.transaction():
            store.conn.execute(
                "INSERT OR REPLACE INTO saved_views (view_id, owner, name, query_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (view_id, identity.username, name, json.dumps(query, sort_keys=True), utc_now_iso()),
            )
    finally:
        store.close()
    return RedirectResponse(url="/portfolio?" + urlencode(query), status_code=303)


@app.post("/portfolio/views/{view_id}/delete")
async def delete_portfolio_view(
    view_id: str, identity: Identity = Depends(require_role(*SUPERVISORY_READ_ROLES))
) -> Response:
    if not SAVED_VIEW_ID_RE.match(view_id):
        raise HTTPException(status_code=400, detail="Malformed view id")
    store = get_sqlite_store()
    try:
        with store.transaction():
            store.conn.execute("DELETE FROM saved_views WHERE view_id = ? AND owner = ?", (view_id, identity.username))
    finally:
        store.close()
    return RedirectResponse(url="/portfolio", status_code=303)


@app.get("/entity/{entity_id}", response_class=HTMLResponse, dependencies=[Depends(require_authenticated)])
async def view_entity_profile(request: Request, entity_id: str, run_id: str | None = None) -> Response:
    require_valid_entity_id(entity_id)
    require_valid_run_id(run_id)
    identity = get_current_identity(request)
    if identity:
        require_cse_access(entity_id, identity)
    duckdb_store, sqlite_store = get_stores()

    cur = sqlite_store.conn.cursor()
    try:
        run_row = _selected_run(sqlite_store, run_id)
    except HTTPException:
        duckdb_store.close()
        sqlite_store.close()
        raise
    run_id = run_row["run_id"] if run_row else ""

    # Fetch entity info
    ent_res = duckdb_store.query("SELECT * FROM entity WHERE entity_id = ?", [entity_id])
    if ent_res.is_empty():
        duckdb_store.close()
        sqlite_store.close()
        raise HTTPException(status_code=404, detail="Entity not found")
    entity_dict = ent_res.to_dicts()[0]

    # Fetch score
    cur.execute(
        "SELECT * FROM entity_scores WHERE entity_id = ? AND run_id = ?", (entity_id, run_id)
    )
    score_row = cur.fetchone()
    # No score in this run is "not assessed", never a reassuring "Low" (brief B01).
    score_dict = (
        dict(score_row)
        if score_row
        else {"risk_index": None, "risk_band": "Not assessed in this run", "distinct_rules_triggered": 0,
              "classification_status": None, "coverage": None}
    )

    # Fetch findings
    cur.execute(
        """
        SELECT finding_id, rule_id, domain, severity, score, title, rationale, exception_id
        FROM findings
        WHERE entity_id = ? AND run_id = ?
        ORDER BY score DESC
    """,
        (entity_id, run_id),
    )
    findings = [dict(r) for r in cur.fetchall()]

    # Fetch domain scores for radar
    cur.execute(
        "SELECT domain, score FROM domain_scores WHERE entity_id = ? AND run_id = ?",
        (entity_id, run_id),
    )
    dom_scores = {r["domain"]: r["score"] for r in cur.fetchall()}
    radar_domains = [
        "Threat Detection",
        "Investigation",
        "Escalation",
        "Incident Response",
        "Security Operations",
        "Governance and Oversight",
        "Operational Discipline",
        "Cyber Resilience",
    ]
    # "-" is ECharts' missing value: a domain that could not be assessed is not drawn as 0.
    radar_entity_vals = [
        "-" if d in dom_scores and dom_scores[d] is None else dom_scores.get(d, 0.0) for d in radar_domains
    ]
    cohort = sqlite_store.get_peer_comparison(run_id, entity_id) if run_id else None
    radar_peer_vals, peer_label = _peer_median_domain_scores(
        duckdb_store, cur, entity_id, run_id, radar_domains, cohort
    )
    kpi_comparison = _kpi_reconciliation(duckdb_store, entity_id)
    # The stored band can be higher than the index alone gives (band_floors in scoring.yaml).
    band_note = ""
    if score_row:
        index_band = ScoringEngine().classify_risk_band(float(score_row["risk_index"]))
        if index_band != score_row["risk_band"]:
            band_note = (
                f"The risk index alone would be “{index_band}”. The band is raised because this entity "
                "has a critical or high severity finding (band_floors in config/scoring.yaml)."
            )
    kpi_gap_threshold = float(
        _load_rules_config()["rules"].get("EG10", {}).get("params", {}).get("mttr_gap_ratio_threshold", 0.60)
    )
    anomaly_leads = _display_signals(sqlite_store.get_anomaly_signals(run_id, entity_id))
    from satsa.context import build_contexts, entity_context_records

    entity_ctx = build_contexts([Entity(**entity_dict)], duckdb_store)[entity_id]
    context_records = entity_context_records(sqlite_store, entity_id)
    rule_ids = [r.id for r in RuleRegistry().get_all_rules()]
    excepted = {f["finding_id"] for f in findings if f.get("exception_id")}

    duckdb_store.close()
    sqlite_store.close()

    return templates.TemplateResponse(
        request=request,
        name="entity_profile.html",
        context={
            "active_tab": "portfolio",
            "entity": entity_dict,
            "score": score_dict,
            "findings": findings,
            "radar_domains": radar_domains,
            "radar_entity_vals": radar_entity_vals,
            "radar_peer_vals": radar_peer_vals,
            "peer_label": peer_label,
            "band_note": band_note,
            "kpi_comparison": kpi_comparison,
            "kpi_gap_threshold": kpi_gap_threshold,
            "anomaly_leads": anomaly_leads,
            "run": dict(run_row) if run_row else None,
            "cohort": cohort,
            "entity_ctx": entity_ctx,
            "context_records": context_records,
            "rule_ids": rule_ids,
            "excepted": excepted,
            "viewer": identity,
        },
    )


def _display_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Anomaly signals with their value and baseline formatted on the metric's own scale."""
    for sig in signals:
        scale = sig.get("detail", {}).get("scale", "per_unit")
        sig["value_display"] = format_metric_value(sig["value"], scale)
        sig["baseline_display"] = format_metric_value(sig["baseline"], scale)
    return signals


MIN_PEERS_FOR_MEDIAN = 3


def _peer_median_domain_scores(
    duckdb_store: DuckDBStore,
    cur: Any,
    entity_id: str,
    run_id: str,
    domains: list[str],
    cohort: dict[str, Any] | None = None,
) -> tuple[list[float | str] | None, str]:
    """Median domain score of the entity's peer cohort in this run.

    The cohort is the one the run recorded (peer_comparisons). Runs recorded before cohorts were
    stored fall back to resolving it from today's entity table, and the label says so.
    Returns (None, reason) when the cohort is too small for a median that does not
    simply reveal one or two peers' scores.
    """
    if not run_id:
        return None, "no peer group"
    if cohort is not None:
        peers, cohort_label = list(cohort["member_ids"]), f"{cohort['cohort_label']}, {cohort['strength']}"
    else:
        all_entities = [Entity(**row) for row in duckdb_store.query("SELECT * FROM entity").iter_rows(named=True)]
        target = next((e for e in all_entities if e.entity_id == entity_id), None)
        if target is None:
            return None, "no peer group"
        peers, label, _is_weak = PeerResolver().resolve_peers(target, all_entities)
        cohort_label = f"{label}, re-derived from current data: not recorded for this run"
    if len(peers) < MIN_PEERS_FOR_MEDIAN:
        return None, f"fewer than {MIN_PEERS_FOR_MEDIAN} peers"
    placeholders = ",".join("?" for _ in peers)
    cur.execute(
        f"SELECT entity_id, domain, score FROM domain_scores WHERE run_id = ? AND entity_id IN ({placeholders})",
        (run_id, *peers),
    )
    by_domain: dict[str, dict[str, float | None]] = {}
    for r in cur.fetchall():
        by_domain.setdefault(r["domain"], {})[r["entity_id"]] = None if r["score"] is None else float(r["score"])
    # A peer with no finding in a domain has no domain_scores row: that is a score of 0. A peer
    # whose domain could not be assessed (score None) is left out of that domain's median.
    medians: list[float | str] = []
    for d in domains:
        known = [v for p in peers if (v := by_domain.get(d, {}).get(p, 0.0)) is not None]
        medians.append(float(statistics.median(known)) if known else "-")
    return medians, f"{cohort_label} ({len(peers)} peers)"


def _selected_run(sqlite_store: SQLiteStore, run_id: str | None) -> Any:
    """The run a page or report shows: `run_id` if given (404 if unknown), else the latest."""
    if run_id:
        row = sqlite_store.conn.execute(
            "SELECT run_id, period, config_hash, fingerprint, created_at FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Assessment run not found")
        return row
    return sqlite_store.conn.execute(
        "SELECT run_id, period, config_hash, fingerprint, created_at FROM runs ORDER BY created_at DESC LIMIT 1"
    ).fetchone()


def _kpi_reconciliation(duckdb_store: DuckDBStore, entity_id: str) -> list[dict[str, Any]]:
    """Declared vs recomputed MTTR per declared High/Critical severity (EG10's comparison)."""
    df = duckdb_store.query(
        """
        WITH declared AS (
            SELECT lower(severity) AS severity, avg(value) AS declared
            FROM declared_kpi
            WHERE entity_id = ? AND upper(metric) = 'MTTR' AND lower(severity) IN ('high', 'critical')
            GROUP BY lower(severity)
        ),
        empirical AS (
            SELECT severity_final AS severity, avg(epoch(closed_at) - epoch(created_at)) / 60.0 AS empirical
            FROM alert
            WHERE entity_id = ? AND severity_final IN ('high', 'critical') AND closed_at >= created_at
            GROUP BY severity_final
        )
        SELECT d.severity, d.declared, e.empirical
        FROM declared d JOIN empirical e ON d.severity = e.severity
        ORDER BY d.severity DESC
        """,
        [entity_id, entity_id],
    )
    return [
        {
            "metric": "MTTR",
            "severity": r["severity"],
            "declared": round(r["declared"], 1),
            "empirical": round(r["empirical"], 1),
            "gap_ratio": (r["empirical"] - r["declared"]) / max(r["declared"], 1.0),
        }
        for r in df.iter_rows(named=True)
    ]


def _rule_parameters(rule_id: str, rules_snapshot: str | None = None) -> dict[str, Any]:
    """The rule's parameters (defaults included): as the run's recorded configuration set them
    when it has a snapshot, else as the current configuration sets them."""
    if rules_snapshot is not None:
        rule = RuleRegistry.from_yaml_text(rules_snapshot).get_rule(rule_id)
    else:
        rule = RuleRegistry(RULES_CONFIG_PATH).get_rule(rule_id) if RULES_CONFIG_PATH.exists() else None
    return dict(rule.params) if rule is not None else {}


def _current_config_hashes() -> list[str]:
    """Hashes the current configuration has under each scheme a run may have recorded: the
    result-affecting configuration (scoring.fingerprint.config_hash) first, then
    config/rules.yaml alone (runs recorded before configuration snapshots existed)."""
    from satsa.scoring.fingerprint import config_hash, config_snapshot

    if not RULES_CONFIG_PATH.exists():
        return []
    folder = RULES_CONFIG_PATH.parent
    paths = {"rules": RULES_CONFIG_PATH, **{k: folder / f"{k}.yaml" for k in ("scoring", "peers", "systemic", "anomaly")}}
    return [
        config_hash(config_snapshot(paths)),
        hashlib.sha256(RULES_CONFIG_PATH.read_bytes()).hexdigest()[:16],
    ]


def _config_status(run_config_hash: str | None, recorded: bool = False) -> dict[str, Any]:
    """Whether the configuration now is the one the run used, and where the shown values come from.

    `recorded`: the run stored a full snapshot of its configuration, so the page shows the
    values the run applied whatever has changed since. Runs recorded before snapshots existed
    kept only a hash; for them the current values are shown, with a warning when they differ.
    """
    current = _current_config_hashes()
    return {
        "run_hash": run_config_hash,
        "current_hash": current[0] if current else None,
        "unchanged": run_config_hash is not None and run_config_hash in current,
        "recorded": recorded,
    }


@app.get("/finding/{finding_id}", response_class=HTMLResponse, dependencies=[Depends(require_authenticated)])
async def view_finding_detail(request: Request, finding_id: str) -> Response:
    sqlite_store = get_sqlite_store()
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
    f_row = cur.fetchone()
    if not f_row:
        sqlite_store.close()
        raise HTTPException(status_code=404, detail="Finding not found")
    viewer = get_current_identity(request)
    if viewer:
        try:
            require_cse_access(f_row["entity_id"], viewer)
        except HTTPException:
            sqlite_store.close()
            raise

    cur.execute(
        "SELECT record_type, record_id, details_json FROM finding_evidences WHERE finding_id = ?",
        (finding_id,),
    )
    ev_rows = cur.fetchall()
    evidences = [
        {
            "record_type": r["record_type"],
            "record_id": r["record_id"],
            **json.loads(r["details_json"] or "{}"),
        }
        for r in ev_rows
    ]
    # The configuration the run recorded (runs before snapshots existed have none).
    rules_snapshot = sqlite_store.get_config_snapshot(f_row["run_id"]).get("rules", {}).get("content")

    card = FindingCard(
        finding_id=f_row["finding_id"],
        run_id=f_row["run_id"],
        entity_id=f_row["entity_id"],
        rule_id=f_row["rule_id"],
        rule_version=f_row["rule_version"],
        rule_name=f_row["title"],
        domain=f_row["domain"],
        score=f_row["score"],
        confidence=f_row["confidence"],
        severity=f_row["severity"],
        title=f_row["title"],
        rationale=f_row["rationale"],
        why_it_matters=WHY_IT_MATTERS.get(f_row["rule_id"], ""),
        peer_comparison=json.loads(f_row["peer_comparison_json"] or "{}"),
        parameters_used=_rule_parameters(f_row["rule_id"], rules_snapshot),
        limitations=f_row["limitations"]
        or "Evaluated on ingested metadata; raw payload inspection not performed.",
        benign_explanations=json.loads(f_row["benign_explanations_json"] or "[]"),
        examiner_check=f_row["examiner_check"],
        evidence_records=evidences,
    )
    cur.execute("SELECT config_hash FROM runs WHERE run_id = ?", (card.run_id,))
    run_row = cur.fetchone()
    config_status = _config_status(run_row["config_hash"] if run_row else None, recorded=rules_snapshot is not None)
    identity = get_current_identity(request)
    if identity:
        sqlite_store.record_live_event(
            "FINDING_VIEWED",
            actor=identity.username,
            role=identity.role,
            entity_id=card.entity_id,
            details={"finding_id": finding_id, "rule_id": card.rule_id, "title": card.title},
        )
    # The supervisory case of this concern (entity and rule), open or most recently closed.
    from satsa.cases.workflow import STATE_LABELS, case_for_lineage

    case = case_for_lineage(sqlite_store, card.entity_id, card.rule_id)
    # What the rule had to work with, the cohort the run recorded, and any exception it was
    # recorded under -- all as of this finding's run, never re-derived from today's data.
    support = cur.execute(
        "SELECT population, min_sample, state FROM rule_results WHERE run_id = ? AND entity_id = ? AND rule_id = ?",
        (card.run_id, card.entity_id, card.rule_id),
    ).fetchone()
    cohort = sqlite_store.get_peer_comparison(card.run_id, card.entity_id)
    exception = (
        cur.execute("SELECT * FROM rule_exceptions WHERE exception_id = ?", (f_row["exception_id"],)).fetchone()
        if f_row["exception_id"] else None
    )
    sqlite_store.close()

    return templates.TemplateResponse(
        request=request,
        name="finding_detail.html",
        context={"active_tab": "portfolio", "card": card, "config": config_status, "case": case,
                 "case_state_labels": STATE_LABELS, "support": dict(support) if support else None,
                 "cohort": cohort, "exception": dict(exception) if exception else None},
    )


# Examiner dispositions the review queue can be filtered by, in the order the filter shows them.
QUEUE_STATUS_FILTERS: dict[str, str] = {
    "pending": "Pending Review",
    "confirmed": "Confirmed concern",
    "not_an_issue": "Marked as Justified",
    "needs_more_data": "More data needed",
}
# The most queue rows one page shows, highest score first.
QUEUE_PAGE_ROWS = 200


def _queue_status(value: str | None) -> str:
    """A known disposition, or "" for the whole queue."""
    return value if value in QUEUE_STATUS_FILTERS else ""


@app.get("/queue", response_class=HTMLResponse, dependencies=[Depends(require_authenticated)])
async def view_review_queue(request: Request, status: str | None = None) -> Response:
    status_filter = _queue_status(status)
    sqlite_store = get_sqlite_store()
    cur = sqlite_store.conn.cursor()
    # Every run saves a full queue; the examiner works the latest one. Earlier runs' copies
    # of the same records are history (a new run keeps their decisions: save_review_queue).
    run_id = _latest_run_id(sqlite_store)
    cur.execute(
        "SELECT examiner_status, COUNT(*) AS n FROM review_queue WHERE run_id = ? GROUP BY examiner_status",
        (run_id,),
    )
    status_counts = {key: 0 for key in QUEUE_STATUS_FILTERS}
    for r in cur.fetchall():
        status_counts[r["examiner_status"]] = r["n"]
    status_counts[""] = sum(status_counts.values())
    # The stat cards count the whole queue, like the filter, not just the rows the page shows.
    cur.execute("SELECT COUNT(*) FROM review_queue WHERE run_id = ? AND is_random", (run_id,))
    random_count = cur.fetchone()[0]

    # The filter goes in the query, so the row limit applies to the disposition asked for.
    cur.execute(
        f"""
        SELECT queue_id, run_id, entity_id, record_type, record_id, severity, score, selection_reason, is_random, examiner_status
        FROM review_queue
        WHERE run_id = ? {"AND examiner_status = ?" if status_filter else ""}
        ORDER BY score DESC, queue_id ASC
        LIMIT {QUEUE_PAGE_ROWS}
        """,
        (run_id, status_filter) if status_filter else (run_id,),
    )
    queue_items = [dict(r, evidence_cards=[]) for r in cur.fetchall()]

    # The evidence cards of the findings that cite each record, from the same run and entity.
    # A random control is cited by none: it was drawn regardless of the findings.
    if queue_items:
        by_id = {item["queue_id"]: item for item in queue_items}
        cur.execute(
            f"""
            SELECT q.queue_id, f.finding_id, f.rule_id, f.title
            FROM review_queue q
            JOIN finding_evidences e ON e.record_type = q.record_type AND e.record_id = q.record_id
            JOIN findings f ON f.finding_id = e.finding_id AND f.run_id = q.run_id AND f.entity_id = q.entity_id
            WHERE q.queue_id IN ({", ".join("?" for _ in by_id)})
            ORDER BY f.score DESC, f.rule_id ASC
            """,
            list(by_id),
        )
        for r in cur.fetchall():
            by_id[r["queue_id"]]["evidence_cards"].append(
                {"finding_id": r["finding_id"], "rule_id": r["rule_id"], "title": r["title"]}
            )
    # Each entity's evidence coverage in this run, so a record is read with its limits.
    entity_evidence = {
        r["entity_id"]: {"status": r["classification_status"], "text": coverage_sentence(dict(r))}
        for r in cur.execute("SELECT * FROM entity_scores WHERE run_id = ?", (run_id,))
    }
    sqlite_store.close()

    return templates.TemplateResponse(
        request=request,
        name="review_queue.html",
        context={
            "active_tab": "queue",
            "entity_evidence": entity_evidence,
            "queue_items": queue_items,
            "status_filter": status_filter,
            "status_filters": QUEUE_STATUS_FILTERS,
            "status_counts": status_counts,
            "random_count": random_count,
            "run_id": run_id,
        },
    )


@app.get("/dq", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def view_dq_coverage(request: Request) -> Response:
    sqlite_store = get_sqlite_store()
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT * FROM dq_issues ORDER BY count DESC")
    dq_issues = [
        {
            "issue_id": r["issue_id"],
            "entity_id": r["entity_id"],
            "check_name": r["check_name"],
            "severity": r["severity"],
            "count": r["count"],
            "details": r["details"],
            "sample_records": json.loads(r["sample_records_json"] or "[]"),
        }
        for r in cur.fetchall()
    ]
    total_count = sum(i["count"] for i in dq_issues)
    error_count = sum(1 for i in dq_issues if i["severity"] == "error")
    warning_count = sum(1 for i in dq_issues if i["severity"] != "error")
    affected_entities = len({i["entity_id"] for i in dq_issues})

    return templates.TemplateResponse(
        request=request,
        name="dq_coverage.html",
        context={
            "active_tab": "dq",
            "dq_issues": dq_issues,
            "total_records_affected": total_count,
            "error_count": error_count,
            "warning_count": warning_count,
            "affected_entities": affected_entities,
        },
    )


@app.get("/audit", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
@app.get("/runs", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def view_runs_audit(request: Request) -> Response:
    sqlite_store = get_sqlite_store()
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT * FROM runs ORDER BY created_at DESC")
    runs = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM audit_log ORDER BY rowid DESC LIMIT 100")
    audit_entries = [dict(r) for r in cur.fetchall()]

    ok, msg = sqlite_store.verify_audit_chain()
    sqlite_store.close()

    latest_hash = audit_entries[0]["curr_hash"] if audit_entries else "GENESIS_INITIALIZED"

    return templates.TemplateResponse(
        request=request,
        name="runs_audit.html",
        context={
            "active_tab": "audit",
            "runs": runs,
            "audit_entries": audit_entries,
            "audit_ok": ok,
            "audit_msg": msg,
            "latest_hash": latest_hash,
        },
    )


SHADOW_REQUIRED_COLUMNS = {"entity_id", "record_id", "rule_id", "label"}
SHADOW_MAX_BYTES = 5 * 1024 * 1024


@app.get("/shadow-pilot", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def view_shadow_pilot(request: Request, message: str = "") -> Response:
    sqlite_store = get_sqlite_store()
    row = sqlite_store.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
    history = sqlite_store.list_shadow_results(limit=20)
    sqlite_store.close()
    return templates.TemplateResponse(
        request=request,
        name="shadow_pilot.html",
        context={
            "active_tab": "shadow_pilot",
            "message": message,
            "latest_run_id": row["run_id"] if row else None,
            "history": history,
            "latest": history[0] if history else None,
        },
    )


@app.post("/shadow-pilot")
def handle_shadow_pilot(
    workpaper: UploadFile = File(...),
    identity: Identity = Depends(require_role(*ANALYST_ROLES)),
) -> Response:
    """Evaluate a historical examiner workpaper CSV against the latest assessment run."""
    import urllib.parse

    from satsa.validate.harness import ShadowPilotAdapter

    def done(msg: str) -> RedirectResponse:
        return RedirectResponse(url=f"/shadow-pilot?message={urllib.parse.quote_plus(msg)}", status_code=303)

    raw = workpaper.file.read(SHADOW_MAX_BYTES + 1)
    if len(raw) > SHADOW_MAX_BYTES:
        return done("Error: workpaper larger than 5 MB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return done("Error: workpaper must be a UTF-8 CSV file.")
    header = next(csv.reader(io.StringIO(text)), [])
    missing = SHADOW_REQUIRED_COLUMNS - {h.strip().lower() for h in header}
    if missing:
        return done(f"Error: workpaper is missing column(s): {', '.join(sorted(missing))}.")

    source_name = Path((workpaper.filename or "workpaper.csv").replace("\\", "/")).name
    sqlite_store = get_sqlite_store()
    try:
        row = sqlite_store.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
        if row is None:
            return done("Error: no assessment run yet. Run an assessment before a shadow-pilot evaluation.")
        run_id = row["run_id"]
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "workpaper.csv"
            csv_path.write_text(text, encoding="utf-8")
            adapter = ShadowPilotAdapter(sqlite_store)
            result = adapter.evaluate_shadow_pilot(adapter.load_manual_reviews(csv_path), run_id)
        if result.get("status") != "success":
            return done("Error: the workpaper has no rows to evaluate.")
        sqlite_store.save_shadow_result(run_id, identity.username, source_name, result)
        sqlite_store.append_audit(
            action="shadow_pilot_evaluated",
            actor=identity.username,
            details={
                "run_id": run_id,
                "source_name": source_name,
                "total_manual_reviews": result["total_manual_reviews"],
                "rule_finding_recall": result["rule_finding_recall"],
                "queue_record_recall": result["queue_record_recall"],
                "workpaper_precision": result["workpaper_precision"],
            },
        )
    finally:
        sqlite_store.close()
    return done(
        f"Evaluated {source_name} against {run_id}: finding recall "
        f"{result['rule_finding_recall'] * 100:.1f}%, queue record recall {result['queue_record_recall'] * 100:.1f}%, "
        f"precision {_pct_or_na(result['workpaper_precision'])}."
    )


def _pct_or_na(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


# --- REST API Endpoints ---


@app.get("/api/v1/runs", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def api_list_runs() -> list[dict[str, Any]]:
    sqlite_store = get_sqlite_store()
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT * FROM runs ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    sqlite_store.close()
    return rows


@app.get("/api/v1/entities", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def api_list_entities(run_id: str | None = None) -> list[dict[str, Any]]:
    """Entity scores of one run (default: the latest), with each entity's evidence coverage."""
    require_valid_run_id(run_id)
    duckdb_store, sqlite_store = get_stores()
    try:
        run_row = _selected_run(sqlite_store, run_id)
        df_ent = duckdb_store.query("SELECT entity_id, name, sector, size_band FROM entity")
        ent_map = {row["entity_id"]: row for row in df_ent.iter_rows(named=True)}
        cur = sqlite_store.conn.cursor()
        cur.execute(
            "SELECT * FROM entity_scores WHERE run_id = ? ORDER BY risk_index DESC, entity_id",
            (run_row["run_id"] if run_row else "",),
        )
        rows = []
        for r in cur.fetchall():
            eid = r["entity_id"]
            e_info = ent_map.get(eid, {"name": eid, "sector": "general", "size_band": "medium"})
            rows.append(
                {
                    "entity_id": eid,
                    "run_id": r["run_id"],
                    "name": e_info["name"],
                    "sector": e_info["sector"],
                    "risk_index": r["risk_index"],
                    "risk_band": r["risk_band"],
                    "distinct_rules_triggered": r["distinct_rules_triggered"],
                    "classification_status": r["classification_status"],
                    "coverage": r["coverage"],
                    "rules_applicable": r["rules_applicable"],
                    "rules_assessed": r["rules_assessed"],
                    "missing_inputs": json.loads(r["missing_inputs_json"] or "[]"),
                    "evidence": coverage_sentence(dict(r)),
                }
            )
    finally:
        duckdb_store.close()
        sqlite_store.close()
    return rows


@app.get("/api/v1/findings", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def api_list_findings(entity_id: str | None = None) -> list[dict[str, Any]]:
    sqlite_store = get_sqlite_store()
    cur = sqlite_store.conn.cursor()
    if entity_id:
        cur.execute("SELECT * FROM findings WHERE entity_id = ? ORDER BY score DESC", (entity_id,))
    else:
        cur.execute("SELECT * FROM findings ORDER BY score DESC")
    # A finding that leaves the tool as data still says what it is.
    rows = [{**dict(r), "supervisory_notice": FINDING_NOTICE} for r in cur.fetchall()]
    sqlite_store.close()
    return rows


def _latest_run_id(sqlite_store: SQLiteStore) -> str:
    row = sqlite_store.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
    return row["run_id"] if row else ""


@app.get("/api/v1/anomalies", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def api_list_anomalies(entity_id: str | None = None, run_id: str | None = None) -> list[dict[str, Any]]:
    """Exploratory anomaly signals (leads, not findings) of a run, the latest by default."""
    if entity_id:
        require_valid_entity_id(entity_id)
    sqlite_store = get_sqlite_store()
    try:
        signals = sqlite_store.get_anomaly_signals(run_id or _latest_run_id(sqlite_store), entity_id)
    finally:
        sqlite_store.close()
    return [{**sig, "supervisory_notice": FINDING_NOTICE} for sig in signals]


@app.get("/api/v1/priorities", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def api_priorities(run_id: str | None = None) -> dict[str, Any]:
    """Controls (rules) and processes (domains) ranked for manual review in a run."""
    sqlite_store = get_sqlite_store()
    try:
        rid = run_id or _latest_run_id(sqlite_store)
        controls = rank_controls(sqlite_store.conn, rid)
        processes = rank_processes(sqlite_store.conn, rid)
    finally:
        sqlite_store.close()
    return {
        "run_id": rid,
        "controls": [{**c, "supervisory_notice": FINDING_NOTICE} for c in controls],
        "processes": [{**p, "supervisory_notice": FINDING_NOTICE} for p in processes],
        "supervisory_notice": SUPERVISORY_NOTICE,
    }


@app.get("/api/v1/queue", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def api_get_queue(entity_id: str | None = None, run_id: str | None = None) -> list[dict[str, Any]]:
    """The queue of one run, the latest by default, like the queue page."""
    sqlite_store = get_sqlite_store()
    cur = sqlite_store.conn.cursor()
    rid = run_id or _latest_run_id(sqlite_store)
    if entity_id:
        cur.execute(
            "SELECT * FROM review_queue WHERE run_id = ? AND entity_id = ? ORDER BY score DESC",
            (rid, entity_id),
        )
    else:
        cur.execute("SELECT * FROM review_queue WHERE run_id = ? ORDER BY score DESC", (rid,))
    rows = [{**dict(r), "supervisory_notice": FINDING_NOTICE} for r in cur.fetchall()]
    sqlite_store.close()
    return rows


@app.post("/api/v1/feedback")
async def api_submit_feedback(
    queue_id: Annotated[str, Form()],
    status: Annotated[str, Form()],  # no default: a missing decision must not escalate
    notes: Annotated[str, Form()] = "",
    return_status: Annotated[str, Form()] = "",
    identity: Identity = Depends(require_role(*REVIEW_ROLES)),
) -> RedirectResponse:
    # Only a real decision on a record that is in the queue: anything else would be saved,
    # audited and reported as done while changing nothing, or leave the record in no filter.
    if status not in EXAMINER_DECISIONS:
        raise HTTPException(status_code=400, detail=f"Unknown decision {status!r}")
    sqlite_store = get_sqlite_store()
    known = sqlite_store.conn.execute(
        "SELECT 1 FROM review_queue WHERE queue_id = ?", (queue_id,)
    ).fetchone()
    if not known:
        sqlite_store.close()
        raise HTTPException(status_code=404, detail="No such queue record")

    examiner_id = identity.username
    feedback = ExaminerFeedback(
        feedback_id="", queue_id=queue_id, examiner_id=examiner_id, status=status, notes=notes
    )
    # One feedback row per submission: a decision made again later is a new entry in the
    # history, not an overwrite of the earlier one.
    feedback.feedback_id = hashlib.sha256(
        f"{queue_id}:{examiner_id}:{status}:{feedback.created_at.isoformat()}".encode()
    ).hexdigest()[:16]
    sqlite_store.save_feedback(feedback)
    sqlite_store.append_audit(
        action="feedback",
        actor=examiner_id,
        details={"queue_id": queue_id, "status": status, "notes": notes},
    )
    sqlite_store.close()
    # Back to the filtered view the decision was made from.
    back = _queue_status(return_status)
    return RedirectResponse(url=f"/queue?status={back}" if back else "/queue", status_code=303)


@app.get("/api/v1/audit/verify", dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def api_verify_audit() -> dict[str, Any]:
    sqlite_store = get_sqlite_store()
    ok, msg = sqlite_store.verify_audit_chain()
    sqlite_store.close()
    return {"verified": ok, "message": msg}


@app.get("/api/v1/export/queue.csv", dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def api_export_queue_csv() -> Response:
    sqlite_store = get_sqlite_store()
    cur = sqlite_store.conn.cursor()
    cur.execute(
        "SELECT * FROM review_queue WHERE run_id = ? ORDER BY score DESC",
        (_latest_run_id(sqlite_store),),
    )
    rows = cur.fetchall()
    sqlite_store.close()

    output = io.StringIO()
    writer = SafeWriter(output)
    if rows:
        writer.writerow([*rows[0].keys(), "supervisory_notice"])
        for r in rows:
            writer.writerow([*r, FINDING_NOTICE])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=review_queue.csv"},
    )


# --- Production Features: Alert Explorer, Ingest Wizard, Blind Review, Tuning & Direct Reports ---


@app.get("/alerts", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def view_alerts(
    request: Request,
    q: str = "",
    entity: str = "",
    severity: str = "",
    actor_type: str = "",
    page: int = 1,
) -> Response:
    duckdb_store, sqlite_store = get_stores()

    # Query entities for filter dropdown
    df_ents = duckdb_store.query("SELECT entity_id FROM entity ORDER BY entity_id")
    all_entities = [r["entity_id"] for r in df_ents.iter_rows(named=True)]

    # Build filtered DuckDB query. Every user-supplied value is bound as a
    # parameter; only fixed clause text is joined into the SQL string.
    if entity:
        require_valid_entity_id(entity)
    where_clauses = ["1=1"]
    where_params: list[Any] = []
    if entity:
        where_clauses.append("entity_id = ?")
        where_params.append(entity)
    if severity:
        where_clauses.append("severity_final = ?")
        where_params.append(severity)
    if actor_type:
        where_clauses.append("closed_by_type = ?")
        where_params.append(actor_type)
    if q:
        like_q = f"%{q}%"
        where_clauses.append("(alert_id LIKE ? OR rule_id LIKE ? OR asset_id LIKE ?)")
        where_params.extend([like_q, like_q, like_q])

    where_sql = " AND ".join(where_clauses)

    # Count total matching for pagination
    page_size = 25
    total_matching_df = duckdb_store.query(
        f"SELECT count(*) as count FROM alert WHERE {where_sql}", where_params
    )
    total_matching = total_matching_df.to_dicts()[0]["count"]
    total_pages = max(1, (total_matching + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    offset = (page - 1) * page_size

    df_alerts = duckdb_store.query(f"""
        SELECT alert_id, entity_id, rule_id, severity_final, disposition,
               closed_by_type, created_at, closed_at,
               ROUND(epoch(closed_at - created_at) / 60.0, 1) as duration_min
        FROM alert
        WHERE {where_sql}
        ORDER BY created_at DESC
        LIMIT {int(page_size)} OFFSET {int(offset)}
    """, where_params)

    alerts_list = []
    for r in df_alerts.iter_rows(named=True):
        dur = r.get("duration_min")
        dur_str = f"{dur} min" if dur is not None else "In Progress"
        alerts_list.append({**r, "duration_str": dur_str})

    start_item = offset + 1 if total_matching > 0 else 0
    end_item = min(offset + page_size, total_matching)

    # High-level stats
    stats_df = duckdb_store.query("""
        SELECT
            count(*) as total,
            count(CASE WHEN severity_final IN ('high', 'critical') THEN 1 END) as high_crit,
            count(CASE WHEN closed_by_type = 'soar' THEN 1 END) as soar_count,
            count(CASE WHEN disposition = 'false_positive' THEN 1 END) * 100.0 / greatest(count(*), 1) as fp_rate
        FROM alert
    """).to_dicts()[0]

    duckdb_store.close()
    sqlite_store.close()

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "active_tab": "alerts",
            "alerts": alerts_list,
            "all_entities": all_entities,
            "total_alerts": stats_df.get("total", 0),
            "high_crit_count": stats_df.get("high_crit", 0),
            "soar_count": stats_df.get("soar_count", 0),
            "fp_rate": round(stats_df.get("fp_rate", 0.0), 1),
            "q": q,
            "entity_filter": entity,
            "sev_filter": severity,
            "actor_filter": actor_type,
            "page": page,
            "total_pages": total_pages,
            "total_matching": total_matching,
            "start_item": start_item,
            "end_item": end_item,
        },
    )


@app.get("/upload", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def view_upload(request: Request, message: str = "") -> Response:
    duckdb_store, sqlite_store = get_stores()
    cur = sqlite_store.conn.cursor()
    cur.execute(
        "SELECT log_id, ts, action, actor, curr_hash FROM audit_log ORDER BY rowid DESC LIMIT 8"
    )
    recent_batches = [dict(r) for r in cur.fetchall()]

    # Fetch all registered entities
    df_ent = duckdb_store.query(
        "SELECT entity_id, name, sector, size_band FROM entity ORDER BY entity_id"
    )
    all_entities = [dict(r) for r in df_ent.iter_rows(named=True)] if not df_ent.is_empty() else []

    duckdb_store.close()
    sqlite_store.close()

    from satsa.store.catalog import Catalog

    catalog = Catalog("data")
    try:
        submissions = catalog.batches(limit=15)
        held_batches = [b for b in catalog.batches(limit=500) if b["state"] == "held"]
    finally:
        catalog.close()

    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context={
            "active_tab": "upload",
            "message": message,
            "recent_batches": recent_batches,
            "all_entities": all_entities,
            "submissions": submissions,
            "held_batches": held_batches,
            "retired_entities": _retired_entities(),
        },
    )


def _retired_entities() -> set[str]:
    store = get_sqlite_store()
    try:
        return store.retired_entities()
    finally:
        store.close()


BATCH_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _held_batch_decision(batch_id: str, actor: str, publish: bool) -> str:
    if not BATCH_ID_RE.match(batch_id):
        return "Error: invalid batch id"
    duckdb_store = DuckDBStore("data")
    sqlite_store = SQLiteStore("data/satsa.db")
    try:
        if publish:
            pub_seq = duckdb_store.catalog.publish_held(batch_id, actor=actor)
        else:
            duckdb_store.catalog.discard_held(batch_id, actor=actor)
        sqlite_store.append_audit(
            action="batch_published_after_review" if publish else "batch_discarded_after_review",
            actor=actor,
            details={"batch_id": batch_id, **({"pub_seq": pub_seq} if publish else {})},
        )
    except PublicationError as exc:
        return f"Error: {exc}"
    finally:
        duckdb_store.close()
        sqlite_store.close()
    return (
        f"Batch {batch_id} published."
        if publish
        else f"Batch {batch_id} discarded; nothing of it was stored."
    )


@app.post("/batches/{batch_id}/publish")
def publish_held_batch(batch_id: str, identity: Identity = Depends(require_role(*INGEST_RUN_ROLES))) -> Response:
    """Publish a submission that was held for review, as it is (its rejected rows stay out), and
    queue an assessment that includes it."""
    msg = _held_batch_decision(batch_id, identity.username, publish=True)
    if not msg.startswith("Error"):
        duckdb_store = DuckDBStore("data")
        sqlite_store = get_sqlite_store()
        try:
            batch = duckdb_store.catalog.batch(batch_id) or {}
            period = batch.get("period_label") or _latest_period(sqlite_store)
        finally:
            duckdb_store.close()
            sqlite_store.close()
        job = enqueue_assessment(period, identity, f"held batch {batch_id} published")
        msg += f" Assessment queued as job {job['job_id']} (see Jobs)."
    return RedirectResponse(url=f"/upload?message={msg}", status_code=303)


@app.post("/batches/{batch_id}/discard")
def discard_held_batch(batch_id: str, identity: Identity = Depends(require_role(*INGEST_RUN_ROLES))) -> Response:
    """Discard a submission that was held for review: nothing of it is ever published."""
    msg = _held_batch_decision(batch_id, identity.username, publish=False)
    return RedirectResponse(url=f"/upload?message={msg}", status_code=303)


@app.post("/upload/add-entity")
def handle_add_entity(
    entity_id: Annotated[str, Form()],
    name: Annotated[str, Form()],
    sector: Annotated[str, Form()],
    size_band: Annotated[str, Form()],
    declared_mtta: Annotated[float, Form()] = 15.0,
    declared_mttr: Annotated[float, Form()] = 60.0,
    declared_sla: Annotated[float, Form()] = 95.0,
    custom_sector: Annotated[str | None, Form()] = None,
    identity: Identity = Depends(require_role(*INGEST_RUN_ROLES)),
) -> Response:
    clean_id = entity_id.strip().upper()
    if not clean_id:
        return RedirectResponse(
            url="/upload?message=Error:+Entity+ID+cannot+be+empty", status_code=303
        )
    if not is_valid_entity_id(clean_id):
        return RedirectResponse(
            url="/upload?message=Error:+Entity+ID+may+only+contain+letters,+digits,+'.',+'_'+and+'-'",
            status_code=303,
        )

    # If "Other" sector was selected, use the custom sector text
    resolved_sector = sector.strip()
    if resolved_sector.lower() == "other" and custom_sector and custom_sector.strip():
        resolved_sector = custom_sector.strip()
    elif not resolved_sector:
        resolved_sector = "General Infrastructure"

    duckdb_store, sqlite_store = get_write_stores()

    # 1. Insert into entity table and parquet
    ent_df = pl.DataFrame(
        [
            {
                "entity_id": clean_id,
                "name": name.strip() or f"{clean_id} Critical Infrastructure",
                "sector": resolved_sector,
                "size_band": size_band.strip() or "Medium",
            }
        ]
    )
    duckdb_store.write_partitioned_parquet("entity", ent_df)

    # 1b. Insert into SQLite entities table for persistent storage across runs
    cur = sqlite_store.conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO entities (entity_id, name, sector, size_band) VALUES (?, ?, ?, ?)",
        (
            clean_id,
            name.strip() or f"{clean_id} Critical Infrastructure",
            resolved_sector,
            size_band.strip() or "Medium",
        ),
    )
    sqlite_store.conn.commit()

    # 2. Insert into declared_kpi table
    kpi_rows = [
        {
            "entity_id": clean_id,
            "period": "2026-Q1",
            "metric": "MTTA",
            "severity": "all",
            "value": float(declared_mtta),
        },
        {
            "entity_id": clean_id,
            "period": "2026-Q1",
            "metric": "MTTR",
            "severity": "all",
            "value": float(declared_mttr),
        },
        {
            "entity_id": clean_id,
            "period": "2026-Q1",
            "metric": "sla_compliance",
            "severity": "all",
            "value": float(declared_sla),
        },
    ]
    kpi_df = pl.DataFrame(kpi_rows)
    duckdb_store.write_partitioned_parquet("declared_kpi", kpi_df)

    # 3. Log to cryptographic audit log
    sqlite_store.append_audit(
        action="register_entity",
        actor=identity.username,
        details={
            "entity_id": clean_id,
            "name": name,
            "sector": resolved_sector,
            "size_band": size_band,
            "declared_mtta": declared_mtta,
            "declared_mttr": declared_mttr,
            "declared_sla": declared_sla,
        },
    )

    # 4. Queue an assessment to establish the baseline
    period = _latest_period(sqlite_store)
    duckdb_store.close()
    sqlite_store.close()
    job = enqueue_assessment(period, identity, f"entity {clean_id} registered", clean_id)

    msg = (f"Entity {clean_id} successfully registered! Sector: {resolved_sector} | "
           f"Assessment queued as job {job['job_id']}")
    return RedirectResponse(url=f"/upload?message={msg}", status_code=303)


@app.post("/upload/delete-entity/{entity_id}")
async def handle_delete_entity(
    entity_id: str, identity: Identity = Depends(require_role(*INGEST_RUN_ROLES))
) -> Response:
    """Retire an entity: leave it out of future assessments and queue a re-assessment.

    Nothing is erased. Its published submissions, past runs, findings, scores and review history
    stay (brief section 10: ordinary deletion must not silently erase historical evidence); a
    retirement can be undone with `satsa entity reinstate`. Until Phase 2 this route deleted the
    entity's findings and scores from every run and removed its Parquet partitions."""
    clean_id = require_valid_entity_id(entity_id.strip().upper())
    sqlite_store = get_sqlite_store()
    try:
        retired = sqlite_store.retire_entity(clean_id, identity.username, "retired from the upload page")
        period = _latest_period(sqlite_store)
    finally:
        sqlite_store.close()
    if not retired:
        return RedirectResponse(url=f"/upload?message=Error:+{clean_id}+is+already+retired.", status_code=303)
    job = enqueue_assessment(period, identity, f"entity {clean_id} retired")
    msg = (f"Entity {clean_id} retired: it is left out of future assessments; its submissions, runs and "
           f"findings are kept. Re-assessment queued as job {job['job_id']}.")
    return RedirectResponse(url=f"/upload?message={msg}", status_code=303)


@app.get("/templates/{template_name}", dependencies=[Depends(require_role(*ANALYST_ROLES))])
def download_template(template_name: str) -> Response:
    """Generate and serve canonical CSV schema templates or sample zip bundle."""
    templates_dir = Path("data/templates")
    templates_dir.mkdir(parents=True, exist_ok=True)

    t_name = template_name.lower().removesuffix(".csv").removesuffix(".zip")
    # Allow-list: the name is used to build a file path, so only known template
    # names are accepted (anything else, e.g. "..\\..\\x", is a 404).
    is_bundle = t_name in ("bundle", "canonical_soc_submission_bundle", "canonical_soc_telemetry_bundle")
    if not is_bundle and t_name not in TEMPLATE_CSV_CONTENT:
        raise HTTPException(status_code=404, detail="Unknown template.")

    if is_bundle:
        zip_path = templates_dir / "canonical_soc_submission_bundle.zip"
        with zipfile.ZipFile(zip_path, "w") as z:
            alert_csv = "alert_id,entity_id,rule_id,category,severity_orig,severity_final,asset_id,created_at,acknowledged_at,closed_at,closed_by,closed_by_type,disposition,status\nALT-001,CSE-DEMO,DET-BRUTE-FORCE,Credential Access,high,high,SRV-AUTH-01,2026-01-15T08:30:00Z,2026-01-15T08:35:00Z,2026-01-15T09:15:00Z,analyst_sharma,human,true_positive,closed\nALT-002,CSE-DEMO,DET-PORT-SCAN,Discovery,medium,low,SRV-WEB-02,2026-01-15T10:00:00Z,2026-01-15T10:01:00Z,2026-01-15T10:02:00Z,soar_bot,soar,false_positive,closed\n"
            z.writestr("alerts.csv", alert_csv)

            case_csv = "case_id,entity_id,alert_id,severity,status,opened_at,resolved_at,lead_analyst_id,root_cause\nCAS-001,CSE-DEMO,ALT-001,high,resolved,2026-01-15T08:40:00Z,2026-01-15T09:15:00Z,analyst_sharma,Compromised service account credential brute forced\n"
            z.writestr("cases.csv", case_csv)

            asset_csv = "asset_id,entity_id,asset_type,criticality,zone,is_monitored\nSRV-AUTH-01,CSE-DEMO,server,4,dmz,true\nSRV-WEB-02,CSE-DEMO,server,3,internal,true\n"
            z.writestr("assets.csv", asset_csv)

            closure_csv = "closure_id,record_id,entity_id,closed_by_type,comment,duration_seconds,disposition\nCLS-001,ALT-001,CSE-DEMO,human,Malicious credential brute-force contained and account password reset.,2700,true_positive\n"
            z.writestr("closures.csv", closure_csv)

        return FileResponse(
            zip_path,
            filename="canonical_soc_submission_bundle.zip",
            media_type="application/zip",
        )

    content = TEMPLATE_CSV_CONTENT[t_name]
    csv_file = templates_dir / f"{t_name}.csv"
    csv_file.write_text(content, encoding="utf-8")
    return FileResponse(csv_file, filename=f"{t_name}_template.csv", media_type="text/csv")


TEMPLATE_CSV_CONTENT: dict[str, str] = {
    "alerts": (
        "alert_id,entity_id,rule_id,category,severity_orig,severity_final,asset_id,created_at,acknowledged_at,closed_at,closed_by,closed_by_type,disposition,status\n"
        "ALT-001,CSE-01,DET-01,Threat Detection,high,high,ASSET-01,2026-01-15T08:30:00Z,2026-01-15T08:35:00Z,2026-01-15T09:15:00Z,analyst_1,human,true_positive,closed\n"
    ),
    "cases": (
        "case_id,entity_id,alert_id,severity,status,opened_at,resolved_at,lead_analyst_id,root_cause\n"
        "CAS-001,CSE-01,ALT-001,high,resolved,2026-01-15T08:40:00Z,2026-01-15T09:15:00Z,analyst_1,Malicious IP scan confirmed\n"
    ),
    "escalations": (
        "escalation_id,alert_id,case_id,entity_id,from_tier,to_tier,escalated_at,acknowledged_at,outcome\n"
        "ESC-001,ALT-001,CAS-001,CSE-01,Tier-1,Tier-2,2026-01-15T08:36:00Z,2026-01-15T08:42:00Z,contained\n"
    ),
    "closures": (
        "closure_id,record_id,entity_id,closed_by_type,comment,duration_seconds,disposition\n"
        "CLS-001,ALT-001,CSE-01,human,Malicious credential brute-force contained and host isolated.,2700,true_positive\n"
    ),
    "assets": (
        "asset_id,entity_id,asset_type,criticality,zone,is_monitored\n"
        "ASSET-01,CSE-01,domain_controller,4,core,true\n"
        "ASSET-02,CSE-01,scada_gateway,4,ot_substation,true\n"
    ),
    "kpis": (
        "entity_id,period,metric,severity,value\n"
        "CSE-01,2026-Q1,mtta,all,15.0\n"
        "CSE-01,2026-Q1,mttr,all,45.0\n"
        "CSE-01,2026-Q1,sla_compliance,all,95.0\n"
    ),
}


@app.post("/upload")
def handle_upload(
    files: list[UploadFile] = File(...),
    target_entity: Annotated[str, Form()] = "",
    period: Annotated[str, Form()] = "",
    preview: Annotated[bool, Form()] = False,
    identity: Identity = Depends(require_role(*INGEST_RUN_ROLES)),
) -> Response:
    """Receive a file submission and queue it as an import job (satsa.jobs). With `preview`
    ("Check only") the job reads, maps and validates the files and reports, publishing nothing.

    The request only checks the form, the upload size and archive limits, and saves the files
    under data/jobs/<job>/input. The worker then validates and ingests them through the
    ingestion service: a target entity binds the submission (rows naming another entity are
    rejected); a clean submission is published and assessed; one with rejected rows, unreadable
    files or values is held unpublished until an analyst publishes or discards it. The browser
    is sent to the job's page, which shows the outcome when the worker is done."""
    target_clean = target_entity.strip() or None
    if target_clean is not None and not is_valid_entity_id(target_clean):
        return RedirectResponse(
            url="/upload?message=Error:+invalid+target+entity+ID", status_code=303
        )
    period_clean = period.strip() or None
    if period_clean is not None and (not re.match(PERIOD_RE, period_clean) or period_bounds(period_clean) is None):
        return RedirectResponse(
            url="/upload?message=Error:+period+must+look+like+2026-Q1,+2026-H2+or+2026-03", status_code=303
        )
    job_id = new_job_id()
    workdir = job_dir("data", job_id)
    inbox = workdir / IMPORT_INPUT
    inbox.mkdir(parents=True)
    digest = hashlib.sha256()
    names: list[str] = []
    try:
        budget = MAX_UPLOAD_BYTES
        for uf in files:
            # Only the base name of the client-supplied filename is used, so a
            # name like "../../x.csv" cannot write outside the job's directory, and characters
            # outside a portable set (Windows refuses <>:"|?* in a file name) become "_".
            safe_name = UNSAFE_FILE_CHARS.sub("_", Path((uf.filename or "").replace("\\", "/")).name).strip(" .")
            if not safe_name or safe_name.split(".")[0].upper() in WINDOWS_RESERVED_NAMES:
                safe_name = f"upload-{safe_name}" if safe_name else "upload.csv"
            if safe_name in names:
                safe_name = f"{len(names)}-{safe_name}"
            names.append(safe_name)
            dest = inbox / safe_name
            budget -= _copy_limited(uf.file, dest, budget)
            digest.update(safe_name.encode() + hashlib.sha256(dest.read_bytes()).digest())
            # Archive limits and member paths are checked now, before the job is queued, and
            # again by the job before it extracts anything.
            if dest.suffix.lower() == ".zip":
                with zipfile.ZipFile(dest, "r") as z:
                    check_zip_limits(z)
    except (ValueError, OSError, zipfile.BadZipFile) as e:
        shutil.rmtree(workdir, ignore_errors=True)
        return RedirectResponse(url=f"/upload?message=Ingestion error: {e}", status_code=303)

    sqlite_store = get_sqlite_store()
    try:
        params: dict[str, Any] = {"target_entity": target_clean, "period": period_clean, "files": names,
                                  "default_period": _latest_period(sqlite_store)}
        if preview:
            params["preview"] = True
        job = JobQueue(sqlite_store).enqueue(
            "import", {**params, "role": identity.role}, identity.username,
            input_fingerprint=fingerprint("import", params, extra=digest.hexdigest()), job_id=job_id,
        )
        if job["deduplicated"]:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            sqlite_store.append_audit(action="job_queued", actor=identity.username,
                                      details={"job_id": job_id, "kind": "import", "files": names})
            sqlite_store.record_live_event(
                "ASSESSMENT_UPLOAD", actor=identity.username, role=identity.role, entity_id=target_clean,
                details={"file_count": len(files), "filenames": names, "job_id": job_id},
            )
    finally:
        sqlite_store.close()
    return RedirectResponse(url=f"/jobs/{job['job_id']}", status_code=303)


@app.post("/upload/trigger-demo")
def handle_trigger_demo(
    identity: Identity = Depends(require_role(*INGEST_RUN_ROLES)),
) -> Response:
    """Queue the demonstration dataset: synthetic data, its assessment and three historical
    periods (see satsa.jobs.handlers.demo_seed). The browser goes to the job's page.

    Demonstration deployments only: synthetic data never enters a production deployment."""
    if _deployment_settings().get("mode") != "demo":
        raise HTTPException(status_code=403, detail="Demonstration data can only be loaded in a demo deployment.")
    job = enqueue_job("demo_seed", {}, identity, max_attempts=1)
    return RedirectResponse(url=f"/jobs/{job['job_id']}", status_code=303)


@app.get("/rules", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def view_rules_catalog(
    request: Request, category: str = "", domain: str = "", q: str = ""
) -> Response:
    config_path = Path("config/rules.yaml")
    rules_cfg = (
        yaml.safe_load(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    )
    raw_rules = rules_cfg.get("rules", {})

    rules_list = []
    for r_id, r_meta in raw_rules.items():
        cat = "Execution Gap" if r_id.startswith("EG") else "Negative Space"
        r_domain = r_meta.get("domain", "General")
        name = r_meta.get("name", r_id)
        desc = r_meta.get("description", "")
        sev_weight = r_meta.get("severity_weight", 50)
        params = r_meta.get("params", {})

        # Filters
        if category and category.lower() not in cat.lower():
            continue
        if domain and domain.lower() != r_domain.lower():
            continue
        if q:
            safe_q = q.lower()
            if (
                safe_q not in r_id.lower()
                and safe_q not in name.lower()
                and safe_q not in desc.lower()
                and safe_q not in r_domain.lower()
            ):
                continue

        rules_list.append(
            {
                "rule_id": r_id,
                "name": name,
                "category": cat,
                "domain": r_domain,
                "version": r_meta.get("version", "1.0.0"),
                "level": r_meta.get("level", "entity"),
                "severity_weight": sev_weight,
                "description": desc,
                "params": params,
            }
        )

    config_hash = (
        hashlib.sha256(config_path.read_bytes()).hexdigest()[:16] if config_path.exists() else "N/A"
    )
    all_domains = sorted({r.get("domain", "General") for r in raw_rules.values()})

    return templates.TemplateResponse(
        request=request,
        name="rules_catalog.html",
        context={
            "active_tab": "rules",
            "rules": rules_list,
            "total_rules": len(raw_rules),
            "eg_count": sum(1 for k in raw_rules if k.startswith("EG")),
            "ns_count": sum(1 for k in raw_rules if k.startswith("NS")),
            "config_hash": config_hash,
            "all_domains": all_domains,
            "category_filter": category,
            "domain_filter": domain,
            "q": q,
        },
    )


# Every threshold the Tuning page can change. Each entry maps 1:1 to a key the
# rule reads via self.params.get(key, default) (enforced by
# tests/test_config_drift.py); labels describe the rule's REAL logic. The form
# field for an entry is named "<RULE>__<key>", e.g. "EG04__max_comment_hash_share".
TUNABLE_PARAMS: list[dict[str, Any]] = [
    {"rule": "EG01", "key": "fast_share_threshold", "type": "float", "min": 0.0, "max": 1.0, "step": 0.01,
     "label": "EG01 - min share of closures faster than peer p5",
     "help": "Flag when more than this share of human-closed High/Critical alerts close faster than the portfolio p5 close time with <= 1 workflow event."},
    {"rule": "EG01", "key": "min_fast_count", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "EG01 - min number of such fast closures",
     "help": "Minimum count of fast, minimally-worked closures required before EG01 can fire."},
    {"rule": "EG02", "key": "max_uninvestigated_share", "type": "float", "min": 0.0, "max": 1.0, "step": 0.01,
     "label": "EG02 - max share of closures with no investigation",
     "help": "Flag when more than this share of human-closed alerts have no 'investigate' workflow event and a closure comment under 25 characters."},
    {"rule": "EG02", "key": "min_uninvestigated_count", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "EG02 - min number of such closures",
     "help": "Minimum count of uninvestigated, trivially-commented closures required before EG02 can fire."},
    {"rule": "EG04", "key": "max_comment_hash_share", "type": "float", "min": 0.0, "max": 1.0, "step": 0.01,
     "label": "EG04 - max share of closures in repeated-comment groups",
     "help": "Flag when more than this share of human-closed alerts carry a closure comment whose normalized hash repeats at least the group size below."},
    {"rule": "EG04", "key": "min_hash_group_size", "type": "int", "min": 2, "max": 100000, "step": 1,
     "label": "EG04 - min repeats for a comment-hash group",
     "help": "A normalized comment hash counts as boilerplate only if it repeats at least this many times."},
    {"rule": "EG05", "key": "min_repeat_count", "type": "int", "min": 2, "max": 100000, "step": 1,
     "label": "EG05 - min repeats of an all-benign (asset, rule) pair",
     "help": "An (asset, rule) pair counts when it fired at least this many times and was always closed false-positive/benign."},
    {"rule": "EG05", "key": "min_unaddressed_pairs", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "EG05 - min unremediated repeat pairs",
     "help": "Flag when at least this many such pairs have no linked remediation ticket."},
    {"rule": "EG05", "key": "max_chance_pairs", "type": "float", "min": 0.01, "max": 100.0, "step": 0.05,
     "label": "EG05 - pairs chance may push over the repeat threshold",
     "help": "The repeat threshold is raised (up to 2x the minimum) until fewer than this many pairs would reach it by coincidence, given the entity's alert volume and its asset x rule space."},
    {"rule": "EG06", "key": "min_bulk_closures_per_minute", "type": "int", "min": 2, "max": 100000, "step": 1,
     "label": "EG06 - min closures by one analyst in one minute (bulk batch)",
     "help": "A batch of at least this many human closures by the same analyst in the same minute counts as a bulk closure."},
    {"rule": "EG06", "key": "max_deadline_hugging_share", "type": "float", "min": 0.0, "max": 1.0, "step": 0.01,
     "label": "EG06 - max share closed in the last 10% of the SLA window",
     "help": "Flag when more than this share of human closures land between 90% and 100% of the SLA resolve time."},
    {"rule": "EG07", "key": "min_closures_per_analyst_hour", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "EG07 - min closures by one analyst in one hour",
     "help": "Flag when any analyst closes at least this many alerts within a single clock hour."},
    {"rule": "EG08", "key": "min_unacknowledged_escalations", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "EG08 - min escalations with no Tier-2 acknowledgement",
     "help": "Flag when at least this many escalations have no acknowledgement timestamp."},
    {"rule": "EG09", "key": "stale_case_days", "type": "int", "min": 1, "max": 3660, "step": 1,
     "label": "EG09 - days after which an open case is stale",
     "help": "An open case older than this many days counts as stale."},
    {"rule": "EG09", "key": "min_stale_cases", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "EG09 - min stale open cases",
     "help": "Flag when at least this many open cases are stale."},
    {"rule": "EG10", "key": "mttr_gap_ratio_threshold", "type": "float", "min": 0.0, "max": 100.0, "step": 0.05,
     "label": "EG10 - max relative gap, empirical vs declared MTTR",
     "help": "Flag when (empirical - declared) / declared High/Critical MTTR exceeds this ratio (0.60 = 60%)."},
    {"rule": "EG11", "key": "min_alert_volume", "type": "int", "min": 1, "max": 10000000, "step": 1,
     "label": "EG11 - min alert volume before dispositions are judged",
     "help": "EG11 is only evaluated for entities with at least this many alerts."},
    {"rule": "EG11", "key": "max_robust_z", "type": "float", "min": 0.5, "max": 20.0, "step": 0.5,
     "label": "EG11 - robust z-score vs peers that flags the FP rate",
     "help": "Flag when the entity's false-positive/benign rate is at least this many robust standard deviations above its peer cohort's median (zero true positives always flags)."},
    {"rule": "EG11", "key": "min_spread", "type": "float", "min": 0.0, "max": 1.0, "step": 0.005,
     "label": "EG11 - minimum peer spread for the z-score",
     "help": "Floor on the peer spread (1.4826 x MAD) so near-identical peers don't make a trivial difference look extreme."},
    {"rule": "EG11", "key": "max_fp_rate", "type": "float", "min": 0.0, "max": 1.0, "step": 0.01,
     "label": "EG11 - fallback max false-positive/benign rate",
     "help": "Used only when fewer than 3 peers have enough alerts to compare: flag when more than this share of alerts are closed false positive or benign."},
    {"rule": "EG12", "key": "min_skipped_cases", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "EG12 - min critical cases that skipped containment",
     "help": "Flag when at least this many critical cases have no 'contain' workflow stage."},
    {"rule": "NS01", "key": "min_silent_days", "type": "int", "min": 1, "max": 3660, "step": 1,
     "label": "NS01 - min zero-event days on a critical asset",
     "help": "Flag monitored critical assets with at least this many days of zero log events (days need not be consecutive)."},
    {"rule": "NS01", "key": "min_asset_criticality", "type": "int", "min": 1, "max": 5, "step": 1,
     "label": "NS01 - min asset criticality considered",
     "help": "Only assets at or above this criticality level are checked."},
    {"rule": "NS02", "key": "min_peer_share", "type": "float", "min": 0.0, "max": 1.0, "step": 0.05,
     "label": "NS02 - share of peers reporting a category for it to be 'standard'",
     "help": "A category is expected of an entity when at least this share of its peer cohort reports it; its complete absence is flagged."},
    {"rule": "NS03", "key": "max_night_share", "type": "float", "min": 0.0, "max": 1.0, "step": 0.01,
     "label": "NS03 - fallback max night-time (20:00-08:00) share of alerts",
     "help": "Used only when fewer than 3 peers have enough alerts to compare: flag when the night-time share falls below this value."},
    {"rule": "NS03", "key": "max_robust_z", "type": "float", "min": 0.5, "max": 20.0, "step": 0.5,
     "label": "NS03 - robust z-score below peers that flags night share",
     "help": "Flag when the entity's night-time share is at least this many robust standard deviations below its peer cohort's median."},
    {"rule": "NS03", "key": "min_spread", "type": "float", "min": 0.0, "max": 1.0, "step": 0.005,
     "label": "NS03 - minimum peer spread for the z-score",
     "help": "Floor on the peer spread (1.4826 x MAD) so near-identical peers don't make a trivial difference look extreme."},
    {"rule": "NS03", "key": "min_alert_volume", "type": "int", "min": 1, "max": 10000000, "step": 1,
     "label": "NS03 - min alert volume before NS03 applies",
     "help": "NS03 is only evaluated for entities with at least this many alerts."},
    {"rule": "NS04", "key": "min_tp_without_case", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "NS04 - min High/Critical TP alerts with no case",
     "help": "Flag when at least this many High/Critical true-positive alerts have no linked incident case."},
    {"rule": "NS05", "key": "max_dormant_share", "type": "float", "min": 0.0, "max": 1.0, "step": 0.01,
     "label": "NS05 - max share of enabled rules that never fired",
     "help": "Flag when more than this share of enabled detection rules produced no alert in the period."},
    {"rule": "NS05", "key": "min_dormant_rules", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "NS05 - min number of dormant rules",
     "help": "Minimum count of never-firing enabled rules required before NS05 can fire."},
    {"rule": "NS06", "key": "min_ghost_assets", "type": "int", "min": 1, "max": 100000, "step": 1,
     "label": "NS06 - min inventory assets with no telemetry",
     "help": "Flag when at least this many inventory assets have no log events and no alerts."},
    {"rule": "NS08", "key": "review_period_months", "type": "int",
     "min": REVIEW_PERIOD_MONTHS_RANGE[0], "max": REVIEW_PERIOD_MONTHS_RANGE[1], "step": 1,
     "label": "NS08 - supervisory review period (months)",
     "help": "Months a submission is expected to cover. An entity is held to the months the portfolio submitted, up to this many; an entity alone in the portfolio is held to all of them."},
]

RULES_CONFIG_PATH = Path("config/rules.yaml")
# Source mappings an upload is matched against by its columns (detect_source_mapping).
MAPPINGS_DIR = Path("config/mappings")


def _load_rules_config() -> dict[str, Any]:
    if not RULES_CONFIG_PATH.exists():
        return {"rules": {}}
    return load_yaml(RULES_CONFIG_PATH) or {"rules": {}}


def _render_rules_config(cfg: dict[str, Any]) -> str:
    """The text of config/rules.yaml for `cfg`, keeping the file's leading comment header."""
    header = ""
    if RULES_CONFIG_PATH.exists():
        lines = RULES_CONFIG_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
        for line in lines:
            if not line.startswith("#"):
                break
            header += line
    return header + yaml.dump(cfg, sort_keys=False, width=100)


def _tunable_param_rows(rules_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """TUNABLE_PARAMS annotated with each parameter's current configured value."""
    rows = []
    for spec in TUNABLE_PARAMS:
        current = (
            rules_cfg.get("rules", {}).get(spec["rule"], {}).get("params", {}).get(spec["key"])
        )
        rows.append({**spec, "field": f"{spec['rule']}__{spec['key']}", "value": current})
    return rows


@app.get("/rule-versions", response_class=HTMLResponse, dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def view_rule_versions(request: Request, message: str = "") -> Response:
    """Rule configuration versions, for examiners and analysts (approve / reject; analysts also
    put approved versions in force)."""
    sqlite_store = get_sqlite_store()
    try:
        rules_drift = lifecycle.drift(sqlite_store, RULES_CONFIG_PATH)
        lifecycle.active(sqlite_store, RULES_CONFIG_PATH)
        rule_versions = lifecycle.versions(sqlite_store)
    finally:
        sqlite_store.close()
    return templates.TemplateResponse(request=request, name="rule_versions.html", context={
        "active_tab": "tuning", "message": message, "rule_versions": rule_versions, "rules_drift": rules_drift,
        "viewer": get_current_identity(request),
    })


@app.get("/tuning", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def view_tuning(request: Request, message: str = "") -> Response:
    rules_cfg = _load_rules_config()
    sqlite_store = get_sqlite_store()
    try:
        selected_period = _latest_period(sqlite_store)
        rules_drift = lifecycle.drift(sqlite_store, RULES_CONFIG_PATH)
        lifecycle.active(sqlite_store, RULES_CONFIG_PATH)
        rule_versions = lifecycle.versions(sqlite_store)
    finally:
        sqlite_store.close()
    config_hash = (
        hashlib.sha256(RULES_CONFIG_PATH.read_bytes()).hexdigest()[:16]
        if RULES_CONFIG_PATH.exists()
        else "N/A"
    )

    return templates.TemplateResponse(
        request=request,
        name="tuning.html",
        context={
            "active_tab": "tuning",
            "message": message,
            "rules_config": rules_cfg,
            "tunable_params": _tunable_param_rows(rules_cfg),
            "config_hash": config_hash,
            "preview": None,
            "selected_period": selected_period,
            "rule_versions": rule_versions,
            "rules_drift": rules_drift,
            "viewer": get_current_identity(request),
        },
    )


@app.post("/tuning/save")
async def handle_tuning_save(
    request: Request,
    identity: Identity = Depends(require_role(*TUNING_ROLES)),
) -> Response:
    """Update rule thresholds in config/rules.yaml and re-run the assessment.

    Only fields named "<RULE>__<key>" for an entry in TUNABLE_PARAMS are
    accepted, and each is written to cfg["rules"][RULE]["params"][key] -- the
    exact place the rule reads it from. Fields that are omitted are left
    unchanged; out-of-range or non-numeric values are rejected (HTTP 422).
    """
    form = await request.form()
    cfg, changes = _apply_tuning_form(form, _load_rules_config())

    # A change is a version (satsa.rules.lifecycle): a draft that another person approves before
    # it is put in force. A demonstration deployment puts it in force at once, and says so.
    demo = _deployment_settings().get("mode") == "demo"
    sqlite_store = get_sqlite_store()
    try:
        period = _selected_period(form, sqlite_store)
        version = None
        if changes:
            try:
                change_list = [{"field": field.replace("__", "."), "old": c["old"], "new": c["new"]}
                               for field, c in changes.items()]
                version = lifecycle.propose(sqlite_store, _render_rules_config(cfg), change_list,
                                            identity.username, identity.role)
                if demo:
                    version = lifecycle.activate(sqlite_store, version["version_no"], identity.username,
                                                 identity.role, RULES_CONFIG_PATH, demo=True)
            except CaseError as exc:
                raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    finally:
        sqlite_store.close()
    if version is not None and version["state"] == "draft":
        msg = (f"Draft version {version['version_no']} proposed ({len(changes)} change(s)). Another analyst or "
               "an examiner must approve it, then an analyst puts it in force; nothing was re-assessed yet.")
        return RedirectResponse(url=f"/tuning?message={urllib.parse.quote_plus(msg)}#versions", status_code=303)

    # Re-evaluate with the (possibly) updated thresholds, for the selected period, in the worker
    job = enqueue_assessment(period, identity, "rule parameters saved")
    sqlite_store = get_sqlite_store()
    try:
        sqlite_store.append_audit(
            action="tuning_save",
            actor=identity.username,
            details={"changes": changes, "job_id": job["job_id"], "period": period},
        )
    finally:
        sqlite_store.close()

    msg = (
        f"Parameters updated! Period: {period} | Re-assessment queued as job {job['job_id']} "
        "(see Jobs for its findings)"
    )
    if version is not None:
        msg += f" | Version {version['version_no']}: {lifecycle.DEMO_ACTIVATION_NOTE}"
    return RedirectResponse(url=f"/tuning?message={msg}", status_code=303)


@app.post("/tuning/versions/{version_no}/{decision}")
async def decide_rule_version(
    version_no: int,
    decision: str,
    note: Annotated[str, Form()] = "",
    period: Annotated[str, Form()] = "",
    identity: Identity = Depends(require_role(*SUPERVISORY_READ_ROLES)),
) -> Response:
    """approve / reject (an analyst or examiner other than the author) or activate (an analyst;
    queues a re-assessment of the latest period) one rule configuration version."""
    if decision not in ("approve", "reject", "activate"):
        raise HTTPException(status_code=404, detail="Not Found")
    sqlite_store = get_sqlite_store()
    try:
        if decision == "approve":
            lifecycle.approve(sqlite_store, version_no, identity.username, identity.role, note)
            msg = f"Version {version_no} approved. An analyst can now put it in force."
        elif decision == "reject":
            lifecycle.reject(sqlite_store, version_no, identity.username, identity.role, note)
            msg = f"Version {version_no} rejected."
        else:
            # The period is checked before anything changes, so a bad one cannot leave a version
            # in force with no re-assessment queued.
            chosen = period.strip() or _latest_period(sqlite_store)
            if period.strip() and not re.match(PERIOD_RE, chosen):
                raise HTTPException(status_code=422, detail="period must look like 2026-Q1, 2026-H1 or 2026-03")
            lifecycle.activate(sqlite_store, version_no, identity.username, identity.role, RULES_CONFIG_PATH)
            job = enqueue_assessment(chosen, identity, f"rule version {version_no} put in force")
            msg = f"Version {version_no} is in force. Re-assessment of {chosen} queued as job {job['job_id']}."
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    finally:
        sqlite_store.close()
    page = "/tuning" if is_analyst(identity.role) else "/rule-versions"
    return RedirectResponse(url=f"{page}?message={urllib.parse.quote_plus(msg)}#versions", status_code=303)


@app.post("/tuning/preview", response_class=HTMLResponse)
async def handle_tuning_preview(
    request: Request,
    identity: Identity = Depends(require_role(*TUNING_ROLES)),
) -> Response:
    """Show what the submitted thresholds WOULD change, without saving anything.

    The proposed config is written to a temporary file and assessed with a dry run: no
    config write, no run row, no findings, no audit entry. The result is compared with
    the latest stored run for the same period selection.
    """
    form = await request.form()
    current_cfg = _load_rules_config()
    proposed_cfg, changes = _apply_tuning_form(form, copy.deepcopy(current_cfg))

    duckdb_store, sqlite_store = get_write_stores()
    try:
        period = _selected_period(form, sqlite_store)
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "rules.yaml"
            cfg_path.write_text(yaml.safe_dump(proposed_cfg, sort_keys=False), encoding="utf-8")
            runner = AssessmentRunner(duckdb_store, sqlite_store, rules_config_path=cfg_path)
            res = runner.run_assessment(period=period, actor=identity.username, dry_run=True)
        if res.get("status") != "success":
            raise HTTPException(status_code=409, detail=res.get("message", "Nothing to assess."))

        cur = sqlite_store.conn.cursor()
        cur.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1")
        run_row = cur.fetchone()
        baseline_run = run_row["run_id"] if run_row else ""
        cur.execute("SELECT entity_id, rule_id FROM findings WHERE run_id = ?", (baseline_run,))
        before = {(r["entity_id"], r["rule_id"]) for r in cur.fetchall()}
        cur.execute("SELECT entity_id, risk_band FROM entity_scores WHERE run_id = ?", (baseline_run,))
        bands_before = {r["entity_id"]: r["risk_band"] for r in cur.fetchall()}
        # Read-only: a preview records nothing, not even a configuration edited outside the lifecycle.
        rule_versions = lifecycle.versions(sqlite_store)
        rules_drift = lifecycle.drift(sqlite_store, RULES_CONFIG_PATH)
    finally:
        duckdb_store.close()
        sqlite_store.close()

    after = {(f["entity_id"], f["rule_id"]) for f in res["findings"]}
    band_changes = [
        {"entity_id": eid, "before": bands_before.get(eid, "n/a"), "after": info["risk_band"]}
        for eid, info in sorted(res["entity_scores"].items())
        if bands_before.get(eid) != info["risk_band"]
    ]
    preview = {
        "period": period,
        "baseline_run": baseline_run,
        "changes": changes,
        "findings_before": len(before),
        "findings_after": len(after),
        "added": [f"{e} / {r}" for e, r in sorted(after - before)],
        "removed": [f"{e} / {r}" for e, r in sorted(before - after)],
        "band_changes": band_changes,
    }
    return templates.TemplateResponse(
        request=request,
        name="tuning.html",
        context={
            "active_tab": "tuning",
            "message": "",
            "rules_config": proposed_cfg,
            "tunable_params": _tunable_param_rows(proposed_cfg),
            "config_hash": hashlib.sha256(RULES_CONFIG_PATH.read_bytes()).hexdigest()[:16]
            if RULES_CONFIG_PATH.exists()
            else "N/A",
            "preview": preview,
            "selected_period": period,
            "rule_versions": rule_versions,
            "rules_drift": rules_drift,
            "viewer": get_current_identity(request),
        },
    )


def _apply_tuning_form(form: Any, cfg: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Apply "<RULE>__<key>" form fields to a rules config; returns (config, changes).

    Validates every value against TUNABLE_PARAMS (HTTP 422 on a non-number or out of range).
    The config passed in is modified and returned; callers decide whether to persist it.
    """
    rules = cfg.setdefault("rules", {})
    changes: dict[str, dict[str, Any]] = {}
    for spec in TUNABLE_PARAMS:
        field = f"{spec['rule']}__{spec['key']}"
        raw = form.get(field)
        if raw is None or str(raw).strip() == "":
            continue
        try:
            value: float | int = float(str(raw)) if spec["type"] == "float" else int(str(raw))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"{field} must be a number.") from None
        if not (spec["min"] <= value <= spec["max"]):
            raise HTTPException(
                status_code=422, detail=f"{field} must be between {spec['min']} and {spec['max']}."
            )
        params = rules.setdefault(spec["rule"], {}).setdefault("params", {})
        old = params.get(spec["key"])
        if old != value:
            changes[field] = {"old": old, "new": value}
        params[spec["key"]] = value
    return cfg, changes


DEFAULT_PERIOD = "2026-Q1"


def _latest_period(sqlite_store: SQLiteStore) -> str:
    """Period of the most recent assessment run (the one the dashboard shows)."""
    row = sqlite_store.conn.execute("SELECT period FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
    return row["period"] if row and row["period"] else DEFAULT_PERIOD


def _selected_period(form: Any, sqlite_store: SQLiteStore) -> str:
    """The period chosen on the form, or the latest run's period when none was given."""
    raw = str(form.get("period") or "").strip()
    if not raw:
        return _latest_period(sqlite_store)
    if not re.match(PERIOD_RE, raw):
        raise HTTPException(status_code=422, detail="period must look like 2026-Q1, 2026-H2 or 2026-03.")
    return raw


RULEPACK_DISABLED_DETAIL = (
    "Rule-pack signing is disabled on this server: SATSA_RULEPACK_SECRET is not configured "
    "(or is unsafe). There is no built-in default key."
)


@app.get("/tuning/export-pack")
async def handle_export_pack(
    identity: Identity = Depends(require_role(*RULEPACK_ROLES)),
) -> Response:
    try:
        signer = RulePackSigner()
    except RulePackKeyError:
        raise HTTPException(status_code=503, detail=RULEPACK_DISABLED_DETAIL) from None
    out_tar = Path("dist/rule_pack_active.tar.gz")
    signer.export_rule_pack(config_dir="config", output_path=out_tar, version="1.0.0")
    return FileResponse(
        path=out_tar,
        filename="satsa_signed_rule_pack_v1.0.0.tar.gz",
        media_type="application/gzip",
    )


@app.post("/tuning/import-pack")
def handle_import_pack(
    pack_file: UploadFile = File(...),
    identity: Identity = Depends(require_role(*RULEPACK_ROLES)),
) -> Response:
    try:
        signer = RulePackSigner()
    except RulePackKeyError:
        raise HTTPException(status_code=503, detail=RULEPACK_DISABLED_DETAIL) from None
    sqlite_store = get_sqlite_store()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
        shutil.copyfileobj(pack_file.file, tmp)
        tmp_path = Path(tmp.name)

    try:
        lifecycle.active(sqlite_store, RULES_CONFIG_PATH)  # the configuration before the pack is on record
        res = signer.import_rule_pack(
            tmp_path,
            target_config_dir="config",
            sqlite_store=sqlite_store,
            actor=identity.username,
        )
        recorded = lifecycle.record_signed_pack(sqlite_store, RULES_CONFIG_PATH, identity.username,
                                                res.get("version"), res.get("signature", ""))
        msg = f"Rule pack verified and installed! Version: {res.get('version')} | Files: {res.get('files_imported')}"
        if recorded is not None:
            msg += f" | Rule configuration version {recorded['version_no']} (approved by the pack's signature)"
    except (ValueError, KeyError, OSError, RuntimeError) as e:
        msg = f"Failed to import rule pack: {e}"
    finally:
        sqlite_store.close()
        if tmp_path.exists():
            tmp_path.unlink()

    return RedirectResponse(url=f"/tuning?message={msg}", status_code=303)


# --- Direct Report Downloads ---


REPORTS_DIR = Path("reports")
_REPORT_NOT_FOUND_DETAIL = {
    "Entity": "Entity not found",
    "Finding": "Finding not found",
    "Assessment run": "Assessment run not found",
    "Report data": "No assessment results stored for this run",
}


def require_valid_run_id(run_id: str | None) -> str | None:
    """Reject an externally supplied run_id that fails satsa.security.RUN_ID_RE (HTTP 400)."""
    if run_id is not None and not is_valid_run_id(run_id):
        raise HTTPException(status_code=400, detail="Invalid run_id.")
    return run_id


def _pdf_response(
    request: Request,
    report_kind: str,
    prepare: Callable[[ReportGenerator], tuple[str, Callable[[Path], Path]]],
    entity_id: str | None = None,
) -> FileResponse:
    """Build a PDF report and return it as a download, with clean 404/500 errors.

    `prepare` resolves the report's data (raising ReportNotFoundError or an
    HTTPException) and returns the download filename plus a build function.
    The filename contains only validated IDs; the file is built atomically, so a
    failure never leaves a partial PDF behind.
    """
    duckdb_store, sqlite_store = get_stores()
    try:
        rep = ReportGenerator(duckdb_store, sqlite_store)
        try:
            filename, build = prepare(rep)
            out_path = safe_join(REPORTS_DIR, filename)
            build(out_path)
        except ReportNotFoundError as exc:
            raise HTTPException(
                status_code=404, detail=_REPORT_NOT_FOUND_DETAIL.get(exc.what, "Not found")
            ) from None
        except HTTPException:
            raise
        except Exception:
            logger.exception("PDF report generation failed (%s)", report_kind)
            raise HTTPException(status_code=500, detail="Report generation failed.") from None
        identity = get_current_identity(request)
        actor = identity.username if identity else "operator"
        role = identity.role if identity else "examiner"
        for event in ("REPORT_GENERATED", "REPORT_DOWNLOADED"):
            sqlite_store.record_live_event(
                event, actor=actor, role=role, entity_id=entity_id, details={"report": report_kind}
            )
    finally:
        duckdb_store.close()
        sqlite_store.close()

    return FileResponse(path=out_path, filename=filename, media_type="application/pdf")


@app.get("/reports/entity/{entity_id}/pdf", dependencies=[Depends(require_authenticated)])
async def download_entity_pdf(
    request: Request, entity_id: str, run_id: str | None = None
) -> FileResponse:
    require_valid_entity_id(entity_id)
    require_valid_run_id(run_id)
    identity = get_current_identity(request)
    if identity:
        require_cse_access(entity_id, identity)

    def prepare(rep: ReportGenerator) -> tuple[str, Callable[[Path], Path]]:
        meta = rep.resolve_run(run_id)
        return (
            entity_pdf_name(entity_id, meta.run_id),
            lambda path: rep.generate_entity_pdf(entity_id, path, meta.run_id),
        )

    return _pdf_response(request, "entity_pdf", prepare, entity_id=entity_id)


@app.get("/reports/portfolio/pdf", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def download_portfolio_pdf(request: Request, run_id: str | None = None) -> FileResponse:
    require_valid_run_id(run_id)

    def prepare(rep: ReportGenerator) -> tuple[str, Callable[[Path], Path]]:
        meta = rep.resolve_run(run_id)
        return (
            portfolio_pdf_name(meta.run_id),
            lambda path: rep.generate_portfolio_pdf(path, meta.run_id),
        )

    return _pdf_response(request, "portfolio_pdf", prepare)


@app.get(
    "/reports/finding/{finding_id}/pdf",
    dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))],
)
async def download_finding_pdf(request: Request, finding_id: str) -> FileResponse:
    if not is_valid_finding_id(finding_id):
        raise HTTPException(status_code=400, detail="Invalid finding_id.")
    identity = get_current_identity(request)

    def prepare(rep: ReportGenerator) -> tuple[str, Callable[[Path], Path]]:
        row = rep.sqlite_store.conn.execute(
            "SELECT entity_id, rule_id FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise ReportNotFoundError("Finding")
        if identity:
            require_cse_access(row["entity_id"], identity)
        return (
            finding_pdf_name(finding_id, row["rule_id"], row["entity_id"]),
            lambda path: rep.generate_finding_pdf(finding_id, path),
        )

    return _pdf_response(request, "finding_pdf", prepare)


def _built_report(
    request: Request,
    report_kind: str,
    run_id: str | None,
    build: Callable[[ReportGenerator, Path, str], Path],
    filename: Callable[[str], str],
    media_type: str,
    entity_id: str | None = None,
) -> Response:
    """Build an HTML or CSV report of one run (default: the latest) in a private temporary
    directory and return its bytes: no shared fixed path, so concurrent downloads cannot
    overwrite each other, and nothing is left behind."""
    require_valid_run_id(run_id)
    duckdb_store, sqlite_store = get_stores()
    try:
        rep = ReportGenerator(duckdb_store, sqlite_store)
        try:
            meta = rep.resolve_run(run_id)
        except ReportNotFoundError:
            raise HTTPException(status_code=404, detail="Assessment run not found") from None
        with tempfile.TemporaryDirectory(prefix="satsa-report-") as tmp:
            content = build(rep, Path(tmp) / "report", meta.run_id).read_bytes()
        identity = get_current_identity(request)
        actor = identity.username if identity else "operator"
        role = identity.role if identity else "examiner"
        for event in ("REPORT_GENERATED", "REPORT_DOWNLOADED"):
            sqlite_store.record_live_event(
                event, actor=actor, role=role, entity_id=entity_id,
                details={"report": report_kind, "run_id": meta.run_id},
            )
    finally:
        duckdb_store.close()
        sqlite_store.close()
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename(meta.run_id)}"'},
    )


@app.get("/reports/entity/{entity_id}/html", dependencies=[Depends(require_authenticated)])
async def download_entity_html(request: Request, entity_id: str, run_id: str | None = None) -> Response:
    require_valid_entity_id(entity_id)
    identity = get_current_identity(request)
    if identity:
        require_cse_access(entity_id, identity)
    return _built_report(
        request, "entity_html", run_id,
        lambda rep, path, rid: rep.generate_entity_html(entity_id, path, rid),
        lambda rid: f"{entity_id}_Supervisory_Report_{rid}.html", "text/html", entity_id=entity_id,
    )


@app.get("/reports/portfolio/html", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def download_portfolio_html(request: Request, run_id: str | None = None) -> Response:
    return _built_report(
        request, "portfolio_html", run_id,
        lambda rep, path, rid: rep.generate_portfolio_html(path, rid),
        lambda rid: f"Portfolio_Supervisory_Report_{rid}.html", "text/html",
    )


@app.get("/reports/export/findings-csv", dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def download_findings_csv(request: Request, run_id: str | None = None) -> Response:
    return _built_report(
        request, "findings_csv", run_id,
        lambda rep, path, rid: rep.export_findings_csv(path, rid),
        lambda rid: f"SATSA_Findings_Export_{rid}.csv", "text/csv",
    )


@app.get("/reports/export/queue-csv", dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def download_queue_csv(request: Request, run_id: str | None = None) -> Response:
    return _built_report(
        request, "queue_csv", run_id,
        lambda rep, path, rid: rep.export_queue_csv(path, rid),
        lambda rid: f"SATSA_Review_Queue_Export_{rid}.csv", "text/csv",
    )


# Supervisory review period label, e.g. "2026-Q1", "2026-H2" or "2026-03".
PERIOD_RE = r"^\d{4}-(Q[1-4]|H[12]|0[1-9]|1[0-2])$"


# Payload section -> canonical table. Every table a rule reads can be submitted.
SUBMISSION_SECTIONS: dict[str, str] = {
    "alerts": "alert",
    "cases": "case",
    "assets": "asset",
    "closures": "closure",
    "escalations": "escalation",
    "workflow_events": "workflow_event",
    "case_alert_links": "case_alert_link",
    "remediations": "remediation",
    "external_reports": "external_report",
    "log_source_daily": "log_source_daily",
    "detection_rules": "detection_rule",
    "declared_kpis": "declared_kpi",
    "sla_policies": "sla_policy",
}


class BatchSubmissionPayload(BaseModel):
    entity_id: str = Field(..., description="Unique code for the CSE, e.g. CSE-11")
    period: str = Field(
        default="2026-Q1", pattern=PERIOD_RE, description="Supervisory review period (e.g. 2026-Q1)"
    )
    alerts: list[dict[str, Any]] = Field(default=[], description="Alert records")
    cases: list[dict[str, Any]] = Field(default=[], description="Case management records")
    assets: list[dict[str, Any]] = Field(default=[], description="Asset inventory records")
    closures: list[dict[str, Any]] = Field(default=[], description="Closure records")
    escalations: list[dict[str, Any]] = Field(default=[], description="Escalation records")
    workflow_events: list[dict[str, Any]] = Field(default=[], description="Workflow events")
    case_alert_links: list[dict[str, Any]] = Field(default=[], description="Case-to-alert links")
    remediations: list[dict[str, Any]] = Field(default=[], description="Remediation tickets")
    external_reports: list[dict[str, Any]] = Field(default=[], description="Reports to external bodies")
    log_source_daily: list[dict[str, Any]] = Field(default=[], description="Daily log-source volumes")
    detection_rules: list[dict[str, Any]] = Field(default=[], description="Detection rule inventory")
    declared_kpis: list[dict[str, Any]] = Field(default=[], description="KPIs the CSE declares")
    sla_policies: list[dict[str, Any]] = Field(default=[], description="SLA policy per severity")
    declared_empty: list[str] = Field(
        default=[],
        description="Sections (e.g. 'escalations') the CSE declares complete with no records for the "
        "period. A section that is neither submitted nor declared is treated as not submitted.",
    )
    revision_of: str | None = Field(
        default=None, description="Batch id this submission corrects (required for an overlapping period)"
    )
    idempotency_key: str | None = Field(
        default=None,
        max_length=128,
        description="Client key for safe retries; default: derived from entity and period",
    )
    run_assessment_now: bool = Field(
        default=True, description="Whether to run the periodic assessment after the batch is stored"
    )


@app.post("/api/v1/submissions", tags=["Periodic Batch Submission"])
async def api_batch_submission(
    payload: BatchSubmissionPayload,
    request: Request,
    identity: Identity = Depends(require_submitter),
) -> dict[str, Any]:
    """
    Submit ONE periodic batch (a CSE's records for a supervisory review period) as JSON -- the
    programmatic equivalent of the /upload file submission, used after the fact at each
    assessment cycle.

    This is not a streaming or event-driven feed: each entity and review period is submitted
    once. The batch goes through the same ingestion service as a file upload (validation,
    pseudonymisation, redaction, canonical columns only) and is published whole or not at all.

    - Every row must belong to `entity_id` (rows without one get it); a row naming another
      entity rejects the batch (422), as does any unreadable timestamp; the response lists
      each error with its table, field and row.
    - Exactly the same submission again (same idempotency key and content) is an idempotent
      retry: 200 with `idempotent_replay`, nothing stored twice.
    - Different content for the same entity and period, or a period that overlaps an earlier
      submission (`2026-02` inside `2026-Q1`), is rejected with HTTP 409. A correction names
      the batch it corrects in `revision_of`; it then replaces the earlier records by key.

    Machine clients authenticate with a service credential (`Authorization: Bearer
    satsa_sc_...`, docs/api_credentials.md), which may submit only for the entities it was
    issued for. An analyst's browser session is also accepted.
    """
    clean_id = payload.entity_id.strip().upper()
    if not clean_id:
        raise HTTPException(status_code=400, detail="entity_id is required")
    require_valid_entity_id(clean_id)
    principal = getattr(request.state, "service_principal", None)
    if principal is not None:
        store = get_sqlite_store()
        try:
            allowed = principal.may_submit_for(clean_id)
            store.append_audit(
                action="service_credential_used" if allowed else "service_credential_refused",
                actor=principal.actor,
                details={"credential_id": principal.credential_id, "entity_id": clean_id, "period": payload.period},
            )
        finally:
            store.close()
        if not allowed:
            raise HTTPException(status_code=403, detail=f"This credential may not submit for {clean_id}.")
    sections = {name: getattr(payload, name) for name in SUBMISSION_SECTIONS}
    for rows in sections.values():
        for row in rows:
            row_eid = row.get("entity_id")
            if row_eid and not is_valid_entity_id(str(row_eid)):
                raise HTTPException(status_code=400, detail="Invalid entity_id in submitted rows.")
    unknown = sorted(set(payload.declared_empty) - set(SUBMISSION_SECTIONS))
    if unknown:
        raise HTTPException(status_code=422, detail=f"declared_empty names unknown sections: {', '.join(unknown)}")
    both = sorted(name for name in payload.declared_empty if sections[name])
    if both:
        raise HTTPException(status_code=422, detail=f"sections both submitted and declared empty: {', '.join(both)}")
    bounds = period_bounds(payload.period)
    assert bounds is not None  # PERIOD_RE guarantees it
    idempotency_key = payload.idempotency_key or hashlib.sha256(
        f"{clean_id}|{bounds[0].isoformat()}|{bounds[1].isoformat()}|{payload.revision_of or ''}".encode()
    ).hexdigest()

    duckdb_store, sqlite_store = get_write_stores()
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            for name, rows in sections.items():
                if rows:
                    (tmp_path / f"{SUBMISSION_SECTIONS[name]}.json").write_text(json.dumps(rows), encoding="utf-8")
            res = IngestionPipeline(duckdb_store, sqlite_store).ingest_directory(
                tmp_path,
                bound_entity=clean_id,
                period=payload.period,
                transport="api",
                submitted_by=identity.username,
                policy="strict",
                idempotency_key=idempotency_key,
                revision_of=payload.revision_of,
                reject_overlap=True,
                declared_empty=[SUBMISSION_SECTIONS[n] for n in payload.declared_empty],
            )
        status = res.get("status")
        if status == "rejected":
            sqlite_store.append_audit(
                action="api_batch_rejected",
                actor=identity.username,
                details={"entity_id": clean_id, "period": payload.period, "error_count": res.get("error_count", 0)},
            )
            raise HTTPException(
                status_code=422,
                detail={"message": res.get("message"), "errors": res.get("errors", []),
                        "error_count": res.get("error_count", 0)},
            )
        if status == "conflict":
            raise HTTPException(
                status_code=409,
                detail=(
                    f"A batch for {clean_id} / {payload.period} has already been submitted, or overlaps one "
                    f"that has: {res.get('message')}"
                ),
            )
        if status == "empty" and not payload.declared_empty:
            raise HTTPException(status_code=422, detail="The batch holds no records and declares no empty section.")
        if status not in ("success", "empty"):
            raise HTTPException(status_code=422, detail=str(res.get("message") or "The batch could not be stored."))

        counts = res.get("row_counts", {})
        ingested_counts = {
            name: counts.get(table, 0) for name, table in SUBMISSION_SECTIONS.items() if sections[name]
        }
        assessment_job: str | None = None
        replay = bool(res.get("idempotent_replay"))
        if not replay:
            sqlite_store.append_audit(
                action="api_batch_submission",
                actor=identity.username,
                details={
                    "entity_id": clean_id,
                    "period": payload.period,
                    "batch_id": res.get("batch_id"),
                    "revision_of": payload.revision_of,
                    "ingested_counts": ingested_counts,
                    "declared_empty": payload.declared_empty,
                },
            )
            if payload.run_assessment_now and any(ingested_counts.values()):
                assessment_job = enqueue_assessment(payload.period, identity, f"API batch {res.get('batch_id')}",
                                                    clean_id)["job_id"]
    finally:
        duckdb_store.close()
        sqlite_store.close()

    return {
        "status": "success",
        "idempotent_replay": replay,
        "entity_id": clean_id,
        "period": payload.period,
        "batch_id": res.get("batch_id"),
        "ingested_counts": ingested_counts,
        "declared_empty": payload.declared_empty,
        # Assessments run in the worker (satsa.jobs): the run id is on the job once it succeeds
        # (GET /api/v1/jobs/{assessment_job_id}). `assessment_run_id` stays for compatibility
        # and is always null from API 1.1 on.
        "assessment_run_id": None,
        "assessment_job_id": assessment_job,
        "message": (
            "This batch was already received; nothing new was stored."
            if replay
            else f"Stored periodic batch of {sum(ingested_counts.values())} records for {clean_id} / {payload.period}"
        ),
    }


# Examiner workflow (cases, response packages, blind-review tasks): satsa.api.case_routes.
from satsa.api.case_routes import router as _case_router

app.include_router(_case_router)

# Entity context (maintenance windows, rule exceptions, applicability): satsa.api.context_routes.
from satsa.api.context_routes import router as _context_router

app.include_router(_context_router)
