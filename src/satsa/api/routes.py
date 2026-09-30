"""FastAPI application providing offline server-rendered UI and REST endpoints."""

import csv
import hashlib
import io
import json
import logging
import os
import shutil
import statistics
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import polars as pl
import yaml
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from satsa.admin.rbac import SATSA_OPERATOR_ROLES, is_analyst, is_examiner
from satsa.auth.session import (
    SESSION_COOKIE_NAME,
    Identity,
    get_current_identity,
    require_authenticated,
    require_cse_access,
    require_role,
)
from satsa.bundle.rules_signer import RulePackKeyError, RulePackSigner
from satsa.explain.finding_card import FindingCard
from satsa.ingest.pipeline import IngestionPipeline, default_entity_record
from satsa.models.canonical import Entity
from satsa.models.outputs import ExaminerFeedback
from satsa.peers.grouping import PeerResolver
from satsa.report.generator import ReportGenerator, ReportNotFoundError
from satsa.scoring.history import seed_historical_periods
from satsa.scoring.runner import AssessmentRunner
from satsa.scoring.scorer import ScoringEngine, band_tier
from satsa.security import (
    is_valid_entity_id,
    is_valid_finding_id,
    is_valid_run_id,
    safe_archive_member,
    safe_join,
)
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.synth.generator import SyntheticDataGenerator

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

app = FastAPI(
    title="SAT-SA Supervisory API",
    description="Supervisory Analytics Tool for SOC Assessment (NCIIPC)",
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
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
templates.env.globals["band_tier"] = band_tier
templates.env.globals["is_analyst"] = is_analyst
templates.env.globals["is_examiner"] = is_examiner


# Paths anyone may reach without a session. Everything else requires one; the
# route's own dependency then enforces the specific role (see the RBAC table
# in tests/test_rbac_matrix.py, which must list every route).
PUBLIC_PATHS = {"/", "/login", "/logout", "/splash", "/api/session/status", "/openapi.json"}
PUBLIC_PREFIXES = ("/static/", "/docs")
# Non-page GET endpoints (JSON APIs and file downloads): an anonymous request
# gets 401 rather than a login redirect.
NON_PAGE_PREFIXES = ("/api/", "/reports/", "/templates/", "/tuning/export-pack")
NOT_SATSA_OPERATOR = (
    "This account is not a SAT-SA operator account (analyst or examiner). "
    "NCIIPC administrators use the Admin Portal at :8000."
)


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

    return await call_next(request)


def require_valid_entity_id(entity_id: str) -> str:
    """Reject an externally supplied entity_id that fails satsa.security.ENTITY_ID_RE (HTTP 400)."""
    if not is_valid_entity_id(entity_id):
        raise HTTPException(status_code=400, detail="Invalid entity_id.")
    return entity_id


def session_cookie_secure() -> bool:
    """Whether to set the Secure cookie flag (off by default: the app serves plain-HTTP localhost)."""
    return os.environ.get("SATSA_COOKIE_SECURE", "").lower() in ("1", "true", "yes")


def get_stores() -> tuple[DuckDBStore, SQLiteStore]:
    duckdb_store = DuckDBStore("data")
    duckdb_store.load_all_tables()
    sqlite_store = SQLiteStore("data/satsa.db")
    return duckdb_store, sqlite_store


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
    safe_next = next if (next.startswith("/") and not next.startswith("//")) else "/portfolio"
    # One generic message for unknown user, wrong passphrase AND lockout, so the
    # response never reveals whether a username exists or is locked.
    generic_error = RedirectResponse(
        url=f"/login?error={urllib.parse.quote_plus('Invalid username or passphrase.')}&next={safe_next}",
        status_code=303,
    )

    _, sqlite_store = get_stores()
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
            "Access Denied: This account has been blocked. Please contact an NCIIPC administrator."
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
    sqlite_store.append_audit(
        action="login", actor=identity_row["username"], details={"role": identity_row["role"]}
    )
    sqlite_store.record_live_event(
        "USER_LOGIN",
        actor=identity_row["username"],
        role=identity_row["role"],
        entity_id=identity_row.get("cse_id"),
        details={"org_id": identity_row.get("org_id")},
    )
    sqlite_store.close()

    resp = RedirectResponse(url=safe_next, status_code=303)
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=session_cookie_secure(),
        max_age=8 * 3600,
    )
    return resp


@app.post("/logout")
async def handle_logout(request: Request) -> Response:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        _, sqlite_store = get_stores()
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

    _, sqlite_store = get_stores()
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
async def view_portfolio(request: Request) -> Response:
    identity = get_current_identity(request)
    if identity is None:
        if request.url.path == "/portfolio":
            return RedirectResponse(url="/login?next=/portfolio", status_code=303)
        return templates.TemplateResponse(
            request=request,
            name="splash.html",
            context={"active_tab": "splash"},
        )

    duckdb_store, sqlite_store = get_stores()

    # Query latest run
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT run_id, period FROM runs ORDER BY created_at DESC LIMIT 1")
    run_row = cur.fetchone()
    period = run_row["period"] if run_row else "2026-Q1"
    run_id = run_row["run_id"] if run_row else ""

    # Fetch entities from DuckDB
    df_ent = duckdb_store.query("SELECT entity_id, name, sector, size_band FROM entity")
    ent_map = {row["entity_id"]: row for row in df_ent.iter_rows(named=True)}

    # Fetch entity scores from SQLite
    cur.execute(
        """
        SELECT entity_id, risk_index, risk_band, distinct_rules_triggered
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
        if r["entity_id"] in heatmap_entities and r["domain"] in domains:
            y_idx = heatmap_entities.index(r["entity_id"])
            x_idx = domains.index(r["domain"])
            heatmap_data.append([x_idx, y_idx, round(r["score"], 1)])

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

    # Counts
    cur.execute("SELECT count(*) FROM findings WHERE run_id = ?", (run_id,))
    total_findings = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM review_queue WHERE run_id = ?", (run_id,))
    queue_count = cur.fetchone()[0]

    critical_count = sum(1 for e in ranked_entities if band_tier(e["risk_band"]) != "low")

    # Cross-entity ("systemic") findings for this run -- a distinct section,
    # not folded into any per-entity finding card. See satsa.rules.systemic.
    systemic_findings = sqlite_store.get_systemic_findings(run_id)

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
            "queue_count": queue_count,
            "heatmap_entities": heatmap_entities,
            "heatmap_domains": domains,
            "heatmap_data": heatmap_data,
            "systemic_findings": systemic_findings,
        },
    )


@app.get("/entity/{entity_id}", response_class=HTMLResponse, dependencies=[Depends(require_authenticated)])
async def view_entity_profile(request: Request, entity_id: str) -> Response:
    require_valid_entity_id(entity_id)
    identity = get_current_identity(request)
    if identity:
        require_cse_access(entity_id, identity)
    duckdb_store, sqlite_store = get_stores()

    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1")
    run_row = cur.fetchone()
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
    score_dict = (
        dict(score_row)
        if score_row
        else {"risk_index": 0.0, "risk_band": "Low", "distinct_rules_triggered": 0}
    )

    # Fetch findings
    cur.execute(
        """
        SELECT finding_id, rule_id, domain, severity, score, title, rationale
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
    radar_entity_vals = [dom_scores.get(d, 0.0) for d in radar_domains]
    radar_peer_vals, peer_label = _peer_median_domain_scores(
        duckdb_store, cur, entity_id, run_id, radar_domains
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
        },
    )


MIN_PEERS_FOR_MEDIAN = 3


def _peer_median_domain_scores(
    duckdb_store: DuckDBStore, cur: Any, entity_id: str, run_id: str, domains: list[str]
) -> tuple[list[float] | None, str]:
    """Median domain score of the entity's peer cohort in this run (same resolver as scoring).

    Returns (None, reason) when the cohort is too small for a median that does not
    simply reveal one or two peers' scores.
    """
    all_entities = [Entity(**row) for row in duckdb_store.query("SELECT * FROM entity").iter_rows(named=True)]
    target = next((e for e in all_entities if e.entity_id == entity_id), None)
    if target is None or not run_id:
        return None, "no peer group"
    peers, cohort_label, _is_weak = PeerResolver().resolve_peers(target, all_entities)
    if len(peers) < MIN_PEERS_FOR_MEDIAN:
        return None, f"fewer than {MIN_PEERS_FOR_MEDIAN} peers"
    placeholders = ",".join("?" for _ in peers)
    cur.execute(
        f"SELECT entity_id, domain, score FROM domain_scores WHERE run_id = ? AND entity_id IN ({placeholders})",
        (run_id, *peers),
    )
    by_domain: dict[str, dict[str, float]] = {}
    for r in cur.fetchall():
        by_domain.setdefault(r["domain"], {})[r["entity_id"]] = float(r["score"])
    # A peer with no finding in a domain has no domain_scores row: that is a score of 0.
    medians = [float(statistics.median(by_domain.get(d, {}).get(p, 0.0) for p in peers)) for d in domains]
    return medians, f"{cohort_label} ({len(peers)} peers)"


def _kpi_reconciliation(duckdb_store: DuckDBStore, entity_id: str) -> list[dict[str, Any]]:
    """Declared vs recomputed MTTR per declared High/Critical severity (EG10's comparison)."""
    df = duckdb_store.query(
        """
        WITH declared AS (
            SELECT severity, avg(value) AS declared
            FROM declared_kpi
            WHERE entity_id = ? AND metric = 'MTTR' AND severity IN ('high', 'critical')
            GROUP BY severity
        ),
        empirical AS (
            SELECT severity_final AS severity, avg(epoch(closed_at) - epoch(created_at)) / 60.0 AS empirical
            FROM alert
            WHERE entity_id = ? AND severity_final IN ('high', 'critical') AND closed_at IS NOT NULL
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


@app.get("/finding/{finding_id}", response_class=HTMLResponse, dependencies=[Depends(require_authenticated)])
async def view_finding_detail(request: Request, finding_id: str) -> Response:
    _, sqlite_store = get_stores()
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
        peer_comparison=json.loads(f_row["peer_comparison_json"] or "{}"),
        limitations=f_row["limitations"]
        or "Evaluated on ingested metadata; raw payload inspection not performed.",
        benign_explanations=json.loads(f_row["benign_explanations_json"] or "[]"),
        examiner_check=f_row["examiner_check"],
        evidence_records=evidences,
    )
    identity = get_current_identity(request)
    if identity:
        sqlite_store.record_live_event(
            "FINDING_VIEWED",
            actor=identity.username,
            role=identity.role,
            entity_id=card.entity_id,
            details={"finding_id": finding_id, "rule_id": card.rule_id, "title": card.title},
        )
    sqlite_store.close()

    return templates.TemplateResponse(
        request=request,
        name="finding_detail.html",
        context={"active_tab": "portfolio", "card": card},
    )


@app.get("/queue", response_class=HTMLResponse, dependencies=[Depends(require_authenticated)])
async def view_review_queue(request: Request) -> Response:
    _, sqlite_store = get_stores()
    cur = sqlite_store.conn.cursor()
    cur.execute("""
        SELECT queue_id, run_id, entity_id, record_type, record_id, severity, score, selection_reason, is_random, examiner_status
        FROM review_queue
        ORDER BY score DESC, queue_id ASC
        LIMIT 200
    """)
    queue_items = [dict(r) for r in cur.fetchall()]
    sqlite_store.close()

    return templates.TemplateResponse(
        request=request,
        name="review_queue.html",
        context={"active_tab": "queue", "queue_items": queue_items},
    )


@app.get("/dq", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def view_dq_coverage(request: Request) -> Response:
    _, sqlite_store = get_stores()
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
    _, sqlite_store = get_stores()
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
    _, sqlite_store = get_stores()
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
    _, sqlite_store = get_stores()
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
    _, sqlite_store = get_stores()
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT * FROM runs ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    sqlite_store.close()
    return rows


@app.get("/api/v1/entities", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def api_list_entities() -> list[dict[str, Any]]:
    duckdb_store, sqlite_store = get_stores()
    df_ent = duckdb_store.query("SELECT entity_id, name, sector, size_band FROM entity")
    ent_map = {row["entity_id"]: row for row in df_ent.iter_rows(named=True)}

    cur = sqlite_store.conn.cursor()
    cur.execute("""
        SELECT entity_id, risk_index, risk_band, distinct_rules_triggered
        FROM entity_scores
        ORDER BY risk_index DESC
    """)
    rows = []
    for r in cur.fetchall():
        eid = r["entity_id"]
        e_info = ent_map.get(eid, {"name": eid, "sector": "general", "size_band": "medium"})
        rows.append(
            {
                "entity_id": eid,
                "name": e_info["name"],
                "sector": e_info["sector"],
                "risk_index": r["risk_index"],
                "risk_band": r["risk_band"],
                "distinct_rules_triggered": r["distinct_rules_triggered"],
            }
        )
    duckdb_store.close()
    sqlite_store.close()
    return rows


@app.get("/api/v1/findings", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def api_list_findings(entity_id: str | None = None) -> list[dict[str, Any]]:
    _, sqlite_store = get_stores()
    cur = sqlite_store.conn.cursor()
    if entity_id:
        cur.execute("SELECT * FROM findings WHERE entity_id = ? ORDER BY score DESC", (entity_id,))
    else:
        cur.execute("SELECT * FROM findings ORDER BY score DESC")
    rows = [dict(r) for r in cur.fetchall()]
    sqlite_store.close()
    return rows


@app.get("/api/v1/queue", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def api_get_queue(entity_id: str | None = None) -> list[dict[str, Any]]:
    _, sqlite_store = get_stores()
    cur = sqlite_store.conn.cursor()
    if entity_id:
        cur.execute(
            "SELECT * FROM review_queue WHERE entity_id = ? ORDER BY score DESC", (entity_id,)
        )
    else:
        cur.execute("SELECT * FROM review_queue ORDER BY score DESC")
    rows = [dict(r) for r in cur.fetchall()]
    sqlite_store.close()
    return rows


@app.post("/api/v1/feedback")
async def api_submit_feedback(
    queue_id: Annotated[str, Form()],
    status: Annotated[str, Form()] = "confirmed",
    notes: Annotated[str, Form()] = "",
    identity: Identity = Depends(require_role(*REVIEW_ROLES)),
) -> RedirectResponse:
    _, sqlite_store = get_stores()
    import hashlib

    examiner_id = identity.username
    fb_id = hashlib.sha256(f"{queue_id}:{examiner_id}:{status}".encode()).hexdigest()[:16]

    feedback = ExaminerFeedback(
        feedback_id=fb_id, queue_id=queue_id, examiner_id=examiner_id, status=status, notes=notes
    )
    sqlite_store.save_feedback(feedback)
    sqlite_store.append_audit(
        action="feedback",
        actor=examiner_id,
        details={"queue_id": queue_id, "status": status, "notes": notes},
    )
    sqlite_store.close()
    return RedirectResponse(url="/queue", status_code=303)


@app.get("/api/v1/audit/verify", dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def api_verify_audit() -> dict[str, Any]:
    _, sqlite_store = get_stores()
    ok, msg = sqlite_store.verify_audit_chain()
    sqlite_store.close()
    return {"verified": ok, "message": msg}


@app.get("/api/v1/export/queue.csv", dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def api_export_queue_csv() -> Response:
    _, sqlite_store = get_stores()
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT * FROM review_queue ORDER BY score DESC")
    rows = cur.fetchall()
    sqlite_store.close()

    output = io.StringIO()
    writer = csv.writer(output)
    if rows:
        writer.writerow(rows[0].keys())
        for r in rows:
            writer.writerow(list(r))

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

    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context={
            "active_tab": "upload",
            "message": message,
            "recent_batches": recent_batches,
            "all_entities": all_entities,
        },
    )


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

    duckdb_store, sqlite_store = get_stores()

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
            "metric": "mtta",
            "severity": "all",
            "value": float(declared_mtta),
        },
        {
            "entity_id": clean_id,
            "period": "2026-Q1",
            "metric": "mttr",
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

    # 4. Run assessment to establish baseline
    runner = AssessmentRunner(duckdb_store, sqlite_store)
    run_res = runner.run_assessment(period="2026-Q1", actor=identity.username)

    duckdb_store.close()
    sqlite_store.close()

    msg = f"Entity {clean_id} successfully registered! Sector: {resolved_sector} | Assessment Run: {run_res.get('run_id')}"
    return RedirectResponse(url=f"/upload?message={msg}", status_code=303)


@app.post("/upload/delete-entity/{entity_id}")
async def handle_delete_entity(
    entity_id: str, identity: Identity = Depends(require_role(*INGEST_RUN_ROLES))
) -> Response:
    """Permanently delete an entity, its data partitions, and recalculate portfolio."""
    clean_id = require_valid_entity_id(entity_id.strip().upper())
    duckdb_store, sqlite_store = get_stores()

    # 1. Delete from SQLite
    cur = sqlite_store.conn.cursor()
    cur.execute("DELETE FROM entities WHERE entity_id = ?", (clean_id,))
    cur.execute("DELETE FROM entity_scores WHERE entity_id = ?", (clean_id,))
    cur.execute("DELETE FROM findings WHERE entity_id = ?", (clean_id,))
    cur.execute("DELETE FROM domain_scores WHERE entity_id = ?", (clean_id,))
    cur.execute("DELETE FROM review_queue WHERE entity_id = ?", (clean_id,))
    cur.execute("DELETE FROM submitted_tables WHERE entity_id = ?", (clean_id,))
    sqlite_store.conn.commit()

    # 2. Delete from DuckDB parquet files: only the exact `entity_id=<id>`
    # partition directory under each table (no glob patterns, so an ID can
    # never match another entity's partitions), confined to the parquet root.
    parquet_root = duckdb_store.parquet_dir
    partition_name = f"entity_id={clean_id}"
    if parquet_root.is_dir():
        for table_dir in parquet_root.iterdir():
            if not table_dir.is_dir():
                continue
            part = safe_join(parquet_root, f"{table_dir.name}/{partition_name}")
            if part.is_dir() and part.name == partition_name:
                shutil.rmtree(part, ignore_errors=True)

    # 3. Audit log
    sqlite_store.append_audit(
        action="delete_entity",
        actor=identity.username,
        details={"entity_id": clean_id},
    )

    # 4. Trigger assessment run to re-score remaining entities
    runner = AssessmentRunner(duckdb_store, sqlite_store)
    runner.run_assessment(period="2026-Q1", actor=identity.username)

    duckdb_store.close()
    sqlite_store.close()

    return RedirectResponse(
        url=f"/upload?message=Entity+{clean_id}+has+been+permanently+deleted+and+portfolio+recalculated.",
        status_code=303,
    )


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
    identity: Identity = Depends(require_role(*INGEST_RUN_ROLES)),
) -> Response:
    target_clean = target_entity.strip() or None
    if target_clean is not None and not is_valid_entity_id(target_clean):
        return RedirectResponse(
            url="/upload?message=Error:+invalid+target+entity+ID", status_code=303
        )
    duckdb_store, sqlite_store = get_stores()
    pipeline = IngestionPipeline(duckdb_store, sqlite_store)

    try:
        sqlite_store.record_live_event(
            "ASSESSMENT_UPLOAD",
            actor=identity.username,
            role=identity.role,
            entity_id=target_clean,
            details={"file_count": len(files), "filenames": [uf.filename for uf in files]},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            for uf in files:
                # Only the base name of the client-supplied filename is used, so a
                # name like "../../x.csv" cannot write outside the temp directory.
                safe_name = Path((uf.filename or "").replace("\\", "/")).name or "upload.csv"
                dest = tmp_path / safe_name
                with open(dest, "wb") as f:
                    shutil.copyfileobj(uf.file, f)
                # If ZIP, validate every member path before unpacking anything.
                if dest.suffix.lower() == ".zip":
                    with zipfile.ZipFile(dest, "r") as z:
                        for member in z.namelist():
                            safe_archive_member(member)
                        z.extractall(tmp_path)

            res = pipeline.ingest_directory(
                tmp_path, default_entity_id=target_clean
            )

            if res.get("status") == "empty":
                msg = "Warning: No supported CSV/JSON files could be parsed from upload."
            elif res.get("status") == "error":
                msg = f"Error: {res.get('message', 'Failed to ingest batch')}"
            elif res.get("status") == "partial":
                # Do not assess on a half-stored submission: a missing table reads as a SOC defect.
                msg = (
                    "Error: these tables could not be stored: "
                    f"{', '.join(res.get('failed_tables', []))}. No assessment was run; see Data Quality, "
                    "fix the files and upload again."
                )
            else:
                # Trigger assessment run
                sqlite_store.record_live_event(
                    "ASSESSMENT_STARTED",
                    actor=identity.username,
                    role=identity.role,
                    entity_id=target_clean or "PORTFOLIO",
                    details={"period": "2026-Q1"},
                )
                runner = AssessmentRunner(duckdb_store, sqlite_store)
                run_res = runner.run_assessment(period="2026-Q1", actor=identity.username)
                sqlite_store.record_live_event(
                    "ASSESSMENT_COMPLETED",
                    actor=identity.username,
                    role=identity.role,
                    entity_id=target_clean or "PORTFOLIO",
                    details={"period": "2026-Q1", "findings_count": run_res.get("findings_count", 0)},
                )

                detected = ", ".join(res.get("entities", [])) or target_entity or "Auto"
                row_str = " | ".join(f"{k}: {v}" for k, v in res.get("row_counts", {}).items())
                msg = (
                    f"Batch ingested successfully! [{row_str}] | Entities: {detected} | "
                    f"Assessment: {run_res.get('findings_count', 0)} findings flagged."
                )
                skipped = res.get("unattributed_rows") or {}
                if skipped:
                    counts = ", ".join(f"{t}: {n}" for t, n in sorted(skipped.items()))
                    msg += (
                        f" | Warning: rows with no entity_id were not stored [{counts}]; "
                        "add an entity_id column or choose a target entity."
                    )
    except (ValueError, KeyError, OSError, RuntimeError) as e:
        msg = f"Ingestion error: {e}"
    finally:
        duckdb_store.close()
        sqlite_store.close()

    return RedirectResponse(url=f"/upload?message={msg}", status_code=303)


@app.post("/upload/trigger-demo")
def handle_trigger_demo(
    identity: Identity = Depends(require_role(*INGEST_RUN_ROLES)),
) -> Response:
    """One-click demo re-seed and assessment execution.

    Also seeds genuine multi-period historical runs (see
    satsa.scoring.history.seed_historical_periods) so the portfolio trend
    chart has real, non-fabricated historical data to plot immediately
    after the demo re-seed.
    """
    duckdb_store, sqlite_store = get_stores()
    sqlite_store.record_live_event(
        "ASSESSMENT_STARTED",
        actor=identity.username,
        role=identity.role,
        entity_id="DEMO_PORTFOLIO",
        details={"period": "2026-Q1", "mode": "demo_seed"},
    )
    gen = SyntheticDataGenerator(seed=42, base_alerts_per_entity=1500)
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_dir, _ = gen.save_dataset(Path(tmpdir))
        pipeline = IngestionPipeline(duckdb_store, sqlite_store)
        _ = pipeline.ingest_directory(csv_dir)
        runner = AssessmentRunner(duckdb_store, sqlite_store)
        run_res = runner.run_assessment(period="2026-Q1", actor=identity.username)

    duckdb_store.close()

    seed_historical_periods("data", sqlite_store, n_periods=3, actor=identity.username)
    sqlite_store.record_live_event(
        "ASSESSMENT_COMPLETED",
        actor=identity.username,
        role=identity.role,
        entity_id="DEMO_PORTFOLIO",
        details={"period": "2026-Q1", "findings_count": run_res.get("findings_count", 0)},
    )
    sqlite_store.close()
    return RedirectResponse(url="/", status_code=303)


@app.get("/blind-review", response_class=HTMLResponse, dependencies=[Depends(require_authenticated)])
async def view_blind_review(request: Request, entity_id: str = "CSE-02") -> Response:
    require_valid_entity_id(entity_id)
    duckdb_store, sqlite_store = get_stores()

    df_ents = duckdb_store.query("SELECT entity_id FROM entity ORDER BY entity_id")
    all_entities = [r["entity_id"] for r in df_ents.iter_rows(named=True)]
    if entity_id not in all_entities and all_entities:
        entity_id = all_entities[0]

    # Compute raw objective signals without revealing risk scores
    m_df = duckdb_store.query("""
        SELECT
            count(*) as total_alerts,
            ROUND(quantile_cont(epoch(acknowledged_at - created_at) / 60.0, 0.5), 1) as median_mtta_min,
            ROUND(quantile_cont(epoch(closed_at - created_at) / 60.0, 0.5), 1) as median_mttr_min,
            count(CASE WHEN closed_by_type = 'soar' THEN 1 END) * 100.0 / greatest(count(*), 1) as soar_share,
            count(CASE WHEN disposition = 'false_positive' THEN 1 END) * 100.0 / greatest(count(*), 1) as fp_rate
        FROM alert
        WHERE entity_id = ?
    """, [entity_id]).to_dicts()[0]

    # Declared MTTR
    kpi_df = duckdb_store.query(
        "SELECT value FROM declared_kpi WHERE entity_id = ? AND metric = 'mttr' LIMIT 1",
        [entity_id],
    )
    declared_mttr = kpi_df.to_dicts()[0]["value"] if not kpi_df.is_empty() else "N/A"

    # Escalations
    esc_df = duckdb_store.query(
        "SELECT count(*) as c FROM alert WHERE entity_id = ? AND severity_final IN ('high', 'critical')",
        [entity_id],
    )
    tot_high = esc_df.to_dicts()[0]["c"] if not esc_df.is_empty() else 1
    esc_c_df = duckdb_store.query(
        "SELECT count(*) as c FROM escalation WHERE entity_id = ?", [entity_id]
    )
    tot_esc = esc_c_df.to_dicts()[0]["c"] if not esc_c_df.is_empty() else 0
    esc_rate = round((tot_esc / max(tot_high, 1)) * 100.0, 1)

    # Silent assets
    silent_df = duckdb_store.query("""
        SELECT count(*) as c FROM asset
        WHERE entity_id = ? AND criticality >= 3 AND asset_id NOT IN (
            SELECT DISTINCT asset_id FROM log_source_daily WHERE entity_id = ?
        )
    """, [entity_id, entity_id])
    silent_assets = silent_df.to_dicts()[0]["c"] if not silent_df.is_empty() else 0

    # Sample anonymized comments
    c_df = duckdb_store.query(
        "SELECT comment_norm_hash FROM closure WHERE entity_id = ? LIMIT 5", [entity_id]
    )
    sample_comments = [
        f"Normalised closure text hash: {r['comment_norm_hash']}" for r in c_df.to_dicts()
    ]

    metrics = {
        "total_alerts": m_df.get("total_alerts", 0),
        "median_mtta_min": m_df.get("median_mtta_min", 0.0),
        "median_mttr_min": m_df.get("median_mttr_min", 0.0),
        "declared_mttr": declared_mttr,
        "soar_share": round(m_df.get("soar_share", 0.0), 1),
        "fp_rate": round(m_df.get("fp_rate", 0.0), 1),
        "esc_rate": esc_rate,
        "silent_assets": silent_assets,
        "sample_comments": sample_comments,
    }

    # Fetch latest blind review for this entity if present
    cur = sqlite_store.conn.cursor()
    cur.execute(
        "SELECT * FROM blind_reviews WHERE entity_id = ? ORDER BY created_at DESC LIMIT 1",
        (entity_id,),
    )
    latest_row = cur.fetchone()
    latest_review = dict(latest_row) if latest_row else None

    # Fetch system findings for the reveal
    cur.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1")
    run_row = cur.fetchone()
    run_id = run_row["run_id"] if run_row else ""

    cur.execute(
        "SELECT rule_id, title, score FROM findings WHERE entity_id = ? AND run_id = ?",
        (entity_id, run_id),
    )
    system_findings = [dict(r) for r in cur.fetchall()]

    historical_reviews = sqlite_store.get_blind_reviews(entity_id)

    duckdb_store.close()
    sqlite_store.close()

    return templates.TemplateResponse(
        request=request,
        name="blind_review.html",
        context={
            "active_tab": "blind_review",
            "all_entities": all_entities,
            "selected_entity": entity_id,
            "metrics": metrics,
            "latest_review": latest_review,
            "system_findings": system_findings,
            "historical_reviews": historical_reviews,
        },
    )


@app.post("/blind-review/submit")
async def handle_blind_review_submit(
    entity_id: Annotated[str, Form()],
    examiner_concern: Annotated[str, Form()],
    examiner_priority: Annotated[str, Form()],
    examiner_recommendation: Annotated[str, Form()],
    examiner_notes: Annotated[str, Form()],
    identity: Identity = Depends(require_role(*REVIEW_ROLES)),
) -> Response:
    require_valid_entity_id(entity_id)
    _, sqlite_store = get_stores()
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1")
    run_row = cur.fetchone()
    run_id = run_row["run_id"] if run_row else ""

    cur.execute(
        "SELECT risk_index, risk_band FROM entity_scores WHERE entity_id = ? AND run_id = ?",
        (entity_id, run_id),
    )
    score_row = cur.fetchone()
    sys_index = score_row["risk_index"] if score_row else 0.0
    sys_band = score_row["risk_band"] if score_row else "Low Supervisory Concern"

    # Compute concordance score (0-100%)
    concern_levels = {"Low": 1, "Moderate": 2, "Elevated": 3, "Critical": 4}
    band_levels = {
        "Low Supervisory Concern": 1,
        "Moderate Supervisory Concern": 2,
        "Elevated Concern": 3,
        "High Concern": 4,
    }
    examiner_num = concern_levels.get(examiner_concern, 2)
    sys_num = 1
    for k, v in band_levels.items():
        if k.lower() in sys_band.lower():
            sys_num = v
            break

    diff = abs(examiner_num - sys_num)
    concordance = max(0.0, round(100.0 - (diff * 25.0), 1))

    rev_id = f"BLIND-{hashlib.sha256(f'{entity_id}:{run_id}:{examiner_concern}'.encode()).hexdigest()[:12]}"
    sqlite_store.save_blind_review(
        review_id=rev_id,
        entity_id=entity_id,
        run_id=run_id,
        examiner_id=identity.username,
        examiner_concern=examiner_concern,
        examiner_priority=examiner_priority,
        examiner_recommendation=examiner_recommendation,
        examiner_notes=examiner_notes,
        system_risk_index=sys_index,
        system_risk_band=sys_band,
        concordance_score=concordance,
    )
    sqlite_store.close()

    return RedirectResponse(url=f"/blind-review?entity_id={entity_id}", status_code=303)


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
]

RULES_CONFIG_PATH = Path("config/rules.yaml")


def _load_rules_config() -> dict[str, Any]:
    if not RULES_CONFIG_PATH.exists():
        return {"rules": {}}
    return yaml.safe_load(RULES_CONFIG_PATH.read_text(encoding="utf-8")) or {"rules": {}}


def _write_rules_config(cfg: dict[str, Any]) -> None:
    """Write config/rules.yaml, preserving its leading comment header."""
    header = ""
    if RULES_CONFIG_PATH.exists():
        lines = RULES_CONFIG_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
        for line in lines:
            if not line.startswith("#"):
                break
            header += line
    RULES_CONFIG_PATH.write_text(
        header + yaml.dump(cfg, sort_keys=False, width=100), encoding="utf-8"
    )


def _tunable_param_rows(rules_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """TUNABLE_PARAMS annotated with each parameter's current configured value."""
    rows = []
    for spec in TUNABLE_PARAMS:
        current = (
            rules_cfg.get("rules", {}).get(spec["rule"], {}).get("params", {}).get(spec["key"])
        )
        rows.append({**spec, "field": f"{spec['rule']}__{spec['key']}", "value": current})
    return rows


@app.get("/tuning", response_class=HTMLResponse, dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def view_tuning(request: Request, message: str = "") -> Response:
    rules_cfg = _load_rules_config()
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
    cfg = _load_rules_config()
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

    if changes:
        _write_rules_config(cfg)

    # Re-evaluate with the (possibly) updated thresholds
    duckdb_store, sqlite_store = get_stores()
    runner = AssessmentRunner(duckdb_store, sqlite_store)
    res = runner.run_assessment(period="2026-Q1", actor=identity.username)
    sqlite_store.append_audit(
        action="tuning_save",
        actor=identity.username,
        details={"changes": changes, "run_id": res.get("run_id")},
    )
    duckdb_store.close()
    sqlite_store.close()

    msg = f"Parameters updated and re-calibrated! New Run ID: {res.get('run_id')} | Findings: {res.get('findings_count')}"
    return RedirectResponse(url=f"/tuning?message={msg}", status_code=303)


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
    _, sqlite_store = get_stores()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
        shutil.copyfileobj(pack_file.file, tmp)
        tmp_path = Path(tmp.name)

    try:
        res = signer.import_rule_pack(
            tmp_path,
            target_config_dir="config",
            sqlite_store=sqlite_store,
            actor=identity.username,
        )
        msg = f"Rule pack verified and installed! Version: {res.get('version')} | Files: {res.get('files_imported')}"
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
            f"SAT-SA_CSE_{entity_id}_Report_{meta.run_id}.pdf",
            lambda path: rep.generate_entity_pdf(entity_id, path, meta.run_id),
        )

    return _pdf_response(request, "entity_pdf", prepare, entity_id=entity_id)


@app.get("/reports/portfolio/pdf", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def download_portfolio_pdf(request: Request, run_id: str | None = None) -> FileResponse:
    require_valid_run_id(run_id)

    def prepare(rep: ReportGenerator) -> tuple[str, Callable[[Path], Path]]:
        meta = rep.resolve_run(run_id)
        return (
            f"SAT-SA_Portfolio_Report_{meta.run_id}.pdf",
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
            "SELECT entity_id FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise ReportNotFoundError("Finding")
        if identity:
            require_cse_access(row["entity_id"], identity)
        return (
            f"SAT-SA_Finding_{finding_id}.pdf",
            lambda path: rep.generate_finding_pdf(finding_id, path),
        )

    return _pdf_response(request, "finding_pdf", prepare)


@app.get("/reports/entity/{entity_id}/html", dependencies=[Depends(require_authenticated)])
async def download_entity_html(request: Request, entity_id: str) -> FileResponse:
    require_valid_entity_id(entity_id)
    identity = get_current_identity(request)
    if identity:
        require_cse_access(entity_id, identity)
    duckdb_store, sqlite_store = get_stores()
    rep = ReportGenerator(duckdb_store, sqlite_store)
    html_path = Path(f"reports/{entity_id}_supervisory_report.html")
    rep.generate_entity_html(entity_id, html_path)
    actor = identity.username if identity else "operator"
    role = identity.role if identity else "examiner"
    sqlite_store.record_live_event("REPORT_GENERATED", actor=actor, role=role, entity_id=entity_id, details={"report": "entity_html"})
    sqlite_store.record_live_event("REPORT_DOWNLOADED", actor=actor, role=role, entity_id=entity_id, details={"report": "entity_html"})
    duckdb_store.close()
    sqlite_store.close()

    return FileResponse(
        path=html_path,
        filename=f"{entity_id}_Supervisory_Report.html",
        media_type="text/html",
    )


@app.get("/reports/portfolio/html", dependencies=[Depends(require_role(*SUPERVISORY_READ_ROLES))])
async def download_portfolio_html(request: Request) -> FileResponse:
    duckdb_store, sqlite_store = get_stores()
    rep = ReportGenerator(duckdb_store, sqlite_store)
    p_path = Path("reports/portfolio_summary_report.html")
    rep.generate_portfolio_html(p_path)
    identity = get_current_identity(request)
    actor = identity.username if identity else "operator"
    role = identity.role if identity else "examiner"
    sqlite_store.record_live_event("REPORT_GENERATED", actor=actor, role=role, details={"report": "portfolio_html"})
    sqlite_store.record_live_event("REPORT_DOWNLOADED", actor=actor, role=role, details={"report": "portfolio_html"})
    duckdb_store.close()
    sqlite_store.close()

    return FileResponse(
        path=p_path,
        filename="NCIIPC_Portfolio_Supervisory_Report.html",
        media_type="text/html",
    )


@app.get("/reports/export/findings-csv", dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def download_findings_csv(request: Request) -> FileResponse:
    duckdb_store, sqlite_store = get_stores()
    rep = ReportGenerator(duckdb_store, sqlite_store)
    f_path = Path("reports/findings_export.csv")
    rep.export_findings_csv(f_path)
    identity = get_current_identity(request)
    actor = identity.username if identity else "operator"
    role = identity.role if identity else "examiner"
    sqlite_store.record_live_event("REPORT_GENERATED", actor=actor, role=role, details={"report": "findings_csv"})
    sqlite_store.record_live_event("REPORT_DOWNLOADED", actor=actor, role=role, details={"report": "findings_csv"})
    duckdb_store.close()
    sqlite_store.close()

    return FileResponse(
        path=f_path,
        filename="SATSA_Findings_Export.csv",
        media_type="text/csv",
    )


@app.get("/reports/export/queue-csv", dependencies=[Depends(require_role(*ANALYST_ROLES))])
async def download_queue_csv() -> FileResponse:
    duckdb_store, sqlite_store = get_stores()
    rep = ReportGenerator(duckdb_store, sqlite_store)
    q_path = Path("reports/review_queue_export.csv")
    rep.export_queue_csv(q_path)
    duckdb_store.close()
    sqlite_store.close()

    return FileResponse(
        path=q_path,
        filename="SATSA_Review_Queue_Export.csv",
        media_type="text/csv",
    )


# Supervisory review period label, e.g. "2026-Q1", "2026-H2" or "2026-03".
PERIOD_RE = r"^\d{4}-(Q[1-4]|H[12]|0[1-9]|1[0-2])$"


class BatchSubmissionPayload(BaseModel):
    entity_id: str = Field(..., description="Unique code for the CSE, e.g. CSE-11")
    period: str = Field(
        default="2026-Q1", pattern=PERIOD_RE, description="Supervisory review period (e.g. 2026-Q1)"
    )
    alerts: list[dict[str, Any]] = Field(
        default=[], description="List of alert metadata dictionaries"
    )
    cases: list[dict[str, Any]] = Field(
        default=[], description="List of case management record dictionaries"
    )
    assets: list[dict[str, Any]] = Field(
        default=[], description="List of asset inventory dictionaries"
    )
    closures: list[dict[str, Any]] = Field(default=[], description="List of closure dictionaries")
    run_assessment_now: bool = Field(
        default=True, description="Whether to run the periodic assessment after the batch is stored"
    )


@app.post("/api/v1/submissions", tags=["Periodic Batch Submission"])
async def api_batch_submission(
    payload: BatchSubmissionPayload,
    identity: Identity = Depends(require_role(*INGEST_RUN_ROLES)),
) -> dict[str, Any]:
    """
    Submit ONE periodic batch (a CSE's alert/case/asset/closure records for a
    supervisory review period) as JSON -- the programmatic equivalent of the
    /upload file submission, used after the fact at each assessment cycle.

    This is not a streaming or event-driven feed: each (entity_id, period) may be
    submitted exactly once. A repeat submission for the same entity and period is
    rejected with HTTP 409, so the endpoint cannot be used as a continuous
    collection channel. Corrections to an already-submitted period go through a
    supervised re-ingest (/upload) by an analyst.

    Requires an authenticated analyst session (POST /login first and
    retain the session cookie).
    """
    clean_id = payload.entity_id.strip().upper()
    if not clean_id:
        raise HTTPException(status_code=400, detail="entity_id is required")
    require_valid_entity_id(clean_id)
    for rows in (payload.alerts, payload.cases, payload.assets, payload.closures):
        for row in rows:
            row_eid = row.get("entity_id")
            if row_eid and not is_valid_entity_id(str(row_eid)):
                raise HTTPException(status_code=400, detail="Invalid entity_id in submitted rows.")

    duckdb_store, sqlite_store = get_stores()
    try:
        # Claim the (entity, period) slot first: it is unique, so a concurrent or
        # repeated submission fails here before any data is written.
        if not sqlite_store.claim_batch_submission(clean_id, payload.period, identity.username):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"A batch for {clean_id} / {payload.period} has already been submitted. "
                    "Each entity and period may be submitted once; use a supervised re-ingest "
                    "via /upload for corrections."
                ),
            )
        ingested_counts: dict[str, int] = {}
        submitted_eids: set[str] = set()
        new_entities: list[dict[str, Any]] = []
        stored_tables: list[str] = []
        try:
            # canonical DuckDB table for each payload section
            for section, table, rows in (
                ("alerts", "alert", payload.alerts),
                ("cases", "case", payload.cases),
                ("assets", "asset", payload.assets),
                ("closures", "closure", payload.closures),
            ):
                if not rows:
                    continue
                for r in rows:
                    if not r.get("entity_id"):
                        r["entity_id"] = clean_id
                    submitted_eids.add(str(r["entity_id"]))
                duckdb_store.write_partitioned_parquet(table, pl.DataFrame(rows))
                ingested_counts[section] = len(rows)
                stored_tables.append(table)

            # The assessment (and so every UI view) only covers registered
            # entities, so a CSE first seen in this batch is registered here,
            # exactly as the /upload pipeline auto-registers one.
            registered = set(duckdb_store.query("SELECT entity_id FROM entity")["entity_id"].to_list())
            new_entities = [default_entity_record(e) for e in sorted(submitted_eids - registered)]
            if new_entities:
                duckdb_store.write_partitioned_parquet("entity", pl.DataFrame(new_entities))
        except Exception:
            # Nothing usable was stored: free the slot so the batch can be resubmitted.
            sqlite_store.release_batch_submission(clean_id, payload.period)
            raise

        # Submission manifest: this endpoint carries only these sections, so rules that need
        # other tables (escalations, workflow events, ...) are reported as not assessed
        # rather than read as SOC defects.
        sqlite_store.record_submitted_tables(submitted_eids | {clean_id}, stored_tables)

        sqlite_store.append_audit(
            action="api_batch_submission",
            actor=identity.username,
            details={
                "entity_id": clean_id,
                "period": payload.period,
                "ingested_counts": ingested_counts,
                "entities_registered": [e["entity_id"] for e in new_entities],
            },
        )

        run_id = None
        if payload.run_assessment_now and any(ingested_counts.values()):
            runner = AssessmentRunner(duckdb_store, sqlite_store)
            res = runner.run_assessment(period=payload.period, actor=identity.username)
            run_id = res.get("run_id")
    finally:
        duckdb_store.close()
        sqlite_store.close()

    return {
        "status": "success",
        "entity_id": clean_id,
        "period": payload.period,
        "ingested_counts": ingested_counts,
        "assessment_run_id": run_id,
        "message": f"Stored periodic batch of {sum(ingested_counts.values())} records for {clean_id} / {payload.period}",
    }
