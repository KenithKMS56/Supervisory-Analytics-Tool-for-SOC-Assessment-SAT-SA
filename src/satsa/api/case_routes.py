"""Routes of the examiner workflow: supervisory cases, response packages and blind-review tasks
(satsa.cases; docs/examiner_workflow.md). Included by satsa.api.routes.

Examiners act; analysts read cases and draw blind samples. The rules of every transition live
in satsa.cases.workflow, not here: these handlers only translate HTTP to it and its errors
(CaseError.status) back to HTTP.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

import duckdb
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from satsa.admin.rbac import is_analyst as is_analyst_role
from satsa.auth.session import Identity, get_current_identity, require_role
from satsa.cases import blind, packages, workflow
from satsa.cases.workflow import CASE_ID_RE, STATE_LABELS, Attachment, CaseError
from satsa.security import is_valid_finding_id
from satsa.store.sqlite import SQLiteStore

router = APIRouter()

REVIEW = ("examiner",)
ANALYST = ("analyst",)
READ = ("analyst", "examiner")
DATA_DIR = "data"


def _templates() -> Any:
    from satsa.api.routes import templates

    return templates


def _store() -> SQLiteStore:
    return SQLiteStore(f"{DATA_DIR}/satsa.db")


def _case_id(case_id: str) -> str:
    if not CASE_ID_RE.match(case_id):
        raise HTTPException(status_code=400, detail="Malformed case id")
    return case_id


def _task_id(task_id: str) -> str:
    if not blind.TASK_ID_RE.match(task_id):
        raise HTTPException(status_code=400, detail="Malformed task id")
    return task_id


async def _read_upload(upload: UploadFile, limit: int, what: str) -> bytes:
    data = await upload.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"{what} is larger than {limit // (1024 * 1024)} MiB")
    return data


# ---- cases: pages -------------------------------------------------------------------------------


def _case_context(store: SQLiteStore, case: dict[str, Any], identity: Identity | None) -> dict[str, Any]:
    evts = workflow.events(store, case["case_id"])
    actor, role = (identity.username, identity.role) if identity else ("", "")
    return {
        "case": case,
        "state_label": STATE_LABELS[case["state"]],
        "events": evts,
        "attachments": workflow.attachments(store, case["case_id"]),
        "corrective_actions": workflow.corrective_actions(store, case["case_id"]),
        "packages": packages.packages(store, case["case_id"]),
        "allowed": workflow.allowed_actions(store, case, actor, role),
        "reassessment": workflow.reassessment(store, case),
        "lineage": workflow.linked_findings(store, case),
        "dissent": workflow.unresolved_disagreement(evts),
        "examiners": workflow.examiners(store),
        "state_labels": STATE_LABELS,
    }


def _render_case(request: Request, store: SQLiteStore, case_id: str, error: str | None = None,
                 status: int = 200) -> Response:
    identity = get_current_identity(request)
    case = workflow.get_case(store, case_id)
    context = {"active_tab": "cases", "error": error, **_case_context(store, case, identity)}
    return _templates().TemplateResponse(request=request, name="case_detail.html", context=context,
                                         status_code=status)


@router.get("/cases", response_class=HTMLResponse, dependencies=[Depends(require_role(*READ))])
async def view_cases(request: Request, state: str = "open", entity_id: str | None = None) -> Response:
    if state not in ("open", "all", *STATE_LABELS):
        state = "open"
    store = _store()
    try:
        cases = workflow.list_cases(store, None if state == "all" else state, entity_id)
        counts = {r[0]: r[1] for r in store.conn.execute("SELECT state, COUNT(*) FROM cases GROUP BY state")}
    finally:
        store.close()
    return _templates().TemplateResponse(request=request, name="cases.html", context={
        "active_tab": "cases", "cases": cases, "state_filter": state, "counts": counts,
        "state_labels": STATE_LABELS, "entity_filter": entity_id or "",
    })


@router.post("/cases")
async def open_case(
    request: Request,
    finding_id: Annotated[str, Form()],
    rationale: Annotated[str, Form()] = "",
    identity: Identity = Depends(require_role(*REVIEW)),
) -> Response:
    if not is_valid_finding_id(finding_id):
        raise HTTPException(status_code=400, detail="Malformed finding id")
    store = _store()
    try:
        case, _created = workflow.open_case(store, finding_id, identity.username, identity.role, rationale)
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    finally:
        store.close()
    return RedirectResponse(url=f"/cases/{case['case_id']}", status_code=303)


@router.get("/cases/{case_id}", response_class=HTMLResponse, dependencies=[Depends(require_role(*READ))])
async def view_case(request: Request, case_id: str) -> Response:
    _case_id(case_id)
    store = _store()
    try:
        return _render_case(request, store, case_id)
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    finally:
        store.close()


@router.post("/cases/{case_id}/actions")
async def case_action(
    request: Request,
    case_id: str,
    action: Annotated[str, Form()],
    expected_version: Annotated[int, Form()],
    rationale: Annotated[str, Form()] = "",
    owner: Annotated[str, Form()] = "",
    due_date: Annotated[str, Form()] = "",
    outcome: Annotated[str, Form()] = "",
    opinion: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
    action_owner: Annotated[str, Form()] = "",
    verification_criteria: Annotated[str, Form()] = "",
    result: Annotated[str, Form()] = "",
    reassessment_run_id: Annotated[str, Form()] = "",
    attachment: Annotated[UploadFile | None, File()] = None,
    identity: Identity = Depends(require_role(*REVIEW)),
) -> Response:
    _case_id(case_id)
    files = []
    if attachment is not None and attachment.filename:
        content = await _read_upload(attachment, packages.MAX_ATTACHMENT_BYTES, "The attachment")
        name = attachment.filename.replace("\\", "/").rsplit("/", 1)[-1][:200] or "attachment"
        files.append(Attachment(name, content))
    fields = {k: v for k, v in {
        "owner": owner, "due_date": due_date, "outcome": outcome, "opinion": opinion, "description": description,
        "action_owner": action_owner, "verification_criteria": verification_criteria, "result": result,
        "reassessment_run_id": reassessment_run_id,
    }.items() if v}
    store = _store()
    try:
        workflow.apply(store, case_id, action, identity.username, identity.role, expected_version,
                       rationale, fields, files, data_dir=DATA_DIR)
    except workflow.CaseNotFound as exc:
        store.close()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CaseError as exc:
        try:
            return _render_case(request, store, case_id, error=str(exc), status=exc.status)
        finally:
            store.close()
    store.close()
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@router.post("/cases/{case_id}/request-package")
async def export_request_package(case_id: str, identity: Identity = Depends(require_role(*REVIEW))) -> Response:
    _case_id(case_id)
    from satsa.deployment import settings

    store = _store()
    try:
        name, content = packages.export_request(store, case_id, identity.username, identity.role,
                                                data_dir=DATA_DIR, deployment_name=settings(store).get("name", ""))
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    finally:
        store.close()
    return Response(content=content, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/cases/{case_id}/response-package")
async def import_response_package(
    request: Request,
    case_id: str,
    expected_version: Annotated[int, Form()],
    package: Annotated[UploadFile, File()],
    identity: Identity = Depends(require_role(*REVIEW)),
) -> Response:
    _case_id(case_id)
    content = await _read_upload(package, packages.MAX_PACKAGE_BYTES, "The response package")
    store = _store()
    try:
        packages.import_response(store, case_id, content, identity.username, identity.role, expected_version,
                                 data_dir=DATA_DIR)
    except workflow.CaseNotFound as exc:
        store.close()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CaseError as exc:
        try:
            return _render_case(request, store, case_id, error=str(exc), status=exc.status)
        finally:
            store.close()
    store.close()
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@router.get("/cases/{case_id}/attachments/{attachment_id}", dependencies=[Depends(require_role(*READ))])
async def download_attachment(case_id: str, attachment_id: str) -> Response:
    _case_id(case_id)
    store = _store()
    try:
        row = store.conn.execute(
            "SELECT filename, sha256 FROM case_attachments WHERE case_id = ? AND attachment_id = ?",
            (case_id, attachment_id),
        ).fetchone()
    finally:
        store.close()
    if row is None:
        raise HTTPException(status_code=404, detail="No such attachment")
    path = workflow.attachment_path(DATA_DIR, row["sha256"])
    if not path.is_file():
        raise HTTPException(status_code=410, detail="The attachment's file is missing from data/case_files")
    content = path.read_bytes()
    import hashlib

    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        raise HTTPException(status_code=409, detail="The attachment's file no longer matches its recorded hash")
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in row["filename"])[:120] or "attachment"
    return Response(content=content, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{safe_name}"', "X-Content-Type-Options": "nosniff",
    })


# ---- cases: JSON API ----------------------------------------------------------------------------


class CaseOpen(BaseModel):
    finding_id: str
    rationale: str = ""


class CaseTransition(BaseModel):
    action: str
    expected_version: int
    rationale: str = ""
    fields: dict[str, str] = Field(default_factory=dict)


def _json_error(exc: CaseError) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content={"detail": str(exc), "error": type(exc).__name__})


@router.get("/api/v1/cases", dependencies=[Depends(require_role(*READ))])
async def api_list_cases(state: str | None = None, entity_id: str | None = None) -> list[dict[str, Any]]:
    store = _store()
    try:
        return workflow.list_cases(store, state, entity_id)
    finally:
        store.close()


@router.get("/api/v1/cases/{case_id}")
async def api_get_case(request: Request, case_id: str,
                       identity: Identity = Depends(require_role(*READ))) -> Response:
    _case_id(case_id)
    store = _store()
    try:
        case = workflow.get_case(store, case_id)
        ctx = _case_context(store, case, identity)
    except CaseError as exc:
        return _json_error(exc)
    finally:
        store.close()
    body = {k: ctx[k] for k in ("case", "events", "attachments", "corrective_actions", "packages",
                                "reassessment", "lineage")}
    body["allowed_actions"] = [a.name for a in ctx["allowed"]]
    body["unresolved_disagreement"] = bool(ctx["dissent"])
    return JSONResponse(json.loads(json.dumps(body, default=str)))


@router.post("/api/v1/cases")
async def api_open_case(body: CaseOpen, identity: Identity = Depends(require_role(*REVIEW))) -> Response:
    if not is_valid_finding_id(body.finding_id):
        raise HTTPException(status_code=400, detail="Malformed finding id")
    store = _store()
    try:
        case, created = workflow.open_case(store, body.finding_id, identity.username, identity.role, body.rationale)
    except CaseError as exc:
        return _json_error(exc)
    finally:
        store.close()
    return JSONResponse(status_code=201 if created else 200, content={"case": case, "created": created})


@router.post("/api/v1/cases/{case_id}/transitions")
async def api_case_transition(case_id: str, body: CaseTransition,
                              identity: Identity = Depends(require_role(*REVIEW))) -> Response:
    _case_id(case_id)
    store = _store()
    try:
        event = workflow.apply(store, case_id, body.action, identity.username, identity.role,
                               body.expected_version, body.rationale, body.fields, data_dir=DATA_DIR)
        case = workflow.get_case(store, case_id)
    except CaseError as exc:
        return _json_error(exc)
    finally:
        store.close()
    return JSONResponse(json.loads(json.dumps({"event": event, "case": case}, default=str)))


# ---- blind review -------------------------------------------------------------------------------


def _raw_signals(entity_id: str) -> dict[str, Any]:
    """Operational signals only: no score, band, rule or finding (the blind task's whole view)."""
    from satsa.api.routes import get_stores

    duckdb_store, sqlite_store = get_stores()
    sqlite_store.close()
    q = duckdb_store.query
    try:
        m = q("""
            SELECT count(*) AS total_alerts,
                   ROUND(quantile_cont(epoch(acknowledged_at - created_at) / 60.0, 0.5), 1) AS median_mtta_min,
                   ROUND(quantile_cont(epoch(closed_at - created_at) / 60.0, 0.5), 1) AS median_mttr_min,
                   count(CASE WHEN closed_by_type = 'soar' THEN 1 END) * 100.0 / greatest(count(*), 1) AS soar_share,
                   count(CASE WHEN disposition = 'false_positive' THEN 1 END) * 100.0 / greatest(count(*), 1) AS fp_rate
            FROM alert WHERE entity_id = ?""", [entity_id]).to_dicts()[0]
        kpi = q("SELECT value FROM declared_kpi WHERE entity_id = ? AND upper(metric) = 'MTTR' "
                "ORDER BY period DESC LIMIT 1", [entity_id]).to_dicts()
        high = q("SELECT count(*) AS c FROM alert WHERE entity_id = ? AND severity_final IN ('high', 'critical')",
                 [entity_id]).to_dicts()[0]["c"]
        esc = q("SELECT count(*) AS c FROM escalation WHERE entity_id = ?", [entity_id]).to_dicts()[0]["c"]
        silent = q("""SELECT count(*) AS c FROM asset WHERE entity_id = ? AND criticality >= 3 AND asset_id NOT IN (
                      SELECT DISTINCT asset_id FROM log_source_daily WHERE entity_id = ?)""",
                   [entity_id, entity_id]).to_dicts()[0]["c"]
        comments = q("SELECT comment_norm_hash FROM closure WHERE entity_id = ? LIMIT 5", [entity_id]).to_dicts()
    except duckdb.Error as exc:  # a table the entity never submitted: say so instead of a 500
        return {"unavailable": f"Signals could not be computed: {type(exc).__name__}: {str(exc)[:200]}"}
    finally:
        duckdb_store.close()
    return {
        "total_alerts": m.get("total_alerts", 0),
        "median_mtta_min": m.get("median_mtta_min"),
        "median_mttr_min": m.get("median_mttr_min"),
        "declared_mttr": kpi[0]["value"] if kpi else "not declared",
        "soar_share": round(m.get("soar_share") or 0.0, 1),
        "fp_rate": round(m.get("fp_rate") or 0.0, 1),
        "esc_rate": round(esc / max(high, 1) * 100.0, 1),
        "silent_assets": silent,
        "sample_comments": [f"Normalised closure text hash: {c['comment_norm_hash']}" for c in comments],
    }


@router.get("/blind-review", response_class=HTMLResponse, dependencies=[Depends(require_role(*READ))])
async def view_blind_review(request: Request, created: str | None = None) -> Response:
    identity = get_current_identity(request)
    assert identity is not None  # the dependency guarantees it
    store = _store()
    try:
        is_analyst = is_analyst_role(identity.role)
        context: dict[str, Any] = {"active_tab": "blind_review", "is_analyst_view": is_analyst, "created": created}
        if is_analyst:
            context["samples"] = blind.samples_by(store, identity.username)
            context["examiners"] = workflow.examiners(store)
            context["runs"] = [dict(r) for r in store.conn.execute(
                "SELECT run_id, period, created_at FROM runs WHERE status = 'completed' ORDER BY created_at DESC LIMIT 20")]
            context["legacy_reviews"] = store.get_blind_reviews()
        else:
            context["tasks"] = blind.my_tasks(store, identity.username)
    finally:
        store.close()
    return _templates().TemplateResponse(request=request, name="blind_review.html", context=context)


@router.post("/blind-review/samples")
async def create_blind_sample(
    run_id: Annotated[str, Form()],
    assignee: Annotated[str, Form()],
    flagged: Annotated[int, Form()] = 0,
    random_n: Annotated[int, Form()] = 0,
    control: Annotated[int, Form()] = 0,
    seed: Annotated[str, Form()] = "",
    identity: Identity = Depends(require_role(*ANALYST)),
) -> Response:
    if seed and not seed.isdigit():
        raise HTTPException(status_code=422, detail="The seed must be a whole number")
    store = _store()
    try:
        sample = blind.create_sample(store, run_id, identity.username, identity.role, assignee,
                                     flagged, random_n, control, int(seed) if seed else None)
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    finally:
        store.close()
    return RedirectResponse(url=f"/blind-review?created={sample['sample_id']}", status_code=303)


@router.get("/blind-review/tasks/{task_id}", response_class=HTMLResponse)
async def view_blind_task(request: Request, task_id: str,
                          identity: Identity = Depends(require_role(*REVIEW))) -> Response:
    _task_id(task_id)
    store = _store()
    try:
        task = blind.task_for(store, task_id, identity.username, identity.role)
        findings = []
        if task["revealed_at"]:
            findings = [dict(r) for r in store.conn.execute(
                "SELECT finding_id, rule_id, title, score FROM findings WHERE run_id = ? AND entity_id = ? "
                "ORDER BY score DESC",
                (task["run_id"], task["entity_id"]))]
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    finally:
        store.close()
    return _templates().TemplateResponse(request=request, name="blind_task.html", context={
        "active_tab": "blind_review", "task": task, "signals": _raw_signals(task["entity_id"]),
        "findings": findings, "concerns": blind.CONCERNS,
    })


@router.post("/blind-review/tasks/{task_id}/submit")
async def submit_blind_task(
    task_id: str,
    examiner_concern: Annotated[str, Form()],
    examiner_priority: Annotated[str, Form()],
    examiner_recommendation: Annotated[str, Form()],
    examiner_notes: Annotated[str, Form()],
    identity: Identity = Depends(require_role(*REVIEW)),
) -> Response:
    _task_id(task_id)
    store = _store()
    try:
        blind.submit(store, task_id, identity.username, identity.role, examiner_concern, examiner_priority,
                     examiner_recommendation, examiner_notes)
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    finally:
        store.close()
    return RedirectResponse(url=f"/blind-review/tasks/{task_id}", status_code=303)


@router.post("/blind-review/tasks/{task_id}/reveal")
async def reveal_blind_task(task_id: str, identity: Identity = Depends(require_role(*REVIEW))) -> Response:
    _task_id(task_id)
    store = _store()
    try:
        blind.reveal(store, task_id, identity.username, identity.role)
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    finally:
        store.close()
    return RedirectResponse(url=f"/blind-review/tasks/{task_id}", status_code=303)
