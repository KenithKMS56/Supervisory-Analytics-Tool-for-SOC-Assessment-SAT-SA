"""Routes for entity context: maintenance windows, rule exceptions and applicability decisions
(satsa.context; docs/analytics_context.md). Included by satsa.api.routes.

Supervisory staff (analysts and examiners) record maintenance windows the entity reports; an
examiner other than the requester approves them. Rule exceptions and applicability decisions are
supervisory judgements: examiners only, and an exception needs a second examiner's approval.
Every change is audited by satsa.context / SQLiteStore. Nothing here changes a recorded run: the
context applies from the next assessment, and a replay of an old run uses what was then in force.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse, Response

from satsa import context
from satsa.auth.session import Identity, require_role
from satsa.rules.registry import RuleRegistry
from satsa.security import is_valid_entity_id
from satsa.store.sqlite import SQLiteStore

router = APIRouter()

SUPERVISORY = ("analyst", "examiner")
REVIEW = ("examiner",)
DATA_DIR = "data"
WINDOW_ID_RE = re.compile(r"^MW-[A-F0-9]{12}$")
EXCEPTION_ID_RE = re.compile(r"^EXC-[A-F0-9]{12}$")
DECISION_ID_RE = re.compile(r"^APD-[a-f0-9]{12}$")
ASSET_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")


def _store() -> SQLiteStore:
    return SQLiteStore(f"{DATA_DIR}/satsa.db")


def _entity(entity_id: str) -> str:
    if not is_valid_entity_id(entity_id):
        raise HTTPException(status_code=400, detail="Invalid entity_id.")
    return entity_id


def _match(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.match(value):
        raise HTTPException(status_code=400, detail=f"Malformed {what}.")
    return value


def _rule_version(rule_id: str) -> str:
    rule = next((r for r in RuleRegistry().get_all_rules() if r.id == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=400, detail="Unknown rule.")
    return str(rule.version)


def _back(entity_id: str) -> Response:
    return RedirectResponse(url=f"/entity/{entity_id}#context", status_code=303)


def _do(entity_id: str, action: object) -> Response:
    store = _store()
    try:
        action(store)  # type: ignore[operator]
    except context.ContextError as exc:
        raise HTTPException(status_code=409 if "already" in str(exc) else 400, detail=str(exc)) from exc
    finally:
        store.close()
    return _back(entity_id)


def _owned(store: SQLiteStore, table: str, key: str, item_id: str, entity_id: str) -> None:
    row = store.conn.execute(f"SELECT entity_id FROM {table} WHERE {key} = ?", (item_id,)).fetchone()
    if row is None or row["entity_id"] != entity_id:
        raise HTTPException(status_code=404, detail="Not found for this entity.")


@router.post("/entity/{entity_id}/maintenance")
async def request_maintenance(
    entity_id: str,
    starts_on: Annotated[str, Form()],
    ends_on: Annotated[str, Form()],
    reason: Annotated[str, Form()],
    evidence_ref: Annotated[str, Form()],
    asset_id: Annotated[str, Form()] = "",
    identity: Identity = Depends(require_role(*SUPERVISORY)),
) -> Response:
    _entity(entity_id)
    if asset_id.strip():
        _match(ASSET_ID_RE, asset_id.strip(), "asset id")
    return _do(entity_id, lambda s: context.request_maintenance(
        s, entity_id, starts_on, ends_on, reason, evidence_ref, identity.username, identity.role, asset_id
    ))


@router.post("/entity/{entity_id}/maintenance/{window_id}/approve")
async def approve_maintenance(
    entity_id: str, window_id: str, identity: Identity = Depends(require_role(*REVIEW))
) -> Response:
    _entity(entity_id)
    _match(WINDOW_ID_RE, window_id, "window id")

    def act(s: SQLiteStore) -> None:
        _owned(s, "maintenance_windows", "window_id", window_id, entity_id)
        context.approve_maintenance(s, window_id, identity.username, identity.role)

    return _do(entity_id, act)


@router.post("/entity/{entity_id}/maintenance/{window_id}/revoke")
async def revoke_maintenance(
    entity_id: str,
    window_id: str,
    reason: Annotated[str, Form()],
    identity: Identity = Depends(require_role(*REVIEW)),
) -> Response:
    _entity(entity_id)
    _match(WINDOW_ID_RE, window_id, "window id")

    def act(s: SQLiteStore) -> None:
        _owned(s, "maintenance_windows", "window_id", window_id, entity_id)
        context.revoke_maintenance(s, window_id, identity.username, identity.role, reason)

    return _do(entity_id, act)


@router.post("/entity/{entity_id}/exceptions")
async def request_exception(
    entity_id: str,
    rule_id: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    reason: Annotated[str, Form()],
    evidence_ref: Annotated[str, Form()],
    expires_on: Annotated[str, Form()],
    identity: Identity = Depends(require_role(*REVIEW)),
) -> Response:
    _entity(entity_id)
    _rule_version(rule_id)
    return _do(entity_id, lambda s: context.request_exception(
        s, entity_id, rule_id, scope, reason, evidence_ref, expires_on, identity.username, identity.role
    ))


@router.post("/entity/{entity_id}/exceptions/{exception_id}/approve")
async def approve_exception(
    entity_id: str, exception_id: str, identity: Identity = Depends(require_role(*REVIEW))
) -> Response:
    _entity(entity_id)
    _match(EXCEPTION_ID_RE, exception_id, "exception id")

    def act(s: SQLiteStore) -> None:
        _owned(s, "rule_exceptions", "exception_id", exception_id, entity_id)
        context.approve_exception(s, exception_id, identity.username, identity.role)

    return _do(entity_id, act)


@router.post("/entity/{entity_id}/exceptions/{exception_id}/revoke")
async def revoke_exception(
    entity_id: str,
    exception_id: str,
    reason: Annotated[str, Form()],
    identity: Identity = Depends(require_role(*REVIEW)),
) -> Response:
    _entity(entity_id)
    _match(EXCEPTION_ID_RE, exception_id, "exception id")

    def act(s: SQLiteStore) -> None:
        _owned(s, "rule_exceptions", "exception_id", exception_id, entity_id)
        context.revoke_exception(s, exception_id, identity.username, identity.role, reason)

    return _do(entity_id, act)


@router.post("/entity/{entity_id}/applicability")
async def decide_applicability(
    entity_id: str,
    rule_id: Annotated[str, Form()],
    reason: Annotated[str, Form()],
    expires_on: Annotated[str, Form()] = "",
    identity: Identity = Depends(require_role(*REVIEW)),
) -> Response:
    """Record that a rule does not apply to the entity (its result becomes `not_applicable`)."""
    _entity(entity_id)
    version = _rule_version(rule_id)
    expires_at = None
    if expires_on.strip():
        try:
            day = context.parse_date(expires_on, "expiry date")
        except context.ContextError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        expires_at = f"{day.isoformat()}T00:00:00.000000+00:00"

    def act(s: SQLiteStore) -> None:
        if not reason.strip():
            raise context.ContextError("a reason is required")
        s.add_applicability_decision(entity_id, rule_id, reason, identity.username, version, expires_at)

    return _do(entity_id, act)


@router.post("/entity/{entity_id}/applicability/{decision_id}/revoke")
async def revoke_applicability(
    entity_id: str,
    decision_id: str,
    reason: Annotated[str, Form()],
    identity: Identity = Depends(require_role(*REVIEW)),
) -> Response:
    _entity(entity_id)
    _match(DECISION_ID_RE, decision_id, "decision id")

    def act(s: SQLiteStore) -> None:
        _owned(s, "applicability_decisions", "decision_id", decision_id, entity_id)
        if not reason.strip():
            raise context.ContextError("a reason is required")
        if not s.revoke_applicability_decision(decision_id, identity.username, reason.strip()):
            raise context.ContextError(f"{decision_id} is already revoked")

    return _do(entity_id, act)
