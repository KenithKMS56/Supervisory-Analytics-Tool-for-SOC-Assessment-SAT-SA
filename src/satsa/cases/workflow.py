"""Supervisory cases: one concern, from a finding to an evidence-based closure (docs/examiner_workflow.md).

A case follows one concern: an entity and a rule. It is opened from a finding, and later
findings of the same entity and rule are linked to it while it is open, so its lineage spans
assessment periods. A closed concern that recurs opens a new case that points back to the old
one (`previous_case_id`).

    new -> assigned -> explanation_requested -> response_received
        -> confirmed | dismissed | inconclusive
    confirmed -> corrective_action -> verification -> closed
    dismissed | inconclusive -> closed            (second-examiner sign-off)
    closed -> reopened -> assigned ...

The server decides every transition (`ACTIONS`): which states it leaves, who may make it, and
what it must carry. Rules beyond the table:

- Only examiners act on cases; analysts can read them. Only the case owner requests
  explanations, records responses, decides and sets corrective actions.
- Sign-off is by a second person. Closing a dismissed or inconclusive case, and verifying a
  corrective action, must be done by an examiner who is neither the owner nor whoever made
  the decision.
- A decision is never edited. A correction is a superseding decision with a reason. Another
  examiner can record agreement or disagreement; an unresolved disagreement blocks closure
  and corrective action until a third examiner adjudicates (or the owner decides again).
- Remediation is verified only on comparable next-period evidence (`reassessment`): a later
  run, not covering the original period, that assessed the same rule version for the entity
  and found it clear. Missing, degraded or insufficient evidence is not improvement, so it
  cannot close the case. Nothing closes a case automatically.
- Every change carries the version the examiner saw (`expected_version`). A stale version is
  refused, so concurrent edits are detected instead of silently overwriting each other.

`case_events` is the immutable history (database triggers refuse UPDATE and DELETE); `cases`
and `corrective_actions` are projections of it.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from satsa.admin.rbac import is_examiner
from satsa.store.sqlite import SQLiteStore, utc_now_iso
from satsa.store.sqlite_migrations import CASE_STATES

DECISION_STATES = frozenset({"confirmed", "dismissed", "inconclusive"})
OPEN_STATES = frozenset(CASE_STATES) - {"closed"}
OUTCOME = "<outcome>"  # the transition goes to the outcome the examiner chose
VERIFY_RESULT = "<verify>"  # closed if verification passed, back to corrective_action if not
DECISION_ACTIONS = ("decide", "supersede_decision", "adjudicate")
MAX_TEXT = 5000
CASE_ID_RE = re.compile(r"^CASE-[A-F0-9]{12}$")
STATE_LABELS = {
    "new": "New concern",
    "assigned": "Assigned for review",
    "explanation_requested": "Explanation requested",
    "response_received": "Response received",
    "confirmed": "Confirmed concern",
    "dismissed": "Dismissed",
    "inconclusive": "Inconclusive",
    "corrective_action": "Corrective action",
    "verification": "Awaiting verification",
    "closed": "Closed",
    "reopened": "Reopened",
}


class CaseError(Exception):
    status = 400


class CaseNotFound(CaseError):
    status = 404


class CaseForbidden(CaseError):
    status = 403


class InvalidTransition(CaseError):
    status = 409


class VersionConflict(CaseError):
    status = 409


class CaseInvalid(CaseError):
    status = 422


@dataclass(frozen=True)
class Action:
    name: str
    label: str
    from_states: frozenset[str]
    to_state: str | None  # None: no state change
    owner_only: bool
    needs_rationale: bool = True
    fields: tuple[str, ...] = ()
    help: str = ""


ACTIONS: dict[str, Action] = {
    a.name: a
    for a in (
        Action("assign", "Assign", frozenset({"new", "reopened"}), "assigned", owner_only=False,
               needs_rationale=False, fields=("owner",), help="Name the examiner who owns the review."),
        Action("reassign", "Reassign", OPEN_STATES - {"new", "reopened"}, None, owner_only=False,
               fields=("owner",), help="Hand the case to another examiner (reason required)."),
        Action("request_explanation", "Request explanation",
               frozenset({"assigned", "response_received", "inconclusive", "reopened"}), "explanation_requested",
               owner_only=True, fields=("due_date",),
               help="What the entity must explain, and by when. Export the request package to send it."),
        Action("record_response", "Record response", frozenset({"explanation_requested"}), "response_received",
               owner_only=True, help="The entity's explanation, if it arrived outside a response package."),
        Action("decide", "Decide", frozenset({"assigned", "explanation_requested", "response_received"}), OUTCOME,
               owner_only=True, fields=("outcome",), help="Confirmed concern, dismissed or inconclusive, with reasons."),
        Action("supersede_decision", "Correct the decision", DECISION_STATES, OUTCOME, owner_only=True,
               fields=("outcome",), help="A new decision that supersedes the last one; the old one stays on record."),
        Action("record_review", "Record review", DECISION_STATES, None, owner_only=False, fields=("opinion",),
               help="A second examiner agrees or disagrees with the decision."),
        Action("adjudicate", "Adjudicate", DECISION_STATES, OUTCOME, owner_only=False, fields=("outcome",),
               help="A third examiner settles a disagreement."),
        Action("require_corrective_action", "Require corrective action", frozenset({"confirmed"}),
               "corrective_action", owner_only=True,
               fields=("description", "action_owner", "due_date", "verification_criteria"),
               help="What the entity must do, by when, and how completion will be verified."),
        Action("submit_for_verification", "Submit for verification", frozenset({"corrective_action"}),
               "verification", owner_only=True, help="The entity reports the action done; say what it provided."),
        Action("verify", "Verify", frozenset({"verification"}), VERIFY_RESULT, owner_only=False,
               fields=("result", "reassessment_run_id"),
               help="A second examiner checks the next-period evidence. Passing needs sufficient comparable evidence."),
        Action("close", "Close", frozenset({"dismissed", "inconclusive"}), "closed", owner_only=False,
               help="Sign-off by an examiner other than the owner and the decision maker."),
        Action("reopen", "Reopen", frozenset({"closed"}), "reopened", owner_only=False),
        Action("add_note", "Add note", OPEN_STATES, None, owner_only=False, help="A note or evidence file."),
    )
}


@dataclass
class Attachment:
    filename: str
    content: bytes
    source: str = "examiner_upload"
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        self.sha256 = hashlib.sha256(self.content).hexdigest()


# ---- reading -------------------------------------------------------------------------------------


def get_case(store: SQLiteStore, case_id: str) -> dict[str, Any]:
    row = store.conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    if row is None:
        raise CaseNotFound(f"No case {case_id}")
    return dict(row)


def list_cases(store: SQLiteStore, state: str | None = None, entity_id: str | None = None,
               limit: int = 500) -> list[dict[str, Any]]:
    clauses, params = [], []
    if state == "open":
        clauses.append("state != 'closed'")
    elif state:
        clauses.append("state = ?")
        params.append(state)
    if entity_id:
        clauses.append("entity_id = ?")
        params.append(entity_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = store.conn.execute(
        f"SELECT * FROM cases {where} ORDER BY updated_at DESC, case_id LIMIT ?", (*params, limit)
    ).fetchall()
    return [dict(r) for r in rows]


def events(store: SQLiteStore, case_id: str) -> list[dict[str, Any]]:
    out = []
    for r in store.conn.execute("SELECT * FROM case_events WHERE case_id = ? ORDER BY seq", (case_id,)):
        d = dict(r)
        d["payload"] = json.loads(d.pop("payload_json") or "{}")
        out.append(d)
    superseded = {e["supersedes_event_id"] for e in out if e["supersedes_event_id"]}
    for e in out:
        e["superseded"] = e["event_id"] in superseded
    return out


def attachments(store: SQLiteStore, case_id: str) -> list[dict[str, Any]]:
    return [dict(r) for r in store.conn.execute(
        "SELECT * FROM case_attachments WHERE case_id = ? ORDER BY added_at, attachment_id", (case_id,)
    )]


def corrective_actions(store: SQLiteStore, case_id: str) -> list[dict[str, Any]]:
    return [dict(r) for r in store.conn.execute(
        "SELECT * FROM corrective_actions WHERE case_id = ? ORDER BY created_at", (case_id,)
    )]


def case_for_lineage(store: SQLiteStore, entity_id: str, rule_id: str) -> dict[str, Any] | None:
    """The open case of an entity and rule, else the most recent closed one."""
    row = store.conn.execute(
        "SELECT * FROM cases WHERE entity_id = ? AND rule_id = ? ORDER BY (state = 'closed'), created_at DESC LIMIT 1",
        (entity_id, rule_id),
    ).fetchone()
    return dict(row) if row else None


def _decision_events(evts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in evts if e["action"] in DECISION_ACTIONS]


def unresolved_disagreement(evts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Disagreeing reviews recorded after the latest decision (none once it is settled)."""
    decisions = _decision_events(evts)
    if not decisions:
        return []
    last = decisions[-1]["seq"]
    return [e for e in evts if e["action"] == "record_review" and e["seq"] > last
            and e["payload"].get("opinion") == "disagree"]


def allowed_actions(store: SQLiteStore, case: dict[str, Any], actor: str, role: str) -> list[Action]:
    """The actions this user could take now (the server re-checks every one when it is made)."""
    if not is_examiner(role):
        return []
    evts = events(store, case["case_id"])
    out = []
    for action in ACTIONS.values():
        if case["state"] not in action.from_states:
            continue
        try:
            _check_actor(action, case, actor, evts)
        except CaseError:
            continue
        out.append(action)
    return out


# ---- reassessment: is there comparable next-period evidence? ---------------------------------------


def _run(store: SQLiteStore, run_id: str) -> dict[str, Any] | None:
    row = store.conn.execute(
        "SELECT run_id, period, created_at, status, selection_json, config_hash FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["selection"] = json.loads(d.pop("selection_json") or "{}") or {}
    return d


def _config_shas(store: SQLiteStore, run_id: str) -> dict[str, str]:
    return {r[0]: r[1] for r in store.conn.execute(
        "SELECT key, sha256 FROM run_config_snapshots WHERE run_id = ?", (run_id,))}


def _evidence_ids(store: SQLiteStore, finding_id: str) -> set[str]:
    return {f"{r[0]}:{r[1]}" for r in store.conn.execute(
        "SELECT record_type, record_id FROM finding_evidences WHERE finding_id = ?", (finding_id,))}


def _parse(value: str | None) -> _dt.datetime | None:
    if not value:
        return None
    dt = _dt.datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=_dt.UTC)


def evaluate_run(store: SQLiteStore, case: dict[str, Any], run_id: str) -> dict[str, Any]:
    """Whether one later run gives comparable evidence that the concern was remediated, and why not."""
    base = _run(store, case["run_id"])
    later = _run(store, run_id)
    if later is None:
        raise CaseInvalid(f"No assessment run {run_id}")
    reasons: list[str] = []
    warnings: list[str] = []
    out: dict[str, Any] = {"run_id": run_id, "period": later["period"], "created_at": later["created_at"]}

    if base is not None and later["created_at"] <= base["created_at"]:
        reasons.append("This run is not later than the run the case was opened from.")
    if later["status"] != "completed":
        reasons.append(f"The run did not complete (status {later['status']}).")

    rr = store.conn.execute(
        "SELECT state, reason, rule_version, population, min_sample FROM rule_results "
        "WHERE run_id = ? AND entity_id = ? AND rule_id = ?",
        (run_id, case["entity_id"], case["rule_id"]),
    ).fetchone()
    finding = store.conn.execute(
        "SELECT finding_id, score, severity, rule_version, peer_comparison_json FROM findings "
        "WHERE run_id = ? AND entity_id = ? AND rule_id = ? ORDER BY score DESC LIMIT 1",
        (run_id, case["entity_id"], case["rule_id"]),
    ).fetchone()
    es = store.conn.execute(
        "SELECT risk_index, classification_status, coverage FROM entity_scores WHERE run_id = ? AND entity_id = ?",
        (run_id, case["entity_id"]),
    ).fetchone()
    state = rr["state"] if rr else None
    out.update(
        rule_state=state,
        rule_reason=rr["reason"] if rr else None,
        population=rr["population"] if rr else None,
        finding_id=finding["finding_id"] if finding else None,
        score=finding["score"] if finding else None,
        classification_status=es["classification_status"] if es else None,
        coverage=es["coverage"] if es else None,
    )
    if rr is None:
        reasons.append("The rule was not evaluated for this entity in this run, so there is no evidence either way.")
    elif state == "finding" or finding is not None:
        reasons.append("The rule still produces a finding: the concern recurs.")
    elif state in ("insufficient_evidence", "degraded"):
        reasons.append(
            f"The rule could not be fully assessed ({state.replace('_', ' ')}: {rr['reason']}). "
            "Missing or degraded data is not evidence of improvement."
        )
    elif state == "not_applicable":
        reasons.append("The rule was marked not applicable to this entity; that is not evidence of remediation.")
    rule_version = (rr["rule_version"] if rr else None) or (finding["rule_version"] if finding else None)
    out["rule_version"] = rule_version
    if rule_version and rule_version != case["rule_version"]:
        reasons.append(
            f"The rule changed from version {case['rule_version']} to {rule_version}: the results are not comparable."
        )

    base_sel = (base or {}).get("selection") or {}
    later_sel = later["selection"] or {}
    base_end, later_start = _parse(base_sel.get("end_exclusive")), _parse(later_sel.get("start"))
    if later_sel.get("mode") != "window":
        reasons.append("The run is not limited to a review period, so it does not show the next period on its own.")
    elif base_end is not None and later_start is not None and later_start < base_end:
        reasons.append("The run covers part of the period the concern was found in, not a later period.")
    elif base_end is None:
        warnings.append("The original finding was not limited to a period; the comparison is with all data submitted then.")

    base_shas, later_shas = _config_shas(store, case["run_id"]), _config_shas(store, run_id)
    if base_shas and later_shas:
        if base_shas.get("rules") != later_shas.get("rules") and not any("rule changed" in r for r in reasons):
            warnings.append("Rule parameters (rules.yaml) differ between the two runs.")
        if base_shas.get("peers") != later_shas.get("peers"):
            warnings.append("The peer-group definition changed between the two runs: peer comparisons differ.")
    base_finding = store.conn.execute(
        "SELECT score, peer_comparison_json FROM findings WHERE finding_id = ?", (case["finding_id"],)
    ).fetchone()
    if finding is not None and base_finding is not None:
        base_peers = json.loads(base_finding["peer_comparison_json"] or "{}").get("peer_count")
        later_peers = json.loads(finding["peer_comparison_json"] or "{}").get("peer_count")
        if base_peers is not None and later_peers is not None and base_peers != later_peers:
            warnings.append(f"The peer group changed size ({base_peers} to {later_peers} entities).")
        before, after = _evidence_ids(store, case["finding_id"]), _evidence_ids(store, finding["finding_id"])
        out["evidence_change"] = {
            "score_before": base_finding["score"], "score_after": finding["score"],
            "records_before": len(before), "records_after": len(after),
            "records_added": len(after - before), "records_no_longer_cited": len(before - after),
        }
    out["reasons"] = reasons
    out["warnings"] = warnings
    out["sufficient_for_closure"] = not reasons and state == "assessed_clear"
    return out


def reassessment(store: SQLiteStore, case: dict[str, Any], limit: int = 12) -> list[dict[str, Any]]:
    """Every completed run after the case's run, newest first, evaluated for remediation evidence."""
    base = _run(store, case["run_id"])
    if base is None:
        return []
    rows = store.conn.execute(
        "SELECT run_id FROM runs WHERE created_at > ? AND status = 'completed' ORDER BY created_at DESC LIMIT ?",
        (base["created_at"], limit),
    ).fetchall()
    return [evaluate_run(store, case, r[0]) for r in rows]


def linked_findings(store: SQLiteStore, case: dict[str, Any]) -> list[dict[str, Any]]:
    """Findings of the same entity and rule in every run: the concern's lineage across periods."""
    return [dict(r) for r in store.conn.execute(
        "SELECT f.finding_id, f.run_id, r.period, r.created_at, f.score, f.severity, f.rule_version, f.title "
        "FROM findings f JOIN runs r ON r.run_id = f.run_id WHERE f.entity_id = ? AND f.rule_id = ? "
        "ORDER BY r.created_at DESC LIMIT 50",
        (case["entity_id"], case["rule_id"]),
    )]


# ---- writing ------------------------------------------------------------------------------------


def _text(value: Any, what: str, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise CaseInvalid(f"{what} is required.")
    if len(text) > MAX_TEXT:
        raise CaseInvalid(f"{what} is longer than {MAX_TEXT} characters.")
    return text


def _date(value: Any, what: str) -> str:
    text = _text(value, what)
    try:
        return _dt.date.fromisoformat(text).isoformat()
    except ValueError as exc:
        raise CaseInvalid(f"{what} must be a date (YYYY-MM-DD).") from exc


def _active_examiner(store: SQLiteStore, username: str) -> str:
    username = _text(username, "Owner")
    row = store.conn.execute(
        "SELECT role, is_blocked, status FROM identities WHERE username = ?", (username,)
    ).fetchone()
    if row is None or not is_examiner(row["role"]) or row["is_blocked"] or (row["status"] or "ACTIVE") != "ACTIVE":
        raise CaseInvalid(f"{username!r} is not an active examiner account.")
    return username


def examiners(store: SQLiteStore) -> list[str]:
    return [r["username"] for r in store.conn.execute(
        "SELECT username, role, is_blocked, status FROM identities ORDER BY username")
        if is_examiner(r["role"]) and not r["is_blocked"] and (r["status"] or "ACTIVE") == "ACTIVE"]


def _check_actor(action: Action, case: dict[str, Any], actor: str, evts: list[dict[str, Any]]) -> None:
    """Who may make this action on this case (the role was checked already)."""
    if action.owner_only and case.get("owner") != actor:
        raise CaseForbidden(f"Only the case owner ({case.get('owner') or 'unassigned'}) can {action.label.lower()}.")
    if action.name == "record_review" and actor == case.get("decided_by"):
        raise CaseForbidden("A review must come from an examiner other than the one who made the decision.")
    if action.name == "adjudicate":
        dissent = unresolved_disagreement(evts)
        if not dissent:
            raise InvalidTransition("There is no unresolved disagreement to adjudicate.")
        if actor == case.get("decided_by") or actor in {e["actor"] for e in dissent}:
            raise CaseForbidden("Adjudication must come from an examiner who neither made the decision nor disagreed with it.")
    if action.name in ("close", "verify") and actor in {case.get("owner"), case.get("decided_by")}:
        raise CaseForbidden(f"{action.label} needs sign-off by an examiner other than the owner and the decision maker.")
    if action.name in ("close", "require_corrective_action") and unresolved_disagreement(evts):
        raise InvalidTransition("A reviewer disagrees with the decision: it must be adjudicated first.")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6).upper()}"


def store_file(data_dir: Path | str, att: Attachment) -> Path:
    """Content-addressed, written once: data/case_files/<sha[:2]>/<sha>."""
    path = Path(data_dir) / "case_files" / att.sha256[:2] / att.sha256
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{att.sha256}.tmp")
        tmp.write_bytes(att.content)
        tmp.replace(path)
    return path


def attachment_path(data_dir: Path | str, sha256: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise CaseInvalid("bad attachment reference")
    return Path(data_dir) / "case_files" / sha256[:2] / sha256


def _insert_event(store: SQLiteStore, case_id: str, action: str, actor: str, role: str,
                  from_state: str | None, to_state: str | None, rationale: str | None,
                  payload: dict[str, Any], supersedes: str | None = None) -> dict[str, Any]:
    seq = store.conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM case_events WHERE case_id = ?",
                             (case_id,)).fetchone()[0]
    event = {
        "event_id": _new_id("CEV"), "case_id": case_id, "seq": seq, "action": action, "actor": actor,
        "actor_role": role, "from_state": from_state, "to_state": to_state, "rationale": rationale,
        "payload": payload, "supersedes_event_id": supersedes, "created_at": utc_now_iso(),
    }
    store.conn.execute(
        "INSERT INTO case_events (event_id, case_id, seq, action, actor, actor_role, from_state, to_state, "
        "rationale, payload_json, supersedes_event_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event["event_id"], case_id, seq, action, actor, role, from_state, to_state, rationale,
         json.dumps(payload, sort_keys=True), supersedes, event["created_at"]),
    )
    return event


def _insert_attachments(store: SQLiteStore, case_id: str, event_id: str, actor: str,
                        files: list[Attachment]) -> list[dict[str, Any]]:
    rows = []
    for att in files:
        row = {"attachment_id": _new_id("ATT"), "filename": att.filename, "sha256": att.sha256,
               "bytes": len(att.content), "source": att.source}
        store.conn.execute(
            "INSERT INTO case_attachments (attachment_id, case_id, event_id, filename, sha256, bytes, source, "
            "added_by, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (row["attachment_id"], case_id, event_id, att.filename, att.sha256, len(att.content), att.source,
             actor, utc_now_iso()),
        )
        rows.append(row)
    return rows


def open_case(store: SQLiteStore, finding_id: str, actor: str, role: str,
              rationale: str = "") -> tuple[dict[str, Any], bool]:
    """Open a case from a finding, or link the finding to the open case of its entity and rule.

    Returns (case, created)."""
    if not is_examiner(role):
        raise CaseForbidden("Only examiners open supervisory cases.")
    note = _text(rationale, "Reason", required=False)
    with store.audited_transaction():
        f = store.conn.execute(
            "SELECT finding_id, run_id, entity_id, rule_id, rule_version, title FROM findings WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        if f is None:
            raise CaseNotFound(f"No finding {finding_id}")
        current = store.conn.execute(
            "SELECT * FROM cases WHERE entity_id = ? AND rule_id = ? AND state != 'closed'",
            (f["entity_id"], f["rule_id"]),
        ).fetchone()
        if current is not None:
            case = dict(current)
            linked = {e["payload"].get("finding_id") for e in events(store, case["case_id"])}
            if finding_id not in linked:
                _insert_event(store, case["case_id"], "link_finding", actor, role, case["state"], None,
                              note or None, {"finding_id": finding_id, "run_id": f["run_id"]})
                now = utc_now_iso()
                store.conn.execute("UPDATE cases SET version = version + 1, updated_at = ? WHERE case_id = ?",
                                   (now, case["case_id"]))
                store.append_audit("case_link_finding", actor, {"case_id": case["case_id"], "finding_id": finding_id})
            return get_case(store, case["case_id"]), False
        previous = store.conn.execute(
            "SELECT case_id FROM cases WHERE entity_id = ? AND rule_id = ? AND state = 'closed' "
            "ORDER BY closed_at DESC LIMIT 1",
            (f["entity_id"], f["rule_id"]),
        ).fetchone()
        case_id = _new_id("CASE")
        now = utc_now_iso()
        store.conn.execute(
            "INSERT INTO cases (case_id, entity_id, rule_id, rule_version, finding_id, run_id, title, state, "
            "previous_case_id, created_by, created_at, updated_at, version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, 1)",
            (case_id, f["entity_id"], f["rule_id"], f["rule_version"], finding_id, f["run_id"], f["title"],
             previous["case_id"] if previous else None, actor, now, now),
        )
        _insert_event(store, case_id, "open", actor, role, None, "new", note or None,
                      {"finding_id": finding_id, "run_id": f["run_id"],
                       "previous_case_id": previous["case_id"] if previous else None})
        store.append_audit("case_open", actor, {"case_id": case_id, "finding_id": finding_id})
        return get_case(store, case_id), True


def apply(store: SQLiteStore, case_id: str, action_name: str, actor: str, role: str, expected_version: int,
          rationale: str = "", fields: dict[str, Any] | None = None, files: list[Attachment] | None = None,
          data_dir: Path | str = "data", payload_extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Make one transition (or record a note, review ...) on a case. Raises a CaseError subclass
    whose `status` is the HTTP status to answer with."""
    fields = dict(fields or {})
    files = list(files or [])
    action = ACTIONS.get(action_name)
    if action is None:
        raise CaseInvalid(f"Unknown action {action_name!r}")
    if not is_examiner(role):
        raise CaseForbidden("Only examiners act on supervisory cases.")
    for att in files:
        store_file(data_dir, att)  # content-addressed: harmless if the transaction then fails

    with store.audited_transaction():
        case = get_case(store, case_id)
        if case["version"] != expected_version:
            raise VersionConflict(
                f"This case changed since you loaded it (you had version {expected_version}, it is now "
                f"{case['version']}). Reload it and check the latest history before acting."
            )
        if case["state"] not in action.from_states:
            raise InvalidTransition(
                f"'{action.label}' is not allowed while the case is {STATE_LABELS[case['state']].lower()}."
            )
        evts = events(store, case_id)
        _check_actor(action, case, actor, evts)
        text = _text(rationale, "A reason" if action.needs_rationale else "Note", required=action.needs_rationale)
        if action.name == "add_note" and not text and not files:
            raise CaseInvalid("A note needs text or a file.")

        updates: dict[str, Any] = {}
        payload: dict[str, Any] = dict(payload_extra or {})
        supersedes = None
        to_state = action.to_state

        if action.name in ("assign", "reassign"):
            owner = _active_examiner(store, fields.get("owner", ""))
            if action.name == "reassign" and owner == case["owner"]:
                raise CaseInvalid(f"{owner} already owns this case.")
            updates["owner"] = owner
            payload.update(owner=owner, previous_owner=case["owner"])
            if fields.get("due_date"):
                updates["due_date"] = payload["due_date"] = _date(fields["due_date"], "Due date")
        elif action.name == "request_explanation":
            payload["respond_by"] = _date(fields.get("due_date"), "Response due date")
        elif action.name in DECISION_ACTIONS:
            outcome = str(fields.get("outcome", ""))
            if outcome not in DECISION_STATES:
                raise CaseInvalid("The outcome must be confirmed, dismissed or inconclusive.")
            last = _decision_events(evts)
            if action.name == "supersede_decision":
                if outcome == case["state"]:
                    raise CaseInvalid("A superseding decision must change the outcome; add a note to add reasons.")
                supersedes = last[-1]["event_id"] if last else None
            if action.name == "adjudicate":
                supersedes = last[-1]["event_id"] if last else None
                payload["dissent_event_ids"] = [e["event_id"] for e in unresolved_disagreement(evts)]
            to_state = outcome
            updates.update(outcome=outcome, decided_by=actor)
            payload["outcome"] = outcome
        elif action.name == "record_review":
            opinion = str(fields.get("opinion", ""))
            if opinion not in ("agree", "disagree"):
                raise CaseInvalid("A review must agree or disagree.")
            payload.update(opinion=opinion, decision_event_id=_decision_events(evts)[-1]["event_id"])
        elif action.name == "require_corrective_action":
            ca = {
                "description": _text(fields.get("description"), "The corrective action"),
                "owner": _text(fields.get("action_owner"), "The entity-side owner"),
                "due_date": _date(fields.get("due_date"), "The due date"),
                "verification_criteria": _text(fields.get("verification_criteria"), "The verification criteria"),
            }
            payload["corrective_action"] = ca
        elif action.name == "verify":
            result = str(fields.get("result", ""))
            if result not in ("passed", "failed"):
                raise CaseInvalid("Verification must pass or fail.")
            run_id = _text(fields.get("reassessment_run_id"), "The reassessment run")
            evaluation = evaluate_run(store, case, run_id)
            if result == "passed" and not evaluation["sufficient_for_closure"]:
                raise InvalidTransition(
                    "Remediation cannot be verified on this run: "
                    + " ".join(evaluation["reasons"] or ["the rule did not assess the entity as clear."])
                )
            payload.update(result=result, reassessment=evaluation)
            to_state = "closed" if result == "passed" else "corrective_action"

        if files:
            payload["attachments"] = [{"filename": a.filename, "sha256": a.sha256, "bytes": len(a.content)}
                                      for a in files]
        new_state = to_state or case["state"]
        event = _insert_event(store, case_id, action.name, actor, role, case["state"],
                              to_state, text or None, payload, supersedes)
        if files:
            event["attachments"] = _insert_attachments(store, case_id, event["event_id"], actor, files)

        if action.name == "require_corrective_action":
            ca = payload["corrective_action"]
            store.conn.execute(
                "INSERT INTO corrective_actions (action_id, case_id, description, owner, due_date, "
                "verification_criteria, state, created_event_id, created_at) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)",
                (_new_id("CA"), case_id, ca["description"], ca["owner"], ca["due_date"], ca["verification_criteria"],
                 event["event_id"], event["created_at"]),
            )
        elif action.name in ("submit_for_verification", "verify"):
            new_ca_state = {"submit_for_verification": "submitted"}.get(
                action.name, "verified" if payload.get("result") == "passed" else "failed")
            store.conn.execute(
                "UPDATE corrective_actions SET state = ?, resolved_event_id = ?, resolved_at = ? "
                "WHERE action_id = (SELECT action_id FROM corrective_actions WHERE case_id = ? "
                "ORDER BY created_at DESC LIMIT 1)",
                (new_ca_state, event["event_id"] if action.name == "verify" else None,
                 event["created_at"] if action.name == "verify" else None, case_id),
            )
        if action.name == "reopen":
            other = store.conn.execute(
                "SELECT case_id FROM cases WHERE entity_id = ? AND rule_id = ? AND state != 'closed'",
                (case["entity_id"], case["rule_id"]),
            ).fetchone()
            if other is not None:
                raise InvalidTransition(f"Case {other['case_id']} is already open for this entity and rule; "
                                        "work the concern there.")
            updates.update(closed_at=None, outcome=None, decided_by=None)
        if new_state == "closed":
            updates["closed_at"] = event["created_at"]

        updates.update(state=new_state, updated_at=event["created_at"])
        assignments = ", ".join(f"{k} = ?" for k in updates)
        cur = store.conn.execute(
            f"UPDATE cases SET {assignments}, version = version + 1 WHERE case_id = ? AND version = ?",
            (*updates.values(), case_id, expected_version),
        )
        if cur.rowcount != 1:  # cannot happen inside the IMMEDIATE transaction; kept as a guard
            raise VersionConflict("This case changed while the action was being recorded. Reload it.")
        store.append_audit(f"case_{action.name}", actor, {
            "case_id": case_id, "event_id": event["event_id"], "from_state": case["state"], "to_state": new_state,
        })
        return event
