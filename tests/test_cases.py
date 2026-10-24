"""Supervisory cases (satsa.cases.workflow; docs/product_brief.md section 8).

Acceptance: a concern proceeds end to end through an authorised human decision and an
evidence-based closure; unauthorised transitions fail; conflicting concurrent edits are
detected; history stays intact; insufficient next-period evidence cannot close remediation.
"""

from __future__ import annotations

import io
import json
import sqlite3
import threading
import zipfile

import pytest
from case_fixtures import (
    ENTITY,
    Q1,
    Q2,
    RULE,
    add_finding,
    add_result,
    add_run,
    make_store,
    seed_q1_concern,
)

from satsa.cases import packages, workflow
from satsa.cases.workflow import CaseForbidden, CaseInvalid, InvalidTransition, VersionConflict

EX, EX2, EX3 = "examiner", "examiner2", "examiner3"


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = make_store(tmp_path)
    yield s
    s.close()


def act(store, case_id, action, actor=EX, rationale="reasons", **fields):
    version = workflow.get_case(store, case_id)["version"]
    return workflow.apply(store, case_id, action, actor, "examiner", version, rationale, fields)


def opened_and_assigned(store) -> str:
    finding = seed_q1_concern(store)
    case, created = workflow.open_case(store, finding, EX, "examiner", "off-shift gap looks real")
    assert created and case["state"] == "new"
    act(store, case["case_id"], "assign", owner=EX, due_date="2026-05-31", rationale="")
    return case["case_id"]


def response_zip(request_zip: bytes, explanation="Night shift was understaffed in Q1.",
                 attachments: dict[str, bytes] | None = None, **overrides) -> bytes:
    with zipfile.ZipFile(io.BytesIO(request_zip)) as z:
        template = json.loads(z.read("response_template.json"))
    template.update(responder_name="R. Iyer", responder_role="SOC manager", explanation=explanation,
                    attachments=sorted(attachments or {}), **overrides)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        out.writestr("response.json", json.dumps(template))
        for name, content in (attachments or {}).items():
            out.writestr(f"attachments/{name}", content)
    return buf.getvalue()


def to_verification(store, case_id):
    act(store, case_id, "request_explanation", rationale="Explain the off-shift delays.", due_date="2026-05-15")
    _name, request = packages.export_request(store, case_id, EX, "examiner")
    version = workflow.get_case(store, case_id)["version"]
    packages.import_response(store, case_id, response_zip(request, attachments={"rota.pdf": b"%PDF rota"}),
                             EX, "examiner", version)
    act(store, case_id, "decide", outcome="confirmed", rationale="The response confirms the gap.")
    act(store, case_id, "record_review", actor=EX2, opinion="agree", rationale="Evidence is clear.")
    act(store, case_id, "require_corrective_action", description="Staff the night shift.",
        action_owner="CSE SOC manager", due_date="2026-06-30",
        verification_criteria="Q2 off-shift acknowledgement within peer range.", rationale="Required.")
    act(store, case_id, "submit_for_verification", rationale="CSE reports a new rota from 1 April.")


def test_a_concern_goes_end_to_end_to_an_evidence_based_closure(store):
    case_id = opened_and_assigned(store)
    to_verification(store, case_id)
    # Next period: Q2 assessed the same rule version for the entity and found it clear.
    add_run(store, "RUN-Q2", "2026-07-02T00:00:00+00:00", window=Q2, period="2026-Q2")
    add_result(store, "RUN-Q2", "assessed_clear")
    [evaluation] = workflow.reassessment(store, workflow.get_case(store, case_id))
    assert evaluation["sufficient_for_closure"] and evaluation["reasons"] == []

    act(store, case_id, "verify", actor=EX2, result="passed", reassessment_run_id="RUN-Q2",
        rationale="Q2 shows the gap closed.")
    case = workflow.get_case(store, case_id)
    assert case["state"] == "closed" and case["closed_at"] and case["outcome"] == "confirmed"
    actions = [e["action"] for e in workflow.events(store, case_id)]
    assert actions == ["open", "assign", "request_explanation", "record_response", "decide", "record_review",
                       "require_corrective_action", "submit_for_verification", "verify"]
    [ca] = workflow.corrective_actions(store, case_id)
    assert ca["state"] == "verified" and ca["resolved_event_id"]
    [att] = workflow.attachments(store, case_id)
    assert att["filename"] == "rota.pdf" and att["source"] == "response_package"
    assert workflow.attachment_path("data", att["sha256"]).read_bytes() == b"%PDF rota"
    ok, msg = store.verify_audit_chain()
    assert ok, msg
    audited = {r[0] for r in store.conn.execute("SELECT action FROM audit_log WHERE action LIKE 'case_%'")}
    assert {"case_open", "case_decide", "case_verify", "case_record_response"} <= audited


def test_unauthorised_transitions_fail(store):
    case_id = opened_and_assigned(store)
    version = workflow.get_case(store, case_id)["version"]
    with pytest.raises(CaseForbidden):  # analysts read cases; they do not decide them
        workflow.apply(store, case_id, "decide", "analyst", "analyst", version, "x", {"outcome": "confirmed"})
    with pytest.raises(CaseForbidden):
        workflow.open_case(store, "FND-Q1-NS03", "analyst", "analyst")
    with pytest.raises(CaseForbidden, match="owner"):  # only the owner decides
        act(store, case_id, "decide", actor=EX2, outcome="confirmed")
    with pytest.raises(InvalidTransition):  # not from this state
        act(store, case_id, "verify", actor=EX2, result="passed", reassessment_run_id="RUN-Q1")
    with pytest.raises(CaseInvalid):  # an owner must be an active examiner account
        act(store, case_id, "reassign", owner="analyst")
    with pytest.raises(CaseInvalid, match="reason"):
        act(store, case_id, "decide", outcome="dismissed", rationale="  ")
    with pytest.raises(CaseInvalid):
        act(store, case_id, "decide", outcome="statutory_notice")
    with pytest.raises(CaseInvalid):
        act(store, case_id, "no_such_action")

    act(store, case_id, "decide", outcome="dismissed", rationale="Shift data explains it.")
    with pytest.raises(CaseForbidden, match="sign-off"):  # the decider cannot sign off their own decision
        act(store, case_id, "close", actor=EX)
    with pytest.raises(CaseForbidden):  # nor review it
        act(store, case_id, "record_review", actor=EX, opinion="agree")
    act(store, case_id, "close", actor=EX2, rationale="Agreed: dismissed.")
    assert workflow.get_case(store, case_id)["state"] == "closed"
    # Nothing that failed left a trace in the history.
    assert [e["action"] for e in workflow.events(store, case_id)] == ["open", "assign", "decide", "close"]


def test_allowed_actions_follow_the_same_rules(store):
    case_id = opened_and_assigned(store)
    case = workflow.get_case(store, case_id)
    owner = {a.name for a in workflow.allowed_actions(store, case, EX, "examiner")}
    other = {a.name for a in workflow.allowed_actions(store, case, EX2, "examiner")}
    assert {"decide", "request_explanation"} <= owner
    assert "decide" not in other and "reassign" in other
    assert workflow.allowed_actions(store, case, "analyst", "analyst") == []


def test_conflicting_concurrent_edits_are_detected(store, tmp_path):
    case_id = opened_and_assigned(store)
    seen = workflow.get_case(store, case_id)["version"]
    act(store, case_id, "add_note", rationale="first examiner's note")
    with pytest.raises(VersionConflict, match="changed since you loaded"):
        workflow.apply(store, case_id, "decide", EX, "examiner", seen, "stale view", {"outcome": "dismissed"})

    # Two writers on separate connections racing from the same version: exactly one wins.
    version = workflow.get_case(store, case_id)["version"]
    barrier = threading.Barrier(2)
    results: list[str] = []

    def writer(note: str) -> None:
        s = make_store(tmp_path)
        try:
            barrier.wait()
            workflow.apply(s, case_id, "add_note", EX, "examiner", version, note)
            results.append("ok")
        except VersionConflict:
            results.append("conflict")
        finally:
            s.close()

    threads = [threading.Thread(target=writer, args=(n,)) for n in ("racer A", "racer B")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["conflict", "ok"]
    notes = [e["rationale"] for e in workflow.events(store, case_id) if e["action"] == "add_note"]
    assert notes[0] == "first examiner's note" and len(notes) == 2


def test_history_is_immutable_and_corrections_supersede(store):
    case_id = opened_and_assigned(store)
    act(store, case_id, "decide", outcome="dismissed", rationale="Looked benign.")
    act(store, case_id, "supersede_decision", outcome="confirmed", rationale="Response contradicted the rota.")
    evts = workflow.events(store, case_id)
    first, second = [e for e in evts if e["action"] in ("decide", "supersede_decision")]
    assert first["superseded"] and second["supersedes_event_id"] == first["event_id"]
    assert first["rationale"] == "Looked benign." and first["payload"]["outcome"] == "dismissed"
    assert workflow.get_case(store, case_id)["state"] == "confirmed"
    with pytest.raises(CaseInvalid):  # a "correction" to the same outcome is a note, not a decision
        act(store, case_id, "supersede_decision", outcome="confirmed")

    for sql in ("UPDATE case_events SET rationale = 'rewritten' WHERE event_id = ?",
                "DELETE FROM case_events WHERE event_id = ?"):
        with pytest.raises(sqlite3.DatabaseError, match="immutable"), store.conn:
            store.conn.execute(sql, (first["event_id"],))
    assert workflow.events(store, case_id)[2]["rationale"] == "Looked benign."


def test_a_disagreement_must_be_adjudicated_by_a_third_examiner(store):
    case_id = opened_and_assigned(store)
    act(store, case_id, "decide", outcome="dismissed", rationale="Benign.")
    act(store, case_id, "record_review", actor=EX2, opinion="disagree", rationale="The response does not explain it.")
    with pytest.raises(InvalidTransition, match="adjudicated"):
        act(store, case_id, "close", actor=EX3)
    with pytest.raises(CaseForbidden):
        act(store, case_id, "adjudicate", actor=EX2, outcome="confirmed")  # the dissenter
    with pytest.raises(CaseForbidden):
        act(store, case_id, "adjudicate", actor=EX, outcome="dismissed")  # the decider
    act(store, case_id, "adjudicate", actor=EX3, outcome="confirmed", rationale="Concern stands.")
    case = workflow.get_case(store, case_id)
    assert case["state"] == "confirmed" and case["decided_by"] == EX3
    assert workflow.unresolved_disagreement(workflow.events(store, case_id)) == []
    with pytest.raises(InvalidTransition, match="no unresolved disagreement"):
        act(store, case_id, "adjudicate", actor=EX3, outcome="dismissed")
    # The original decision and the dissent are still on record.
    actions = [e["action"] for e in workflow.events(store, case_id)]
    assert actions[-3:] == ["decide", "record_review", "adjudicate"]


@pytest.mark.parametrize(
    ("later", "reason"),
    [
        ({"state": "insufficient_evidence", "risk_index": 5.0, "classification": "insufficient_evidence",
          "coverage": 0.2, "band": "Insufficient evidence"}, "not evidence of improvement"),
        ({"state": "degraded"}, "not evidence of improvement"),
        ({"state": "finding"}, "concern recurs"),
        ({"state": "not_applicable"}, "not applicable"),
        ({"state": "assessed_clear", "version": "2.0"}, "not comparable"),
        (None, "not evaluated"),
    ],
)
def test_insufficient_next_period_evidence_cannot_close_remediation(store, later, reason):
    case_id = opened_and_assigned(store)
    to_verification(store, case_id)
    add_run(store, "RUN-Q2", "2026-07-02T00:00:00+00:00", window=Q2, period="2026-Q2")
    if later is not None:
        add_result(store, "RUN-Q2", **later)
    if later and later["state"] == "finding":
        add_finding(store, "RUN-Q2", "FND-Q2-NS03", score=64.0, records=("A-2", "B-9"))
    evaluation = workflow.evaluate_run(store, workflow.get_case(store, case_id), "RUN-Q2")
    assert not evaluation["sufficient_for_closure"]
    assert any(reason in r for r in evaluation["reasons"]), evaluation["reasons"]
    with pytest.raises(InvalidTransition, match="cannot be verified"):
        act(store, case_id, "verify", actor=EX2, result="passed", reassessment_run_id="RUN-Q2")
    assert workflow.get_case(store, case_id)["state"] == "verification"
    # Failing verification is always possible: it sends the case back to corrective action.
    act(store, case_id, "verify", actor=EX2, result="failed", reassessment_run_id="RUN-Q2", rationale="Not shown.")
    assert workflow.get_case(store, case_id)["state"] == "corrective_action"
    assert workflow.corrective_actions(store, case_id)[0]["state"] == "failed"


@pytest.mark.parametrize(
    ("window", "reason"),
    [((Q1[0], Q2[1]), "covers part of the period"), (None, "not limited to a review period")],
)
def test_a_run_that_is_not_a_later_period_is_not_next_period_evidence(store, window, reason):
    case_id = opened_and_assigned(store)
    to_verification(store, case_id)
    add_run(store, "RUN-H1", "2026-07-02T00:00:00+00:00", window=window, period="2026-H1")
    add_result(store, "RUN-H1", "assessed_clear")
    evaluation = workflow.evaluate_run(store, workflow.get_case(store, case_id), "RUN-H1")
    assert not evaluation["sufficient_for_closure"]
    assert any(reason in r for r in evaluation["reasons"]), evaluation["reasons"]


def test_reassessment_shows_what_changed_and_warns_on_config_changes(store):
    case_id = opened_and_assigned(store)
    add_run(store, "RUN-Q2", "2026-07-02T00:00:00+00:00", window=Q2, period="2026-Q2",
            rules_sha="rules-v2", peers_sha="peers-v2")
    add_result(store, "RUN-Q2", "finding")
    add_finding(store, "RUN-Q2", "FND-Q2-NS03", score=64.0, records=("A-2", "B-8", "B-9"), peer_count=4)
    [ev] = workflow.reassessment(store, workflow.get_case(store, case_id))
    assert ev["evidence_change"] == {"score_before": 72.0, "score_after": 64.0, "records_before": 3,
                                     "records_after": 3, "records_added": 2, "records_no_longer_cited": 2}
    assert any("Rule parameters" in w for w in ev["warnings"])
    assert any("peer-group definition" in w for w in ev["warnings"])
    assert any("6 to 4" in w for w in ev["warnings"])


def test_lineage_links_recurrences_and_reopening(store):
    finding = seed_q1_concern(store)
    case, _ = workflow.open_case(store, finding, EX, "examiner")
    add_run(store, "RUN-Q2", "2026-07-02T00:00:00+00:00", window=Q2, period="2026-Q2")
    add_finding(store, "RUN-Q2", "FND-Q2-NS03")
    again, created = workflow.open_case(store, "FND-Q2-NS03", EX, "examiner")
    assert not created and again["case_id"] == case["case_id"]  # one open case per entity and rule
    assert workflow.events(store, case["case_id"])[-1]["action"] == "link_finding"
    assert {f["finding_id"] for f in workflow.linked_findings(store, again)} == {finding, "FND-Q2-NS03"}
    _same, created = workflow.open_case(store, "FND-Q2-NS03", EX, "examiner")  # linking twice adds nothing
    assert not created and [e["action"] for e in workflow.events(store, case["case_id"])].count("link_finding") == 1

    cid = case["case_id"]
    act(store, cid, "assign", owner=EX, rationale="")
    act(store, cid, "decide", outcome="inconclusive", rationale="Cannot tell.")
    act(store, cid, "close", actor=EX2, rationale="Closed inconclusive.")
    add_run(store, "RUN-Q3", "2026-10-02T00:00:00+00:00", window=("2026-07-01T00:00:00+00:00",
                                                                     "2026-10-01T00:00:00+00:00"), period="2026-Q3")
    add_finding(store, "RUN-Q3", "FND-Q3-NS03")
    recurrence, created = workflow.open_case(store, "FND-Q3-NS03", EX, "examiner")
    assert created and recurrence["previous_case_id"] == cid
    with pytest.raises(InvalidTransition, match="already open"):  # one open case per concern
        act(store, cid, "reopen", rationale="New information.")
    assert (ENTITY, RULE) == (recurrence["entity_id"], recurrence["rule_id"])
