"""Blind review as assigned tasks (docs/examiner_workflow.md, "Blind review").

An analyst draws a *sample* from one assessment run and assigns it to an examiner. The sample
mixes three kinds of entity, so the examiner cannot tell from being asked why an entity was
chosen:

- **flagged**: the highest risk index among entities the run could classify;
- **control**: entities the run classified in the lowest band, drawn at random;
- **random**: drawn uniformly from the rest of the run's entities.

The draw is reproducible: the seed, the pool each entity came from, its rank or pool size and
the run are stored with every task (`provenance_json`), and the tasks are shuffled with the
same seed.

A task page serves raw operational signals only. The system's band, index, findings, the
sample kind and its provenance stay on the server until the examiner has submitted a
judgement and then asks to reveal them; the reveal time is recorded. The system values a
judgement is compared with are those of the task's run, fixed at submission.
"""

from __future__ import annotations

import json
import random
import re
import secrets
from typing import Any

from satsa.admin.rbac import is_analyst, is_examiner
from satsa.cases.workflow import (
    CaseError,
    CaseForbidden,
    CaseInvalid,
    CaseNotFound,
    InvalidTransition,
    examiners,
)
from satsa.scoring.scorer import blind_review_concordance
from satsa.store.sqlite import SQLiteStore, utc_now_iso

TASK_ID_RE = re.compile(r"^BLT-[A-F0-9]{12}$")
CONCERNS = ("Low", "Moderate", "Elevated", "Critical")
PRIORITIES = ("Routine", "P3", "P2", "P1")
RECOMMENDATIONS = ("Satisfactory", "Advisory", "Formal Audit", "Formal Inquiry")
MAX_PER_KIND = 50
# Hidden until the examiner reveals: never put in a task view before then.
SYSTEM_FIELDS = ("sample_kind", "provenance", "system_risk_index", "system_risk_band",
                 "system_classification", "concordance_score")


def create_sample(store: SQLiteStore, run_id: str, created_by: str, role: str, assignee: str,
                  flagged: int, random_n: int, control: int, seed: int | None = None) -> dict[str, Any]:
    if not is_analyst(role):
        raise CaseForbidden("Blind samples are drawn by an analyst and assigned to an examiner.")
    if assignee not in examiners(store):
        raise CaseInvalid(f"{assignee!r} is not an active examiner account.")
    if assignee == created_by:
        raise CaseInvalid("The examiner who reviews a sample cannot be the one who drew it.")
    counts = {"flagged": flagged, "random": random_n, "control": control}
    if any(n < 0 or n > MAX_PER_KIND for n in counts.values()) or sum(counts.values()) == 0:
        raise CaseInvalid(f"Ask for 0 to {MAX_PER_KIND} entities of each kind, and at least one in all.")
    run = store.conn.execute("SELECT run_id, status FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if run is None or run["status"] != "completed":
        raise CaseNotFound(f"No completed run {run_id}")
    scores = [dict(r) for r in store.conn.execute(
        "SELECT entity_id, risk_index, risk_band, classification_status FROM entity_scores "
        "WHERE run_id = ? ORDER BY entity_id", (run_id,))]
    if not scores:
        raise CaseInvalid("The run scored no entities.")
    seed = secrets.randbelow(2**31) if seed is None else int(seed)
    rng = random.Random(seed)

    def classified(s: dict[str, Any]) -> bool:
        return (s["classification_status"] or "assessable") != "insufficient_evidence"

    chosen: list[tuple[str, dict[str, Any]]] = []
    taken: set[str] = set()
    pool = sorted((s for s in scores if classified(s)), key=lambda s: (-s["risk_index"], s["entity_id"]))
    for rank, s in enumerate(pool[:flagged], start=1):
        chosen.append((s["entity_id"], {"kind": "flagged", "method": "highest risk index among classified entities",
                                        "rank": rank, "pool_size": len(pool)}))
        taken.add(s["entity_id"])
    low = [s["entity_id"] for s in scores if classified(s) and s["entity_id"] not in taken
           and s["risk_band"].lower().startswith("low")]
    for eid in rng.sample(low, min(control, len(low))):
        chosen.append((eid, {"kind": "control", "method": "random draw from entities in the lowest band",
                             "pool_size": len(low)}))
        taken.add(eid)
    rest = [s["entity_id"] for s in scores if s["entity_id"] not in taken]
    for eid in rng.sample(rest, min(random_n, len(rest))):
        chosen.append((eid, {"kind": "random", "method": "uniform random draw from the run's other entities",
                             "pool_size": len(rest)}))
    rng.shuffle(chosen)

    sample_id = f"BLS-{secrets.token_hex(6).upper()}"
    now = utc_now_iso()
    method = {"seed": seed, "requested": counts,
              "drawn": {k: sum(1 for _, p in chosen if p["kind"] == k) for k in counts},
              "order": "shuffled with the seed"}
    with store.audited_transaction():
        store.conn.execute(
            "INSERT INTO blind_samples (sample_id, run_id, seed, flagged_n, random_n, control_n, method_json, "
            "assigned_to, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sample_id, run_id, seed, flagged, random_n, control, json.dumps(method), assignee, created_by, now),
        )
        for position, (eid, prov) in enumerate(chosen, start=1):
            store.conn.execute(
                "INSERT INTO blind_tasks (task_id, sample_id, position, entity_id, run_id, sample_kind, "
                "provenance_json, assigned_to, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"BLT-{secrets.token_hex(6).upper()}", sample_id, position, eid, run_id, prov["kind"],
                 json.dumps({**prov, "seed": seed, "run_id": run_id}), assignee, now),
            )
        store.append_audit("blind_sample_created", created_by, {
            "sample_id": sample_id, "run_id": run_id, "assigned_to": assignee, "seed": seed, "drawn": method["drawn"],
        })
    return {"sample_id": sample_id, "seed": seed, "tasks": len(chosen), "drawn": method["drawn"]}


def _task(store: SQLiteStore, task_id: str) -> dict[str, Any]:
    row = store.conn.execute("SELECT * FROM blind_tasks WHERE task_id = ?", (task_id,)).fetchone()
    if row is None:
        raise CaseNotFound("No such blind-review task.")
    d = dict(row)
    d["provenance"] = json.loads(d.pop("provenance_json"))
    return d


def task_for(store: SQLiteStore, task_id: str, actor: str, role: str) -> dict[str, Any]:
    """The task as its examiner may see it: without anything scored until it is revealed."""
    if not is_examiner(role):
        raise CaseForbidden("Blind-review tasks are worked by their examiner.")
    task = _task(store, task_id)
    if task["assigned_to"] != actor:
        raise CaseForbidden("This blind-review task is assigned to another examiner.")
    if not task["revealed_at"]:
        for name in SYSTEM_FIELDS:
            task.pop(name, None)
    return task


def my_tasks(store: SQLiteStore, actor: str) -> list[dict[str, Any]]:
    """An examiner's tasks, without kind or scores: position, entity and progress only."""
    return [dict(r) for r in store.conn.execute(
        "SELECT task_id, sample_id, position, entity_id, created_at, submitted_at, revealed_at "
        "FROM blind_tasks WHERE assigned_to = ? ORDER BY (submitted_at IS NOT NULL), created_at DESC, position",
        (actor,))]


def samples_by(store: SQLiteStore, created_by: str) -> list[dict[str, Any]]:
    rows = store.conn.execute(
        "SELECT s.*, COUNT(t.task_id) AS tasks, SUM(t.submitted_at IS NOT NULL) AS submitted, "
        "SUM(t.revealed_at IS NOT NULL) AS revealed, AVG(CASE WHEN t.revealed_at IS NOT NULL "
        "THEN t.concordance_score END) AS mean_concordance FROM blind_samples s "
        "LEFT JOIN blind_tasks t ON t.sample_id = s.sample_id WHERE s.created_by = ? "
        "GROUP BY s.sample_id ORDER BY s.created_at DESC", (created_by,)).fetchall()
    return [dict(r, method=json.loads(r["method_json"])) for r in rows]


def submit(store: SQLiteStore, task_id: str, actor: str, role: str, concern: str, priority: str,
           recommendation: str, notes: str) -> dict[str, Any]:
    if concern not in CONCERNS:
        raise CaseInvalid(f"The concern level must be one of {', '.join(CONCERNS)}.")
    if priority not in PRIORITIES or recommendation not in RECOMMENDATIONS:
        raise CaseInvalid("Choose a priority and a recommendation from the form.")
    notes = (notes or "").strip()
    if not notes or len(notes) > 5000:
        raise CaseInvalid("Notes are required (at most 5000 characters).")
    with store.audited_transaction():
        task = task_for(store, task_id, actor, role)
        if task["submitted_at"]:
            raise InvalidTransition("This task was already submitted; a blind judgement is made once.")
        score = store.conn.execute(
            "SELECT risk_index, risk_band, classification_status FROM entity_scores WHERE run_id = ? AND entity_id = ?",
            (task["run_id"], task["entity_id"]),
        ).fetchone()
        band = score["risk_band"] if score else None
        try:
            concordance = blind_review_concordance(concern, band) if band else None
        except ValueError:
            concordance = None  # the system did not classify the entity: nothing to agree with
        store.conn.execute(
            "UPDATE blind_tasks SET examiner_concern = ?, examiner_priority = ?, examiner_recommendation = ?, "
            "examiner_notes = ?, submitted_at = ?, system_risk_index = ?, system_risk_band = ?, "
            "system_classification = ?, concordance_score = ? WHERE task_id = ? AND submitted_at IS NULL",
            (concern, priority, recommendation, notes, utc_now_iso(), score["risk_index"] if score else None,
             band, score["classification_status"] if score else None, concordance, task_id),
        )
        store.append_audit("blind_task_submitted", actor, {"task_id": task_id, "entity_id": task["entity_id"]})
    return {"task_id": task_id}


def reveal(store: SQLiteStore, task_id: str, actor: str, role: str) -> None:
    with store.audited_transaction():
        task = task_for(store, task_id, actor, role)
        if not task["submitted_at"]:
            raise InvalidTransition("Submit your judgement before revealing the system's assessment.")
        if task["revealed_at"]:
            return
        store.conn.execute("UPDATE blind_tasks SET revealed_at = ? WHERE task_id = ? AND revealed_at IS NULL",
                           (utc_now_iso(), task_id))
        store.append_audit("blind_task_revealed", actor, {"task_id": task_id})


__all__ = ["CaseError", "create_sample", "my_tasks", "reveal", "samples_by", "submit", "task_for"]
