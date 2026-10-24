"""Independent validation of the tool against blinded examiner judgements (docs/product_brief.md
section 14, docs/shadow_pilot_runbook.md Part B).

Builds on blind review (satsa.cases.blind): an analyst draws a sample of entities from one run --
the tool's highest-ranked entities ("flagged", the tool arm), a uniform random draw ("random", the
baseline arm) and low-band entities ("control") -- shuffled, so an examiner cannot tell why an
entity was chosen, and the examiner judges each from raw signals before the system's view is
revealed. This module adds what a credible pilot needs on top:

- **Frozen protocol** (`freeze_protocol`): before any judgement is read, record the configuration
  hash the thresholds are frozen at, a seeded split of the entities into calibration and
  held-out sets, and the review budget. Only runs with that configuration hash are evaluated;
  held-out entities give the headline figures, calibration entities are reported apart.
- **Independent second labels** (`replicate_sample`): the same entities, assigned to another
  examiner in a different order (seeded), so two blinded labels exist per entity.
- **Reviewer time**: from the first opening of a task (`open_task`) to its submission.
- **Adjudication** (`adjudicate`): a third examiner settles an entity the two reviewers disagreed
  on (important concern or not).
- **Evaluation** (`evaluate`): per arm, important concerns confirmed within a fixed review budget
  and overall, with Wilson intervals and an entity-cluster bootstrap (several runs of one entity
  are correlated); false positives of the tool arm; important concerns in the baseline and
  control arms that the system rated low (missed); agreement between reviewers (Cohen's kappa,
  binary and linearly weighted on the four levels); reviewer time.

An unanswered task, or a disagreement nobody has adjudicated, is *not* a negative: it is left out
of every rate and counted on its own. An "important concern" is an examiner concern of Elevated or
Critical. On a demonstration deployment every figure is a synthetic implementation check, and the
report says so: real reviewers and authorised data cannot be simulated.
"""

from __future__ import annotations

import hashlib
import json
import random
import secrets
import statistics
from collections import defaultdict
from datetime import datetime
from typing import Any

from satsa.admin.rbac import is_analyst, is_examiner
from satsa.cases.workflow import CaseForbidden, CaseInvalid, CaseNotFound, examiners
from satsa.store.sqlite import SQLiteStore, utc_now_iso
from satsa.validate.harness import wilson_interval

CONCERN_LEVEL = {"Low": 0, "Moderate": 1, "Elevated": 2, "Critical": 3}
IMPORTANT = frozenset({"Elevated", "Critical"})
SYSTEM_FLAGGED_BANDS = ("elevated", "high", "critical", "severe")
BOOTSTRAP_RESAMPLES = 2000


# ---------------------------------------------------------------- protocol


def split_entities(entities: list[str], seed: int, calibration_fraction: float) -> dict[str, str]:
    """Each entity to "calibration" or "held_out", by a seeded hash order: an entity's place in
    the order depends only on the seed and its own id, not on the order it was listed in."""
    if not 0 <= calibration_fraction < 1:
        raise CaseInvalid("The calibration fraction must be at least 0 and below 1.")
    ordered = sorted(set(entities), key=lambda e: hashlib.sha256(f"{seed}:{e}".encode()).hexdigest())
    n_cal = round(calibration_fraction * len(ordered))
    return {e: ("calibration" if i < n_cal else "held_out") for i, e in enumerate(ordered)}


def freeze_protocol(store: SQLiteStore, name: str, run_id: str, created_by: str, role: str, *,
                    seed: int | None = None, calibration_fraction: float = 0.3, budget: int = 10,
                    notes: str = "") -> dict[str, Any]:
    """Freeze the evaluation before any judgement is looked at."""
    if not is_analyst(role):
        raise CaseForbidden("A pilot protocol is frozen by an analyst.")
    name = (name or "").strip()
    if not name or len(name) > 100:
        raise CaseInvalid("Give the protocol a name (at most 100 characters).")
    if budget <= 0:
        raise CaseInvalid("The review budget must be a positive number of entities.")
    run = store.conn.execute("SELECT run_id, status, config_hash FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if run is None or run["status"] != "completed" or not run["config_hash"]:
        raise CaseNotFound(f"No completed run {run_id} with a recorded configuration hash")
    if store.conn.execute("SELECT 1 FROM pilot_protocols WHERE name = ?", (name,)).fetchone():
        raise CaseInvalid(f"A protocol named {name!r} exists already; protocols are never edited.")
    entities = [r[0] for r in store.conn.execute(
        "SELECT entity_id FROM entity_scores WHERE run_id = ? ORDER BY entity_id", (run_id,))]
    if not entities:
        raise CaseInvalid("The run scored no entities.")
    seed = secrets.randbelow(2**31) if seed is None else int(seed)
    split = split_entities(entities, seed, calibration_fraction)
    protocol_id = f"PLT-{secrets.token_hex(6).upper()}"
    with store.audited_transaction():
        store.conn.execute(
            "INSERT INTO pilot_protocols (protocol_id, name, frozen_run_id, frozen_config_hash, seed, "
            "calibration_fraction, budget, split_json, notes, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (protocol_id, name, run_id, run["config_hash"], seed, calibration_fraction, budget,
             json.dumps(split, sort_keys=True), notes.strip()[:2000], created_by, utc_now_iso()),
        )
        store.append_audit("pilot_protocol_frozen", created_by, {
            "protocol_id": protocol_id, "name": name, "run_id": run_id, "config_hash": run["config_hash"],
            "seed": seed, "calibration_fraction": calibration_fraction, "budget": budget,
        })
    return {"protocol_id": protocol_id, "config_hash": run["config_hash"], "seed": seed,
            "calibration": sorted(e for e, s in split.items() if s == "calibration"),
            "held_out": sorted(e for e, s in split.items() if s == "held_out")}


def protocol(store: SQLiteStore, protocol_id: str) -> dict[str, Any]:
    row = store.conn.execute("SELECT * FROM pilot_protocols WHERE protocol_id = ?", (protocol_id,)).fetchone()
    if row is None:
        raise CaseNotFound(f"No pilot protocol {protocol_id}")
    return dict(row, split=json.loads(row["split_json"]))


# ---------------------------------------------------------------- second reviewer, timing, adjudication


def replicate_sample(store: SQLiteStore, sample_id: str, assignee: str, created_by: str, role: str) -> dict[str, Any]:
    """The same entities (and the same hidden kinds and provenance) for a second examiner, in a
    new seeded order, so their judgements are independent of the first examiner's."""
    if not is_analyst(role):
        raise CaseForbidden("A sample is replicated by an analyst.")
    sample = store.conn.execute("SELECT * FROM blind_samples WHERE sample_id = ?", (sample_id,)).fetchone()
    if sample is None:
        raise CaseNotFound(f"No blind sample {sample_id}")
    if sample["replica_of"]:
        raise CaseInvalid("Replicate the original sample, not a replica.")
    if assignee not in examiners(store):
        raise CaseInvalid(f"{assignee!r} is not an active examiner account.")
    reviewers = {sample["assigned_to"]} | {r[0] for r in store.conn.execute(
        "SELECT assigned_to FROM blind_samples WHERE replica_of = ?", (sample_id,))}
    if assignee in reviewers:
        raise CaseInvalid(f"{assignee} already reviews these entities; the second label must be independent.")
    if assignee == created_by:
        raise CaseInvalid("The examiner who reviews a sample cannot be the one who drew it.")
    tasks = [dict(r) for r in store.conn.execute(
        "SELECT entity_id, run_id, sample_kind, provenance_json FROM blind_tasks WHERE sample_id = ? ORDER BY position",
        (sample_id,))]
    seed = (int(sample["seed"]) * 7919 + len(reviewers)) % (2**31)
    random.Random(seed).shuffle(tasks)
    new_id = f"BLS-{secrets.token_hex(6).upper()}"
    now = utc_now_iso()
    method = {**json.loads(sample["method_json"]), "replica_of": sample_id, "order_seed": seed,
              "order": "the original entities, shuffled with order_seed"}
    with store.audited_transaction():
        store.conn.execute(
            "INSERT INTO blind_samples (sample_id, run_id, seed, flagged_n, random_n, control_n, method_json, "
            "assigned_to, created_by, created_at, replica_of) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (new_id, sample["run_id"], sample["seed"], sample["flagged_n"], sample["random_n"], sample["control_n"],
             json.dumps(method), assignee, created_by, now, sample_id),
        )
        for position, t in enumerate(tasks, start=1):
            store.conn.execute(
                "INSERT INTO blind_tasks (task_id, sample_id, position, entity_id, run_id, sample_kind, "
                "provenance_json, assigned_to, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"BLT-{secrets.token_hex(6).upper()}", new_id, position, t["entity_id"], t["run_id"],
                 t["sample_kind"], t["provenance_json"], assignee, now),
            )
        store.append_audit("blind_sample_replicated", created_by,
                           {"sample_id": new_id, "replica_of": sample_id, "assigned_to": assignee})
    return {"sample_id": new_id, "replica_of": sample_id, "tasks": len(tasks), "order_seed": seed}


def open_task(store: SQLiteStore, task_id: str, actor: str) -> None:
    """Record when the task's own examiner first opened it (the start of their review time)."""
    store.conn.execute("UPDATE blind_tasks SET opened_at = ? WHERE task_id = ? AND assigned_to = ? "
                       "AND opened_at IS NULL AND submitted_at IS NULL", (utc_now_iso(), task_id, actor))


def adjudicate(store: SQLiteStore, protocol_id: str, run_id: str, entity_id: str, label: str, actor: str,
               role: str, rationale: str) -> dict[str, Any]:
    """A third examiner's label for an entity whose two reviewers disagreed."""
    if not is_examiner(role):
        raise CaseForbidden("Disagreements are adjudicated by an examiner.")
    if label not in CONCERN_LEVEL:
        raise CaseInvalid(f"The label must be one of {', '.join(CONCERN_LEVEL)}.")
    rationale = (rationale or "").strip()
    if not rationale or len(rationale) > 5000:
        raise CaseInvalid("A rationale is required (at most 5000 characters).")
    protocol(store, protocol_id)
    labels = _labels(store).get((run_id, entity_id), [])
    if len({lab["concern"] in IMPORTANT for lab in labels}) < 2:
        raise CaseInvalid("Only an entity whose reviewers disagreed is adjudicated.")
    if actor in {lab["reviewer"] for lab in labels}:
        raise CaseForbidden("The adjudicator must not be one of the entity's reviewers.")
    adjudication_id = f"ADJ-{secrets.token_hex(6).upper()}"
    with store.audited_transaction():
        if store.conn.execute("SELECT 1 FROM pilot_adjudications WHERE protocol_id = ? AND run_id = ? AND entity_id = ?",
                              (protocol_id, run_id, entity_id)).fetchone():
            raise CaseInvalid("This disagreement has been adjudicated already.")
        store.conn.execute(
            "INSERT INTO pilot_adjudications (adjudication_id, protocol_id, run_id, entity_id, label, rationale, "
            "adjudicated_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (adjudication_id, protocol_id, run_id, entity_id, label, rationale, actor, utc_now_iso()),
        )
        store.append_audit("pilot_adjudicated", actor, {"adjudication_id": adjudication_id, "protocol_id": protocol_id,
                                                        "run_id": run_id, "entity_id": entity_id, "label": label})
    return {"adjudication_id": adjudication_id}


# ---------------------------------------------------------------- statistics


def cohens_kappa(pairs: list[tuple[int, int]], categories: int, weighted: bool = False) -> float | None:
    """Cohen's kappa for two raters over `categories` ordered levels (0..k-1); linear weights if
    `weighted`. None when it is undefined (no pairs, or chance agreement is total)."""
    if not pairs:
        return None
    n = len(pairs)
    observed = [[0.0] * categories for _ in range(categories)]
    for a, b in pairs:
        observed[a][b] += 1 / n
    row = [sum(observed[i]) for i in range(categories)]
    col = [sum(observed[i][j] for i in range(categories)) for j in range(categories)]

    def w(i: int, j: int) -> float:
        if weighted:
            return 1 - abs(i - j) / (categories - 1)
        return 1.0 if i == j else 0.0

    p_o = sum(w(i, j) * observed[i][j] for i in range(categories) for j in range(categories))
    p_e = sum(w(i, j) * row[i] * col[j] for i in range(categories) for j in range(categories))
    if p_e >= 1:
        return None
    return (p_o - p_e) / (1 - p_e)


def cluster_bootstrap_ci(units: list[tuple[str, bool]], seed: int, resamples: int = BOOTSTRAP_RESAMPLES,
                         level: float = 0.95) -> list[float] | None:
    """Percentile interval for a rate when units are grouped by entity: entities are resampled
    with replacement, each bringing all its units, so correlation within an entity widens the
    interval as it should. None for fewer than two entities."""
    by_entity: dict[str, list[bool]] = defaultdict(list)
    for entity, positive in units:
        by_entity[entity].append(positive)
    groups = list(by_entity.values())
    if len(groups) < 2:
        return None
    rng = random.Random(seed)
    rates = []
    for _ in range(resamples):
        draw = [groups[rng.randrange(len(groups))] for _ in groups]
        total = sum(len(g) for g in draw)
        rates.append(sum(sum(g) for g in draw) / total)
    rates.sort()
    lo = rates[int((1 - level) / 2 * resamples)]
    hi = rates[min(resamples - 1, int((1 + level) / 2 * resamples))]
    return [round(lo, 4), round(hi, 4)]


def _rate_block(units: list[tuple[str, bool]], seed: int) -> dict[str, Any]:
    n = len(units)
    k = sum(1 for _, p in units if p)
    return {"n": n, "positive": k, "rate": round(k / n, 4) if n else None,
            "wilson_95": wilson_interval(k, n) if n else None,
            "entity_cluster_95": cluster_bootstrap_ci(units, seed),
            "entities": len({e for e, _ in units})}


def _seconds(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    try:
        return (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
    except ValueError:
        return None


# ---------------------------------------------------------------- evaluation


def _labels(store: SQLiteStore) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Every submitted blind judgement, grouped by (run, entity)."""
    out: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in store.conn.execute(
            "SELECT t.*, s.replica_of FROM blind_tasks t JOIN blind_samples s ON s.sample_id = t.sample_id "
            "WHERE t.submitted_at IS NOT NULL"):
        out[(r["run_id"], r["entity_id"])].append({
            "reviewer": r["assigned_to"], "concern": r["examiner_concern"], "task_id": r["task_id"],
            "seconds": _seconds(r["opened_at"], r["submitted_at"]), "replica": r["replica_of"] is not None,
        })
    return out


def evaluate(store: SQLiteStore, protocol_id: str) -> dict[str, Any]:
    """The pilot's figures under a frozen protocol (see the module docstring)."""
    from satsa.deployment import DEMO, mode

    proto = protocol(store, protocol_id)
    split: dict[str, str] = proto["split"]
    seed = int(proto["seed"])
    runs = {r["run_id"]: dict(r) for r in store.conn.execute("SELECT run_id, config_hash, period FROM runs")}
    adjudicated = {(r["run_id"], r["entity_id"]): r["label"] for r in store.conn.execute(
        "SELECT run_id, entity_id, label FROM pilot_adjudications WHERE protocol_id = ?", (protocol_id,))}

    tasks = [dict(r) for r in store.conn.execute(
        "SELECT t.*, s.replica_of FROM blind_tasks t JOIN blind_samples s ON s.sample_id = t.sample_id")]
    excluded_runs = sorted({t["run_id"] for t in tasks if runs.get(t["run_id"], {}).get("config_hash")
                            != proto["frozen_config_hash"]})
    tasks = [t for t in tasks if t["run_id"] not in excluded_runs]

    # One unit per (run, entity): its arm, the system's band, and every reviewer's label.
    units: dict[tuple[str, str], dict[str, Any]] = {}
    for t in tasks:
        key = (t["run_id"], t["entity_id"])
        prov = json.loads(t["provenance_json"])
        unit = units.setdefault(key, {"run_id": t["run_id"], "entity_id": t["entity_id"], "arm": t["sample_kind"],
                                      "rank": prov.get("rank"), "order": t["position"], "labels": [],
                                      "unanswered": 0, "system_band": None,
                                      "split": split.get(t["entity_id"], "not_in_protocol")})
        if t["submitted_at"]:
            unit["labels"].append({"reviewer": t["assigned_to"], "concern": t["examiner_concern"],
                                   "seconds": _seconds(t["opened_at"], t["submitted_at"])})
            unit["system_band"] = unit["system_band"] or t["system_risk_band"]
        else:
            unit["unanswered"] += 1
        if not t["replica_of"]:
            unit["order"] = t["position"]

    def final_label(unit: dict[str, Any]) -> tuple[str, str | None]:
        labels = unit["labels"]
        if not labels:
            return "unanswered", None
        verdicts = {lab["concern"] in IMPORTANT for lab in labels}
        if len(verdicts) == 1:
            # Agreement on important-or-not; the higher concern is kept as the level.
            return "agreed" if len(labels) > 1 else "single", max((lab["concern"] for lab in labels),
                                                                  key=CONCERN_LEVEL.__getitem__)
        if (unit["run_id"], unit["entity_id"]) in adjudicated:
            return "adjudicated", adjudicated[(unit["run_id"], unit["entity_id"])]
        return "unresolved", None

    for unit in units.values():
        unit["status"], unit["label"] = final_label(unit)

    def section(which: str) -> dict[str, Any]:
        chosen = [u for u in units.values() if u["split"] == which]
        labelled = [u for u in chosen if u["label"] is not None]
        arms: dict[str, Any] = {}
        for arm in ("flagged", "random", "control"):
            members = [u for u in labelled if u["arm"] == arm]
            block = _rate_block([(u["entity_id"], u["label"] in IMPORTANT) for u in members], seed)
            ordered = sorted(members, key=lambda u: (u["rank"] or 10**9, u["order"]) if arm == "flagged"
                             else (u["order"], u["entity_id"]))
            within = ordered[: int(proto["budget"])]
            block["budget"] = {"reviewed": len(within), "important": sum(u["label"] in IMPORTANT for u in within)}
            arms[arm] = block
        flagged = [u for u in labelled if u["arm"] == "flagged"]
        missed = [u for u in labelled if u["arm"] in ("random", "control") and u["label"] in IMPORTANT
                  and not str(u["system_band"] or "").lower().startswith(SYSTEM_FLAGGED_BANDS)]
        return {
            "units": len(chosen),
            "labelled": len(labelled),
            "unanswered": sum(1 for u in chosen if u["status"] == "unanswered"),
            "unresolved_disagreements": sum(1 for u in chosen if u["status"] == "unresolved"),
            "adjudicated": sum(1 for u in chosen if u["status"] == "adjudicated"),
            "arms": arms,
            "false_positives": {"n": len(flagged), "not_important": sum(u["label"] not in IMPORTANT for u in flagged)},
            "missed_important": [{"run_id": u["run_id"], "entity_id": u["entity_id"], "arm": u["arm"],
                                  "label": u["label"], "system_band": u["system_band"]} for u in missed],
        }

    pairs = [u["labels"][:2] for u in units.values() if len(u["labels"]) >= 2]
    binary = [(int(a["concern"] in IMPORTANT), int(b["concern"] in IMPORTANT)) for a, b in pairs]
    levels = [(CONCERN_LEVEL[a["concern"]], CONCERN_LEVEL[b["concern"]]) for a, b in pairs]
    times = [lab["seconds"] for u in units.values() for lab in u["labels"] if lab["seconds"] is not None]
    by_reviewer: dict[str, list[float]] = defaultdict(list)
    for u in units.values():
        for lab in u["labels"]:
            if lab["seconds"] is not None:
                by_reviewer[lab["reviewer"]].append(lab["seconds"])

    def time_block(values: list[float]) -> dict[str, Any]:
        if not values:
            return {"n": 0}
        ordered = sorted(values)
        return {"n": len(values), "median_s": round(statistics.median(ordered), 1),
                "p90_s": round(ordered[min(len(ordered) - 1, int(0.9 * len(ordered)))], 1)}

    return {
        "protocol": {k: proto[k] for k in ("protocol_id", "name", "frozen_run_id", "frozen_config_hash", "seed",
                                           "calibration_fraction", "budget", "created_by", "created_at")},
        "synthetic": mode(store) == DEMO,
        "runs_evaluated": sorted({t["run_id"] for t in tasks}),
        "runs_excluded_config_changed": excluded_runs,
        "held_out": section("held_out"),
        "calibration": section("calibration"),
        "not_in_protocol": sum(1 for u in units.values() if u["split"] == "not_in_protocol"),
        "agreement": {"pairs": len(pairs),
                      "observed_binary": round(sum(a == b for a, b in binary) / len(binary), 4) if binary else None,
                      "kappa_binary": _round(cohens_kappa(binary, 2)),
                      "kappa_weighted_levels": _round(cohens_kappa(levels, 4, weighted=True))},
        "review_time": {"all": time_block(times),
                        "by_reviewer": {r: time_block(v) for r, v in sorted(by_reviewer.items())},
                        "not_recorded": sum(1 for u in units.values() for lab in u["labels"] if lab["seconds"] is None)},
        "disagreements": sorted(
            [{"run_id": u["run_id"], "entity_id": u["entity_id"], "labels": [lab["concern"] for lab in u["labels"]]}
             for u in units.values() if u["status"] == "unresolved"], key=lambda d: (d["run_id"], d["entity_id"])),
    }


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


def _ci(block: dict[str, Any], key: str) -> str:
    ci = block.get(key)
    return f"{ci[0] * 100:.0f}–{ci[1] * 100:.0f}%" if ci else "n/a"


def evaluation_markdown(res: dict[str, Any]) -> str:
    """A report of `evaluate`'s result, with every exclusion stated."""
    p = res["protocol"]
    lines = [f"# Pilot evaluation: {p['name']}", ""]
    if res["synthetic"]:
        lines += ["> **Synthetic implementation check.** This deployment runs in demonstration mode: the",
                  "> entities and labels are not real, and nothing below is evidence about the tool's",
                  "> accuracy in the field.", ""]
    lines += [
        (f"Protocol `{p['protocol_id']}`, frozen by {p['created_by']} at {p['created_at']} on run "
        f"`{p['frozen_run_id']}`: configuration hash `{p['frozen_config_hash']}`, seed {p['seed']}, "
        f"{p['calibration_fraction']:.0%} of entities for calibration, review budget {p['budget']} entities per arm."),
        "",
        f"Runs evaluated: {', '.join(res['runs_evaluated']) or 'none'}.",
    ]
    if res["runs_excluded_config_changed"]:
        lines.append(f"Runs **left out** because their configuration differs from the frozen one: "
                     f"{', '.join(res['runs_excluded_config_changed'])}.")
    if res["not_in_protocol"]:
        lines.append(f"{res['not_in_protocol']} reviewed entities were not in the run the protocol was frozen on "
                     "and are not counted.")
    for name, sec in (("Held-out entities (headline)", res["held_out"]), ("Calibration entities", res["calibration"])):
        lines += ["", f"## {name}", "",
                  (f"{sec['units']} entity reviews; {sec['labelled']} with a usable label. Left out, not counted as "
                  f"negatives: {sec['unanswered']} unanswered, {sec['unresolved_disagreements']} unresolved "
                  f"disagreements. {sec['adjudicated']} adjudicated."), "",
                  "| Arm | Labelled | Important concern | Rate | 95% Wilson | 95% entity-cluster bootstrap | Within budget |",
                  "|---|---:|---:|---:|---|---|---|"]
        for arm, label in (("flagged", "Tool (highest ranked)"), ("random", "Baseline (random)"),
                           ("control", "Control (lowest band)")):
            b = sec["arms"][arm]
            rate = f"{b['rate'] * 100:.0f}%" if b["rate"] is not None else "n/a"
            lines.append(f"| {label} | {b['n']} | {b['positive']} | {rate} | {_ci(b, 'wilson_95')} | "
                         f"{_ci(b, 'entity_cluster_95')} | {b['budget']['important']} of {b['budget']['reviewed']} |")
        fp = sec["false_positives"]
        lines += ["", (f"Tool-arm entities judged not an important concern (false positives): "
                      f"{fp['not_important']} of {fp['n']}."),
                  (f"Important concerns in the baseline and control arms that the system did not rate elevated "
                  f"(missed): {len(sec['missed_important'])}.")]
        for m in sec["missed_important"]:
            lines.append(f"- {m['entity_id']} ({m['run_id']}, {m['arm']}): examiners {m['label']}, system {m['system_band']}")
    a = res["agreement"]
    t = res["review_time"]
    lines += ["", "## Reviewers", "",
              (f"Entities reviewed independently twice: {a['pairs']}. Observed agreement (important or not): "
              f"{'n/a' if a['observed_binary'] is None else format(a['observed_binary'], '.0%')}; Cohen's kappa "
              f"{'n/a' if a['kappa_binary'] is None else a['kappa_binary']}; linearly weighted kappa on the four "
              f"levels {'n/a' if a['kappa_weighted_levels'] is None else a['kappa_weighted_levels']}."),
              "",
              (f"Review time per entity: median {t['all'].get('median_s', 'n/a')} s, 90th percentile "
              f"{t['all'].get('p90_s', 'n/a')} s over {t['all']['n']} reviews ({t['not_recorded']} not recorded).")]
    for reviewer, block in t["by_reviewer"].items():
        lines.append(f"- {reviewer}: {block['n']} reviews, median {block.get('median_s')} s, p90 {block.get('p90_s')} s")
    if res["disagreements"]:
        lines += ["", "Disagreements awaiting adjudication:"]
        lines += [f"- {d['entity_id']} ({d['run_id']}): {', '.join(d['labels'])}" for d in res["disagreements"]]
    lines += ["", "Small samples give wide intervals; quote them with every figure. A rate here describes these",
              "entities, these periods and these reviewers only.", ""]
    return "\n".join(lines)
