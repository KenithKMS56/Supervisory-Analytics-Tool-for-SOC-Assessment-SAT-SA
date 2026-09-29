"""Validation harness: evaluates SAT-SA findings and scoring against synthetic ground truth."""

import csv
import json
from html import escape
from pathlib import Path
from typing import Any

from satsa.rules.base import BaseRule
from satsa.rules.registry import RuleRegistry
from satsa.scoring.scorer import ScoringEngine
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def compute_spearman_rank_corr(ranks1: list[float], ranks2: list[float]) -> float:
    """Compute Spearman rank correlation coefficient between two ranked lists."""
    n = len(ranks1)
    if n <= 1:
        return 1.0

    d_squared_sum = sum((r1 - r2) ** 2 for r1, r2 in zip(ranks1, ranks2, strict=True))
    rho = 1.0 - (6.0 * d_squared_sum) / (n * (n**2 - 1))
    return max(-1.0, min(1.0, rho))


def assign_ranks(values: list[float], reverse: bool = True) -> list[float]:
    """Assign fractional ranks to values (default highest value gets rank 1)."""
    indexed = sorted(enumerate(values), key=lambda x: x[1], reverse=reverse)
    ranks = [0.0] * len(values)

    i = 0
    while i < len(indexed):
        j = i
        while j < len(indexed) - 1 and indexed[j][1] == indexed[j + 1][1]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            ranks[indexed[k][0]] = avg_rank
        i = j + 1

    return ranks


CONFIRMED_LABELS = ("confirmed", "issue", "true_positive")
CLEARED_LABELS = ("not_an_issue", "cleared", "false_positive", "no_issue")


class ShadowPilotAdapter:
    """Adapter for scoring SAT-SA against historical examiner workpapers (recall and precision)."""

    def __init__(self, sqlite_store: SQLiteStore):
        self.sqlite_store = sqlite_store

    def load_manual_reviews(self, csv_path: Path | str) -> list[dict[str, Any]]:
        """Load past manual review CSV file.

        Expected CSV columns: entity_id, record_id, rule_id, label (confirmed/not_an_issue).
        A not_an_issue row with a rule_id clears that rule for that entity (used for
        precision); one without a rule_id clears only that record.
        """
        path = Path(csv_path)
        if not path.exists():
            return []

        reviews = []
        with open(path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                reviews.append(
                    {
                        "entity_id": row.get("entity_id", "").strip(),
                        "record_id": row.get("record_id", "").strip(),
                        "rule_id": row.get("rule_id", "").strip(),
                        "label": row.get("label", "confirmed").strip().lower(),
                    }
                )
        return reviews

    def evaluate_shadow_pilot(
        self, manual_reviews: list[dict[str, Any]], run_id: str
    ) -> dict[str, Any]:
        """Compare tool's findings and review queue against past manual reviews."""
        if not manual_reviews:
            return {"status": "no_data", "count": 0}

        cur = self.sqlite_store.conn.cursor()
        cur.execute(
            "SELECT entity_id, rule_id, score FROM findings WHERE run_id = ?",
            (run_id,),
        )
        tool_findings = {(r["entity_id"], r["rule_id"]) for r in cur.fetchall()}

        cur.execute(
            "SELECT entity_id, record_id, score FROM review_queue WHERE run_id = ? ORDER BY score DESC",
            (run_id,),
        )
        queue_rows = cur.fetchall()
        tool_queue_records = {(r["entity_id"], r["record_id"]) for r in queue_rows}

        confirmed_reviews = [r for r in manual_reviews if r["label"] in CONFIRMED_LABELS]
        total_confirmed = len(confirmed_reviews)

        matched_findings = 0
        matched_queue = 0
        # Per-row outcome, so the /shadow-pilot page and the validation report can
        # show which workpaper findings SAT-SA did and didn't reproduce.
        rows: list[dict[str, Any]] = []

        for r in confirmed_reviews:
            ent = r["entity_id"]
            rec = r["record_id"]
            rule = r["rule_id"]

            in_findings = (ent, rule) in tool_findings
            in_queue = (ent, rec) in tool_queue_records
            matched_findings += in_findings
            matched_queue += in_queue
            rows.append(
                {
                    "entity_id": ent,
                    "record_id": rec,
                    "rule_id": rule,
                    "in_findings": in_findings,
                    "in_queue": in_queue,
                }
            )

        finding_recall = matched_findings / total_confirmed if total_confirmed > 0 else 1.0
        queue_overlap = matched_queue / total_confirmed if total_confirmed > 0 else 1.0

        # Precision. A row labelled as cleared *with* a rule_id means the examiner looked
        # at that rule for that entity and found no issue, so a SAT-SA finding for the
        # pair is a false positive. A (entity, rule) pair confirmed anywhere in the
        # workpaper counts as confirmed even if another record for it was cleared.
        # Findings the workpaper never mentions are unadjudicated: a workpaper is not a
        # complete audit, so silence is not evidence of a false positive.
        cleared_reviews = [r for r in manual_reviews if r["label"] in CLEARED_LABELS]
        confirmed_pairs = {(r["entity_id"], r["rule_id"]) for r in confirmed_reviews if r["rule_id"]}
        cleared_pairs = {
            (r["entity_id"], r["rule_id"]) for r in cleared_reviews if r["rule_id"]
        } - confirmed_pairs
        findings_confirmed = sorted(p for p in tool_findings if p in confirmed_pairs)
        findings_rejected = sorted(p for p in tool_findings if p in cleared_pairs)
        findings_unadjudicated = sorted(
            p for p in tool_findings if p not in confirmed_pairs and p not in cleared_pairs
        )
        adjudicated = len(findings_confirmed) + len(findings_rejected)
        precision = len(findings_confirmed) / adjudicated if adjudicated else None

        # Record-level false alarms: cleared records that SAT-SA still put in its queue.
        cleared_records = {(r["entity_id"], r["record_id"]) for r in cleared_reviews if r["record_id"]}
        cleared_in_queue = sorted(cleared_records & tool_queue_records)

        return {
            "status": "success",
            "run_id": run_id,
            "total_manual_reviews": len(manual_reviews),
            "total_confirmed_issues": total_confirmed,
            "total_cleared_rows": len(cleared_reviews),
            "rule_finding_recall": round(finding_recall, 4),
            "queue_record_recall": round(queue_overlap, 4),
            "matched_findings": matched_findings,
            "matched_queue": matched_queue,
            "workpaper_precision": round(precision, 4) if precision is not None else None,
            "findings_confirmed": [f"{e}:{r}" for e, r in findings_confirmed],
            "findings_rejected": [f"{e}:{r}" for e, r in findings_rejected],
            "findings_unadjudicated": [f"{e}:{r}" for e, r in findings_unadjudicated],
            "cleared_records": len(cleared_records),
            "cleared_records_in_queue": [f"{e}:{r}" for e, r in cleared_in_queue],
            "rows": rows,
        }


# Benchmark targets from docs/validation.md Section 2; the report's verdicts are computed
# against these, never hardcoded.
TARGETS = {
    "rank_precision": 0.90,
    "rank_recall": 0.90,
    "recall": 0.90,
    "precision": 0.85,
    "f1": 0.85,
    "stability": 0.85,
}


SENSITIVITY_FACTORS = (0.8, 1.2)


def _perturb(value: Any, factor: float) -> Any:
    """Scale a threshold; integers move by at least 1 in the factor's direction (min 1).

    Floats in (0, 1] are shares or rates, so they are capped at 1.0.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return value
    if isinstance(value, int):
        moved = round(value * factor)
        if moved == value:
            moved = value + (1 if factor > 1 else -1)
        return max(1, moved)
    scaled = round(value * factor, 4)
    return min(scaled, 1.0) if 0 < value <= 1 else scaled


def sensitivity_markdown(sens: dict[str, Any]) -> list[str]:
    """Markdown table of the threshold-sensitivity sweep."""
    if not sens or not sens.get("rows"):
        return ["*No tunable thresholds were found to perturb.*"]

    def fmt(out: dict[str, list[str]]) -> str:
        parts = [f"TP {len(out['tp'])}", f"FN {len(out['fn'])}", f"FP {len(out['fp'])}"]
        extra = [f"missed {', '.join(out['fn'])}"] if out["fn"] else []
        extra += [f"false alarm {', '.join(out['fp'])}"] if out["fp"] else []
        return " / ".join(parts) + (f" ({'; '.join(extra)})" if extra else "")

    lines = [
        (
            f"{sens['changed']} of {sens['perturbations']} single-threshold perturbations "
            f"(±{sens['perturbation_percent']}%) changed that rule's outcome."
        ),
        "",
        "| Rule | Threshold | Baseline | Tested | Outcome at baseline | Outcome when tested |",
        "|---|---|---|---|---|---|",
    ]
    for r in sens["rows"]:
        flag = " **changed**" if r["changed"] else ""
        lines.append(
            f"| `{r['rule_id']}` | `{r['param']}` | {r['baseline']} | {r['tested']} ({r['change']}) | "
            f"{fmt(r['baseline_outcome'])} | {fmt(r['outcome'])}{flag} |"
        )
    lines += [
        "",
        (
            f"Not covered: {', '.join(sens['rules_not_covered'])} have no tunable threshold (no `params` in "
            "`config/rules.yaml`): EG03 and NS07 are zero-tolerance and NS08 checks the fixed 6-month "
            "review period. A rule showing TP 0 / FN 0 has no injected defect in this dataset."
        ),
    ]
    return lines


def _verdict(value: float, target: float) -> str:
    return "PASS" if value >= target else "FAIL"


def _badge(verdict: str) -> str:
    return f'<span class="badge{"" if verdict == "PASS" else " fail"}">{verdict}</span>'


SHADOW_CAVEAT = (
    "These figures are only as independent as the workpaper labels supplied: labels "
    "taken from real historical examiner findings are evidence; synthetic or stand-in "
    "labels only rehearse the pipeline (see docs/validation.md Section 5A)."
)


def shadow_markdown(stored: dict[str, Any] | None) -> list[str]:
    """Markdown lines reporting a stored shadow-pilot evaluation, or saying there is none."""
    if not stored:
        return ["*No shadow-pilot evaluation has been recorded for this run.*"]
    res = stored["result"]
    lines = [
        "### Shadow-Pilot Results",
        f"Workpaper `{stored['source_name']}`, evaluated {stored['created_at']} by {stored['actor']}. {SHADOW_CAVEAT}",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Workpaper rows | {res['total_manual_reviews']} ({res['total_confirmed_issues']} confirmed) |",
        (
            f"| Historical finding recall | {res['rule_finding_recall'] * 100:.1f}% "
            f"({res.get('matched_findings', '?')}/{res['total_confirmed_issues']}) |"
        ),
        (
            f"| Queue record recall | {res['queue_record_recall'] * 100:.1f}% "
            f"({res.get('matched_queue', '?')}/{res['total_confirmed_issues']}) |"
        ),
        f"| Workpaper precision | {_precision_text(res)} |",
        f"| Findings not adjudicated by the workpaper | {len(res.get('findings_unadjudicated', []))} |",
        (
            f"| Cleared records still in the review queue | {len(res.get('cleared_records_in_queue', []))}"
            f"/{res.get('cleared_records', 0)} |"
        ),
    ]
    missed = [r for r in res.get("rows", []) if not r["in_findings"]]
    if missed:
        lines += ["", "Confirmed workpaper findings with no matching SAT-SA finding:"]
        lines += [f"- {r['entity_id']} / {r['rule_id']} (record {r['record_id'] or 'n/a'})" for r in missed]
    if res.get("findings_rejected"):
        lines += ["", "SAT-SA findings the workpaper cleared (false positives): " + ", ".join(res["findings_rejected"])]
    return lines


def _precision_text(res: dict[str, Any]) -> str:
    """Workpaper precision with its counts, or why it cannot be computed."""
    if "workpaper_precision" not in res:
        return "not computed (evaluated before precision was supported)"
    if res["workpaper_precision"] is None:
        return "n/a (no SAT-SA finding is confirmed or cleared by a rule-level workpaper row)"
    confirmed, rejected = len(res["findings_confirmed"]), len(res["findings_rejected"])
    return f"{res['workpaper_precision'] * 100:.1f}% ({confirmed}/{confirmed + rejected} adjudicated findings)"


def shadow_html(stored: dict[str, Any] | None) -> str:
    """HTML card reporting a stored shadow-pilot evaluation, or saying there is none."""
    if not stored:
        return (
            '<div class="card"><h2>Shadow-Pilot Results</h2>'
            "<p>No shadow-pilot evaluation has been recorded for this run.</p></div>"
        )
    res = stored["result"]
    missed = [r for r in res.get("rows", []) if not r["in_findings"]]
    rejected_html = (
        f"<p>SAT-SA findings the workpaper cleared (false positives): {escape(', '.join(res['findings_rejected']))}</p>"
        if res.get("findings_rejected")
        else ""
    )
    missed_html = (
        "<p>Confirmed workpaper findings with no matching SAT-SA finding:</p><ul>"
        + "".join(
            f"<li>{escape(r['entity_id'])} / {escape(r['rule_id'])} (record {escape(r['record_id'] or 'n/a')})</li>"
            for r in missed
        )
        + "</ul>"
        if missed
        else ""
    )
    return f"""<div class="card">
    <h2>Shadow-Pilot Results</h2>
    <p>Workpaper <code>{escape(stored["source_name"])}</code>, evaluated {escape(stored["created_at"])} by {escape(stored["actor"])}.</p>
    <p>{escape(SHADOW_CAVEAT)}</p>
    <table>
      <thead><tr><th>Measure</th><th>Value</th></tr></thead>
      <tbody>
        <tr><td><strong>Workpaper rows</strong></td><td>{res["total_manual_reviews"]} ({res["total_confirmed_issues"]} confirmed)</td></tr>
        <tr><td><strong>Historical finding recall</strong></td><td>{res["rule_finding_recall"] * 100:.1f}% ({res.get("matched_findings", "?")}/{res["total_confirmed_issues"]})</td></tr>
        <tr><td><strong>Queue record recall</strong></td><td>{res["queue_record_recall"] * 100:.1f}% ({res.get("matched_queue", "?")}/{res["total_confirmed_issues"]})</td></tr>
        <tr><td><strong>Workpaper precision</strong></td><td>{escape(_precision_text(res))}</td></tr>
        <tr><td><strong>Findings not adjudicated by the workpaper</strong></td><td>{len(res.get("findings_unadjudicated", []))}</td></tr>
        <tr><td><strong>Cleared records still in the review queue</strong></td><td>{len(res.get("cleared_records_in_queue", []))}/{res.get("cleared_records", 0)}</td></tr>
      </tbody>
    </table>
    {rejected_html}
    {missed_html}
  </div>"""


class ValidationHarness:
    """Supervisory validation harness comparing detection and scoring against ground truth."""

    def __init__(
        self,
        duckdb_store: DuckDBStore,
        sqlite_store: SQLiteStore,
        ground_truth_path: Path | str = "data/generated/ground_truth.json",
    ):
        self.duckdb_store = duckdb_store
        self.sqlite_store = sqlite_store
        self.ground_truth_path = Path(ground_truth_path)
        self.ground_truth = self._load_ground_truth()

    def _load_ground_truth(self) -> dict[str, Any]:
        """Load ground truth JSON if available."""
        if self.ground_truth_path.exists():
            return json.loads(self.ground_truth_path.read_text(encoding="utf-8"))
        return {}

    def get_latest_run_id(self) -> str:
        """Fetch the most recent run ID from SQLite."""
        cur = self.sqlite_store.conn.cursor()
        cur.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1")
        row = cur.fetchone()
        return row["run_id"] if row else ""

    def evaluate_entity_ranking(self, run_id: str | None = None) -> dict[str, Any]:
        """Evaluate entity ranking: are injected entities at top, clean at bottom?"""
        run_id = run_id or self.get_latest_run_id()
        cur = self.sqlite_store.conn.cursor()
        cur.execute(
            "SELECT entity_id, risk_index, risk_band FROM entity_scores WHERE run_id = ? ORDER BY risk_index DESC",
            (run_id,),
        )
        rows = cur.fetchall()
        if not rows:
            return {"status": "no_data"}

        ranked_entities = [r["entity_id"] for r in rows]
        clean_entities = set(self.ground_truth.get("clean_entities", []))
        injected_entities = {d["entity_id"] for d in self.ground_truth.get("defects", [])}

        # Check top-k where k = len(injected_entities)
        k = len(injected_entities)
        top_k = set(ranked_entities[:k])
        clean_in_top_k = top_k.intersection(clean_entities)
        injected_in_top_k = top_k.intersection(injected_entities)

        precision_at_k = len(injected_in_top_k) / k if k > 0 else 1.0
        recall_at_k = len(injected_in_top_k) / len(injected_entities) if injected_entities else 1.0

        # Confounder checks
        confounders = self.ground_truth.get("confounders", [])

        return {
            "total_entities": len(ranked_entities),
            "injected_count": len(injected_entities),
            "clean_count": len(clean_entities),
            "top_k": ranked_entities[:k],
            "bottom_clean": ranked_entities[k:],
            "precision_at_k": round(precision_at_k, 4),
            "recall_at_k": round(recall_at_k, 4),
            "clean_entities_in_top_k": list(clean_in_top_k),
            "confounders_evaluated": [c["type"] for c in confounders],
        }

    def evaluate_rule_detection(self, run_id: str | None = None) -> dict[str, Any]:
        """Evaluate precision, recall, and F1 of (entity, rule) findings against injected defects.

        Every finding whose (entity, rule) pair is not an injected defect is a false
        positive, on any entity and for any rule. There are no exempt rules: a rule
        that fires everywhere is exactly what precision has to expose. False
        positives are split into those on clean entities and those on defect
        entities (a rule nobody injected there), so both are visible.
        """
        run_id = run_id or self.get_latest_run_id()
        cur = self.sqlite_store.conn.cursor()
        cur.execute(
            "SELECT entity_id, rule_id, score FROM findings WHERE run_id = ?",
            (run_id,),
        )
        findings = cur.fetchall()
        detected_pairs = {(r["entity_id"], r["rule_id"]): r["score"] for r in findings}

        defects = self.ground_truth.get("defects", [])
        clean_entities = set(self.ground_truth.get("clean_entities", []))

        injected_pairs = {(d["entity_id"], d["rule_id"]): d for d in defects}

        tp_count = 0
        fn_count = 0
        fp_pairs: list[tuple[str, str]] = []

        rule_stats: dict[str, dict[str, int]] = {}

        for pair in injected_pairs:
            rule = pair[1]
            rule_stats.setdefault(rule, {"tp": 0, "fn": 0, "fp": 0})
            if pair in detected_pairs:
                tp_count += 1
                rule_stats[rule]["tp"] += 1
            else:
                fn_count += 1
                rule_stats[rule]["fn"] += 1

        for pair in sorted(detected_pairs):
            if pair not in injected_pairs:
                fp_pairs.append(pair)
                rule_stats.setdefault(pair[1], {"tp": 0, "fn": 0, "fp": 0})
                rule_stats[pair[1]]["fp"] += 1

        fp_count = len(fp_pairs)
        fp_clean = [f"{e}:{r}" for e, r in fp_pairs if e in clean_entities]
        fp_defect_entity = [f"{e}:{r}" for e, r in fp_pairs if e not in clean_entities]

        precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 1.0
        recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 1.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "total_injected_defects": len(injected_pairs),
            "total_findings": len(detected_pairs),
            "true_positives": tp_count,
            "false_negatives": fn_count,
            "false_positives": fp_count,
            "false_positives_on_clean_entities": fp_clean,
            "false_positives_on_defect_entities": fp_defect_entity,
            "missed_defects": sorted(f"{e}:{r}" for e, r in injected_pairs if (e, r) not in detected_pairs),
            "overall_precision": round(precision, 4),
            "overall_recall": round(recall, 4),
            "overall_f1": round(f1, 4),
            "rule_breakdown": dict(sorted(rule_stats.items())),
        }

    def evaluate_review_effort_lift(self, run_id: str | None = None) -> dict[str, Any]:
        """Compute review-effort lift comparing the prioritized queue vs random alert sampling.

        Both sides use the same universe: alert records. Ground-truth affected IDs that
        are not alerts (asset IDs, comment hashes, marker IDs) and non-alert queue items
        are excluded, so the queue hit rate and the random baseline are comparable. When
        a budget exceeds the queue's alert items, only the items that exist are counted
        as examined.
        """
        run_id = run_id or self.get_latest_run_id()
        self.duckdb_store.load_all_tables()

        alert_ids = set(self.duckdb_store.query("SELECT alert_id FROM alert")["alert_id"].to_list())
        total_alerts = len(alert_ids)

        affected_alerts: set[str] = set()
        for d in self.ground_truth.get("defects", []):
            affected_alerts.update(rec for rec in d.get("affected_ids", []) if rec in alert_ids)

        cur = self.sqlite_store.conn.cursor()
        cur.execute(
            "SELECT record_id, score, is_random FROM review_queue WHERE run_id = ? ORDER BY score DESC",
            (run_id,),
        )
        queue_rows = cur.fetchall()
        queue_alert_ids = [r["record_id"] for r in queue_rows if r["record_id"] in alert_ids]

        random_baseline_prevalence = len(affected_alerts) / total_alerts if total_alerts > 0 else 0.0

        budget_results = {}
        for b in (0.01, 0.02, 0.05):
            budget = max(1, int(total_alerts * b))
            sample = queue_alert_ids[:budget]
            examined = len(sample)
            hits = sum(1 for rid in sample if rid in affected_alerts)
            hit_rate_top_k = hits / examined if examined else 0.0
            lift = hit_rate_top_k / random_baseline_prevalence if random_baseline_prevalence > 0 else 0.0

            budget_results[f"{int(b * 100)}%"] = {
                "budget_count": budget,
                "records_examined": examined,
                "queue_exhausted": examined < budget,
                "defects_found": hits,
                "hit_rate_top_k": round(hit_rate_top_k, 4),
                "random_baseline_hit_rate": round(random_baseline_prevalence, 4),
                "lift_factor": round(lift, 2),
            }

        return {
            "total_alerts": total_alerts,
            "total_queue_items": len(queue_rows),
            "total_queue_alert_items": len(queue_alert_ids),
            "total_ground_truth_affected_records": len(affected_alerts),
            "budgets": budget_results,
        }

    def evaluate_stability(
        self, run_id: str | None = None, perturbation: float = 0.20
    ) -> dict[str, Any]:
        """Perturb scoring weights by +/-20% and compute Spearman rank correlation of entity ranks."""
        run_id = run_id or self.get_latest_run_id()
        cur = self.sqlite_store.conn.cursor()
        cur.execute(
            "SELECT entity_id, risk_index FROM entity_scores WHERE run_id = ? ORDER BY entity_id",
            (run_id,),
        )
        base_rows = cur.fetchall()
        if not base_rows:
            return {"status": "no_data"}

        entities = [r["entity_id"] for r in base_rows]
        base_scores = [float(r["risk_index"]) for r in base_rows]
        base_ranks = assign_ranks(base_scores, reverse=True)

        # Perturbed +20% domain weights
        scorer_plus = ScoringEngine()
        scorer_minus = ScoringEngine()

        for d in scorer_plus.domain_weights:
            scorer_plus.domain_weights[d] *= 1.0 + perturbation
            scorer_minus.domain_weights[d] *= max(0.1, 1.0 - perturbation)

        # Normalize weights
        s_p = sum(scorer_plus.domain_weights.values())
        for d in scorer_plus.domain_weights:
            scorer_plus.domain_weights[d] /= s_p

        s_m = sum(scorer_minus.domain_weights.values())
        for d in scorer_minus.domain_weights:
            scorer_minus.domain_weights[d] /= s_m

        # Compute perturbed risk scores for each entity
        plus_scores = []
        minus_scores = []

        for ent in entities:
            cur.execute(
                "SELECT domain, score FROM domain_scores WHERE entity_id = ? AND run_id = ?",
                (ent, run_id),
            )
            doms = {r["domain"]: float(r["score"]) for r in cur.fetchall()}

            cur.execute(
                "SELECT distinct_rules_triggered FROM entity_scores WHERE entity_id = ? AND run_id = ?",
                (ent, run_id),
            )
            score_row = cur.fetchone()
            distinct_rules = score_row["distinct_rules_triggered"] if score_row else 3
            breadth_score = min(100.0, distinct_rules * 10.0)

            weighted_p = sum(
                doms.get(d, 0.0) * scorer_plus.domain_weights[d] for d in scorer_plus.domain_weights
            )
            idx_p = round(
                (1.0 - scorer_plus.breadth_weight) * weighted_p
                + scorer_plus.breadth_weight * breadth_score,
                1,
            )

            weighted_m = sum(
                doms.get(d, 0.0) * scorer_minus.domain_weights[d]
                for d in scorer_minus.domain_weights
            )
            idx_m = round(
                (1.0 - scorer_minus.breadth_weight) * weighted_m
                + scorer_minus.breadth_weight * breadth_score,
                1,
            )

            plus_scores.append(idx_p)
            minus_scores.append(idx_m)

        plus_ranks = assign_ranks(plus_scores, reverse=True)
        minus_ranks = assign_ranks(minus_scores, reverse=True)

        rho_plus = compute_spearman_rank_corr(base_ranks, plus_ranks)
        rho_minus = compute_spearman_rank_corr(base_ranks, minus_ranks)

        return {
            "perturbation_percent": int(perturbation * 100),
            "spearman_rho_plus_20": round(rho_plus, 4),
            "spearman_rho_minus_20": round(rho_minus, 4),
            "is_stable": (rho_plus >= 0.85 and rho_minus >= 0.85),
        }

    def verify_audit_and_determinism(self) -> dict[str, Any]:
        """Verify audit log hash chaining."""
        is_valid, msg = self.sqlite_store.verify_audit_chain()
        return {
            "audit_chain_valid": is_valid,
            "audit_message": msg,
        }

    def _rule_outcome(
        self, rule_cls: type[BaseRule], params: dict[str, Any], entities: list[str]
    ) -> dict[str, list[str]]:
        """Run one rule with the given params on every entity and score it against ground truth."""
        rule = rule_cls(config_override={"params": params})
        injected = {d["entity_id"] for d in self.ground_truth.get("defects", []) if d["rule_id"] == rule.id}
        detected = {e for e in entities if rule.evaluate(e, self.duckdb_store, [], "SENSITIVITY")[0]}
        return {
            "tp": sorted(detected & injected),
            "fn": sorted(injected - detected),
            "fp": sorted(detected - injected),
        }

    def evaluate_threshold_sensitivity(
        self, rules_config_path: Path | str = "config/rules.yaml"
    ) -> dict[str, Any]:
        """Move each tunable rule threshold by -20% and +20% and re-score that rule.

        Unlike evaluate_stability (scoring weights only), this re-runs the detection rules
        themselves, so it shows how much margin each injected defect and each clean entity
        has. Integer params always move by at least 1; shares and rates are capped at 1.0.
        Rules with no `params` in config cannot be perturbed and are listed as not covered.
        """
        registry = RuleRegistry(rules_config_path)
        entities = self.duckdb_store.query("SELECT DISTINCT entity_id FROM entity ORDER BY entity_id")[
            "entity_id"
        ].to_list()
        rows: list[dict[str, Any]] = []
        not_covered: list[str] = []
        for rule in registry.get_all_rules():
            if not rule.params:
                not_covered.append(rule.id)
                continue
            base = self._rule_outcome(type(rule), rule.params, entities)
            for key, value in rule.params.items():
                for factor in SENSITIVITY_FACTORS:
                    tested = _perturb(value, factor)
                    out = self._rule_outcome(type(rule), {**rule.params, key: tested}, entities)
                    rows.append(
                        {
                            "rule_id": rule.id,
                            "param": key,
                            "baseline": value,
                            "tested": tested,
                            "change": f"{factor - 1:+.0%}",
                            "baseline_outcome": base,
                            "outcome": out,
                            "changed": out != base,
                        }
                    )
        return {
            "perturbation_percent": round((SENSITIVITY_FACTORS[1] - 1) * 100),
            "rows": rows,
            "perturbations": len(rows),
            "changed": sum(r["changed"] for r in rows),
            "rules_covered": sorted({r["rule_id"] for r in rows}),
            "rules_not_covered": sorted(not_covered),
        }

    def run_full_validation(self, run_id: str | None = None) -> dict[str, Any]:
        """Execute complete validation suite."""
        run_id = run_id or self.get_latest_run_id()
        ranking_res = self.evaluate_entity_ranking(run_id)
        rule_res = self.evaluate_rule_detection(run_id)
        lift_res = self.evaluate_review_effort_lift(run_id)
        stability_res = self.evaluate_stability(run_id)
        sensitivity_res = self.evaluate_threshold_sensitivity()
        audit_res = self.verify_audit_and_determinism()

        return {
            "run_id": run_id,
            "entity_ranking": ranking_res,
            "rule_detection": rule_res,
            "review_effort_lift": lift_res,
            "stability": stability_res,
            "threshold_sensitivity": sensitivity_res,
            "audit": audit_res,
        }

    def _confounder_findings(self, rules: dict[str, Any]) -> list[str]:
        """Report each ground-truth confounder from this run's actual false positives."""
        fps = rules.get("false_positives_on_clean_entities", []) + rules.get(
            "false_positives_on_defect_entities", []
        )
        confounders = {c["type"] for c in self.ground_truth.get("confounders", [])}
        lines = []
        if "soar_automation" in confounders:
            # Fast automated closures are what could wrongly trip the speed/investigation rules.
            speed_fps = [fp for fp in fps if fp.split(":")[1] in ("EG01", "EG02")]
            lines.append(
                f"  * **SOAR Automation:** {len(speed_fps)} EG01/EG02 finding(s) on entities with no injected "
                f"fast-closure defect{': ' + ', '.join(speed_fps) if speed_fps else ''}."
            )
        if "small_entity" in confounders:
            small = [
                eid for eid, meta in self.ground_truth.get("entities", {}).items() if meta.get("size") == "small"
            ]
            small_fps = [fp for fp in fps if fp.split(":")[0] in small]
            lines.append(
                f"  * **Small Entity Band ({', '.join(small) or 'none'}):** {len(small_fps)} finding(s) for "
                f"rules not injected there{': ' + ', '.join(small_fps) if small_fps else ''}."
            )
        return lines or ["  * No confounders declared in the ground truth."]

    def generate_report(
        self,
        output_md_path: Path | str = "docs/validation_report.md",
        output_html_path: Path | str = "docs/validation_report.html",
        run_id: str | None = None,
        shadow_result: dict[str, Any] | None = None,
    ) -> tuple[Path, Path]:
        """Generate markdown and HTML validation report artifacts.

        `shadow_result` is a stored shadow-pilot evaluation (a row from
        SQLiteStore.list_shadow_results); when given, its figures are reported in
        Section 5 instead of only the method description.
        """
        md_path = Path(output_md_path)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        html_path = Path(output_html_path)
        html_path.parent.mkdir(parents=True, exist_ok=True)

        results = self.run_full_validation(run_id)
        r_id = results["run_id"]
        ranking = results["entity_ranking"]
        rules = results["rule_detection"]
        lift = results["review_effort_lift"]
        stability = results["stability"]
        audit = results["audit"]

        rho_min = min(stability.get("spearman_rho_plus_20", 0.0), stability.get("spearman_rho_minus_20", 0.0))
        verdicts = {
            "rank_precision": _verdict(ranking.get("precision_at_k", 0.0), TARGETS["rank_precision"]),
            "rank_recall": _verdict(ranking.get("recall_at_k", 0.0), TARGETS["rank_recall"]),
            "recall": _verdict(rules.get("overall_recall", 0.0), TARGETS["recall"]),
            "precision": _verdict(rules.get("overall_precision", 0.0), TARGETS["precision"]),
            "f1": _verdict(rules.get("overall_f1", 0.0), TARGETS["f1"]),
            "stability": _verdict(rho_min, TARGETS["stability"]),
            "audit": "PASS" if audit.get("audit_chain_valid") else "FAIL",
        }
        sens = results.get("threshold_sensitivity", {})
        confounder_lines = self._confounder_findings(rules)
        fp_clean = rules.get("false_positives_on_clean_entities", [])
        fp_defect = rules.get("false_positives_on_defect_entities", [])
        missed = rules.get("missed_defects", [])

        # Build Markdown
        md_lines = [
            "# SAT-SA Detector-Implementation Correctness Report",
            "",
            "> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*",
            "",
            f"**Run ID:** `{r_id}` | **Validation Engine:** Fully Deterministic (No AI/ML)",
            "",
            "## 1. Executive Summary & Verification Criteria",
            (
                "This report documents whether each detection rule's code correctly implements its own specified "
                "logic, measured against a synthetic ground-truth dataset across 10 Critical Sector Entities (CSEs) "
                "whose injected defects are deliberately built to clearly exceed each rule's threshold. High scores "
                "here demonstrate implementation correctness on an unambiguous dataset, not real-world detection "
                "accuracy -- see docs/validation.md Section 0 for the harder, more realistic 'stress scenario' "
                "(`satsa validate-stress`) and Section 5 for the Shadow-Pilot mode against real historical findings."
            ),

            "",
            (
                "Precision counts every finding whose (entity, rule) pair is not an injected defect as a false "
                "positive, on any entity and for any rule, with no exempt rules."
            ),
            "",
            "| Assessment Axis | Empirical Result | Target | Status |",
            "|---|---|---|---|",
            f"| **Entity Rank Precision@k** | {ranking.get('precision_at_k', 0.0) * 100:.1f}% | ≥ {TARGETS['rank_precision'] * 100:.0f}% | {verdicts['rank_precision']} |",
            f"| **Entity Rank Recall@k** | {ranking.get('recall_at_k', 0.0) * 100:.1f}% | ≥ {TARGETS['rank_recall'] * 100:.0f}% | {verdicts['rank_recall']} |",
            f"| **Injected Defect Recall** | {rules.get('overall_recall', 0.0) * 100:.1f}% ({rules.get('true_positives')}/{rules.get('total_injected_defects')}) | ≥ {TARGETS['recall'] * 100:.0f}% | {verdicts['recall']} |",
            f"| **Overall Defect Precision** | {rules.get('overall_precision', 0.0) * 100:.1f}% ({rules.get('true_positives')}/{rules.get('true_positives', 0) + rules.get('false_positives', 0)}) | ≥ {TARGETS['precision'] * 100:.0f}% | {verdicts['precision']} |",
            f"| **Overall Defect F1 Score** | {rules.get('overall_f1', 0.0):.4f} | ≥ {TARGETS['f1']:.2f} | {verdicts['f1']} |",
            f"| **Ranking Stability (±20% domain weights)** | Spearman ρ = {stability.get('spearman_rho_plus_20'):.4f} / {stability.get('spearman_rho_minus_20'):.4f} | ≥ {TARGETS['stability']:.2f} | {verdicts['stability']} |",
            f"| **Cryptographic Audit Log Integrity** | {audit.get('audit_message')} | intact | {verdicts['audit']} |",
            "",
            "## 2. Entity-Level Ranking & Confounder Discrimination",
            f"- **Top-k Ranked Entities (k = injected entity count):** {', '.join(ranking.get('top_k', []))}",
            f"- **Remaining Entities:** {', '.join(ranking.get('bottom_clean', []))}",
            f"- **Clean Entities Ranked in Top-k:** {', '.join(ranking.get('clean_entities_in_top_k', [])) or 'none'}",
            "- **Confounder Checks (measured from this run's findings):**",
            *confounder_lines,
            "",
            "## 3. Rule Detection Accuracy (Execution Gaps & Negative Space)",
            f"- **Findings Raised:** {rules.get('total_findings')} (entity, rule) pairs",
            f"- **Injected Defects Detected:** {rules.get('true_positives')} of {rules.get('total_injected_defects')}",
            f"- **Missed Defects (False Negatives):** {rules.get('false_negatives')}{' -- ' + ', '.join(missed) if missed else ''}",
            f"- **False Positives on Clean Entities:** {len(fp_clean)}{' -- ' + ', '.join(fp_clean) if fp_clean else ''}",
            f"- **False Positives on Defect Entities (rule not injected there):** {len(fp_defect)}{' -- ' + ', '.join(fp_defect) if fp_defect else ''}",
            "",
            "### Per-Rule Empirical Breakdown",
            "| Rule ID | True Positives (TP) | False Negatives (FN) | False Positives (FP) |",
            "|---|---|---|---|",
        ]

        for r_code, counts in rules.get("rule_breakdown", {}).items():
            md_lines.append(
                f"| `{r_code}` | {counts.get('tp', 0)} | {counts.get('fn', 0)} | {counts.get('fp', 0)} |"
            )

        md_lines.extend(
            [
                "",
                "## 4. Review-Effort Lift Analysis",
                (
                    "Review-effort lift compares the share of defect-affected alerts among the review queue's "
                    "top alert items with the share among all alerts (what random sampling would find), at "
                    "budgets of 1%, 2% and 5% of total alerts. Both sides count alert records only. The queue "
                    f"holds {lift.get('total_queue_alert_items', 0)} alert items "
                    f"({lift.get('total_queue_items', 0)} items in total); where a budget exceeds that, only the "
                    "items that exist are counted as examined."
                ),
                "",
                "| Audit Budget (% of Alerts) | Budget (alerts) | Queue Alerts Examined | Affected Alerts Found | Queue Hit Rate | Random Sampling Rate | Lift Factor |",
                "|---|---|---|---|---|---|---|",
            ]
        )

        for b_str, b_data in lift.get("budgets", {}).items():
            exhausted = " (queue exhausted)" if b_data.get("queue_exhausted") else ""
            md_lines.append(
                f"| **{b_str}** | {b_data['budget_count']} | {b_data['records_examined']}{exhausted} | "
                f"{b_data['defects_found']} | "
                f"{b_data['hit_rate_top_k'] * 100:.1f}% | {b_data['random_baseline_hit_rate'] * 100:.2f}% | "
                f"**{b_data['lift_factor']:.2f}x** |"
            )

        md_lines.extend(
            [
                "",
                "## 5. Shadow-Pilot Integration Method",
                "The `ShadowPilotAdapter` class allows regulatory examiners to validate SAT-SA against historical manual examination findings.",
                "Examiners provide historical CSV logs with schema `(entity_id, record_id, rule_id, label)`. The harness calculates:",
                "1. **Historical finding recall**: Percentage of prior manually confirmed supervisory findings detected by SAT-SA.",
                "2. **Queue discovery efficiency**: Overlap between past examiner investigations and SAT-SA's top-k review queue.",
                "3. **Workpaper precision**: Of the SAT-SA findings the workpaper adjudicates, the share examiners confirmed. Findings the workpaper does not mention are listed as unadjudicated, not counted as false positives.",
                "",
                *shadow_markdown(shadow_result),
                "",
                "## 6. Sensitivity & Robustness Analysis",
                f"- Evaluated with **±{stability.get('perturbation_percent')}%** perturbation of the scoring **domain weights** only.",
                f"- Spearman rank correlation with +20% weights: **{stability.get('spearman_rho_plus_20'):.4f}**",
                f"- Spearman rank correlation with -20% weights: **{stability.get('spearman_rho_minus_20'):.4f}**",
                (
                    f"- **Conclusion:** {'The entity ranking is stable' if verdicts['stability'] == 'PASS' else 'The entity ranking is NOT stable'} "
                    "under this domain-weight perturbation. This does not move rule detection thresholds; "
                    "Section 7 does."
                ),
                "",
                "## 7. Rule Threshold Sensitivity",
                (
                    "Each tunable rule threshold is moved by -20% and +20% on its own, and that rule is re-run on "
                    "every entity and scored against the ground truth. A changed outcome means an injected defect "
                    "or a clean entity sits within 20% of that threshold. The synthetic defects were built with the "
                    "thresholds in hand, so this measures their margin, not real-world robustness."
                ),
                "",
                *sensitivity_markdown(results.get("threshold_sensitivity", {})),
            ]
        )

        md_content = "\n".join(md_lines)
        md_path.write_text(md_content, encoding="utf-8")

        # Build HTML
        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>SAT-SA Detector-Implementation Correctness Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; color: #1e293b; line-height: 1.6; max-width: 1000px; margin: auto; padding: 20px; }}
    h1, h2, h3 {{ color: #0f172a; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 0.8rem; background: #dcfce7; color: #15803d; }}
    .badge.fail {{ background: #fee2e2; color: #b91c1c; }}
    .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 25px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; margin-bottom: 12px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 10px 14px; text-align: left; }}
    th {{ background: #f1f5f9; }}
    .footer {{ margin-top: 50px; padding-top: 15px; border-top: 2px solid #e2e8f0; font-size: 0.85rem; color: #64748b; text-align: center; }}
    .notice {{ color: #b91c1c; font-weight: 700; }}
  </style>
</head>
<body>
  <h1>SAT-SA Detector-Implementation Correctness Report</h1>
  <div class="notice">Indicators requiring supervisory review; not a compliance determination.</div>
  <p>Run ID: <code>{r_id}</code> | Methodology: Deterministic SQL & Robust Statistics (No AI/ML)</p>

  <div class="card">
    <h2>Detector-Implementation Correctness Summary</h2>
    <table>
      <thead><tr><th>Metric</th><th>Score</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td><strong>Entity Rank Precision@k</strong></td><td>{ranking.get("precision_at_k", 0.0) * 100:.1f}%</td><td>{_badge(verdicts["rank_precision"])}</td></tr>
        <tr><td><strong>Injected Defect Recall</strong></td><td>{rules.get("overall_recall", 0.0) * 100:.1f}%</td><td>{_badge(verdicts["recall"])}</td></tr>
        <tr><td><strong>Defect Precision (all findings)</strong></td><td>{rules.get("overall_precision", 0.0) * 100:.1f}% ({rules.get("true_positives")}/{rules.get("true_positives", 0) + rules.get("false_positives", 0)})</td><td>{_badge(verdicts["precision"])}</td></tr>
        <tr><td><strong>Spearman Rank Stability (±20% domain weights)</strong></td><td>{rho_min:.4f}</td><td>{_badge(verdicts["stability"])}</td></tr>
        <tr><td><strong>Audit Chain Verification</strong></td><td>{escape(str(audit.get("audit_message")))}</td><td>{_badge(verdicts["audit"])}</td></tr>
      </tbody>
    </table>
    <p>False positives on clean entities: {escape(", ".join(fp_clean) or "none")}</p>
    <p>False positives on defect entities (rule not injected there): {escape(", ".join(fp_defect) or "none")}</p>
  </div>

  <div class="card">
    <h2>Review-Effort Lift Factor</h2>
    <table>
      <thead><tr><th>Budget</th><th>Queue Alerts Examined</th><th>Affected Alerts Found</th><th>Queue Hit Rate</th><th>Random Rate</th><th>Lift Factor</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td><strong>{k}</strong></td><td>{v['records_examined']}{' (queue exhausted)' if v['queue_exhausted'] else ''}</td><td>{v['defects_found']}</td><td>{v['hit_rate_top_k'] * 100:.1f}%</td><td>{v['random_baseline_hit_rate'] * 100:.2f}%</td><td><strong>{v['lift_factor']}x</strong></td></tr>" for k, v in lift.get("budgets", {}).items())}
      </tbody>
    </table>
  </div>

  {shadow_html(shadow_result)}

  <div class="card">
    <h2>Rule Threshold Sensitivity (±{sens.get("perturbation_percent", 20)}%)</h2>
    <p>{sens.get("changed", 0)} of {sens.get("perturbations", 0)} single-threshold perturbations changed that rule's outcome.
    Rules with no tunable threshold, not covered: {escape(", ".join(sens.get("rules_not_covered", [])) or "none")}.
    Full table in <code>docs/validation_report.md</code> Section 7.</p>
    <table>
      <thead><tr><th>Rule</th><th>Threshold</th><th>Baseline</th><th>Tested</th><th>Outcome changed</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td>{escape(r['rule_id'])}</td><td>{escape(r['param'])}</td><td>{r['baseline']}</td><td>{r['tested']} ({r['change']})</td><td>{'yes' if r['changed'] else 'no'}</td></tr>" for r in sens.get("rows", []))}
      </tbody>
    </table>
  </div>

  <div class="footer">
    <div>National Critical Information Infrastructure Protection Centre (NCIIPC)</div>
    <div>Fully Offline & Deterministic Supervisory Analytics Engine</div>
  </div>
</body>
</html>
"""
        html_path.write_text(html_content, encoding="utf-8")
        return md_path, html_path
