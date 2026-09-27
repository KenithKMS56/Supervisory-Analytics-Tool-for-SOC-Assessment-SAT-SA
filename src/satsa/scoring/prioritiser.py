"""Review queue prioritization: 70% top-risk alerts, 30% stratified random sample."""

import random
from collections import defaultdict

from satsa.models.outputs import Finding, FindingEvidence, ReviewQueueItem
from satsa.store.duckdb import DuckDBStore


class ReviewPrioritiser:
    """Builds the prioritized supervisory examination queue with explainable selection reasons."""

    def __init__(self, top_ratio: float = 0.70, random_ratio: float = 0.30, seed: int = 42):
        self.top_ratio = top_ratio
        self.random_ratio = random_ratio
        self.seed = seed

    def build_queue(
        self,
        run_id: str,
        entity_id: str,
        findings: list[Finding],
        evidences: list[FindingEvidence],
        store: DuckDBStore,
        total_size: int = 50,
    ) -> list[ReviewQueueItem]:
        """Generate ranked queue containing 70% top-risk items and 30% stratified random items."""
        # 1. Aggregate evidence hits and score per record
        record_scores: dict[str, float] = defaultdict(float)
        record_rules: dict[str, list[str]] = defaultdict(list)
        record_types: dict[str, str] = {}

        finding_map = {f.finding_id: f for f in findings}

        for ev in evidences:
            f = finding_map.get(ev.finding_id)
            if f and f.entity_id == entity_id:
                rec_id = ev.record_id
                record_scores[rec_id] += f.score
                record_rules[rec_id].append(f.rule_id)
                record_types[rec_id] = ev.record_type

        # Query all alerts for this entity to fetch severity and metadata
        sql_alerts = f"""
        SELECT alert_id, severity_final
        FROM alert
        WHERE entity_id = '{entity_id}'
        ORDER BY alert_id ASC
        """
        df_alerts = store.query(sql_alerts)
        alert_sev_map = {
            row["alert_id"]: row["severity_final"] for row in df_alerts.iter_rows(named=True)
        }

        # Sort flagged records by score descending, then record_id ascending
        sorted_flagged = sorted(record_scores.items(), key=lambda x: (-x[1], x[0]))

        target_top_count = int(total_size * self.top_ratio)
        target_rand_count = total_size - target_top_count

        queue_items: list[ReviewQueueItem] = []
        selected_ids: set[str] = set()

        # 1. Add Top-Risk items
        for rec_id, score in sorted_flagged[:target_top_count]:
            rules_str = ", ".join(sorted(set(record_rules[rec_id])))
            sev = alert_sev_map.get(rec_id, "high")
            q_id = f"Q-{run_id}-{entity_id}-{rec_id}"
            item = ReviewQueueItem(
                queue_id=q_id,
                run_id=run_id,
                entity_id=entity_id,
                record_type=record_types.get(rec_id, "alert"),
                record_id=rec_id,
                severity=sev,
                score=round(score, 1),
                selection_reason=f"Top-risk indicator triggered by rules: {rules_str} (score: {score:.1f})",
                is_random=False,
            )
            queue_items.append(item)
            selected_ids.add(rec_id)

        # 2. Add Stratified Random Sample (by severity)
        rng = random.Random(self.seed)
        unselected_alerts = sorted([aid for aid in alert_sev_map if aid not in selected_ids])

        # Group by severity
        by_sev: dict[str, list[str]] = defaultdict(list)
        for aid in unselected_alerts:
            by_sev[alert_sev_map[aid]].append(aid)

        per_sev_quota = max(1, target_rand_count // max(len(by_sev), 1))
        random_selected: list[str] = []

        for sev in sorted(by_sev.keys()):
            aids = sorted(by_sev[sev])
            sample_k = min(len(aids), per_sev_quota)
            if sample_k > 0:
                random_selected.extend(rng.sample(aids, sample_k))

        # Fill any remainder up to target_rand_count
        remaining_pool = sorted(
            [aid for aid in unselected_alerts if aid not in set(random_selected)]
        )
        needed = target_rand_count - len(random_selected)
        if needed > 0 and remaining_pool:
            random_selected.extend(rng.sample(remaining_pool, min(needed, len(remaining_pool))))

        for aid in random_selected:
            sev = alert_sev_map.get(aid, "low")
            q_id = f"Q-{run_id}-{entity_id}-RND-{aid}"
            item = ReviewQueueItem(
                queue_id=q_id,
                run_id=run_id,
                entity_id=entity_id,
                record_type="alert",
                record_id=aid,
                severity=sev,
                score=0.0,
                selection_reason=f"Stratified random sample ({sev.upper()}) for control verification and lift benchmarking",
                is_random=True,
            )
            queue_items.append(item)

        return queue_items
