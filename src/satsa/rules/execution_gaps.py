"""Execution Gap Detection Rules: EG01 through EG12."""

import math
from typing import Any

from satsa.models.outputs import Finding, FindingEvidence
from satsa.rules.base import BaseRule
from satsa.store.duckdb import DuckDBStore

# EG05's chance floor never exceeds this multiple of the configured min_repeat_count.
CHANCE_FLOOR_CAP_FACTOR = 2


def chance_repeat_floor(n_alerts: int, pair_space: int, max_chance_pairs: float, cap: int) -> int:
    """Smallest repeat count k (at most `cap`) that chance alone would rarely reach.

    Models alerts as spread evenly over the entity's asset x rule pairs, so each pair's
    count is Poisson with mean n_alerts / pair_space. Returns the smallest k for which the
    expected number of pairs reaching k by coincidence, pair_space * P(X >= k), is below
    max_chance_pairs. Real alert streams are uneven, so genuinely noisy pairs sit far above
    this floor; it only removes small-count repeats that volume alone explains.

    Capped at `cap`: in a very busy entity with few pairs the model would call any repeat
    count "just volume", but a pair firing dozens of times, always benign and never tuned, is
    the defect itself.
    """
    if n_alerts <= 0 or pair_space <= 0:
        return 1
    lam = n_alerts / pair_space
    pmf = math.exp(-lam)  # P(X = 0)
    tail = 1.0  # P(X >= 0)
    for k in range(1, cap):
        tail -= pmf  # P(X >= k)
        if pair_space * tail < max_chance_pairs:
            return k
        pmf *= lam / k  # P(X = k)
    return cap


class EG01FastClosure(BaseRule):
    """EG01: Fast High-Severity Closure."""

    id = "EG01"
    name = "Fast High-Severity Closure"
    domain = "Investigation"
    level = "entity"
    min_sample = 10
    severity_weight = 85.0
    benign_explanations = [
        "Well-known benign vulnerability scan causing instant recognized alert dismissals.",
        "SOAR playbook misclassified as human closed.",
        "Pre-approved scheduled maintenance window activity.",
    ]
    examiner_check = "Sample 5 fast-closed High/Critical alerts and inspect workflow logs to verify if analysis was truly performed."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Peer-cohort p5 close time for human High/Critical alerts. The entity itself is
        # excluded, so its own fast closures cannot drag down the baseline they are judged by.
        peer_clause, peer_params = self.peer_filter(entity_id, peer_ids)
        peer_sql = f"""
        SELECT quantile_cont(epoch(closed_at) - epoch(created_at), 0.05) as peer_p5
        FROM alert
        WHERE severity_final IN ('high', 'critical') AND closed_by_type = 'human'
          AND closed_at IS NOT NULL AND {peer_clause}
        """
        peer_res = store.query(peer_sql, peer_params)
        peer_p5 = (
            float(peer_res["peer_p5"][0])
            if not peer_res.is_empty() and peer_res["peer_p5"][0]
            else 900.0
        )

        # Find target entity alerts closed faster than peer p5 with <= 1 workflow event
        target_sql = """
        WITH alt_events AS (
            SELECT a.alert_id, a.severity_final, a.closed_by,
                   epoch(a.closed_at) - epoch(a.created_at) as dur_sec,
                   count(w.ref_id) as event_cnt
            FROM alert a
            LEFT JOIN workflow_event w ON a.entity_id = w.entity_id AND w.ref_type = 'alert' AND a.alert_id = w.ref_id
            WHERE a.entity_id = ?
              AND a.severity_final IN ('high', 'critical')
              AND a.closed_by_type = 'human'
              AND a.closed_at IS NOT NULL
            GROUP BY a.alert_id, a.severity_final, a.closed_by, a.closed_at, a.created_at
        )
        SELECT * FROM alt_events
        """
        df = store.query(target_sql, [entity_id])
        if df.is_empty():
            return [], []

        # Tunable: min share of closures faster than peer p5, and min count of such closures.
        fast_share_threshold = float(self.params.get("fast_share_threshold", 0.15))
        min_fast_count = int(self.params.get("min_fast_count", 5))

        total_n = df.shape[0]
        fast_df = df.filter((df["dur_sec"] < peer_p5) & (df["event_cnt"] <= 1))
        fast_count = fast_df.shape[0]
        share = fast_count / total_n

        if share > fast_share_threshold and fast_count >= min_fast_count:
            score, conf = self.compute_rule_score(share / fast_share_threshold, total_n)
            f_id = f"FND-EG01-{entity_id}-{run_id}"
            sample_ids = fast_df["alert_id"].head(10).to_list()

            rationale = (
                f"Entity closed {fast_count} of {total_n} ({share:.1%}) human-handled High/Critical alerts "
                f"faster than peer 5th percentile ({peer_p5 / 60:.1f} mins) with <= 1 workflow event."
            )

            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="high" if score > 70 else "medium",
                title=f"{self.name}: {share:.1%} fast high-severity closures",
                rationale=rationale,
                peer_comparison={
                    "peer_p5_seconds": peer_p5,
                    "entity_share": share,
                    "peer_count": len(peer_ids),
                },
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=sample_ids,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id,
                    record_type="alert",
                    record_id=aid,
                    details={"rule": self.id, "reason": "Fast closure with minimal workflow"},
                )
                for aid in sample_ids
            ]
            return [finding], evidences
        return [], []


class EG02AckWithoutInvestigation(BaseRule):
    """EG02: Ack without Investigation."""

    id = "EG02"
    name = "Ack without Investigation"
    domain = "Investigation"
    level = "entity"
    min_sample = 15
    severity_weight = 80.0
    benign_explanations = [
        "Pre-triaged alert escalated from external feed with notes kept in external ticketing system.",
        "Broad benign storm where supervisor authorized bulk acknowledgment and dismissal.",
    ]
    examiner_check = (
        "Inspect analyst shift logs to verify why no investigation events or notes were captured."
    )

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        sql = """
        WITH alert_summary AS (
            SELECT
                a.alert_id,
                count(CASE WHEN w.action = 'investigate' THEN 1 END) as inv_count,
                coalesce(c.comment_len, 0) as comment_len
            FROM alert a
            LEFT JOIN workflow_event w ON a.entity_id = w.entity_id AND w.ref_type = 'alert' AND a.alert_id = w.ref_id
            LEFT JOIN closure c ON a.entity_id = c.entity_id AND a.alert_id = c.ref_id
            WHERE a.entity_id = ? AND a.closed_by_type = 'human'
            GROUP BY a.alert_id, c.comment_len
        )
        SELECT * FROM alert_summary
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        total_n = df.shape[0]
        zero_inv_df = df.filter((df["inv_count"] == 0) & (df["comment_len"] < 25))
        cnt = zero_inv_df.shape[0]
        share = cnt / total_n

        # Tunable: max share and min count of human closures with no investigation event
        # and a trivial comment. The score normalisation (0.15) stays fixed.
        max_uninvestigated_share = float(self.params.get("max_uninvestigated_share", 0.15))
        min_uninvestigated_count = int(self.params.get("min_uninvestigated_count", 5))
        if share > max_uninvestigated_share and cnt >= min_uninvestigated_count:
            score, conf = self.compute_rule_score(share / 0.15, total_n)
            f_id = f"FND-EG02-{entity_id}-{run_id}"
            sample_ids = zero_inv_df["alert_id"].head(10).to_list()

            rationale = (
                f"{cnt} of {total_n} alerts ({share:.1%}) were acknowledged and closed "
                f"with 0 investigative events and trivial closure commentary (< 25 characters)."
            )
            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="high" if score > 70 else "medium",
                title=f"{self.name}: {share:.1%} closed without investigation",
                rationale=rationale,
                peer_comparison={"entity_share": share},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=sample_ids,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id, record_type="alert", record_id=aid, details={"rule": self.id}
                )
                for aid in sample_ids
            ]
            return [finding], evidences
        return [], []


class EG03CriticalWithoutEscalation(BaseRule):
    """EG03: Critical closed without escalation."""

    id = "EG03"
    name = "Critical Closed without Escalation"
    domain = "Escalation"
    level = "alert"
    min_sample = 5
    severity_weight = 95.0
    benign_explanations = [
        "Critical alert handled directly by Senior Tier-3 responder on duty.",
        "Test alert generated during red-team exercise.",
    ]
    examiner_check = "Review unescalated Critical TP alerts with the incident manager to confirm whether Tier-2/Tier-3 response was engaged."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        sql = """
        SELECT a.alert_id, a.category, a.disposition, count(e.esc_id) as esc_cnt
        FROM alert a
        LEFT JOIN escalation e ON a.entity_id = e.entity_id AND a.alert_id = e.ref_id
        WHERE a.entity_id = ?
          AND a.severity_final = 'critical'
          AND a.disposition = 'true_positive'
        GROUP BY a.alert_id, a.category, a.disposition
        HAVING count(e.esc_id) = 0
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        unesc_ids = df["alert_id"].to_list()
        score, conf = self.compute_rule_score(len(unesc_ids) / 2.0, len(unesc_ids))
        f_id = f"FND-EG03-{entity_id}-{run_id}"

        rationale = (
            f"Detected {len(unesc_ids)} Critical true-positive alerts closed without any "
            f"corresponding Tier-2 escalation record."
        )
        finding = Finding(
            finding_id=f_id,
            run_id=run_id,
            entity_id=entity_id,
            rule_id=self.id,
            rule_version=self.version,
            domain=self.domain,
            level=self.level,
            score=score,
            confidence=conf,
            severity="critical",
            title=f"{self.name}: {len(unesc_ids)} unescalated Critical TPs",
            rationale=rationale,
            peer_comparison={"unescalated_count": len(unesc_ids)},
            examiner_check=self.examiner_check,
            benign_explanations=self.benign_explanations,
            evidence_ids=unesc_ids,
        )
        evidences = [
            FindingEvidence(
                finding_id=f_id,
                record_type="alert",
                record_id=aid,
                details={"severity": "critical"},
            )
            for aid in unesc_ids
        ]
        return [finding], evidences


class EG04TemplateDrivenInvestigations(BaseRule):
    """EG04: Template-driven investigations."""

    id = "EG04"
    name = "Template-Driven Investigations"
    domain = "Investigation"
    level = "entity"
    min_sample = 20
    severity_weight = 75.0
    benign_explanations = [
        "Standardized compliance disclaimers appended by ticketing system macro.",
        "Repetitive false positive from known business software update.",
    ]
    examiner_check = "Sample recurring normalized comments to see if analysts paste boilerplates without conducting individual case inquiry."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Tunable: max share of human closures in repeated-comment-hash groups, and the
        # min size of a hash group to count as boilerplate.
        max_comment_hash_share = float(self.params.get("max_comment_hash_share", 0.25))
        min_hash_group_size = int(self.params.get("min_hash_group_size", 10))
        sql = """
        SELECT
            c.comment_norm_hash,
            count(*) as repeats,
            min(a.alert_id) as sample_alert
        FROM alert a
        JOIN closure c ON a.entity_id = c.entity_id AND a.alert_id = c.ref_id
        WHERE a.entity_id = ? AND a.closed_by_type = 'human'
        GROUP BY c.comment_norm_hash
        HAVING count(*) >= ?
        ORDER BY repeats DESC
        """
        df = store.query(sql, [entity_id, min_hash_group_size])
        if df.is_empty():
            return [], []

        total_human_sql = "SELECT count(*) as total FROM alert WHERE entity_id = ? AND closed_by_type = 'human'"
        total_res = store.query(total_human_sql, [entity_id])
        total_human = total_res["total"][0] if not total_res.is_empty() else 1

        top_repeats = int(df["repeats"].sum())
        repeat_share = top_repeats / max(total_human, 1)

        if repeat_share > max_comment_hash_share:
            score, conf = self.compute_rule_score(
                repeat_share / max_comment_hash_share, total_human
            )
            f_id = f"FND-EG04-{entity_id}-{run_id}"
            sample_ids = df["sample_alert"].head(10).to_list()

            rationale = (
                f"{top_repeats} of {total_human} ({repeat_share:.1%}) human-closed alerts "
                f"share identical normalized comment hashes repeating >= {min_hash_group_size} times."
            )
            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="medium" if score < 70 else "high",
                title=f"{self.name}: {repeat_share:.1%} boilerplate comment reuse",
                rationale=rationale,
                peer_comparison={"repeat_share": repeat_share},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=sample_ids,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id, record_type="alert", record_id=aid, details={"rule": self.id}
                )
                for aid in sample_ids
            ]
            return [finding], evidences
        return [], []


class EG05RepeatAlertsNoRootCause(BaseRule):
    """EG05: Repeat alerts, no root cause."""

    id = "EG05"
    name = "Repeat Alerts without Root Cause"
    domain = "Operational Discipline"
    level = "entity"
    min_sample = 10
    severity_weight = 70.0
    benign_explanations = [
        "Remediation ticket tracked in external Jira/ServiceNow instance not linked in submission.",
        "Low-priority noisy asset slated for decommissioning.",
    ]
    examiner_check = "Review the top repeated (asset, rule) pairs and verify whether root-cause tuning tickets were raised."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Tunable: min repeats of an all-benign (asset, rule) pair, min number of such
        # unremediated pairs before the entity is flagged, and how many pairs chance alone
        # may be expected to push over the repeat threshold.
        min_repeat_count = int(self.params.get("min_repeat_count", 8))
        min_unaddressed_pairs = int(self.params.get("min_unaddressed_pairs", 2))
        max_chance_pairs = float(self.params.get("max_chance_pairs", 0.5))

        # A busy entity with few assets gets pairs repeating several times by coincidence.
        # The repeat threshold is therefore never below the entity's own chance level.
        vol = store.query(
            "SELECT count(*) AS n, count(DISTINCT asset_id) AS a, count(DISTINCT rule_id) AS r FROM alert WHERE entity_id = ?",
            [entity_id],
        )
        n_alerts, pair_space = int(vol["n"][0]), int(vol["a"][0]) * int(vol["r"][0])
        chance_floor = chance_repeat_floor(
            n_alerts, pair_space, max_chance_pairs, cap=CHANCE_FLOOR_CAP_FACTOR * min_repeat_count
        )
        effective_min_repeats = max(min_repeat_count, chance_floor)
        sql = """
        WITH pairs AS (
            SELECT
                asset_id,
                rule_id,
                count(*) as pair_count,
                count(CASE WHEN disposition IN ('false_positive', 'benign') THEN 1 END) as benign_count
            FROM alert
            WHERE entity_id = ?
            GROUP BY asset_id, rule_id
            HAVING count(*) >= ? AND count(CASE WHEN disposition IN ('false_positive', 'benign') THEN 1 END) = count(*)
        ),
        remediated AS (
            SELECT DISTINCT linked_asset_id, linked_rule_id
            FROM remediation
            WHERE entity_id = ?
        )
        SELECT p.asset_id, p.rule_id, p.pair_count
        FROM pairs p
        LEFT JOIN remediated r ON p.asset_id = r.linked_asset_id AND p.rule_id = r.linked_rule_id
        WHERE r.linked_asset_id IS NULL
        ORDER BY p.pair_count DESC
        """
        df = store.query(sql, [entity_id, effective_min_repeats, entity_id])
        if df.is_empty():
            return [], []

        unaddressed_pairs = df.shape[0]
        total_repeat_alerts = int(df["pair_count"].sum())

        if unaddressed_pairs >= min_unaddressed_pairs:
            score, conf = self.compute_rule_score(
                unaddressed_pairs / float(min_unaddressed_pairs), total_repeat_alerts
            )
            f_id = f"FND-EG05-{entity_id}-{run_id}"
            sample_records = [
                f"{row['asset_id']}::{row['rule_id']}" for row in df.head(5).iter_rows(named=True)
            ]

            rationale = (
                f"Identified {unaddressed_pairs} (asset, rule) pairs generating {total_repeat_alerts} repeat alerts "
                f"consistently closed as false positive/benign with no documented remediation or tuning ticket. "
                f"Each pair repeated at least {effective_min_repeats} times (configured minimum {min_repeat_count}; "
                f"chance level for this entity's volume {chance_floor})."
            )
            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="medium",
                title=f"{self.name}: {unaddressed_pairs} recurring unaddressed pairs",
                rationale=rationale,
                peer_comparison={
                    "unaddressed_pairs": unaddressed_pairs,
                    "effective_min_repeats": effective_min_repeats,
                    "chance_floor": chance_floor,
                },
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=sample_records,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id,
                    record_type="asset",
                    record_id=rec.split("::")[0],
                    details={"rule_id": rec.split("::")[1]},
                )
                for rec in sample_records
            ]
            return [finding], evidences
        return [], []


class EG06MetricGaming(BaseRule):
    """EG06: Metric gaming (deadline hugging, bulk closures, etc.)."""

    id = "EG06"
    name = "Metric Gaming"
    domain = "Governance and Oversight"
    level = "entity"
    min_sample = 20
    severity_weight = 90.0
    benign_explanations = [
        "Legitimate automated shift handover script closing bulk triaged alerts.",
        "Batch import of historical incident resolution records.",
    ]
    examiner_check = "Inspect timestamp clusters to determine if alerts were closed legitimately or mass-dismissed to meet SLAs."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Tunable: closures by one actor in one minute that count as a bulk batch, and
        # the share of closures in the last 10% of the SLA window that counts as hugging.
        min_bulk_closures_per_minute = int(self.params.get("min_bulk_closures_per_minute", 8))
        max_deadline_hugging_share = float(self.params.get("max_deadline_hugging_share", 0.25))
        # Check bulk closures with exact same minute by same actor
        sql_bulk = """
        SELECT
            closed_by,
            date_trunc('minute', closed_at) as close_minute,
            count(*) as cnt,
            min(alert_id) as sample_id
        FROM alert
        WHERE entity_id = ? AND closed_by_type = 'human' AND closed_at IS NOT NULL
        GROUP BY closed_by, date_trunc('minute', closed_at)
        HAVING count(*) >= ?
        """
        df_bulk = store.query(sql_bulk, [entity_id, min_bulk_closures_per_minute])

        # Check deadline hugging: closed between 90% and 100% of SLA limit
        sql_deadline = """
        SELECT count(*) as total,
               count(CASE WHEN epoch(a.closed_at) - epoch(a.created_at) >= s.resolve_minutes * 60 * 0.90
                           AND epoch(a.closed_at) - epoch(a.created_at) <= s.resolve_minutes * 60 THEN 1 END) as hugging_cnt
        FROM alert a
        JOIN sla_policy s ON a.entity_id = s.entity_id AND a.severity_final = s.severity
        WHERE a.entity_id = ? AND a.closed_by_type = 'human' AND a.closed_at IS NOT NULL
        """
        df_dead = store.query(sql_deadline, [entity_id])
        dead_cnt = df_dead["hugging_cnt"][0] if not df_dead.is_empty() else 0
        total_alerts = df_dead["total"][0] if not df_dead.is_empty() else 1
        hugging_share = dead_cnt / max(total_alerts, 1)

        has_bulk = not df_bulk.is_empty()
        has_hugging = hugging_share > max_deadline_hugging_share

        if has_bulk or has_hugging:
            score, conf = self.compute_rule_score(
                2.0 if (has_bulk and has_hugging) else 1.2, total_alerts
            )
            f_id = f"FND-EG06-{entity_id}-{run_id}"
            sample_ids = df_bulk["sample_id"].to_list() if has_bulk else []

            rationale = (
                f"Metric gaming indicators detected: {df_bulk.shape[0]} bulk identical-timestamp closure batches "
                f"and {hugging_share:.1%} of alerts closed in the final 10% of the SLA deadline window."
            )
            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="critical" if score > 80 else "high",
                title=f"{self.name}: Bulk closures and SLA deadline-hugging",
                rationale=rationale,
                peer_comparison={"bulk_batches": df_bulk.shape[0], "hugging_share": hugging_share},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=sample_ids,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id, record_type="alert", record_id=aid, details={"rule": self.id}
                )
                for aid in sample_ids
            ]
            return [finding], evidences
        return [], []


class EG07AnalystImplausibility(BaseRule):
    """EG07: Analyst implausibility."""

    id = "EG07"
    name = "Analyst Implausibility"
    domain = "Operational Discipline"
    level = "entity"
    min_sample = 20
    severity_weight = 75.0
    benign_explanations = ["Shared generic analyst login credentials used across shifts."]
    examiner_check = "Review roster and authenticate user accounts to determine if shared accounts were utilized."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Tunable: human closures by one analyst within one clock hour that exceed
        # plausible capacity. The score normalisation (30) stays fixed.
        min_closures_per_analyst_hour = int(self.params.get("min_closures_per_analyst_hour", 30))
        sql = """
        SELECT
            closed_by,
            date_trunc('hour', closed_at) as close_hour,
            count(*) as hourly_closures
        FROM alert
        WHERE entity_id = ? AND closed_by_type = 'human' AND closed_at IS NOT NULL
        GROUP BY closed_by, date_trunc('hour', closed_at)
        HAVING count(*) >= ?
        """
        df = store.query(sql, [entity_id, min_closures_per_analyst_hour])
        if df.is_empty():
            return [], []

        max_hourly_val = df["hourly_closures"].max()
        max_hourly = int(str(max_hourly_val)) if max_hourly_val is not None else 0
        score, conf = self.compute_rule_score(max_hourly / 30.0, df.shape[0])
        f_id = f"FND-EG07-{entity_id}-{run_id}"
        analysts = df["closed_by"].unique().to_list()

        rationale = (
            f"Analyst productivity exceeds plausible cognitive limits: up to {max_hourly} "
            f"closures per hour recorded for analyst '{analysts[0]}'."
        )
        finding = Finding(
            finding_id=f_id,
            run_id=run_id,
            entity_id=entity_id,
            rule_id=self.id,
            rule_version=self.version,
            domain=self.domain,
            level=self.level,
            score=score,
            confidence=conf,
            severity="medium" if score < 75 else "high",
            title=f"{self.name}: {max_hourly} closures/hr exceeding human capacity",
            rationale=rationale,
            peer_comparison={"max_closures_per_hour": max_hourly},
            examiner_check=self.examiner_check,
            benign_explanations=self.benign_explanations,
            evidence_ids=analysts,
        )
        evidences = [
            FindingEvidence(
                finding_id=f_id,
                record_type="actor",
                record_id=a,
                details={"max_hourly": max_hourly},
            )
            for a in analysts
        ]
        return [finding], evidences


class EG08EscalationWithoutFollowThrough(BaseRule):
    """EG08: Escalation without follow-through."""

    id = "EG08"
    name = "Escalation without Follow-Through"
    domain = "Escalation"
    level = "entity"
    min_sample = 5
    severity_weight = 85.0
    benign_explanations = ["Escalation handled over phone / out-of-band during major crisis."]
    examiner_check = "Review escalation records with no acknowledge timestamp or linked case."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        sql = """
        SELECT esc_id, ref_id
        FROM escalation
        WHERE entity_id = ? AND acknowledged_at IS NULL
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        unack_count = df.shape[0]
        # Tunable: unacknowledged escalations needed before the entity is flagged.
        min_unacknowledged_escalations = int(self.params.get("min_unacknowledged_escalations", 3))
        if unack_count >= min_unacknowledged_escalations:
            score, conf = self.compute_rule_score(unack_count / 3.0, unack_count)
            f_id = f"FND-EG08-{entity_id}-{run_id}"
            sample_ids = df["esc_id"].head(5).to_list()

            rationale = f"Detected {unack_count} escalations from Tier-1 with no Tier-2 acknowledgment recorded."
            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="high",
                title=f"{self.name}: {unack_count} unacknowledged escalations",
                rationale=rationale,
                peer_comparison={"unack_count": unack_count},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=sample_ids,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id,
                    record_type="escalation",
                    record_id=eid,
                    details={"rule": self.id},
                )
                for eid in sample_ids
            ]
            return [finding], evidences
        return [], []


class EG09BacklogAndAging(BaseRule):
    """EG09: Backlog and aging."""

    id = "EG09"
    name = "Backlog and Aging"
    domain = "Incident Response"
    level = "entity"
    min_sample = 10
    severity_weight = 70.0
    benign_explanations = [
        "Complex forensic investigation requiring prolonged law enforcement hold."
    ]
    examiner_check = "Examine stale open cases with no recorded updates for over 14 days."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Tunable: age after which an open case is stale, and how many stale cases flag.
        stale_case_days = int(self.params.get("stale_case_days", 14))
        min_stale_cases = int(self.params.get("min_stale_cases", 3))
        sql = """
        SELECT case_id, severity, opened_at
        FROM "case"
        WHERE entity_id = ? AND status = 'open'
          AND epoch(now()) - epoch(opened_at) > ? * 86400
        """
        df = store.query(sql, [entity_id, stale_case_days])
        if df.is_empty():
            return [], []

        stale_count = df.shape[0]
        if stale_count >= min_stale_cases:
            score, conf = self.compute_rule_score(stale_count / 3.0, stale_count)
            f_id = f"FND-EG09-{entity_id}-{run_id}"
            sample_ids = df["case_id"].head(5).to_list()

            rationale = f"Detected {stale_count} open cases aged beyond {stale_case_days} days without resolution."
            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="medium",
                title=f"{self.name}: {stale_count} stale aging cases",
                rationale=rationale,
                peer_comparison={"stale_cases": stale_count},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=sample_ids,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id, record_type="case", record_id=cid, details={"rule": self.id}
                )
                for cid in sample_ids
            ]
            return [finding], evidences
        return [], []


class EG10KPIRadicalGap(BaseRule):
    """EG10: KPI reconciliation gap."""

    id = "EG10"
    name = "KPI Reconciliation Gap"
    domain = "Governance and Oversight"
    level = "entity"
    min_sample = 10
    severity_weight = 95.0
    benign_explanations = [
        "Declared KPI uses business-hours clock stops while SAT-SA recomputation uses wall-clock time."
    ]
    examiner_check = "Cross-examine management KPI reporting methodology against raw alert timestamp calculations."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Compare like with like: only severities the entity declared an MTTR for, each
        # weighted by its alert count. Averaging empirical high+critical MTTR against a
        # critical-only declaration compares different alert mixes and flags healthy
        # entities (high alerts legitimately take longer than critical ones).
        sql = """
        WITH empirical AS (
            SELECT
                severity_final as severity,
                count(*) as n,
                avg(epoch(closed_at) - epoch(created_at)) / 60.0 as emp
            FROM alert
            WHERE entity_id = ? AND severity_final IN ('high', 'critical') AND closed_at IS NOT NULL
            GROUP BY severity_final
        ),
        declared AS (
            SELECT severity, avg(value) as dec
            FROM declared_kpi
            WHERE entity_id = ? AND metric = 'MTTR' AND severity IN ('high', 'critical')
            GROUP BY severity
        )
        SELECT
            sum(e.n * e.emp) / sum(e.n) as emp_mttr,
            sum(e.n * d.dec) / sum(e.n) as dec_mttr
        FROM empirical e
        JOIN declared d ON e.severity = d.severity
        """
        df = store.query(sql, [entity_id, entity_id])
        if df.is_empty():
            return [], []

        emp_mttr = float(df["emp_mttr"][0] or 0.0)
        dec_mttr = float(df["dec_mttr"][0] or 0.0)
        if dec_mttr == 0.0 or emp_mttr == 0.0:
            return [], []

        # Tunable: flag when empirical MTTR exceeds declared MTTR by more than this ratio.
        mttr_gap_ratio_threshold = float(self.params.get("mttr_gap_ratio_threshold", 0.60))
        gap_ratio = (emp_mttr - dec_mttr) / max(dec_mttr, 1.0)
        if gap_ratio > mttr_gap_ratio_threshold:
            # 0.50 is the score-normalisation constant (distance 1.0 at a 50% gap), kept
            # separate from the detection threshold so retuning the threshold doesn't
            # also silently rescale every EG10 score.
            score, conf = self.compute_rule_score(gap_ratio / 0.50, 100)
            f_id = f"FND-EG10-{entity_id}-{run_id}"

            rationale = (
                f"Material reconciliation gap: Entity reported declared MTTR of {dec_mttr:.1f} mins, "
                f"but empirical calculation from operational timestamps reveals actual MTTR of {emp_mttr:.1f} mins "
                f"({gap_ratio:.1%} discrepancy)."
            )
            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="critical",
                title=f"{self.name}: Declared vs empirical MTTR gap ({gap_ratio:.0%})",
                rationale=rationale,
                peer_comparison={
                    "declared_mttr_mins": dec_mttr,
                    "empirical_mttr_mins": emp_mttr,
                    "gap_ratio": gap_ratio,
                },
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=[f"KPI-GAP-{entity_id}"],
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id,
                    record_type="declared_kpi",
                    record_id=f"KPI-{entity_id}",
                    details={
                        "declared": dec_mttr,
                        "empirical": emp_mttr,
                        "formula": "abs(empirical - declared) / declared",
                    },
                )
            ]
            return [finding], evidences
        return [], []


class EG11DispositionExtremes(BaseRule):
    """EG11: Disposition extremes."""

    id = "EG11"
    name = "Disposition Extremes"
    domain = "Threat Detection"
    level = "entity"
    min_sample = 200
    severity_weight = 80.0
    benign_explanations = ["Entity under continuous aggressive benign penetration testing."]
    examiner_check = (
        "Review tuning logs to understand why false positive alarms are not filtered upstream."
    )

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        sql = """
        SELECT
            count(*) as total,
            count(CASE WHEN disposition IN ('false_positive', 'benign') THEN 1 END) as fp_count,
            count(CASE WHEN disposition = 'true_positive' THEN 1 END) as tp_count
        FROM alert
        WHERE entity_id = ?
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        total = df["total"][0]
        tp_count = df["tp_count"][0]
        fp_rate = df["fp_count"][0] / max(total, 1)

        # Tunable: min alert volume before dispositions are judged; the robust-z cut-off and
        # minimum spread for comparing the FP/benign rate with the peer cohort; and the
        # absolute fallback rate used when fewer than MIN_PEERS_FOR_Z peers can be compared.
        # Zero true positives always flags at that volume.
        min_alert_volume = int(self.params.get("min_alert_volume", 200))
        max_robust_z = float(self.params.get("max_robust_z", 3.5))
        min_spread = float(self.params.get("min_spread", 0.01))
        max_fp_rate = float(self.params.get("max_fp_rate", 0.98))
        if total < min_alert_volume:
            return [], []

        peer_clause, peer_params = self.peer_filter(entity_id, peer_ids)
        peer_df = store.query(
            f"""
            SELECT entity_id,
                   count(CASE WHEN disposition IN ('false_positive', 'benign') THEN 1 END) * 1.0 / count(*) as fp_rate
            FROM alert
            WHERE {peer_clause}
            GROUP BY entity_id
            HAVING count(*) >= ?
            """,
            [*peer_params, min_alert_volume],
        )
        peer_rates = [float(v) for v in peer_df["fp_rate"].to_list()] if not peer_df.is_empty() else []
        z_res = self.robust_z(fp_rate, peer_rates, min_spread)

        comparison: dict[str, Any] = {"fp_rate": fp_rate, "total_alerts": total, "peer_count": len(peer_rates)}
        if z_res is not None:
            z, peer_median = z_res
            rate_extreme = z >= max_robust_z
            basis = (
                f"robust z-score {z:.1f} against the median of {len(peer_rates)} peers "
                f"({peer_median:.1%}; flagged at >= {max_robust_z:g})"
            )
            comparison.update(method="peer_robust_z", robust_z=round(z, 2), peer_median=peer_median)
        else:
            rate_extreme = fp_rate > max_fp_rate
            basis = f"absolute threshold {max_fp_rate:.0%} (too few comparable peers)"
            comparison.update(method="absolute")

        if tp_count == 0 or rate_extreme:
            score, conf = self.compute_rule_score(fp_rate / 0.98, total)
            f_id = f"FND-EG11-{entity_id}-{run_id}"

            rationale = (
                f"Abnormal disposition distribution: {total} total alerts processed with "
                f"a {fp_rate:.1%} false-positive/benign rate ({basis}) and {tp_count} true positives "
                "over 6 months."
            )
            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="high",
                title=f"{self.name}: {fp_rate:.1%} false positive rate",
                rationale=rationale,
                peer_comparison=comparison,
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=[f"DISP-EXTREME-{entity_id}"],
            )
            return [finding], []
        return [], []


class EG12WorkflowNonConformance(BaseRule):
    """EG12: Workflow non-conformance."""

    id = "EG12"
    name = "Workflow Non-Conformance"
    domain = "Security Operations"
    level = "entity"
    min_sample = 15
    severity_weight = 80.0
    benign_explanations = [
        "Fast-track incident closure authorized by CISO during active disaster recovery."
    ]
    examiner_check = (
        "Sample non-conforming cases and audit whether mandatory containment steps were skipped."
    )

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Check Critical cases that skipped containment stage
        sql = """
        WITH case_actions AS (
            SELECT
                c.case_id,
                count(CASE WHEN w.action = 'contain' THEN 1 END) as contain_cnt
            FROM "case" c
            LEFT JOIN workflow_event w ON c.entity_id = w.entity_id AND w.ref_type = 'case' AND c.case_id = w.ref_id
            WHERE c.entity_id = ? AND c.severity = 'critical'
            GROUP BY c.case_id
        )
        SELECT case_id FROM case_actions WHERE contain_cnt = 0
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        skipped_cases = df["case_id"].to_list()
        # Tunable: critical cases without a 'contain' stage needed before flagging.
        min_skipped_cases = int(self.params.get("min_skipped_cases", 2))
        if len(skipped_cases) >= min_skipped_cases:
            score, conf = self.compute_rule_score(len(skipped_cases) / 2.0, len(skipped_cases))
            f_id = f"FND-EG12-{entity_id}-{run_id}"

            rationale = (
                f"{len(skipped_cases)} Critical incident cases closed without recording the mandatory "
                f"'contain' workflow phase."
            )
            finding = Finding(
                finding_id=f_id,
                run_id=run_id,
                entity_id=entity_id,
                rule_id=self.id,
                rule_version=self.version,
                domain=self.domain,
                level=self.level,
                score=score,
                confidence=conf,
                severity="high",
                title=f"{self.name}: {len(skipped_cases)} cases skipped containment",
                rationale=rationale,
                peer_comparison={"skipped_cases_count": len(skipped_cases)},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=skipped_cases,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id, record_type="case", record_id=cid, details={"rule": self.id}
                )
                for cid in skipped_cases
            ]
            return [finding], evidences
        return [], []
