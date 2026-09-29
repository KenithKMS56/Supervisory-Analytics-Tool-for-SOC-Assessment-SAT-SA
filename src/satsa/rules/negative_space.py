"""Negative Space Detection Rules: NS01 through NS08."""

from satsa.models.outputs import Finding, FindingEvidence
from satsa.rules.base import BaseRule
from satsa.store.duckdb import DuckDBStore


class NS01SilentCriticalAssets(BaseRule):
    """NS01: Silent critical assets (>= min_silent_days zero-event days on critical monitored assets)."""

    id = "NS01"
    name = "Silent Critical Assets"
    domain = "Threat Detection"
    level = "asset"
    min_sample = 1
    severity_weight = 95.0
    benign_explanations = [
        "Asset officially decommissioned or offline for scheduled turnaround.",
        "Log agent uninstalled during operating system upgrade.",
    ]
    examiner_check = "Review asset management records to verify whether the asset was energized and online during the silent window."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Tunable: min asset criticality considered, and min zero-event days to flag.
        min_silent_days = int(self.params.get("min_silent_days", 3))
        min_asset_criticality = int(self.params.get("min_asset_criticality", 3))
        sql = """
        SELECT
            l.asset_id,
            count(CASE WHEN l.event_count = 0 THEN 1 END) as silent_days,
            min(l.date) as min_date,
            max(l.date) as max_date
        FROM log_source_daily l
        JOIN asset a ON l.entity_id = a.entity_id AND l.asset_id = a.asset_id
        WHERE l.entity_id = ? AND a.criticality >= ? AND a.monitored_flag = true
        GROUP BY l.asset_id
        HAVING count(CASE WHEN l.event_count = 0 THEN 1 END) >= ?
        """
        df = store.query(sql, [entity_id, min_asset_criticality, min_silent_days])
        if df.is_empty():
            return [], []

        silent_assets = df["asset_id"].to_list()
        max_silent_val = df["silent_days"].max()
        max_silent = int(str(max_silent_val)) if max_silent_val is not None else 0
        score, conf = self.compute_rule_score(
            max_silent / float(min_silent_days), len(silent_assets)
        )
        f_id = f"FND-NS01-{entity_id}-{run_id}"

        rationale = (
            f"Logging blind spot: {len(silent_assets)} monitored critical assets "
            f"recorded zero log events on up to {max_silent} days."
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
            title=f"{self.name}: {len(silent_assets)} critical assets silent >= {min_silent_days} days",
            rationale=rationale,
            peer_comparison={
                "silent_assets_count": len(silent_assets),
                "max_silent_days": max_silent,
            },
            examiner_check=self.examiner_check,
            benign_explanations=self.benign_explanations,
            evidence_ids=silent_assets,
        )
        evidences = [
            FindingEvidence(
                finding_id=f_id,
                record_type="asset",
                record_id=aid,
                details={"silent_days": max_silent},
            )
            for aid in silent_assets
        ]
        return [finding], evidences


class NS02MissingAlertCategories(BaseRule):
    """NS02: Missing alert categories reported by >= min_peer_entity_count portfolio entities."""

    id = "NS02"
    name = "Missing Alert Categories"
    domain = "Threat Detection"
    level = "entity"
    min_sample = 30
    severity_weight = 85.0
    benign_explanations = [
        "Entity operates specialized air-gapped ICS network where specific attack vectors do not exist.",
        "Specific category filtered by upstream carrier firewall.",
    ]
    examiner_check = (
        "Compare entity SIEM alert taxonomy against peer sector baseline to inspect detection"
        " coverage gaps."
    )

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Tunable: a category counts as "standard" when at least this many entities
        # in the portfolio report it (6 of the 10 demo entities by default).
        min_peer_entity_count = int(self.params.get("min_peer_entity_count", 6))
        sql_peers = """
        SELECT category, count(DISTINCT entity_id) as ent_count
        FROM alert
        WHERE category IS NOT NULL AND category != ''
        GROUP BY category
        HAVING count(DISTINCT entity_id) >= ?
        """
        df_peers = store.query(sql_peers, [min_peer_entity_count])
        peer_common_cats = (
            {c for c in df_peers["category"].to_list() if c} if not df_peers.is_empty() else set()
        )

        # Find target entity categories
        sql_target = "SELECT DISTINCT category FROM alert WHERE entity_id = ? AND category IS NOT NULL AND category != ''"
        df_target = store.query(sql_target, [entity_id])
        target_cats = (
            {c for c in df_target["category"].to_list() if c} if not df_target.is_empty() else set()
        )

        missing = {m for m in (peer_common_cats - target_cats) if m is not None}
        if missing:
            score, conf = self.compute_rule_score(len(missing) / 1.5, len(peer_common_cats))
            f_id = f"FND-NS02-{entity_id}-{run_id}"
            missing_list = sorted([str(m) for m in missing])

            rationale = (
                f"Negative space detected: Entity completely lacks alert volume for standard categories "
                f"reported by >= {min_peer_entity_count} entities in the portfolio: {', '.join(missing_list)}."
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
                title=f"{self.name}: Missing categories ({', '.join(missing_list[:3])})",
                rationale=rationale,
                peer_comparison={"missing_categories": missing_list},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=missing_list,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id,
                    record_type="category",
                    record_id=cat,
                    details={"status": "absent"},
                )
                for cat in missing_list
            ]
            return [finding], evidences
        return [], []


class NS03UnexpectedlyLowOrFlatActivity(BaseRule):
    """NS03: Unexpectedly low or flat activity (night-time alert share below max_night_share)."""

    id = "NS03"
    name = "Unexpectedly Low or Flat Activity"
    domain = "Security Operations"
    level = "entity"
    min_sample = 30
    severity_weight = 85.0
    benign_explanations = [
        "Entity operates 8x5 business-hours SOC with overnight automated queue hold.",
        "Major network segmentation reduced observable alert volume.",
    ]
    examiner_check = "Inquire regarding overnight staffing and check SIEM forwarder uptime logs."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Calculate night share of alerts
        sql = """
        SELECT
            count(*) as total,
            count(CASE WHEN extract(hour from created_at) < 8 OR extract(hour from created_at) >= 20 THEN 1 END) as night_cnt
        FROM alert
        WHERE entity_id = ?
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        total = df["total"][0]
        night_cnt = df["night_cnt"][0]
        night_share = night_cnt / max(total, 1)

        # Peer average night share
        sql_peer = """
        SELECT avg(night_cnt * 1.0 / total) as peer_night_share
        FROM (
            SELECT entity_id, count(*) as total,
                   count(CASE WHEN extract(hour from created_at) < 8 OR extract(hour from created_at) >= 20 THEN 1 END) as night_cnt
            FROM alert
            GROUP BY entity_id
        )
        """
        peer_res = store.query(sql_peer)
        peer_avg = float(peer_res["peer_night_share"][0] or 0.20)

        # Tunable: flag when the night-time share of alerts is below this, given enough volume.
        max_night_share = float(self.params.get("max_night_share", 0.03))
        min_alert_volume = int(self.params.get("min_alert_volume", 100))
        if total >= min_alert_volume and night_share < max_night_share:
            score, conf = self.compute_rule_score(2.0, total)
            f_id = f"FND-NS03-{entity_id}-{run_id}"

            rationale = (
                f"Abnormal operational flatline: Night-time volume accounts for only {night_share:.1%} of alerts "
                f"(vs peer average of {peer_avg:.1%}), indicating potential monitoring blackouts outside business hours."
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
                title=f"{self.name}: Near-zero night activity ({night_share:.1%})",
                rationale=rationale,
                peer_comparison={"night_share": night_share, "peer_average": peer_avg},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=[f"FLATLINE-{entity_id}"],
            )
            return [finding], []
        return [], []


class NS04MissingRecords(BaseRule):
    """NS04: Missing records (High/Critical TP alerts with no linked case).

    ID sequence gaps are a data-quality check at ingest (DQValidator.check_id_sequence_gaps),
    not part of this rule.
    """

    id = "NS04"
    name = "Missing Records"
    domain = "Governance and Oversight"
    level = "entity"
    min_sample = 10
    severity_weight = 90.0
    benign_explanations = [
        "Alert IDs generated across multi-region clusters where sequence numbers are allocated in blocks."
    ]
    examiner_check = "Audit database sequence generators and confirm why true positive alerts lack corresponding cases."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Check TP alerts without cases
        sql_tp = """
        SELECT a.alert_id
        FROM alert a
        LEFT JOIN case_alert_link l ON a.entity_id = l.entity_id AND a.alert_id = l.alert_id
        WHERE a.entity_id = ? AND a.disposition = 'true_positive' AND a.severity_final IN ('high', 'critical')
          AND l.case_id IS NULL
        """
        df_tp = store.query(sql_tp, [entity_id])
        tp_without_case = df_tp.shape[0] if not df_tp.is_empty() else 0

        if tp_without_case >= 3:
            score, conf = self.compute_rule_score(tp_without_case / 3.0, tp_without_case)
            f_id = f"FND-NS04-{entity_id}-{run_id}"
            sample_ids = df_tp["alert_id"].head(5).to_list()

            rationale = (
                f"Data integrity void: {tp_without_case} confirmed True Positive High/Critical alerts "
                f"have no corresponding case management record."
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
                severity="critical" if score > 75 else "high",
                title=f"{self.name}: {tp_without_case} True Positives lacking cases",
                rationale=rationale,
                peer_comparison={"tp_without_case": tp_without_case},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=sample_ids,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id,
                    record_type="alert",
                    record_id=aid,
                    details={"reason": "Missing case link"},
                )
                for aid in sample_ids
            ]
            return [finding], evidences
        return [], []


class NS05RuleCoverageGaps(BaseRule):
    """NS05: Rule coverage gaps (high share of dormant rules)."""

    id = "NS05"
    name = "Rule Coverage Gaps"
    domain = "Threat Detection"
    level = "entity"
    min_sample = 20
    severity_weight = 75.0
    benign_explanations = [
        "Rules designed for rare advanced threat actor techniques that have not attempted intrusions."
    ]
    examiner_check = "Conduct purple-team synthetic firing tests on dormant rules to ensure detection parsers are functional."

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        sql = """
        SELECT
            r.rule_id,
            count(a.alert_id) as fired_count
        FROM detection_rule r
        LEFT JOIN alert a ON r.entity_id = a.entity_id AND r.rule_id = a.rule_id
        WHERE r.entity_id = ? AND r.enabled = true
        GROUP BY r.rule_id
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        total_rules = df.shape[0]
        dormant_rules = df.filter(df["fired_count"] == 0)["rule_id"].to_list()
        dormant_share = len(dormant_rules) / max(total_rules, 1)

        if dormant_share > 0.40 and len(dormant_rules) >= 5:
            score, conf = self.compute_rule_score(dormant_share / 0.40, total_rules)
            f_id = f"FND-NS05-{entity_id}-{run_id}"

            rationale = (
                f"{len(dormant_rules)} of {total_rules} ({dormant_share:.1%}) enabled SIEM detection rules "
                f"never fired a single alert over the 6-month observation period."
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
                title=f"{self.name}: {dormant_share:.1%} dormant detection rules",
                rationale=rationale,
                peer_comparison={
                    "dormant_rules_count": len(dormant_rules),
                    "dormant_share": dormant_share,
                },
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=dormant_rules[:10],
            )
            return [finding], []
        return [], []


class NS06InventoryVsTelemetry(BaseRule):
    """NS06: Inventory vs telemetry (ghost assets and shadow assets)."""

    id = "NS06"
    name = "Inventory vs Telemetry"
    domain = "Cyber Resilience"
    level = "entity"
    min_sample = 10
    severity_weight = 85.0
    benign_explanations = [
        "Virtual machine provisioned in CMDB ahead of physical hardware racking."
    ]
    examiner_check = (
        "Validate whether CMDB ghost assets correspond to decommissioned or missing hardware."
    )

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        sql = """
        SELECT a.asset_id
        FROM asset a
        LEFT JOIN alert alt ON a.entity_id = alt.entity_id AND a.asset_id = alt.asset_id
        LEFT JOIN log_source_daily l ON a.entity_id = l.entity_id AND a.asset_id = l.asset_id
        WHERE a.entity_id = ?
        GROUP BY a.asset_id
        HAVING count(alt.alert_id) = 0 AND (count(l.event_count) = 0 OR sum(l.event_count) = 0)
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        ghost_assets = df["asset_id"].to_list()
        if len(ghost_assets) >= 2:
            score, conf = self.compute_rule_score(len(ghost_assets) / 2.0, len(ghost_assets))
            f_id = f"FND-NS06-{entity_id}-{run_id}"

            rationale = (
                f"Asset visibility gap: {len(ghost_assets)} assets recorded in configuration inventory "
                f"emitted zero log events and zero alert records throughout the observation period."
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
                title=f"{self.name}: {len(ghost_assets)} ghost inventory assets",
                rationale=rationale,
                peer_comparison={"ghost_assets_count": len(ghost_assets)},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=ghost_assets,
            )
            evidences = [
                FindingEvidence(
                    finding_id=f_id,
                    record_type="asset",
                    record_id=aid,
                    details={"status": "ghost_asset"},
                )
                for aid in ghost_assets
            ]
            return [finding], evidences
        return [], []


class NS07AbsentExternalReporting(BaseRule):
    """NS07: Absent external reporting (no NCIIPC/CERT-In notification record for a Critical case)."""

    id = "NS07"
    name = "Absent External Reporting"
    domain = "Incident Response"
    level = "entity"
    min_sample = 1
    severity_weight = 95.0
    benign_explanations = [
        "Incident classified as internal test / simulated drill exempt from statutory reporting."
    ]
    examiner_check = (
        "Request formal CERT-In / NCIIPC incident confirmation receipt numbers from entity CISO."
    )

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Critical incidents with no external_report row
        sql = """
        SELECT c.case_id, c.opened_at
        FROM "case" c
        LEFT JOIN external_report r ON c.entity_id = r.entity_id AND c.case_id = r.incident_id
        WHERE c.entity_id = ? AND c.severity = 'critical' AND r.incident_id IS NULL
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        unreported_cases = df["case_id"].to_list()
        score, conf = self.compute_rule_score(len(unreported_cases) / 1.0, len(unreported_cases))
        f_id = f"FND-NS07-{entity_id}-{run_id}"

        # NOTE: this checks only that SOME external_report row exists for each
        # Critical case. Whether it was filed within the statutory reporting
        # window is NOT evaluated (external_report.reported_at vs case opened_at);
        # that timeliness check is a documented follow-up (docs/hardening_log.md),
        # so the rationale must not claim a time window was checked.
        rationale = (
            f"Possible reporting gap: {len(unreported_cases)} Critical incident cases have no "
            f"corresponding external notification record (NCIIPC / CERT-In) in the submission. "
            f"Reporting timeliness was not evaluated."
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
            title=f"{self.name}: {len(unreported_cases)} Critical incidents unreported to NCIIPC",
            rationale=rationale,
            peer_comparison={"unreported_cases_count": len(unreported_cases)},
            examiner_check=self.examiner_check,
            benign_explanations=self.benign_explanations,
            evidence_ids=unreported_cases,
        )
        evidences = [
            FindingEvidence(
                finding_id=f_id, record_type="case", record_id=cid, details={"rule": self.id}
            )
            for cid in unreported_cases
        ]
        return [finding], evidences


class NS08SubmissionCompleteness(BaseRule):
    """NS08: Submission completeness (batch row count deviation or high null rate)."""

    id = "NS08"
    name = "Submission Completeness"
    domain = "Governance and Oversight"
    level = "entity"
    min_sample = 1
    severity_weight = 90.0
    benign_explanations = [
        "Entity transitioned between SIEM vendors mid-period causing temporary data format shifts."
    ]
    examiner_check = (
        "Review submission logs for missing monthly batch data or data ingestion parse failures."
    )

    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        # Count months represented in alert timestamps
        sql = """
        SELECT count(DISTINCT date_trunc('month', created_at)) as month_cnt
        FROM alert
        WHERE entity_id = ?
        """
        df = store.query(sql, [entity_id])
        if df.is_empty():
            return [], []

        month_cnt = df["month_cnt"][0]
        if month_cnt < 6:
            missing_months = 6 - month_cnt
            score, conf = self.compute_rule_score(missing_months / 2.0, 10)
            f_id = f"FND-NS08-{entity_id}-{run_id}"

            rationale = (
                f"Incomplete submission: Entity provided alerts covering only {month_cnt} months "
                f"of the required 6-month supervisory review period."
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
                title=f"{self.name}: Missing {missing_months} months in period",
                rationale=rationale,
                peer_comparison={"active_months": month_cnt},
                examiner_check=self.examiner_check,
                benign_explanations=self.benign_explanations,
                evidence_ids=[f"MISSING-MONTHS-{entity_id}"],
            )
            return [finding], []
        return [], []
