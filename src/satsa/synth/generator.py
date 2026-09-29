"""Synthetic SOC alert and case management data generator for SAT-SA."""

import hashlib
import random
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from satsa.models.canonical import (
    Alert,
    Asset,
    Case,
    CaseAlertLink,
    Closure,
    DeclaredKPI,
    DetectionRule,
    Entity,
    Escalation,
    ExternalReport,
    LogSourceDaily,
    Remediation,
    SLAPolicy,
    WorkflowEvent,
)
from satsa.synth.defects import (
    inject_cse02_kpi_gap,
    inject_cse02_unreported_incidents,
    inject_cse03_fast_critical_closures,
    inject_cse03_unacknowledged_escalations,
    inject_cse05_stale_open_cases,
    inject_cse07_metric_gaming_and_templates,
    inject_cse07_no_true_positives,
    inject_cse08_analyst_burst,
    inject_cse08_missing_space,
    inject_cse09_dormant_rules,
    inject_cse09_repeat_alerts,
    inject_cse09_skipped_containment,
    inject_cse10_missing_month,
    inject_cse10_volume_collapse_and_night_flatline,
)
from satsa.synth.ground_truth import GroundTruth, InjectedDefect

SECTORS = ["power", "banking", "telecom", "oil_and_gas", "transport"]

ENTITIES_SPEC = [
    {
        "entity_id": "CSE-01",
        "name": "Northern Power Grid Ltd",
        "sector": "power",
        "size_band": "large",
        "soc_model": "inhouse",
    },
    {
        "entity_id": "CSE-02",
        "name": "Apex Central Bank",
        "sector": "banking",
        "size_band": "large",
        "soc_model": "inhouse",
    },
    {
        "entity_id": "CSE-03",
        "name": "Bharat Telecom Infra",
        "sector": "telecom",
        "size_band": "large",
        "soc_model": "hybrid",
    },
    {
        "entity_id": "CSE-04",
        "name": "Eastern Gas Pipeline Corp",
        "sector": "oil_and_gas",
        "size_band": "medium",
        "soc_model": "inhouse",
    },
    {
        "entity_id": "CSE-05",
        "name": "National Rail Freight Logistics",
        "sector": "transport",
        "size_band": "medium",
        "soc_model": "inhouse",
    },
    {
        "entity_id": "CSE-06",
        "name": "Solaris Energy Transmission",
        "sector": "power",
        "size_band": "medium",
        "soc_model": "mssp",
    },
    {
        "entity_id": "CSE-07",
        "name": "Mercantile Merchant Bank",
        "sector": "banking",
        "size_band": "large",
        "soc_model": "hybrid",
    },
    {
        "entity_id": "CSE-08",
        "name": "Metro Fiber Communications",
        "sector": "telecom",
        "size_band": "small",
        "soc_model": "mssp",
    },
    {
        "entity_id": "CSE-09",
        "name": "Coastal Hydrocarbon Offshore",
        "sector": "oil_and_gas",
        "size_band": "large",
        "soc_model": "inhouse",
    },
    {
        "entity_id": "CSE-10",
        "name": "Metro Transit Automated Rail",
        "sector": "transport",
        "size_band": "small",
        "soc_model": "inhouse",
    },
]

CATEGORIES = [
    "Malware",
    "Ransomware",
    "Data Exfiltration",
    "Command and Control",
    "Unauthorized Access",
    "Privilege Escalation",
    "Phishing",
    "Credential Access",
    "Lateral Movement",
    "Denial of Service",
    "Policy Violation",
    "Suspicious Activity",
]

ASSET_TYPES = [
    "scada_controller",
    "core_banking_server",
    "telecom_switch",
    "domain_controller",
    "workstation",
    "perimeter_firewall",
]

# Entities sharing a single third-party MSSP provider, used to inject a
# genuine cross-entity ("systemic") negative-space defect: all three go
# silent on the SAME criticality-4 asset slot (AST-0001) for the SAME
# March 10-25 window, triggering NS01 in an identical pattern across all
# three -- satisfying satsa.rules.systemic's cross-entity correlation
# check. None of these three are clean baselines, so this is purely
# additive to the existing per-entity ground truth (CSE-05 already had an
# individual NS01 defect; CSE-02 and CSE-09 gain a new one).
SYSTEMIC_MSSP_GROUP = ["CSE-02", "CSE-05", "CSE-09"]
SYSTEMIC_MSSP_PROVIDER = "MSSP-Meridian"


class SyntheticDataGenerator:
    """Generates deterministic synthetic SOC data with injected defects and confounders."""

    def __init__(self, seed: int = 42, base_alerts_per_entity: int = 1500):
        self.seed = seed
        self.rng = random.Random(seed)
        self.base_alerts_per_entity = base_alerts_per_entity
        self.start_date = datetime(2026, 1, 1, 0, 0, 0)
        self.end_date = datetime(2026, 6, 30, 23, 59, 59)

    def generate(self) -> tuple[dict[str, list[Any]], GroundTruth]:
        """Generate all canonical datasets and ground truth."""
        entities: list[Entity] = []
        assets: list[Asset] = []
        log_sources: list[LogSourceDaily] = []
        detection_rules: list[DetectionRule] = []
        alerts: list[Alert] = []
        cases: list[Case] = []
        case_links: list[CaseAlertLink] = []
        workflows: list[WorkflowEvent] = []
        escalations: list[Escalation] = []
        closures: list[Closure] = []
        remediations: list[Remediation] = []
        external_reports: list[ExternalReport] = []
        declared_kpis: list[DeclaredKPI] = []
        sla_policies: list[SLAPolicy] = []

        ground_truth_defects: list[InjectedDefect] = []

        # 1. Generate Entities and SLA policies
        for spec in ENTITIES_SPEC:
            if spec["entity_id"] in SYSTEMIC_MSSP_GROUP:
                soc_provider = SYSTEMIC_MSSP_PROVIDER
            elif spec["soc_model"] == "inhouse":
                soc_provider = "internal"
            else:
                soc_provider = f"vendor-{spec['sector']}"

            ent = Entity(
                entity_id=spec["entity_id"],
                name=spec["name"],
                sector=spec["sector"],
                size_band=spec["size_band"],
                soc_model=spec["soc_model"],
                soc_provider=soc_provider,
                timezone="UTC",
                declared_shift_hours="09:00-18:00",
            )
            entities.append(ent)

            # Standard SLA Policies
            sla_policies.extend(
                [
                    SLAPolicy(
                        entity_id=ent.entity_id,
                        severity="critical",
                        ack_minutes=15,
                        resolve_minutes=60,
                    ),
                    SLAPolicy(
                        entity_id=ent.entity_id,
                        severity="high",
                        ack_minutes=30,
                        resolve_minutes=180,
                    ),
                    SLAPolicy(
                        entity_id=ent.entity_id,
                        severity="medium",
                        ack_minutes=60,
                        resolve_minutes=360,
                    ),
                    SLAPolicy(
                        entity_id=ent.entity_id,
                        severity="low",
                        ack_minutes=120,
                        resolve_minutes=720,
                    ),
                ]
            )

        # 2. Generate Assets, Rules, Declared KPIs, and Daily Log Sources per Entity
        for ent in entities:
            ent_id = ent.entity_id
            asset_count = (
                60 if ent.size_band == "large" else (35 if ent.size_band == "medium" else 15)
            )

            # Asset list
            ent_assets: list[Asset] = []
            for a_idx in range(1, asset_count + 1):
                crit = 4 if a_idx <= 4 else (3 if a_idx <= 12 else (2 if a_idx <= 25 else 1))
                a_type = self.rng.choice(ASSET_TYPES)
                asset_obj = Asset(
                    entity_id=ent_id,
                    asset_id=f"{ent_id.replace('-', '')}-AST-{a_idx:04d}",
                    asset_type=a_type,
                    criticality=crit,
                    monitored_flag=True,
                    owner_unit=f"SEC-OPS-{crit}",
                )
                ent_assets.append(asset_obj)
            assets.extend(ent_assets)

            # Rules. Alerts below draw their rule_id from this same catalog, so every
            # enabled rule can fire; otherwise NS05 (dormant rules) fires on every entity.
            rules_by_category: dict[str, list[str]] = {}
            for r_idx in range(1, 31):
                cat = CATEGORIES[(r_idx - 1) % len(CATEGORIES)]
                catalog_rule_id = f"RULE-{cat.upper().replace(' ', '_')}-{r_idx:02d}"
                rules_by_category.setdefault(cat, []).append(catalog_rule_id)
                detection_rules.append(
                    DetectionRule(
                        entity_id=ent_id,
                        rule_id=catalog_rule_id,
                        category=cat,
                        mitre_tactic=f"TA000{(r_idx % 10) + 1}",
                        mitre_technique=f"T10{r_idx:02d}",
                        enabled=True,
                        last_fired=self.start_date + timedelta(days=self.rng.randint(1, 150)),
                    )
                )

            # Declared KPIs. MTTR is declared for both critical and high, at values
            # consistent with the healthy closure durations generated below (~45 and
            # ~90 min including SOAR closures), so an honest entity reconciles under EG10.
            for period, crit_mttr, high_mttr in (("2026-Q1", 52.0, 97.0), ("2026-Q2", 50.0, 95.0)):
                declared_kpis.append(
                    DeclaredKPI(entity_id=ent_id, period=period, metric="MTTR", severity="high", value=high_mttr)
                )
                declared_kpis.append(
                    DeclaredKPI(entity_id=ent_id, period=period, metric="MTTR", severity="critical", value=crit_mttr)
                )
            declared_kpis.extend(
                [
                    DeclaredKPI(
                        entity_id=ent_id,
                        period="2026-Q1",
                        metric="MTTA",
                        severity="critical",
                        value=12.0,
                    ),
                    DeclaredKPI(
                        entity_id=ent_id,
                        period="2026-Q1",
                        metric="SLA_pct",
                        severity="critical",
                        value=96.5,
                    ),
                    DeclaredKPI(
                        entity_id=ent_id,
                        period="2026-Q2",
                        metric="MTTA",
                        severity="critical",
                        value=11.5,
                    ),
                    DeclaredKPI(
                        entity_id=ent_id,
                        period="2026-Q2",
                        metric="SLA_pct",
                        severity="critical",
                        value=97.0,
                    ),
                ]
            )

            # Daily Log Source telemetry (180 days)
            cur_date = self.start_date.date()
            while cur_date <= self.end_date.date():
                for a in ent_assets:
                    # CSE-05 defect: Silent critical assets (AST-0001, AST-0002) have zero logs for 15 days in March
                    is_cse05_silent = (
                        ent_id == "CSE-05"
                        and a.asset_id.endswith("0001")
                        and date(2026, 3, 10) <= cur_date <= date(2026, 3, 25)
                    )
                    # Systemic/cross-entity defect: ALL THREE SYSTEMIC_MSSP_GROUP
                    # entities' first critical asset (AST-0001, criticality=4) go
                    # silent for the SAME 15-day window in the SAME period,
                    # in addition to CSE-05's pre-existing individual defect
                    # above -- a genuine identical-rule, identical-window,
                    # shared-provider pattern for satsa.rules.systemic to
                    # correlate, not an artifact of an already-universal rule.
                    is_systemic_silent = (
                        ent_id in SYSTEMIC_MSSP_GROUP
                        and a.asset_id.endswith("0001")
                        and date(2026, 3, 10) <= cur_date <= date(2026, 3, 25)
                    )
                    count = 0 if (is_cse05_silent or is_systemic_silent) else self.rng.randint(200, 2500)
                    log_sources.append(
                        LogSourceDaily(
                            entity_id=ent_id,
                            asset_id=a.asset_id,
                            source_type="syslog_edr",
                            date=cur_date,
                            event_count=count,
                        )
                    )
                cur_date += timedelta(days=1)

            # Generate alerts for entity
            ent_alerts_target = self.base_alerts_per_entity
            if ent.size_band == "small":
                ent_alerts_target = max(300, self.base_alerts_per_entity // 4)
            elif ent.size_band == "large":
                ent_alerts_target = int(self.base_alerts_per_entity * 1.5)

            total_days = (self.end_date - self.start_date).days
            for alt_idx in range(1, ent_alerts_target + 1):
                alt_id = f"{ent_id.replace('-', '')}-ALT-{alt_idx:06d}"
                cat = self.rng.choice(CATEGORIES)
                rule = self.rng.choice(rules_by_category[cat])
                asset = self.rng.choice(ent_assets)

                # Time distribution: normal working hours vs night
                day_offset = self.rng.randint(0, total_days)
                is_night = self.rng.random() < 0.22  # 22% night baseline
                if is_night:
                    hour = self.rng.choice([20, 21, 22, 23, 0, 1, 2, 3, 4, 5, 6])
                else:
                    hour = self.rng.randint(8, 19)

                created_ts = self.start_date + timedelta(
                    days=day_offset,
                    hours=hour,
                    minutes=self.rng.randint(0, 59),
                    seconds=self.rng.randint(0, 59),
                )

                # Severity distribution: 5% Critical, 20% High, 45% Medium, 30% Low
                sev_roll = self.rng.random()
                if sev_roll < 0.05:
                    severity = "critical"
                elif sev_roll < 0.25:
                    severity = "high"
                elif sev_roll < 0.70:
                    severity = "medium"
                else:
                    severity = "low"

                # Confounder: 12% automated SOAR closures across entities
                is_automation = self.rng.random() < 0.12
                actor_type = "automation" if is_automation else "human"
                actor_id = (
                    f"ANALYST_{ent_id.replace('-', '')}_{self.rng.randint(1, 8):02d}"
                    if not is_automation
                    else "SOAR_PLAYBOOK_ENGINE"
                )
                playbook = f"PB-AUTO-{self.rng.randint(1, 4):02d}" if is_automation else None

                # Realistic closure duration based on lognormal distribution
                if is_automation:
                    duration_secs = self.rng.randint(15, 90)
                else:
                    # Healthy median: Critical ~45m, High ~90m, Med ~180m, Low ~360m
                    scale_mins = {"critical": 45, "high": 90, "medium": 180, "low": 360}[severity]
                    duration_secs = max(300, int(self.rng.lognormvariate(0, 0.5) * scale_mins * 60))

                closed_ts = created_ts + timedelta(seconds=duration_secs)
                ack_ts = created_ts + timedelta(
                    seconds=min(duration_secs // 3, self.rng.randint(60, 600))
                )
                touch_ts = ack_ts + timedelta(seconds=min(120, duration_secs // 4))

                # Disposition: 80% FP/Benign, 20% TP for High/Crit; 90% FP/Benign for Low/Med
                is_tp = (
                    self.rng.random() < 0.20
                    if severity in ["high", "critical"]
                    else self.rng.random() < 0.05
                )
                disp = (
                    "true_positive"
                    if is_tp
                    else ("false_positive" if self.rng.random() < 0.75 else "benign")
                )

                alert_obj = Alert(
                    entity_id=ent_id,
                    alert_id=alt_id,
                    rule_id=rule,
                    category=cat,
                    severity_orig=severity,
                    severity_final=severity,
                    asset_id=asset.asset_id,
                    created_at=created_ts,
                    acknowledged_at=ack_ts,
                    first_touch_at=touch_ts,
                    closed_at=closed_ts,
                    closed_by=actor_id,
                    closed_by_type=actor_type,
                    playbook_id=playbook,
                    disposition=disp,
                    status="closed",
                )
                alerts.append(alert_obj)

                # Workflow events
                ev_count = (
                    2
                    if is_automation
                    else (5 if severity == "critical" else (4 if severity == "high" else 2))
                )
                workflows.append(
                    WorkflowEvent(
                        entity_id=ent_id,
                        ref_type="alert",
                        ref_id=alt_id,
                        ts=created_ts + timedelta(seconds=10),
                        actor=actor_id,
                        action="triage",
                        from_status="open",
                        to_status="investigating",
                        note_len=25,
                    )
                )
                if ev_count >= 3:
                    workflows.append(
                        WorkflowEvent(
                            entity_id=ent_id,
                            ref_type="alert",
                            ref_id=alt_id,
                            ts=ack_ts,
                            actor=actor_id,
                            action="investigate",
                            from_status="investigating",
                            to_status="investigating",
                            note_len=80,
                        )
                    )
                workflows.append(
                    WorkflowEvent(
                        entity_id=ent_id,
                        ref_type="alert",
                        ref_id=alt_id,
                        ts=closed_ts,
                        actor=actor_id,
                        action="close",
                        from_status="investigating",
                        to_status="closed",
                        note_len=45,
                    )
                )

                # Closure record
                if is_automation:
                    c_text = "SOAR automation: threat signature isolated and verified per automated playbook standard."
                else:
                    c_text = f"Analyst review complete for {cat} on {asset.asset_id}. Evidence confirmed {disp} resolution."
                c_hash = hashlib.sha256(c_text.lower().strip().encode()).hexdigest()[:16]
                closures.append(
                    Closure(
                        entity_id=ent_id,
                        ref_id=alt_id,
                        reason_code="RC_VERIFIED",
                        disposition=disp,
                        comment_norm_hash=c_hash,
                        comment_len=len(c_text),
                        comment_shingles="analyst_review,investigated_threat,resolution_verified",
                    )
                )

                # Escalation & Cases for True Positive Critical/High alerts
                if is_tp and severity in ["high", "critical"]:
                    esc_id = f"ESC-{alt_id}"
                    escalations.append(
                        Escalation(
                            entity_id=ent_id,
                            esc_id=esc_id,
                            ref_id=alt_id,
                            escalated_at=touch_ts,
                            from_role="tier1",
                            to_role="tier2",
                            acknowledged_at=touch_ts + timedelta(minutes=10),
                            outcome="case_created",
                        )
                    )

                    case_id = f"INC-{alt_id}"
                    cases.append(
                        Case(
                            entity_id=ent_id,
                            case_id=case_id,
                            severity=severity,
                            status="closed",
                            owner=f"IR_LEAD_{ent_id.replace('-', '')}",
                            opened_at=touch_ts + timedelta(minutes=5),
                            closed_at=closed_ts + timedelta(hours=2),
                        )
                    )
                    case_links.append(
                        CaseAlertLink(entity_id=ent_id, case_id=case_id, alert_id=alt_id)
                    )
                    # Mandatory case lifecycle. Without it every critical case looks like it
                    # skipped containment and EG12 fires on every entity.
                    ir_lead = f"IR_LEAD_{ent_id.replace('-', '')}"
                    case_open_ts = touch_ts + timedelta(minutes=5)
                    for step, (action, from_st, to_st) in enumerate(
                        [
                            ("triage", "open", "triaged"),
                            ("investigate", "triaged", "investigating"),
                            ("contain", "investigating", "contained"),
                            ("close", "contained", "closed"),
                        ]
                    ):
                        workflows.append(
                            WorkflowEvent(
                                entity_id=ent_id,
                                ref_type="case",
                                ref_id=case_id,
                                ts=case_open_ts + timedelta(minutes=20 * step),
                                actor=ir_lead,
                                action=action,
                                from_status=from_st,
                                to_status=to_st,
                                note_len=60,
                            )
                        )

                    # External report for Critical TP
                    if severity == "critical":
                        external_reports.append(
                            ExternalReport(
                                entity_id=ent_id,
                                incident_id=case_id,
                                reported_to="NCIIPC",
                                reported_at=touch_ts + timedelta(hours=2),
                            )
                        )

        # --- Inject Specific Defects ---

        # CSE-02: KPI gap
        declared_kpis, cse02_info = inject_cse02_kpi_gap(declared_kpis)
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-02",
                rule_id="EG10",
                defect_type=cse02_info["defect_type"],
                affected_ids=["CSE-02-KPI-MTTR"],
                share=1.0,
                description=cse02_info["description"],
            )
        )

        # CSE-03: Fast closure & missing escalation
        alerts, workflows, escalations, cse03_info = inject_cse03_fast_critical_closures(
            alerts, workflows, escalations, self.rng
        )
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-03",
                rule_id="EG01",
                defect_type="fast_closures",
                affected_ids=cse03_info["affected_fast_ids"],
                share=cse03_info["share"],
                description="Fast closures of High/Critical alerts without investigation.",
            )
        )
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-03",
                rule_id="EG03",
                defect_type="missing_escalations",
                affected_ids=cse03_info["affected_unescalated_ids"],
                share=len(cse03_info["affected_unescalated_ids"]) / max(1, len(alerts)),
                description="Critical true-positive alerts closed without escalation.",
            )
        )

        # CSE-05: Silent critical assets (already zero logs generated, also drop alerts on AST-0001 for 15 days)
        # Generalized to the whole SYSTEMIC_MSSP_GROUP (CSE-02, CSE-05, CSE-09):
        # all three entities' AST-0001 (criticality=4) go silent for the SAME
        # window, giving satsa.rules.systemic a genuine, identical NS01 pattern
        # to correlate across a shared MSSP provider (see SYSTEMIC_MSSP_GROUP
        # above and the matching log_source_daily silencing earlier in this loop).
        systemic_dropped_alerts: dict[str, list[str]] = {eid: [] for eid in SYSTEMIC_MSSP_GROUP}
        kept_alerts_cse05: list[Alert] = []
        for a_alt in alerts:
            if (
                a_alt.entity_id in SYSTEMIC_MSSP_GROUP
                and a_alt.asset_id.endswith("0001")
                and a_alt.created_at
                and date(2026, 3, 10) <= a_alt.created_at.date() <= date(2026, 3, 25)
            ):
                systemic_dropped_alerts[a_alt.entity_id].append(a_alt.alert_id)
            else:
                kept_alerts_cse05.append(a_alt)
        alerts = kept_alerts_cse05

        # Add 3 inventory assets never seen in alerts (ghost assets for NS06)
        for g_idx in range(91, 94):
            assets.append(
                Asset(
                    entity_id="CSE-05",
                    asset_id=f"CSE05-AST-{g_idx:04d}",
                    asset_type="core_banking_server",
                    criticality=4,
                    monitored_flag=True,
                    owner_unit="GHOST-UNSEEN",
                )
            )

        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-05",
                rule_id="NS01",
                defect_type="silent_critical_assets",
                affected_ids=["CSE05-AST-0001", "CSE05-AST-0002"],
                share=0.05,
                description="Criticality 4 assets silent for >3 consecutive days.",
            )
        )
        for systemic_eid in ("CSE-02", "CSE-09"):
            prefix = systemic_eid.replace("-", "")
            ground_truth_defects.append(
                InjectedDefect(
                    entity_id=systemic_eid,
                    rule_id="NS01",
                    defect_type="systemic_silent_critical_assets",
                    affected_ids=[f"{prefix}-AST-0001", *systemic_dropped_alerts[systemic_eid]],
                    share=0.03,
                    description=(
                        f"Criticality 4 asset silent for the SAME March 10-25 window as CSE-05 "
                        f"and CSE-02/CSE-09 (all share soc_provider='{SYSTEMIC_MSSP_PROVIDER}') -- "
                        "a shared-vendor systemic pattern, see satsa.rules.systemic."
                    ),
                )
            )
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-05",
                rule_id="NS06",
                defect_type="ghost_inventory_assets",
                affected_ids=["CSE05-AST-0091", "CSE05-AST-0092", "CSE05-AST-0093"],
                share=0.08,
                description="Inventory assets present in configuration database but absent from all telemetry and alerts.",
            )
        )

        # CSE-07: Template comments, deadline-hugging, month-end closures
        alerts, closures, cse07_info = inject_cse07_metric_gaming_and_templates(
            alerts, closures, self.rng
        )
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-07",
                rule_id="EG04",
                defect_type="template_closure_comments",
                affected_ids=[cse07_info.get("template_hash", "")],
                share=0.60,
                description="High repetition of identical normalized closure comment hash.",
            )
        )
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-07",
                rule_id="EG06",
                defect_type="metric_gaming_deadline_bulk",
                affected_ids=["CSE-07-BULK-20260331"],
                share=0.40,
                description="SLA deadline-hugging and month-end identical-timestamp bulk closures.",
            )
        )

        # CSE-08: Missing categories, low volume, sequence gaps, TP without cases
        alerts, cases, cse08_info = inject_cse08_missing_space(alerts, cases, self.rng)
        cse08_id_map: dict[str, str] = cse08_info["id_map"]
        for w in workflows:
            if w.entity_id == "CSE-08" and w.ref_type == "alert" and w.ref_id in cse08_id_map:
                w.ref_id = cse08_id_map[w.ref_id]
        for c in closures:
            if c.entity_id == "CSE-08" and c.ref_id in cse08_id_map:
                c.ref_id = cse08_id_map[c.ref_id]
        for e in escalations:
            if e.entity_id == "CSE-08" and e.ref_id in cse08_id_map:
                e.ref_id = cse08_id_map[e.ref_id]
        # Its cases were dropped, so their alert links go too (NS04's TP-without-case signal).
        case_links = [link for link in case_links if link.entity_id != "CSE-08"]
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-08",
                rule_id="NS02",
                defect_type="missing_alert_categories",
                affected_ids=cse08_info["removed_categories"],
                share=0.30,
                description="Complete absence of standard peer-prevalent alert categories (Malware, Phishing, DoS).",
            )
        )
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-08",
                rule_id="NS04",
                defect_type="tp_alerts_without_cases",
                affected_ids=["ID_GAP_CSE08"],
                share=0.20,
                description=(
                    "High/Critical TP alerts with no case management record (NS04). The injected "
                    "ID sequence gap is a data-quality signal, not an NS04 detection."
                ),
            )
        )

        # CSE-09: Repeat alerts, no remediation
        alerts, cse09_info = inject_cse09_repeat_alerts(alerts, self.rng)
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-09",
                rule_id="EG05",
                defect_type="repeat_alerts_no_root_cause",
                affected_ids=[p[0] for p in cse09_info["pairs"]],
                share=0.08,
                description=cse09_info["description"],
            )
        )

        # CSE-10: Volume collapse and flat night-time profile
        alerts, _cse10_info = inject_cse10_volume_collapse_and_night_flatline(alerts)
        ground_truth_defects.append(
            InjectedDefect(
                entity_id="CSE-10",
                rule_id="NS03",
                defect_type="volume_drop_night_flatline",
                affected_ids=["NIGHT_BLACKOUT_CSE10"],
                share=0.65,
                description="Zero 24x7 night activity and 85% mid-period volume collapse.",
            )
        )

        # Defects for the rules the original ground truth never exercised (see defects.py).
        alerts, cse10_month_info = inject_cse10_missing_month(alerts)
        coverage_defects = [
            ("CSE-08", "EG07", "analyst_implausible_throughput",
             inject_cse08_analyst_burst(alerts, closures, workflows, self.rng),
             "One analyst closed 35 alerts within a single hour."),
            ("CSE-03", "EG08", "unacknowledged_escalations",
             inject_cse03_unacknowledged_escalations(escalations),
             "Four escalations with no Tier-2 acknowledgement."),
            ("CSE-05", "EG09", "stale_open_cases",
             inject_cse05_stale_open_cases(cases),
             "Four high-severity cases left open for months."),
            ("CSE-07", "EG11", "no_true_positives",
             inject_cse07_no_true_positives(alerts, closures),
             "Every alert closed false positive/benign: no true positive in six months."),
            ("CSE-09", "EG12", "skipped_containment",
             inject_cse09_skipped_containment(cases, workflows),
             "Three critical cases closed without the mandatory 'contain' stage."),
            ("CSE-09", "NS05", "dormant_detection_rules",
             inject_cse09_dormant_rules(detection_rules),
             "25 enabled legacy detection rules that never fired (45% of the catalog)."),
            ("CSE-02", "NS07", "unreported_critical_incidents",
             inject_cse02_unreported_incidents(cases, external_reports),
             "Two critical incidents with no external NCIIPC report."),
            ("CSE-10", "NS08", "missing_submission_month",
             cse10_month_info,
             f"No alerts submitted for June 2026 ({cse10_month_info['dropped_alerts']} alerts withheld)."),
        ]
        for entity_id, rule_id, defect_type, info, description in coverage_defects:
            ground_truth_defects.append(
                InjectedDefect(
                    entity_id=entity_id,
                    rule_id=rule_id,
                    defect_type=defect_type,
                    affected_ids=info["affected_ids"],
                    share=0.0,
                    description=description,
                )
            )

        # Build GroundTruth
        ground_truth = GroundTruth(
            version="1.0.0",
            seed=self.seed,
            created_at=datetime.now(UTC).isoformat(),
            entities={
                e.entity_id: {"name": e.name, "sector": e.sector, "size": e.size_band}
                for e in entities
            },
            defects=ground_truth_defects,
            clean_entities=["CSE-01", "CSE-04", "CSE-06"],
            confounders=[
                {
                    "type": "soar_automation",
                    "description": "Automated playbook closures across entities with fast resolution times",
                },
                {
                    "type": "small_entity",
                    "description": "CSE-08 has lower absolute alert volume due to small size band",
                },
            ],
        )

        dataset: dict[str, list[Any]] = {
            "entity": list(entities),
            "asset": list(assets),
            "log_source_daily": list(log_sources),
            "detection_rule": list(detection_rules),
            "alert": list(alerts),
            "case": list(cases),
            "case_alert_link": list(case_links),
            "workflow_event": list(workflows),
            "escalation": list(escalations),
            "closure": list(closures),
            "remediation": list(remediations),
            "external_report": list(external_reports),
            "declared_kpi": list(declared_kpis),
            "sla_policy": list(sla_policies),
        }

        return dataset, ground_truth

    def save_dataset(self, output_dir: Path | str) -> tuple[Path, Path]:
        """Generate dataset and save to CSV files and ground_truth.json."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        csv_dir = out_path / "csv"
        csv_dir.mkdir(parents=True, exist_ok=True)

        data, gt = self.generate()
        import polars as pl

        # Save each table to CSV
        for table_name, records in data.items():
            if records:
                dicts = [r.model_dump() for r in records]
                df = pl.DataFrame(dicts)
                df.write_csv(csv_dir / f"{table_name}.csv")

        gt_path = out_path / "ground_truth.json"
        with open(gt_path, "w", encoding="utf-8") as f:
            f.write(gt.model_dump_json(indent=2))

        return csv_dir, gt_path
