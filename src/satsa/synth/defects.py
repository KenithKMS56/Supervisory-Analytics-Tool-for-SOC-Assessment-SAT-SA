"""Defect injection routines for synthetic dataset."""

import hashlib
import random
from datetime import datetime, timedelta
from typing import Any

from satsa.models.canonical import (
    Alert,
    Case,
    Closure,
    DeclaredKPI,
    DetectionRule,
    Escalation,
    ExternalReport,
    WorkflowEvent,
)


def inject_cse02_kpi_gap(kpis: list[DeclaredKPI]) -> tuple[list[DeclaredKPI], dict[str, Any]]:
    """CSE-02: Declared KPI reconciliation gap.

    CSE-02's alerts are generated like every other entity's (empirical MTTR of
    roughly 45 min critical / 90 min high); only its declaration is gamed, to 35
    minutes for both severities.
    """
    updated_kpis = []
    for k in kpis:
        if k.entity_id == "CSE-02" and k.metric == "MTTR" and k.severity in ["critical", "high"]:
            updated_kpis.append(k.model_copy(update={"value": 35.0}))
        else:
            updated_kpis.append(k)

    defect_info = {
        "rule_id": "EG10",
        "defect_type": "kpi_reconciliation_gap",
        "description": (
            "Declared High/Critical MTTR of 35 minutes, well below the empirical MTTR recomputed "
            "from CSE-02's own alert timestamps (roughly 45 min critical, 90 min high)."
        ),
        "declared_mttr": 35.0,
    }
    return updated_kpis, defect_info


def inject_cse03_fast_critical_closures(
    alerts: list[Alert],
    workflows: list[WorkflowEvent],
    escalations: list[Escalation],
    rng: random.Random,
) -> tuple[list[Alert], list[WorkflowEvent], list[Escalation], dict[str, Any]]:
    """CSE-03: Fast closure of High/Critical alerts (< 5 min, <= 1 event) and unescalated Critical TP."""
    affected_fast = []
    affected_unescalated = []

    # Filter CSE-03 human alerts
    cse03_alerts = [
        a
        for a in alerts
        if a.entity_id == "CSE-03"
        and a.closed_by_type == "human"
        and a.severity_final in ["high", "critical"]
    ]
    sample_size = min(len(cse03_alerts), max(15, int(len(cse03_alerts) * 0.40)))
    target_alerts = rng.sample(cse03_alerts, sample_size) if cse03_alerts else []
    target_ids = {a.alert_id for a in target_alerts}

    # Modify alerts to have fast closure time (e.g. 120 - 300 seconds)
    for a in alerts:
        if a.alert_id in target_ids:
            duration = rng.randint(60, 240)
            a.closed_at = a.created_at + timedelta(seconds=duration)
            a.acknowledged_at = a.created_at + timedelta(seconds=min(30, duration // 2))
            a.first_touch_at = a.acknowledged_at
            affected_fast.append(a.alert_id)
            if a.severity_final == "critical" and a.disposition == "true_positive":
                affected_unescalated.append(a.alert_id)

    # Prune workflows for these alerts to <= 1 event
    filtered_workflows = []
    for w in workflows:
        if w.entity_id == "CSE-03" and w.ref_type == "alert" and w.ref_id in target_ids:
            if w.action == "close":
                filtered_workflows.append(w)
        else:
            filtered_workflows.append(w)

    # Remove escalations for the unescalated critical targets
    target_unesc_set = set(affected_unescalated)
    filtered_escalations = [
        e for e in escalations if not (e.entity_id == "CSE-03" and e.ref_id in target_unesc_set)
    ]

    defect_info = {
        "rule_id": "EG01,EG03",
        "defect_type": "fast_closures_and_missing_escalations",
        "description": f"Injected {len(affected_fast)} fast High/Critical closures and stripped escalations from {len(affected_unescalated)} Critical TPs.",
        "affected_fast_ids": affected_fast,
        "affected_unescalated_ids": affected_unescalated,
        "share": len(affected_fast) / max(1, len(cse03_alerts)),
    }
    return alerts, filtered_workflows, filtered_escalations, defect_info


def inject_cse07_metric_gaming_and_templates(
    alerts: list[Alert], closures: list[Closure], rng: random.Random
) -> tuple[list[Alert], list[Closure], dict[str, Any]]:
    """CSE-07: Template-driven closure comments, deadline-hugging, and month-end bulk closures."""
    cse07_alerts = [a for a in alerts if a.entity_id == "CSE-07" and a.closed_by_type == "human"]
    total = len(cse07_alerts)
    if total == 0:
        return alerts, closures, {}

    # 1. Template comments: Replace comments of 60% of alerts with a repetitive template
    template_text = (
        "Alert investigated and confirmed benign routine network synchronization traffic."
    )
    template_hash = hashlib.sha256(template_text.lower().strip().encode()).hexdigest()[:16]

    template_targets = set(rng.sample([a.alert_id for a in cse07_alerts], int(total * 0.60)))
    for c in closures:
        if c.entity_id == "CSE-07" and c.ref_id in template_targets:
            c.comment_norm_hash = template_hash
            c.comment_len = len(template_text)
            c.comment_shingles = (
                "alert_investigated,confirmed_benign,routine_network,synchronization_traffic"
            )

    # 2. Deadline hugging: SLA is 120 mins for High, 240 mins for Medium
    # Set closure times to 92-98% of SLA limit
    deadline_targets = set(rng.sample([a.alert_id for a in cse07_alerts], int(total * 0.40)))
    for a in alerts:
        if a.alert_id in deadline_targets and a.created_at:
            sla_mins = (
                60
                if a.severity_final == "critical"
                else (120 if a.severity_final == "high" else 240)
            )
            target_delay_mins = int(sla_mins * rng.uniform(0.92, 0.99))
            a.closed_at = a.created_at + timedelta(minutes=target_delay_mins)

    # 3. Bulk month-end closures: 15 alerts closed in the same minute by the same analyst.
    # The sweep clears the low/medium alerts raised most recently before it. Taking the
    # first 15 alerts regardless of date closed some of them months before they were
    # created, and those impossible durations made EG10 fire or not by seed.
    bulk_actor = "ANALYST_G_007"
    bulk_ts = datetime(2026, 3, 31, 17, 58, 0)
    backlog = sorted(
        (a for a in cse07_alerts if a.severity_final in ("low", "medium") and a.created_at and a.created_at < bulk_ts),
        key=lambda a: (a.created_at, a.alert_id),
    )
    bulk_targets = backlog[-15:]
    for a in bulk_targets:
        a.closed_at = bulk_ts
        a.closed_by = bulk_actor

    defect_info = {
        "rule_id": "EG04,EG06",
        "defect_type": "template_comments_and_metric_gaming",
        "description": "Injected template comment reuse (60%), SLA deadline-hugging (40%), and identical month-end bulk closures.",
        "template_hash": template_hash,
        "bulk_closure_timestamp": bulk_ts.isoformat(),
        "share": 0.60,
    }
    return alerts, closures, defect_info


def inject_cse08_missing_space(
    alerts: list[Alert], cases: list[Case], rng: random.Random
) -> tuple[list[Alert], list[Case], dict[str, Any]]:
    """CSE-08: Missing alert categories, low volume, sequence gaps, TP without cases."""
    # 1. Remove standard categories: 'Malware', 'Phishing', 'Denial of Service'
    banned_categories = {"Malware", "Phishing", "Denial of Service"}
    kept_alerts = []
    removed_category_count = 0
    for a in alerts:
        if a.entity_id == "CSE-08" and a.category in banned_categories:
            removed_category_count += 1
        else:
            kept_alerts.append(a)

    # 2. Injected ID sequence gap: CSE-08's first 25 alerts keep their IDs, the rest
    # jump by 500. The caller must apply the returned id_map to every child table
    # (workflow_event, closure, escalation); renaming only the alerts orphans those
    # records and makes EG02/EG03 fire on CSE-08 for defects nobody injected.
    id_map: dict[str, str] = {}
    cse08_seen = 0
    for a in kept_alerts:
        if a.entity_id != "CSE-08":
            continue
        cse08_seen += 1
        if cse08_seen > 25:
            parts = a.alert_id.split("-")
            if len(parts) == 3 and parts[2].isdigit():
                new_id = f"{parts[0]}-{parts[1]}-{int(parts[2]) + 500:06d}"
                id_map[a.alert_id] = new_id
                a.alert_id = new_id

    # 3. True Positives without cases: Remove case links for CSE-08 TP alerts
    tp_alerts = [
        a.alert_id
        for a in kept_alerts
        if a.entity_id == "CSE-08" and a.disposition == "true_positive"
    ]
    kept_cases = [c for c in cases if c.entity_id != "CSE-08"]

    defect_info = {
        "rule_id": "NS02,NS04",
        "defect_type": "missing_categories_and_records",
        "description": "Stripped Malware/Phishing/DoS categories, created ID sequence gap, and dropped incident cases for TP alerts.",
        "removed_categories": list(banned_categories),
        "tp_without_case_count": len(tp_alerts),
        "sequence_gap_injected": True,
        "id_map": id_map,
    }
    return kept_alerts, kept_cases, defect_info


def inject_cse09_repeat_alerts(
    alerts: list[Alert], rng: random.Random
) -> tuple[list[Alert], dict[str, Any]]:
    """CSE-09: Repeat alerts on same asset closed benign with no remediation."""
    # Pick 2 assets and 2 rules to repeat >= 8 times in 30 days
    asset_1 = "CSE09-AST-0001"
    asset_2 = "CSE09-AST-0002"
    rule_1 = "RULE-BRUTE-FORCE"
    rule_2 = "RULE-PORT-SCAN"

    injected_count = 0
    base_time = datetime(2026, 2, 1, 10, 0, 0)
    for i in range(12):
        # One start hour per alert. Drawing the hour separately for created, acknowledged and
        # closed put some closures hours before the alert was raised. Six draws are kept so
        # the random stream, and with it every later injection, is unchanged.
        hour_1, _, _ = (rng.randint(1, 4) for _ in range(3))
        alt1 = Alert(
            entity_id="CSE-09",
            alert_id=f"CSE09-ALT-REP1-{i:03d}",
            rule_id=rule_1,
            category="Suspicious Activity",
            severity_orig="medium",
            severity_final="medium",
            asset_id=asset_1,
            created_at=base_time + timedelta(days=i * 2, hours=hour_1),
            acknowledged_at=base_time + timedelta(days=i * 2, hours=hour_1, minutes=10),
            closed_at=base_time + timedelta(days=i * 2, hours=hour_1, minutes=40),
            closed_by="ANALYST_09_01",
            closed_by_type="human",
            disposition="benign",
            status="closed",
        )
        hour_2, _, _ = (rng.randint(1, 4) for _ in range(3))
        alt2 = Alert(
            entity_id="CSE-09",
            alert_id=f"CSE09-ALT-REP2-{i:03d}",
            rule_id=rule_2,
            category="Suspicious Activity",
            severity_orig="high",
            severity_final="high",
            asset_id=asset_2,
            created_at=base_time + timedelta(days=i * 2, hours=hour_2),
            acknowledged_at=base_time + timedelta(days=i * 2, hours=hour_2, minutes=15),
            closed_at=base_time + timedelta(days=i * 2, hours=hour_2, minutes=55),
            closed_by="ANALYST_09_02",
            closed_by_type="human",
            disposition="false_positive",
            status="closed",
        )
        alerts.extend([alt1, alt2])
        injected_count += 2

    defect_info = {
        "rule_id": "EG05",
        "defect_type": "repeat_alerts_unaddressed",
        "description": f"Injected {injected_count} repeat alerts across (asset_1, rule_1) and (asset_2, rule_2) closed benign/FP with no remediation tickets.",
        "pairs": [(asset_1, rule_1), (asset_2, rule_2)],
        "count": injected_count,
    }
    return alerts, defect_info


def inject_cse10_volume_collapse_and_night_flatline(
    alerts: list[Alert],
) -> tuple[list[Alert], dict[str, Any]]:
    """CSE-10: Sudden volume collapse mid-period and flat night-time profile."""
    kept = []
    dropped_after_date = 0
    dropped_night = 0
    cutoff_date = datetime(2026, 4, 1, 0, 0, 0)

    for a in alerts:
        if a.entity_id == "CSE-10":
            # 1. Night profile flatline: Zero alerts between 20:00 and 08:00
            hour = a.created_at.hour
            if hour < 8 or hour >= 20:
                dropped_night += 1
                continue

            # 2. Mid-period volume drop: Drop 85% of alerts after April 1st
            if a.created_at >= cutoff_date:
                if a.alert_id.endswith("1") or a.alert_id.endswith("2"):
                    kept.append(a)
                else:
                    dropped_after_date += 1
                    continue
            else:
                kept.append(a)
        else:
            kept.append(a)

    defect_info = {
        "rule_id": "NS03",
        "defect_type": "volume_drop_and_no_night_coverage",
        "description": f"Removed {dropped_night} night-time alerts (zero 24x7 coverage) and {dropped_after_date} post-cutoff alerts (85% collapse).",
        "dropped_night": dropped_night,
        "dropped_after_date": dropped_after_date,
    }
    return kept, defect_info


# --- Defects for rules the original ground truth never exercised -----------------
# EG07, EG08, EG09, EG11, EG12, NS05, NS07 and NS08 had no injected defect, so the
# validation only showed they stay quiet on synthetic data, never that they detect
# anything. Each routine below plants one defect in an entity that already carries
# other defects (CSE-01/04/06 stay clean), sized to cross only its own rule.


def inject_cse08_analyst_burst(
    alerts: list[Alert],
    closures: list[Closure],
    workflows: list[WorkflowEvent],
    rng: random.Random,
) -> dict[str, Any]:
    """EG07: one CSE-08 analyst closes 35 alerts inside a single clock hour.

    Closures are spread over distinct minutes (at most one per minute), so EG06's
    8-per-minute bulk check is not tripped; alerts are low severity with multi-hour
    lifetimes, so EG01/EG10 and EG06's deadline-hugging check are unaffected.
    """
    actor = "ANALYST_CSE08_BURST"
    burst_hour = datetime(2026, 2, 17, 14, 0, 0)
    minutes = sorted(rng.sample(range(60), 35))
    affected = []
    for i, minute in enumerate(minutes):
        alert_id = f"CSE08-ALT-BURST-{i:03d}"
        closed_at = burst_hour + timedelta(minutes=minute, seconds=rng.randint(0, 59))
        created_at = closed_at - timedelta(hours=rng.randint(2, 6), minutes=rng.randint(0, 59))
        alerts.append(
            Alert(
                entity_id="CSE-08",
                alert_id=alert_id,
                rule_id="RULE-POLICY_VIOLATION-11",
                category="Policy Violation",
                severity_orig="low",
                severity_final="low",
                asset_id=f"CSE08-AST-{(i % 15) + 1:04d}",
                created_at=created_at,
                acknowledged_at=created_at + timedelta(minutes=10),
                first_touch_at=created_at + timedelta(minutes=12),
                closed_at=closed_at,
                closed_by=actor,
                closed_by_type="human",
                disposition="false_positive",
                status="closed",
            )
        )
        text = f"Reviewed policy alert {alert_id}; user activity matched approved change {i}."
        closures.append(
            Closure(
                entity_id="CSE-08",
                ref_id=alert_id,
                reason_code="RC_VERIFIED",
                disposition="false_positive",
                comment_norm_hash=hashlib.sha256(text.lower().encode()).hexdigest()[:16],
                comment_len=len(text),
            )
        )
        workflows.append(
            WorkflowEvent(
                entity_id="CSE-08",
                ref_type="alert",
                ref_id=alert_id,
                ts=created_at + timedelta(minutes=12),
                actor=actor,
                action="investigate",
                from_status="investigating",
                to_status="investigating",
                note_len=len(text),
            )
        )
        affected.append(alert_id)
    return {"affected_ids": affected, "actor": actor}


def inject_cse03_unacknowledged_escalations(escalations: list[Escalation]) -> dict[str, Any]:
    """EG08: four CSE-03 escalations never acknowledged by Tier-2."""
    targets = sorted((e for e in escalations if e.entity_id == "CSE-03"), key=lambda e: e.esc_id)[:4]
    for e in targets:
        e.acknowledged_at = None
        e.outcome = None
    return {"affected_ids": [e.esc_id for e in targets]}


def inject_cse05_stale_open_cases(cases: list[Case]) -> dict[str, Any]:
    """EG09: four CSE-05 high-severity cases left open since spring (> 14 days stale)."""
    # The four opened earliest. Picking by case id could choose cases opened in the last
    # days of the period, which are open but not stale.
    targets = sorted(
        (c for c in cases if c.entity_id == "CSE-05" and c.severity == "high"),
        key=lambda c: (c.opened_at, c.case_id),
    )[:4]
    for c in targets:
        c.status = "open"
        c.closed_at = None
    return {"affected_ids": [c.case_id for c in targets]}


def inject_cse07_no_true_positives(alerts: list[Alert], closures: list[Closure]) -> dict[str, Any]:
    """EG11: CSE-07 records no true positive in six months (every alert closed FP/benign)."""
    relabelled = []
    for a in alerts:
        if a.entity_id == "CSE-07" and a.disposition == "true_positive":
            a.disposition = "false_positive"
            relabelled.append(a.alert_id)
    ids = set(relabelled)
    for c in closures:
        if c.entity_id == "CSE-07" and c.ref_id in ids:
            c.disposition = "false_positive"
    return {"affected_ids": relabelled}


def inject_cse09_skipped_containment(cases: list[Case], workflows: list[WorkflowEvent]) -> dict[str, Any]:
    """EG12: three CSE-09 critical cases closed without the mandatory 'contain' stage."""
    targets = {
        c.case_id
        for c in sorted((c for c in cases if c.entity_id == "CSE-09" and c.severity == "critical"), key=lambda c: c.case_id)[:3]
    }
    workflows[:] = [
        w for w in workflows if not (w.ref_type == "case" and w.ref_id in targets and w.action == "contain")
    ]
    return {"affected_ids": sorted(targets)}


def inject_cse09_dormant_rules(detection_rules: list[DetectionRule]) -> dict[str, Any]:
    """NS05: CSE-09 keeps 25 enabled legacy rules that never fire (25/55 = 45% dormant)."""
    added = []
    for i in range(1, 26):
        rule_id = f"RULE-LEGACY-{i:02d}"
        detection_rules.append(
            DetectionRule(entity_id="CSE-09", rule_id=rule_id, category="Policy Violation", enabled=True)
        )
        added.append(rule_id)
    return {"affected_ids": added}


def inject_cse02_unreported_incidents(cases: list[Case], external_reports: list[ExternalReport]) -> dict[str, Any]:
    """NS07: two CSE-02 critical incidents with no external (NCIIPC) report."""
    targets = {
        c.case_id
        for c in sorted((c for c in cases if c.entity_id == "CSE-02" and c.severity == "critical"), key=lambda c: c.case_id)[:2]
    }
    external_reports[:] = [r for r in external_reports if not (r.entity_id == "CSE-02" and r.incident_id in targets)]
    return {"affected_ids": sorted(targets)}


def inject_cse10_missing_month(alerts: list[Alert]) -> tuple[list[Alert], dict[str, Any]]:
    """NS08: CSE-10 submits no alerts for June 2026 (5 of the 6 review months)."""
    kept, dropped = [], []
    for a in alerts:
        if a.entity_id == "CSE-10" and a.created_at and (a.created_at.year, a.created_at.month) == (2026, 6):
            dropped.append(a.alert_id)
        else:
            kept.append(a)
    return kept, {"affected_ids": ["MISSING-MONTH-CSE10-2026-06"], "dropped_alerts": len(dropped)}
