"""A genuinely harder validation scenario ("stress scenario").

The main synthetic dataset (satsa.synth.generator) injects defects that are
deliberately hand-tuned to clearly exceed each rule's own threshold (e.g. a
60% template-comment share against a 25% code threshold). That is useful as
a *detector-implementation correctness check* -- it confirms the code
correctly implements its own specified rule logic -- but the resulting
100% precision/recall numbers are close to guaranteed by construction, not
evidence of real-world detection performance at realistic signal-to-noise
ratios.

This module builds a small, independent, harder dataset with three entities:

- STRESS-01: an EG04 (template-driven closures) defect injected at a
  magnitude just barely over the rule's actual code threshold
  (repeat_share > 0.25, with the majority comment-hash group >= 10 alerts).
  A one-alert swing either way changes the classification.
- STRESS-02: an ambiguous case where the SAME closure pattern (short,
  zero-investigation comments repeated across a majority of alerts)
  satisfies both EG02 (ack without investigation) and EG04 (template
  closures) simultaneously on overlapping evidence, so it is genuinely
  unclear which single rule "owns" the defect.
- STRESS-03: a clean entity with realistic jitter/noise (variable closure
  durations, unique comments, mixed day/night activity, varied rule IDs)
  that must NOT cross any rule threshold -- a true-negative-under-noise
  check, rather than a hand-picked, noise-free "clean" baseline.

This is intentionally kept separate from the primary demo dataset in
data/generated/ so it never perturbs the primary correctness-check numbers
reported in docs/validation.md Section 2; its own (likely imperfect)
numbers are reported alongside them in Section 2A, clearly labeled as the
stress scenario.
"""

from __future__ import annotations

import hashlib
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from satsa.models.canonical import (
    Alert,
    Asset,
    Closure,
    DetectionRule,
    Entity,
    LogSourceDaily,
    WorkflowEvent,
)
from satsa.synth.ground_truth import GroundTruth, InjectedDefect

STRESS_SEED_DEFAULT = 9901
_BASE_TIME = datetime(2026, 1, 5, 9, 0, 0)
_RULE_IDS = [f"DET-{i:03d}" for i in range(1, 13)]


def _required_ts(ts: datetime | None) -> datetime:
    """Workflow events need a timestamp; the alerts they derive from always set it here."""
    if ts is None:
        raise ValueError("stress generator produced an alert without the required timestamp")
    return ts

def _make_closure_hash(text: str) -> str:
    return hashlib.sha256(text.lower().strip().encode()).hexdigest()[:16]


def _mk_alert(
    entity_id: str,
    idx: int,
    created_at: datetime,
    duration_min: int,
    asset_id: str,
    rng: random.Random,
) -> Alert:
    return Alert(
        entity_id=entity_id,
        alert_id=f"{entity_id}-ALT-{idx:04d}",
        rule_id=rng.choice(_RULE_IDS),
        category="Suspicious Activity",
        severity_orig="medium",
        severity_final="medium",
        asset_id=asset_id,
        created_at=created_at,
        acknowledged_at=created_at + timedelta(minutes=2),
        first_touch_at=created_at + timedelta(minutes=3),
        closed_at=created_at + timedelta(minutes=duration_min),
        closed_by=f"STRESS_ANALYST_{idx % 3}",
        closed_by_type="human",
        disposition="false_positive" if idx % 4 else "benign",
        status="closed",
    )


def _entity_spec(entity_id: str, name: str) -> Entity:
    return Entity(
        entity_id=entity_id,
        name=name,
        sector="banking",
        size_band="medium",
        soc_model="inhouse",
    )


def _build_stress01(rng: random.Random) -> tuple[list[Alert], list[Closure], InjectedDefect]:
    """EG04 defect injected just barely over the code's real 25% threshold.

    40 human-closed alerts; 11 share an identical, non-trivial comment hash
    (repeat_share = 11/40 = 27.5%, only 2.5 points over the 25% code
    threshold, with 11 >= the required 10-alert hash-group floor).
    """
    entity_id = "STRESS-01"
    asset_id = f"{entity_id}-AST-01"
    total = 40
    borderline_count = 11
    borderline_ids = set(rng.sample(range(total), borderline_count))
    borderline_text = "Alert reviewed and closed as expected recurring pattern."
    borderline_hash = _make_closure_hash(borderline_text)

    alerts: list[Alert] = []
    closures: list[Closure] = []
    for i in range(total):
        created_at = _BASE_TIME + timedelta(hours=i * 3, minutes=rng.randint(0, 40))
        duration_min = rng.randint(25, 90)
        alert = _mk_alert(entity_id, i, created_at, duration_min, asset_id, rng)
        alerts.append(alert)
        if i in borderline_ids:
            closures.append(
                Closure(
                    entity_id=entity_id,
                    ref_id=alert.alert_id,
                    reason_code="reviewed",
                    disposition=alert.disposition,
                    comment_norm_hash=borderline_hash,
                    comment_len=len(borderline_text),
                    comment_shingles="alert_reviewed,expected_recurring,closed_pattern",
                )
            )
        else:
            unique_text = f"Investigated alert {alert.alert_id} and confirmed benign context {i}."
            closures.append(
                Closure(
                    entity_id=entity_id,
                    ref_id=alert.alert_id,
                    reason_code="reviewed",
                    disposition=alert.disposition,
                    comment_norm_hash=_make_closure_hash(unique_text),
                    comment_len=len(unique_text),
                    comment_shingles=None,
                )
            )

    share = borderline_count / total
    defect = InjectedDefect(
        entity_id=entity_id,
        rule_id="EG04",
        defect_type="borderline_template_closures",
        affected_ids=[a.alert_id for i, a in enumerate(alerts) if i in borderline_ids],
        share=share,
        description=(
            f"Borderline EG04 case: {borderline_count}/{total} ({share:.1%}) human-closed alerts "
            "share an identical comment hash, only ~2.5 points over the rule's real 25% code "
            "threshold (not the aspirational 45% figure in config/rules.yaml, which the current "
            "EG04 implementation does not read)."
        ),
    )
    return alerts, closures, defect


def _build_stress02(
    rng: random.Random,
) -> tuple[list[Alert], list[Closure], list[WorkflowEvent], list[InjectedDefect]]:
    """A single closure pattern that satisfies BOTH EG02 and EG04 on overlapping evidence."""
    entity_id = "STRESS-02"
    asset_id = f"{entity_id}-AST-01"
    total = 40
    ambiguous_count = 12
    ambiguous_ids = set(rng.sample(range(total), ambiguous_count))
    ambiguous_text = "Closed - benign."  # 17 chars: < 25 (EG02) and repeated >= 10x (EG04)
    ambiguous_hash = _make_closure_hash(ambiguous_text)

    alerts: list[Alert] = []
    closures: list[Closure] = []
    workflows: list[WorkflowEvent] = []
    for i in range(total):
        created_at = _BASE_TIME + timedelta(hours=i * 3, minutes=rng.randint(0, 40))
        duration_min = rng.randint(25, 90)
        alert = _mk_alert(entity_id, i, created_at, duration_min, asset_id, rng)
        alerts.append(alert)
        if i in ambiguous_ids:
            closures.append(
                Closure(
                    entity_id=entity_id,
                    ref_id=alert.alert_id,
                    reason_code="reviewed",
                    disposition=alert.disposition,
                    comment_norm_hash=ambiguous_hash,
                    comment_len=len(ambiguous_text),
                    comment_shingles="closed_benign",
                )
            )
            # Deliberately no 'investigate' workflow event -> inv_count == 0 for EG02.
            workflows.append(
                WorkflowEvent(
                    entity_id=entity_id,
                    ref_type="alert",
                    ref_id=alert.alert_id,
                    ts=_required_ts(alert.closed_at),
                    actor=f"STRESS_ANALYST_{i % 3}",
                    action="close",
                    from_status="open",
                    to_status="closed",
                    note_len=len(ambiguous_text),
                )
            )
        else:
            unique_text = f"Investigated and remediated alert {alert.alert_id}, root cause {i}."
            closures.append(
                Closure(
                    entity_id=entity_id,
                    ref_id=alert.alert_id,
                    reason_code="reviewed",
                    disposition=alert.disposition,
                    comment_norm_hash=_make_closure_hash(unique_text),
                    comment_len=len(unique_text),
                    comment_shingles=None,
                )
            )
            workflows.append(
                WorkflowEvent(
                    entity_id=entity_id,
                    ref_type="alert",
                    ref_id=alert.alert_id,
                    ts=_required_ts(alert.acknowledged_at),
                    actor=f"STRESS_ANALYST_{i % 3}",
                    action="investigate",
                    from_status="open",
                    to_status="open",
                    note_len=len(unique_text),
                )
            )

    share = ambiguous_count / total
    affected = [a.alert_id for i, a in enumerate(alerts) if i in ambiguous_ids]
    defects = [
        InjectedDefect(
            entity_id=entity_id,
            rule_id="EG02",
            defect_type="ambiguous_dual_rule",
            affected_ids=affected,
            share=share,
            description=(
                f"{ambiguous_count}/{total} ({share:.1%}) alerts closed with a short, zero-"
                "investigation comment -- satisfies EG02's ack-without-investigation criteria."
            ),
        ),
        InjectedDefect(
            entity_id=entity_id,
            rule_id="EG04",
            defect_type="ambiguous_dual_rule",
            affected_ids=affected,
            share=share,
            description=(
                f"The SAME {ambiguous_count}/{total} ({share:.1%}) closures also share an "
                "identical comment hash -- satisfies EG04's template-closure criteria on "
                "exactly the same evidence. It is genuinely ambiguous whether this is an "
                "investigation-skipping defect, a template-comment defect, or both."
            ),
        ),
    ]
    return alerts, closures, workflows, defects


def _build_stress03(rng: random.Random) -> tuple[list[Alert], list[Closure], list[WorkflowEvent]]:
    """A clean entity with realistic jitter -- a true-negative-under-noise check."""
    entity_id = "STRESS-03"
    asset_id = f"{entity_id}-AST-01"
    total = 120

    alerts: list[Alert] = []
    closures: list[Closure] = []
    workflows: list[WorkflowEvent] = []
    for i in range(total):
        # Spread across day AND night hours so no artificial flatline appears.
        hour_offset = rng.randint(0, 23)
        created_at = _BASE_TIME + timedelta(days=i // 4, hours=hour_offset, minutes=rng.randint(0, 59))
        duration_min = rng.randint(15, 180)  # realistic, noisy triage durations
        alert = _mk_alert(entity_id, i, created_at, duration_min, asset_id, rng)
        alerts.append(alert)

        unique_text = (
            f"Reviewed alert {alert.alert_id}: {rng.choice(['no', 'low', 'transient'])} risk "
            f"activity confirmed via log correlation, closing as {alert.disposition}."
        )
        closures.append(
            Closure(
                entity_id=entity_id,
                ref_id=alert.alert_id,
                reason_code="reviewed",
                disposition=alert.disposition,
                comment_norm_hash=_make_closure_hash(unique_text + str(i)),
                comment_len=len(unique_text),
                comment_shingles=None,
            )
        )
        workflows.append(
            WorkflowEvent(
                entity_id=entity_id,
                ref_type="alert",
                ref_id=alert.alert_id,
                ts=_required_ts(alert.acknowledged_at),
                actor=f"STRESS_ANALYST_{i % 4}",
                action="investigate",
                from_status="open",
                to_status="open",
                note_len=len(unique_text),
            )
        )

    return alerts, closures, workflows


def generate_stress_dataset(seed: int = STRESS_SEED_DEFAULT) -> tuple[dict[str, list[Any]], GroundTruth]:
    """Build the full stress-scenario dataset and its ground truth.

    Returns a (dataset, ground_truth) pair with the same table-name shape as
    satsa.synth.generator.SyntheticDataGenerator.generate(), so it can be
    ingested and run through the exact same deterministic pipeline.
    """
    rng = random.Random(seed)

    entities = [
        _entity_spec("STRESS-01", "Stress Test Bank - Borderline Template Closures"),
        _entity_spec("STRESS-02", "Stress Test Bank - Ambiguous Dual-Rule Pattern"),
        _entity_spec("STRESS-03", "Stress Test Bank - Noisy Clean Baseline"),
    ]
    assets = [
        Asset(
            entity_id=e.entity_id,
            asset_id=f"{e.entity_id}-AST-01",
            asset_type="core_banking_server",
            criticality=3,
            monitored_flag=True,
            owner_unit="stress-test",
        )
        for e in entities
    ]
    detection_rules = [
        DetectionRule(entity_id=e.entity_id, rule_id=rid, category="Suspicious Activity", enabled=True)
        for e in entities
        for rid in _RULE_IDS
    ]
    log_sources = [
        LogSourceDaily(
            entity_id=e.entity_id,
            asset_id=f"{e.entity_id}-AST-01",
            source_type="edr",
            date=(_BASE_TIME + timedelta(days=d)).date(),
            event_count=rng.randint(5, 50),
        )
        for e in entities
        for d in range(30)
    ]

    alerts1, closures1, defect1 = _build_stress01(rng)
    alerts2, closures2, workflows2, defects2 = _build_stress02(rng)
    alerts3, closures3, workflows3 = _build_stress03(rng)

    dataset: dict[str, list[Any]] = {
        "entity": entities,
        "asset": assets,
        "detection_rule": detection_rules,
        "log_source_daily": log_sources,
        "alert": [*alerts1, *alerts2, *alerts3],
        "closure": [*closures1, *closures2, *closures3],
        "workflow_event": [*workflows2, *workflows3],
    }

    ground_truth = GroundTruth(
        version="1.0.0-stress",
        seed=seed,
        created_at=datetime.now(UTC).isoformat(),
        entities={e.entity_id: {"name": e.name, "sector": e.sector, "size": e.size_band} for e in entities},
        defects=[defect1, *defects2],
        clean_entities=["STRESS-03"],
        confounders=[
            {
                "type": "borderline_threshold",
                "description": "STRESS-01's defect sits ~2.5 points over EG04's real code threshold.",
            },
            {
                "type": "dual_rule_ambiguity",
                "description": "STRESS-02's defect satisfies EG02 and EG04 on identical overlapping evidence.",
            },
            {
                "type": "realistic_noise",
                "description": "STRESS-03 is clean but has jittered durations/comments/hours, unlike a hand-picked noise-free baseline.",
            },
        ],
    )
    return dataset, ground_truth


def save_stress_dataset(output_dir: Path | str, seed: int = STRESS_SEED_DEFAULT) -> tuple[Path, Path]:
    """Generate the stress dataset and save it to CSV files + ground_truth_stress.json."""
    import polars as pl

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    csv_dir = out_path / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)

    data, gt = generate_stress_dataset(seed)
    for table_name, records in data.items():
        if records:
            dicts = [r.model_dump() for r in records]
            df = pl.DataFrame(dicts)
            df.write_csv(csv_dir / f"{table_name}.csv")

    gt_path = out_path / "ground_truth_stress.json"
    gt_path.write_text(gt.model_dump_json(indent=2), encoding="utf-8")
    return csv_dir, gt_path
