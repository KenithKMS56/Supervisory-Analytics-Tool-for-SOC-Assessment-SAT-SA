"""Regression tests for how validation is scored and for the generator bugs that skewed it.

The primary validation once reported 100% precision because the harness only counted
false positives on the three clean entities and exempted NS05/EG12/EG10; the stress
scenario reported 60% because of generator artifacts. These tests pin down the honest
scoring and each generator bug, so neither kind of error can quietly return.
"""

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

import pytest

from satsa.rules.registry import RuleRegistry
from satsa.store.sqlite import SQLiteStore
from satsa.synth.generator import SyntheticDataGenerator
from satsa.synth.stress import generate_stress_dataset
from satsa.validate.harness import ShadowPilotAdapter, ValidationHarness

RUN = "RUN-TEST-INTEGRITY"


def _store_with(tmp_path: Path, findings: list[tuple[str, str]], queue: list[tuple[str, str]] = ()) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "v.db")
    now = datetime.now(UTC).isoformat()
    store.conn.execute(
        "INSERT INTO runs (run_id, period, created_at, config_hash, code_version, status) VALUES (?,?,?,?,?,?)",
        (RUN, "TEST", now, "x", "x", "success"),
    )
    for ent, rule in findings:
        store.conn.execute(
            "INSERT INTO findings (finding_id, run_id, entity_id, rule_id, rule_version, domain, level, score,"
            " confidence, severity, title, rationale, examiner_check, created_at)"
            " VALUES (?,?,?,?,'1','d','entity',50,0.5,'high','t','r','c',?)",
            (f"F-{ent}-{rule}", RUN, ent, rule, now),
        )
    for ent, rec in queue:
        store.conn.execute(
            "INSERT INTO review_queue (queue_id, run_id, entity_id, record_type, record_id, severity, score,"
            " selection_reason, is_random) VALUES (?,?,?,'alert',?,'high',1,'r',0)",
            (f"Q-{ent}-{rec}", RUN, ent, rec),
        )
    store.conn.commit()
    return store


def _ground_truth(tmp_path: Path) -> Path:
    gt = {
        "defects": [
            {"entity_id": "E-1", "rule_id": "EG01", "affected_ids": []},
            {"entity_id": "E-2", "rule_id": "NS01", "affected_ids": []},
        ],
        "clean_entities": ["E-3"],
    }
    path = tmp_path / "gt.json"
    path.write_text(json.dumps(gt), encoding="utf-8")
    return path


# ------------------------------------------------------------------ harness scoring


def test_every_non_injected_finding_is_a_false_positive(tmp_path):
    """No entity or rule is exempt: extra findings on defect entities, and the formerly
    exempted NS05/EG12/EG10 on clean entities, all count against precision."""
    store = _store_with(
        tmp_path,
        [
            ("E-1", "EG01"),  # TP
            ("E-2", "NS01"),  # TP
            ("E-1", "EG12"),  # extra rule on a defect entity
            ("E-3", "NS05"),  # formerly exempt, clean entity
            ("E-3", "EG10"),  # formerly exempt, clean entity
        ],
    )
    harness = ValidationHarness(None, store, _ground_truth(tmp_path))  # type: ignore[arg-type]
    res = harness.evaluate_rule_detection(RUN)
    store.close()

    assert (res["true_positives"], res["false_negatives"], res["false_positives"]) == (2, 0, 3)
    assert res["overall_precision"] == pytest.approx(0.4)
    assert res["false_positives_on_clean_entities"] == ["E-3:EG10", "E-3:NS05"]
    assert res["false_positives_on_defect_entities"] == ["E-1:EG12"]
    assert res["total_findings"] == 5


def test_missed_defects_are_named(tmp_path):
    store = _store_with(tmp_path, [("E-1", "EG01")])
    res = ValidationHarness(None, store, _ground_truth(tmp_path)).evaluate_rule_detection(RUN)  # type: ignore[arg-type]
    store.close()
    assert res["missed_defects"] == ["E-2:NS01"]
    assert res["overall_recall"] == 0.5


# ------------------------------------------------------------------ shadow-pilot precision


def test_shadow_precision_uses_rule_level_cleared_rows(tmp_path):
    store = _store_with(
        tmp_path,
        [("E-1", "EG01"), ("E-3", "EG05"), ("E-4", "NS02")],
        queue=[("E-3", "ALT-9")],
    )
    reviews = [
        {"entity_id": "E-1", "record_id": "", "rule_id": "EG01", "label": "confirmed"},
        {"entity_id": "E-3", "record_id": "", "rule_id": "EG05", "label": "not_an_issue"},
        {"entity_id": "E-3", "record_id": "ALT-9", "rule_id": "", "label": "not_an_issue"},
    ]
    res = ShadowPilotAdapter(store).evaluate_shadow_pilot(reviews, RUN)
    store.close()

    assert res["workpaper_precision"] == 0.5
    assert res["findings_confirmed"] == ["E-1:EG01"]
    assert res["findings_rejected"] == ["E-3:EG05"]
    # A finding the workpaper never mentions is unadjudicated, not a false positive.
    assert res["findings_unadjudicated"] == ["E-4:NS02"]
    assert res["cleared_records_in_queue"] == ["E-3:ALT-9"]


def test_shadow_precision_is_none_without_rule_level_adjudication(tmp_path):
    store = _store_with(tmp_path, [("E-1", "EG01")])
    reviews = [{"entity_id": "E-9", "record_id": "X", "rule_id": "", "label": "not_an_issue"}]
    res = ShadowPilotAdapter(store).evaluate_shadow_pilot(reviews, RUN)
    store.close()
    assert res["workpaper_precision"] is None
    assert res["findings_unadjudicated"] == ["E-1:EG01"]


# ------------------------------------------------------------------ primary generator bugs


@pytest.fixture(scope="module")
def primary():
    return SyntheticDataGenerator(seed=42, base_alerts_per_entity=400).generate()


def test_alerts_fire_rules_from_the_entitys_own_catalog(primary):
    """Alerts drawn from rule IDs outside the catalog made NS05 fire on every entity."""
    data, _ = primary
    catalog = {(r.entity_id, r.rule_id) for r in data["detection_rule"]}
    # CSE-09's injected repeat-alert rules are deliberately outside the catalog.
    stray = [a for a in data["alert"] if (a.entity_id, a.rule_id) not in catalog and "-REP" not in a.alert_id]
    assert stray == []


def test_every_critical_case_records_containment(primary):
    """A missing case lifecycle made EG12 fire on every entity. Only the cases of the
    injected EG12 defect may skip containment."""
    data, gt = primary
    injected = {cid for d in gt.defects if d.rule_id == "EG12" for cid in d.affected_ids}
    contained = {w.ref_id for w in data["workflow_event"] if w.ref_type == "case" and w.action == "contain"}
    critical = {c.case_id for c in data["case"] if c.severity == "critical"}
    assert injected and injected <= critical
    assert critical - contained == injected


def test_cse08_renumbering_keeps_child_records_attached(primary):
    """Renaming CSE-08 alerts without their children orphaned them and made EG02/EG03 fire."""
    data, _ = primary
    alert_ids = {a.alert_id for a in data["alert"] if a.entity_id == "CSE-08"}
    closed = {c.ref_id for c in data["closure"] if c.entity_id == "CSE-08"}
    touched = {w.ref_id for w in data["workflow_event"] if w.entity_id == "CSE-08" and w.ref_type == "alert"}
    assert alert_ids <= closed and alert_ids <= touched
    # The sequence gap itself is still there.
    assert any(int(a.split("-")[-1]) > 500 for a in alert_ids)


def test_mttr_is_declared_for_every_severity_eg10_compares(primary):
    data, _ = primary
    declared = defaultdict(set)
    for k in data["declared_kpi"]:
        if k.metric == "MTTR":
            declared[k.entity_id].add(k.severity)
    assert all(sev >= {"high", "critical"} for sev in declared.values())
    assert len(declared) == 10


def test_every_rule_has_an_injected_defect(primary):
    """A rule with no injected defect is only ever shown to stay quiet, never to detect.
    Every registered rule must be exercised by the primary or the stress ground truth."""
    _, gt = primary
    _, stress_gt = generate_stress_dataset()
    covered = {d.rule_id for d in gt.defects} | {d.rule_id for d in stress_gt.defects}
    registered = {cls.id for cls in RuleRegistry.RULE_CLASSES}
    assert registered - covered == set()


def test_coverage_defects_leave_clean_entities_clean(primary):
    _, gt = primary
    assert {d.entity_id for d in gt.defects}.isdisjoint(gt.clean_entities)


# ------------------------------------------------------------------ stress generator bugs


def test_stress_entities_span_the_six_month_review_period():
    """A ~1 month span made NS08 (6-month completeness) fire on every stress entity."""
    data, _ = generate_stress_dataset()
    months = defaultdict(set)
    for a in data["alert"]:
        months[a.entity_id].add((a.created_at.year, a.created_at.month))
    assert {e: len(m) for e, m in months.items()} == {"STRESS-01": 6, "STRESS-02": 6, "STRESS-03": 6}


def test_clean_stress_entity_does_not_contain_eg05s_defect_pattern():
    """STRESS-03 was one asset with every alert closed benign and no tickets -- EG05's own
    definition. It now has near-miss noise that stays below EG05's thresholds: one noisy
    pair with a tuning ticket and exactly one unremediated pair (EG05 needs two)."""
    data, _ = generate_stress_dataset()
    alerts = [a for a in data["alert"] if a.entity_id == "STRESS-03"]
    counts = Counter((a.asset_id, a.rule_id) for a in alerts)
    non_benign = {(a.asset_id, a.rule_id) for a in alerts if a.disposition == "true_positive"}
    remediated = {(r.linked_asset_id, r.linked_rule_id) for r in data["remediation"]}
    repeat_all_benign = {p for p, n in counts.items() if n >= 8 and p not in non_benign}
    assert len(repeat_all_benign) == 2
    assert len(repeat_all_benign - remediated) == 1
    assert len({a.asset_id for a in alerts}) > 1
