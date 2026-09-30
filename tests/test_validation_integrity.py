"""Regression tests for how validation is scored and for the generator bugs that skewed it.

The primary validation once reported 100% precision because the harness only counted
false positives on the three clean entities and exempted NS05/EG12/EG10; the stress
scenario reported 60% because of generator artifacts. These tests pin down the honest
scoring and each generator bug, so neither kind of error can quietly return.
"""

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from satsa.rules.execution_gaps import chance_repeat_floor
from satsa.rules.registry import RuleRegistry
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.synth.generator import SyntheticDataGenerator
from satsa.synth.stress import generate_stress_dataset
from satsa.validate.harness import (
    ADJUDICATION_COLUMNS,
    ShadowPilotAdapter,
    ValidationHarness,
    _perturb,
    adjudication_sheet,
    wilson_interval,
)

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


# ------------------------------------------------------------------ peer cohorts


@pytest.fixture
def peer_store(tmp_path):
    """FAST closes 20 high alerts in 60 s; SLOW-1/SLOW-2 take an hour. Only SLOW-* report Malware."""
    store = DuckDBStore(tmp_path / "store")
    base = datetime(2026, 2, 1, 9, 0, 0)
    for ent, secs, cat in (("FAST", 60, "Phishing"), ("SLOW-1", 3600, "Malware"), ("SLOW-2", 3600, "Malware")):
        for i in range(20):
            created = base + timedelta(hours=i)
            store.execute(
                "INSERT INTO alert (entity_id, alert_id, severity_final, closed_by_type, created_at, closed_at, category)"
                " VALUES (?, ?, 'high', 'human', ?, ?, ?)",
                [ent, f"{ent}-{i}", created, created + timedelta(seconds=secs), cat],
            )
    yield store
    store.close()


def test_eg01_baseline_comes_from_peers_not_the_entity_itself(peer_store):
    """With the portfolio-wide p5 (including FAST's own 60 s closures) FAST was never
    'faster than p5'; against its peers' baseline it is."""
    rule = RuleRegistry().get_rule("EG01")
    findings, _ = rule.evaluate("FAST", peer_store, ["SLOW-1", "SLOW-2"], "RUN-X")
    assert findings and findings[0].peer_comparison["peer_p5_seconds"] == 3600
    # No resolved cohort: every other entity is the baseline, still excluding FAST.
    assert rule.evaluate("FAST", peer_store, [], "RUN-X")[0]
    assert rule.evaluate("SLOW-1", peer_store, ["SLOW-2"], "RUN-X")[0] == []


def test_ns02_standard_categories_come_from_the_peer_cohort(peer_store):
    rule = RuleRegistry().get_rule("NS02")
    findings, _ = rule.evaluate("FAST", peer_store, ["SLOW-1", "SLOW-2"], "RUN-X")
    assert findings and findings[0].evidence_ids == ["Malware"]
    # The verdict depends on the cohort: against SLOW-2 nothing is missing; against
    # FAST, SLOW-1 lacks FAST's Phishing.
    assert rule.evaluate("SLOW-1", peer_store, ["SLOW-2"], "RUN-X")[0] == []
    assert rule.evaluate("SLOW-1", peer_store, ["FAST"], "RUN-X")[0][0].evidence_ids == ["Phishing"]


def _disposition_store(tmp_path, specs):
    """specs: {entity: (n_alerts, n_night, n_true_positive)}."""
    store = DuckDBStore(tmp_path / "zstore")
    base = datetime(2026, 2, 1, 0, 0, 0)
    for ent, (n, n_night, n_tp) in specs.items():
        for i in range(n):
            hour = 22 if i < n_night else 12
            disp = "true_positive" if i < n_tp else "false_positive"
            store.execute(
                "INSERT INTO alert (entity_id, alert_id, created_at, disposition) VALUES (?, ?, ?, ?)",
                [ent, f"{ent}-{i}", base + timedelta(days=i % 150, hours=hour), disp],
            )
    return store


def test_ns03_flags_night_share_far_below_peers_even_above_the_absolute_floor(tmp_path):
    store = _disposition_store(
        tmp_path,
        {"LOW": (1000, 100, 50), "P1": (1000, 220, 50), "P2": (1000, 215, 50), "P3": (1000, 225, 50)},
    )
    rule = RuleRegistry().get_rule("NS03")
    try:
        findings, _ = rule.evaluate("LOW", store, ["P1", "P2", "P3"], "RUN-X")
        assert findings and findings[0].peer_comparison["method"] == "peer_robust_z"
        assert findings[0].peer_comparison["robust_z"] <= -3.5
        # Too few comparable peers: the absolute 3% floor applies, and 10% passes it.
        assert rule.evaluate("LOW", store, ["P1", "P2"], "RUN-X")[0] == []
    finally:
        store.close()


def test_eg11_judges_fp_rate_against_peers_not_a_fixed_98_percent(tmp_path):
    # SOC99 closes 99% as FP; its peers sit at 98.5% +/- 0.5%. Normal for this cohort.
    store = _disposition_store(
        tmp_path,
        {"SOC99": (1000, 0, 10), "P1": (1000, 0, 15), "P2": (1000, 0, 10), "P3": (1000, 0, 20)},
    )
    rule = RuleRegistry().get_rule("EG11")
    try:
        assert rule.evaluate("SOC99", store, ["P1", "P2", "P3"], "RUN-X")[0] == []
        # With too few peers the fixed 98% fallback applies and flags it.
        fallback, _ = rule.evaluate("SOC99", store, ["P1"], "RUN-X")
        assert fallback and fallback[0].peer_comparison["method"] == "absolute"
    finally:
        store.close()


def test_chance_repeat_floor_scales_with_volume_and_is_capped():
    # Sparse: 100 alerts over 1,000 pairs. Even 3 repeats would be surprising.
    assert chance_repeat_floor(100, 1000, 0.5, cap=16) == 3
    # The synthetic large entities: 2,250 alerts over 1,800 pairs -> 8, where coincidence stops.
    assert chance_repeat_floor(2250, 1800, 0.5, cap=16) == 8
    # Denser volume needs more repeats before they mean anything...
    assert chance_repeat_floor(9000, 1800, 0.5, cap=100) > chance_repeat_floor(2250, 1800, 0.5, cap=100)
    # ...but never more than the cap, however busy (and no underflow at extreme volume).
    assert chance_repeat_floor(2_000_000, 2, 0.5, cap=16) == 16
    assert chance_repeat_floor(0, 0, 0.5, cap=16) == 1


def test_eg05_ignores_coincidental_repeats_but_keeps_chronic_pairs(tmp_path):
    """BUSY: 3 assets x 3 rules, 54 all-benign alerts (6 per pair): every pair 'repeats', by volume
    alone. CHRONIC adds two pairs firing 40 times each on top of the same background."""
    store = DuckDBStore(tmp_path / "eg05")
    base = datetime(2026, 2, 1, 9, 0, 0)

    def add(ent, asset, rule, n, start):
        for i in range(n):
            store.execute(
                "INSERT INTO alert (entity_id, alert_id, asset_id, rule_id, disposition, created_at)"
                " VALUES (?, ?, ?, ?, 'benign', ?)",
                [ent, f"{ent}-{asset}-{rule}-{start + i}", asset, rule, base + timedelta(hours=start + i)],
            )

    for ent in ("BUSY", "CHRONIC"):
        for a in range(3):
            for r in range(3):
                add(ent, f"A{a}", f"R{r}", 6, 0)
    add("CHRONIC", "A0", "R0", 40, 100)
    add("CHRONIC", "A1", "R1", 40, 100)

    try:
        # With the threshold lowered to 6, BUSY's uniform 6-per-pair background is below its
        # own chance level and is not flagged; without the floor all 9 pairs would count.
        rule = type(RuleRegistry().get_rule("EG05"))(config_override={"params": {"min_repeat_count": 6}})
        assert rule.evaluate("BUSY", store, [], "RUN-X")[0] == []
        findings, _ = rule.evaluate("CHRONIC", store, [], "RUN-X")
        assert findings and findings[0].peer_comparison["unaddressed_pairs"] == 2
        assert findings[0].peer_comparison["effective_min_repeats"] > 6
    finally:
        store.close()


# ------------------------------------------------------------------ threshold sensitivity


def test_perturb_always_moves_integer_thresholds():
    assert _perturb(0.25, 1.2) == 0.3
    assert _perturb(8, 0.8) == 6
    assert _perturb(2, 0.8) == 1  # 1.6 rounds back to 2, so it is moved by one
    assert _perturb(2, 1.2) == 3
    assert _perturb(1, 0.8) == 1  # never below 1
    assert _perturb(True, 1.2) is True
    assert _perturb(0.98, 1.2) == 1.0  # a rate never exceeds 100%
    assert _perturb(0.6, 1.2) == 0.72


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


def test_wilson_interval_is_wide_for_small_samples_and_bounded():
    assert wilson_interval(0, 0) is None
    low, high = wilson_interval(3, 3)
    assert high == 1.0 and 0.40 < low < 0.50  # 3/3 is far from proof of 100%
    low, high = wilson_interval(50, 100)
    assert 0.40 < low < 0.41 and 0.59 < high < 0.60


def test_shadow_reports_per_rule_figures_config_hash_and_firing_rate(tmp_path):
    store = _store_with(tmp_path, [("E-1", "EG01"), ("E-2", "EG01"), ("E-3", "EG05"), ("E-4", "NS02")])
    for ent in ("E-1", "E-2", "E-3", "E-4"):
        store.conn.execute(
            "INSERT INTO entity_scores (run_id, entity_id, risk_index, risk_band, distinct_rules_triggered)"
            " VALUES (?, ?, 1.0, 'Low', 1)",
            (RUN, ent),
        )
    store.conn.commit()
    reviews = [
        {"entity_id": "E-1", "record_id": "", "rule_id": "EG01", "label": "confirmed"},
        {"entity_id": "E-9", "record_id": "", "rule_id": "EG01", "label": "confirmed"},  # missed
        {"entity_id": "E-2", "record_id": "", "rule_id": "EG01", "label": "not_an_issue"},
    ]
    res = ShadowPilotAdapter(store).evaluate_shadow_pilot(reviews, RUN)
    eg01 = next(r for r in res["per_rule"] if r["rule_id"] == "EG01")
    assert (eg01["confirmed"], eg01["reproduced"], eg01["recall"]) == (2, 1, 0.5)
    assert (eg01["findings_confirmed"], eg01["findings_rejected"], eg01["precision"]) == (1, 1, 0.5)
    assert eg01["firing_rate"] == 0.5 and eg01["recall_ci"][0] < 0.5 < eg01["recall_ci"][1]
    ns02 = next(r for r in res["per_rule"] if r["rule_id"] == "NS02")
    assert ns02["precision"] is None and ns02["findings_unadjudicated"] == 1
    assert res["config_hash"] == "x" and res["pair_recall"] == 0.5

    # The blind sheet lists only unadjudicated findings, with no score or severity.
    sheet = adjudication_sheet(store, res)
    store.close()
    assert [(r["entity_id"], r["rule_id"]) for r in sheet] == [("E-3", "EG05"), ("E-4", "NS02")]
    assert set(sheet[0]) == set(ADJUDICATION_COLUMNS) and all(r["label"] == "" for r in sheet)
    assert not {"score", "confidence", "severity"} & set(sheet[0])


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
