"""Tests for the harder 'stress scenario' validation (docs/validation.md Section 2A).

Unlike the primary synthetic dataset's near-guaranteed-by-construction results, this
scenario is designed to produce genuinely imperfect numbers and must never be curated
to look perfect.
"""

import tempfile
from pathlib import Path

from satsa.ingest.pipeline import IngestionPipeline
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.synth.stress import generate_stress_dataset, save_stress_dataset
from satsa.validate.harness import ValidationHarness


def test_stress_dataset_determinism():
    data1, gt1 = generate_stress_dataset(seed=9901)
    data2, gt2 = generate_stress_dataset(seed=9901)
    assert len(data1["alert"]) == len(data2["alert"])
    assert data1["alert"][0].alert_id == data2["alert"][0].alert_id
    assert gt1.defects[0].entity_id == gt2.defects[0].entity_id


def test_stress_dataset_has_the_three_designed_entities():
    data, gt = generate_stress_dataset()
    entity_ids = {e.entity_id for e in data["entity"]}
    assert entity_ids == {"STRESS-01", "STRESS-02", "STRESS-03"}
    assert gt.clean_entities == ["STRESS-03"]
    rule_ids = {d.rule_id for d in gt.defects}
    assert "EG04" in rule_ids
    assert "EG02" in rule_ids


def test_stress01_borderline_share_is_just_over_the_real_code_threshold():
    """STRESS-01's injected share must be close to, not far from, EG04's actual
    25% code threshold -- this is what makes it a genuine borderline case rather
    than another easy, blown-out defect like the primary dataset's CSE-07.
    """
    data, gt = generate_stress_dataset()
    stress01_defect = next(d for d in gt.defects if d.entity_id == "STRESS-01")
    assert 0.25 < stress01_defect.share < 0.35, (
        "STRESS-01 must sit just over EG04's real 25% code threshold, not far above it"
    )


def test_stress02_defects_share_identical_evidence():
    """The ambiguous case's two defects (EG02 and EG04) must cite the SAME affected
    alert IDs -- that overlap is exactly what makes attribution ambiguous.
    """
    data, gt = generate_stress_dataset()
    stress02_defects = [d for d in gt.defects if d.entity_id == "STRESS-02"]
    assert len(stress02_defects) == 2
    rule_ids = {d.rule_id for d in stress02_defects}
    assert rule_ids == {"EG02", "EG04"}
    ids_a = set(stress02_defects[0].affected_ids)
    ids_b = set(stress02_defects[1].affected_ids)
    assert ids_a == ids_b
    assert len(ids_a) > 0


def test_stress_scenario_runs_end_to_end_and_is_not_perfect():
    """The full stress pipeline must run, and — unlike the primary dataset — is not
    required (or expected) to score 100% on every axis. It must, however, actually
    detect the two genuinely-injected defects (recall), proving the borderline/
    ambiguous construction really does cross the rule thresholds as designed.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        csv_dir, gt_path = save_stress_dataset(tmp_path / "generated", seed=9901)

        duckdb_store = DuckDBStore(tmp_path / "store")
        sqlite_store = SQLiteStore(tmp_path / "store" / "stress.db")
        pipeline = IngestionPipeline(duckdb_store, sqlite_store)
        res = pipeline.ingest_directory(csv_dir)
        assert res.get("status") == "success"

        runner = AssessmentRunner(duckdb_store, sqlite_store)
        run_res = runner.run_assessment(period="STRESS", actor="test-suite")
        assert run_res["status"] == "success"

        harness = ValidationHarness(duckdb_store, sqlite_store, gt_path)
        results = harness.run_full_validation(run_res["run_id"])

        duckdb_store.close()
        sqlite_store.close()

    rules = results["rule_detection"]
    # Both genuinely-injected defects (borderline EG04, ambiguous EG02) must be
    # detected -- this validates the stress dataset was constructed correctly.
    assert rules["overall_recall"] == 1.0
    assert rules["total_injected_defects"] == 3  # EG04(STRESS-01) + EG02+EG04(STRESS-02)

    # This scenario is explicitly NOT curated to be perfect. It's fine (expected,
    # even) for precision to be less than 100% because of noise on STRESS-03.
    assert 0.0 < rules["overall_precision"] <= 1.0


def test_stress_dataset_is_isolated_from_primary_demo_dataset():
    """Stress entities must never collide with the primary CSE-01..CSE-10 demo IDs,
    so running the stress scenario can never silently corrupt the primary
    correctness-check numbers in docs/validation.md Section 2.
    """
    data, _ = generate_stress_dataset()
    entity_ids = {e.entity_id for e in data["entity"]}
    assert not any(eid.startswith("CSE-") for eid in entity_ids)
