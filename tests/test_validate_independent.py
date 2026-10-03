"""The independent generator and the validation built on it (docs/validation_independent_report.md)."""

import ast
import hashlib
import json
import math
from pathlib import Path

import pytest

from satsa.synth import independent as ind
from satsa.synth.independent import (
    DOC_THRESHOLDS,
    RULES,
    SHARE_RULES,
    IndependentScenarioGenerator,
    eg05_repeat_threshold,
    poisson_sf,
    robust_z,
)
from satsa.validate.independent import _precision_at_k, run_seed

SRC = Path(ind.__file__)


def test_generator_imports_nothing_from_the_original_generator_or_the_rules():
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    forbidden = {m for m in imported if m.startswith(("satsa.synth.", "satsa.rules", "satsa.validate", "satsa.scoring"))}
    assert forbidden == set(), forbidden
    assert not any(m.startswith("satsa") for m in imported), "the generator must not import satsa at all"


def test_thresholds_are_the_documented_defaults():
    readme = (SRC.parents[3] / "README.md").read_text(encoding="utf-8")
    # A few spot checks against the README catalogue's own wording.
    assert DOC_THRESHOLDS["EG07"]["min_closures_per_analyst_hour"] == 30 and "$\\ge 30$ alerts in a single hour" in readme
    assert DOC_THRESHOLDS["EG09"]["stale_case_days"] == 14 and "14 days" in readme
    assert DOC_THRESHOLDS["NS05"]["max_dormant_share"] == 0.40 and "$>40\\%$" in readme
    assert sorted(DOC_THRESHOLDS) == RULES and len(RULES) == 20


def _gt(seed):
    gt = IndependentScenarioGenerator(seed).generate()
    gt.pop("created_at")
    return gt


def test_generation_is_deterministic_per_seed(tmp_path):
    hashes = []
    for run in ("a", "b"):
        csv_dir, gt_path = IndependentScenarioGenerator(7).save(tmp_path / run)
        digest = hashlib.sha256()
        for p in sorted(csv_dir.glob("*.csv")):
            digest.update(p.read_bytes())
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        gt.pop("created_at")
        hashes.append((digest.hexdigest(), json.dumps(gt, sort_keys=True)))
    assert hashes[0] == hashes[1]
    assert _gt(7)["defects"] != _gt(8)["defects"]


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_ground_truth_is_consistent(seed):
    gt = _gt(seed)
    defects = {(d["entity_id"], d["rule_id"]) for d in gt["defects"]}
    decoys = {(d["entity_id"], d["rule_id"]) for d in gt["decoys"]}
    assert {r for _, r in defects} == set(RULES), "every rule has at least one defect"
    assert not defects & decoys, "an (entity, rule) is a defect or a decoy, never both"
    assert not {e for e, _ in defects} & set(gt["clean_entities"])
    assert len(gt["entities"]) == 15
    group = gt["systemic_expected"][0]
    assert len(group["entities"]) == 3
    assert all((e, group["rule_id"]) in defects for e in group["entities"])
    assert all(gt["entities"][e]["soc_provider"] == group["provider"] for e in group["entities"])
    pair = gt["systemic_decoys"][0]
    assert len(pair["entities"]) == 2
    for d in gt["defects"]:
        f = d["measured"].get("design_factor")
        if f is not None:
            assert d["rule_id"] in SHARE_RULES and 1.08 <= f <= 1.9
    for d in gt["decoys"]:
        f = d["measured"].get("design_factor")
        if f is not None and "did_not_meet" not in d["defect_type"]:
            assert 0.4 <= f <= 0.8


def test_decoys_stay_under_the_threshold_or_the_minimum_count():
    sized = IndependentScenarioGenerator._sized
    for pop in (20, 30, 60, 400):
        for share in (0.06, 0.1, 0.12):
            n = sized(share, pop, 5, decoy=True)
            assert n < 5 or n / pop < 0.15
        n = sized(0.2, pop, 5, decoy=False)
        assert n >= 5 and n / pop > 0.15


def test_statistics_follow_the_documented_formulas():
    assert robust_z(0.1, [0.3, 0.32, 0.34, 0.36], 0.02) == pytest.approx((0.1 - 0.33) / max(1.4826 * 0.02, 0.02))
    assert poisson_sf(0, 2.0) == 1.0
    assert poisson_sf(3, 2.0) == pytest.approx(1 - 5 * math.exp(-2))  # 1 - P(0) - P(1) - P(2)
    # Low volume: k stays at the minimum of 8; very high volume: capped at 16.
    assert eg05_repeat_threshold(500, 1000) == 8
    assert eg05_repeat_threshold(10**6, 100) == 16


def test_precision_at_k_averages_over_ties():
    ranked = [("A", 3.0), ("B", 1.0), ("C", 1.0), ("D", 0.0)]
    assert _precision_at_k(ranked, {"A", "B"}) == (1.5, 2)
    assert _precision_at_k(ranked, {"A", "D"}) == (1.0, 2)
    assert _precision_at_k(ranked, set()) == (0.0, 0)


def test_one_seed_end_to_end_is_internally_consistent():
    r = run_seed(1, sweep=False)
    e = r["engine"]
    assert e["tp"] + e["fn"] == r["defects"]
    assert e["fp_on_decoys"] <= e["fp"] and e["decoys_flagged"] <= e["decoys"]
    # Removing a family never adds a detection of that family's rules.
    for fam, abl in r["ablation"].items():
        assert all(not rule.startswith(fam) or c["tp"] == 0 for rule, c in abl["per_rule"].items())
        assert abl["tp"] <= e["tp"]
    for name, b in r["baselines"].items():
        if name.startswith("_"):
            continue
        assert b["engine"]["tp"] + b["engine"]["fn"] == b["baseline"]["tp"] + b["baseline"]["fn"]


def test_eg11_is_built_both_ways():
    # Zero true positives (caught whatever the peers look like) and a skewed FP rate with some
    # true positives left (caught only by the peer robust-z test), so both branches of EG11 are exercised.
    kinds: dict[str, list[dict]] = {}
    for seed in range(1, 11):
        for d in _gt(seed)["defects"]:
            if d["rule_id"] == "EG11":
                kinds.setdefault(d["defect_type"], []).append(d)
    assert kinds.get("no_true_positives") and kinds.get("skewed_fp_rate")
    assert all(d["measured"]["true_positives"] > 0 and d["criterion"]["robust_z"] >= 3.5 for d in kinds["skewed_fp_rate"])
