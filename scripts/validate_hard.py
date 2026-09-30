"""Harder validation set: many seeds, low volumes, borderline and noisy scenarios.

    python scripts/validate_hard.py --out docs/validation_hard_report.md

The primary set (`satsa validate`) is one seed of a generator whose defects clear each
threshold by a wide margin. This set keeps that one apart and runs, each in its own
temporary store:

  portfolio   the 10-entity generator under other seeds, at the standard volume and at
              low volumes, where rule volume gates and peer statistics have less to work with
  stress      the stress scenario (an EG04 defect one alert over its threshold, an ambiguous
              EG02/EG04 case, a noisy clean entity) under many seeds

and reports, from the runs themselves: per-rule recall and precision with 95% Wilson
intervals, false positives on clean entities, and which thresholds change an outcome when
moved by 20% (in how many runs). Still synthetic: see docs/validation_summary.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from satsa.ingest.pipeline import IngestionPipeline
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.synth.generator import SyntheticDataGenerator
from satsa.synth.stress import save_stress_dataset
from satsa.validate.harness import ValidationHarness, wilson_interval

PRIMARY_SEED = 42  # the easy set's seed: never used here
PORTFOLIO_SEEDS = [101, 202, 303, 404, 505, 606, 707, 808]
PORTFOLIO_VOLUMES = [1500, 600, 300]  # base alerts per entity; 1500 is the primary set's volume
STRESS_SEEDS = list(range(1, 21))


def run_scenario(kind: str, seed: int, volume: int | None) -> dict:
    """Generate, ingest, assess and score one scenario in a throwaway store."""
    started = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        if kind == "portfolio":
            generator = SyntheticDataGenerator(seed=seed, base_alerts_per_entity=volume or 1500)
            csv_dir, gt_path = generator.save_dataset(tmp_path / "generated")
        else:
            csv_dir, gt_path = save_stress_dataset(tmp_path / "generated", seed=seed)
        duck = DuckDBStore(tmp_path / "store")
        sql = SQLiteStore(tmp_path / "store" / "hard.db")
        try:
            IngestionPipeline(duck, sql, salt_file=tmp_path / "salt").ingest_directory(csv_dir)
            run = AssessmentRunner(duck, sql).run_assessment(period="HARD", actor="validate-hard")
            harness = ValidationHarness(duck, sql, gt_path)
            detection = harness.evaluate_rule_detection(run["run_id"])
            sensitivity = harness.evaluate_threshold_sensitivity()
            clean = list(harness.ground_truth.get("clean_entities", []))
        finally:
            duck.close()
            sql.close()
    return {
        "kind": kind,
        "seed": seed,
        "volume": volume,
        "seconds": round(time.perf_counter() - started, 1),
        "injected": detection["total_injected_defects"],
        "tp": detection["true_positives"],
        "fn": detection["false_negatives"],
        "fp": detection["false_positives"],
        "missed": detection["missed_defects"],
        "fp_clean": detection["false_positives_on_clean_entities"],
        "fp_defect_entity": detection["false_positives_on_defect_entities"],
        "rules": detection["rule_breakdown"],
        "clean_entities": len(clean),
        "changed": [
            {"rule": r["rule_id"], "param": r["param"], "change": r["change"],
             "lost": sorted(set(r["baseline_outcome"]["tp"]) - set(r["outcome"]["tp"])),
             "new_fp": sorted(set(r["outcome"]["fp"]) - set(r["baseline_outcome"]["fp"]))}
            for r in sensitivity["rows"] if r["changed"]
        ],
        "perturbations": sensitivity["perturbations"],
    }


def _pct(successes: int, n: int) -> str:
    if n == 0:
        return "n/a"
    low, high = wilson_interval(successes, n) or [0.0, 0.0]
    return f"{successes / n:.1%} ({successes}/{n}; 95% CI {low:.1%}-{high:.1%})"


def _group_table(title: str, runs: list[dict]) -> list[str]:
    tp, fn, fp = (sum(r[k] for r in runs) for k in ("tp", "fn", "fp"))
    clean_total = sum(r["clean_entities"] for r in runs)
    clean_flagged = sum(len({item.split(":")[0] for item in r["fp_clean"]}) for r in runs)
    lines = [
        f"### {title}",
        "",
        f"- Runs: {len(runs)} | injected defects: {tp + fn}",
        f"- Recall: {_pct(tp, tp + fn)}",
        f"- Precision: {_pct(tp, tp + fp)}",
        f"- Clean entities with at least one finding: {_pct(clean_flagged, clean_total)}",
        "",
        "| Rule | Injected | Detected | Missed | False positives | Recall (95% CI) | Precision (95% CI) |",
        "|---|---:|---:|---:|---:|---|---|",
    ]
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    for r in runs:
        for rule, stats in r["rules"].items():
            for key in ("tp", "fn", "fp"):
                per_rule[rule][key] += stats[key]
    for rule, s in sorted(per_rule.items()):
        lines.append(
            f"| `{rule}` | {s['tp'] + s['fn']} | {s['tp']} | {s['fn']} | {s['fp']} | "
            f"{_pct(s['tp'], s['tp'] + s['fn'])} | {_pct(s['tp'], s['tp'] + s['fp'])} |"
        )
    missed = sorted({(m, r['seed']) for r in runs for m in r["missed"]})
    false_pos = sorted({(m, r['seed']) for r in runs for m in r["fp_clean"] + r["fp_defect_entity"]})
    if missed:
        lines += ["", "Missed (entity:rule @ seed): " + ", ".join(f"{m} @ {s}" for m, s in missed)]
    if false_pos:
        lines += ["", "False positives (entity:rule @ seed): " + ", ".join(f"{m} @ {s}" for m, s in false_pos)]
    return [*lines, ""]


def _fragility(runs: list[dict]) -> list[str]:
    """Thresholds whose 20% move changed that rule's outcome, and in how many runs."""
    counts: dict[tuple[str, str, str], dict[str, int]] = defaultdict(lambda: {"runs": 0, "lost": 0, "new_fp": 0})
    for r in runs:
        for c in r["changed"]:
            entry = counts[(c["rule"], c["param"], c["change"])]
            entry["runs"] += 1
            entry["lost"] += len(c["lost"])
            entry["new_fp"] += len(c["new_fp"])
    lines = [
        "| Rule | Threshold | Moved by | Runs where the outcome changed | Detections lost | New false positives |",
        "|---|---|---|---:|---:|---:|",
    ]
    for (rule, param, change), e in sorted(counts.items(), key=lambda kv: (-kv[1]["runs"], kv[0])):
        lines.append(f"| `{rule}` | `{param}` | {change} | {e['runs']} of {len(runs)} | {e['lost']} | {e['new_fp']} |")
    if not counts:
        lines.append("| none | | | 0 | 0 | 0 |")
    return lines


def render(runs: list[dict], command: str) -> str:
    portfolio = [r for r in runs if r["kind"] == "portfolio"]
    stress = [r for r in runs if r["kind"] == "stress"]
    lines = [
        "# SAT-SA Hard-Set Validation Report",
        "",
        "> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*",
        "",
        f"Generated {datetime.now(UTC).strftime('%Y-%m-%d')} by `{command}`. Every figure is counted from the runs",
        "listed at the end. **All data is synthetic**: these figures show how the rules behave under",
        "other random seeds, lower volumes and near-threshold cases. They are not real-world accuracy;",
        "see `docs/validation_summary.md`.",
        "",
        f"The primary (easy) set is seed {PRIMARY_SEED} at 1,500 alerts per entity and is reported separately in",
        "`docs/validation_report.md`; no run here uses that seed.",
        "",
        "## 1. Portfolio generator under other seeds and volumes",
        "",
    ]
    for volume in PORTFOLIO_VOLUMES:
        group = [r for r in portfolio if r["volume"] == volume]
        if group:
            lines += _group_table(f"{volume:,} base alerts per entity ({len(group)} seeds)", group)
    lines += ["## 2. Stress scenario under many seeds", ""]
    lines += _group_table("Borderline EG04, ambiguous EG02/EG04, noisy clean entity", stress)
    lines += [
        "## 3. Fragile thresholds",
        "",
        "Each tunable threshold was moved by -20% and +20%, one at a time, in every run. A row below",
        "is a threshold whose move changed what its rule detected in at least one run: the injected",
        "defect or clean entity sits within 20% of it.",
        "",
        "### Portfolio runs",
        "",
        *_fragility(portfolio),
        "",
        "### Stress runs",
        "",
        *_fragility(stress),
        "",
        "## 4. Runs",
        "",
        "| Scenario | Seed | Base alerts per entity | Injected | Detected | Missed | False positives | Seconds |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in runs:
        lines.append(
            f"| {r['kind']} | {r['seed']} | {r['volume'] or ''} | {r['injected']} | {r['tp']} | {r['fn']} | {r['fp']} | {r['seconds']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="SAT-SA hard-set validation")
    parser.add_argument("--out", default="docs/validation_hard_report.md")
    parser.add_argument("--json", default=None, help="also write the raw per-run results")
    parser.add_argument("--quick", action="store_true", help="two portfolio seeds and five stress seeds")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)

    portfolio_seeds = PORTFOLIO_SEEDS[:2] if args.quick else PORTFOLIO_SEEDS
    stress_seeds = STRESS_SEEDS[:5] if args.quick else STRESS_SEEDS
    runs = []
    for volume in PORTFOLIO_VOLUMES:
        for seed in portfolio_seeds:
            result = run_scenario("portfolio", seed, volume)
            print(f"portfolio seed={seed} volume={volume}: tp={result['tp']} fn={result['fn']} fp={result['fp']} "
                  f"({result['seconds']}s) missed={result['missed']} fp={result['fp_clean'] + result['fp_defect_entity']}",
                  flush=True)  # fmt: skip
            runs.append(result)
    for seed in stress_seeds:
        result = run_scenario("stress", seed, None)
        print(f"stress seed={seed}: tp={result['tp']} fn={result['fn']} fp={result['fp']} ({result['seconds']}s) "
              f"missed={result['missed']} fp={result['fp_clean'] + result['fp_defect_entity']}", flush=True)  # fmt: skip
        runs.append(result)

    command = "python scripts/validate_hard.py " + " ".join(sys.argv[1:])
    Path(args.out).write_text(render(runs, command.strip()), encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(runs, indent=1), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
