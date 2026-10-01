"""Per-entity statistics behind five thresholds, measured on the independent scenarios.

For each seed this generates the independent scenario (src/satsa/synth/independent.py), ingests it
through the normal pipeline and computes, per entity, the quantity each rule compares with its
threshold, using the same SQL as the rule. Each value is labelled with the generator's ground truth
(defect, decoy or neither) and then counted against a few candidate thresholds. The current config
value is always one of the candidates, which checks that this script agrees with the engine (it
should reproduce the recall and decoy figures of docs/validation_independent_report.md).

Nothing here changes config/. Used for docs/threshold_rationale.md.

    uv run python scripts/threshold_probe.py --seeds 20 [--json FILE]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from satsa.ingest.pipeline import IngestionPipeline
from satsa.models.canonical import Entity
from satsa.peers.grouping import PeerResolver
from satsa.rules.execution_gaps import CHANCE_FLOOR_CAP_FACTOR, chance_repeat_floor
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.synth.independent import IndependentScenarioGenerator

ROOT = Path(__file__).resolve().parents[1]
PARAMS = {k: v.get("params", {}) for k, v in yaml.safe_load((ROOT / "config/rules.yaml").read_text())["rules"].items()}

# Candidate values per parameter; the current config value is added if missing.
CANDIDATES: dict[tuple[str, str], list[float]] = {
    ("EG04", "max_comment_hash_share"): [0.15, 0.20, 0.25, 0.30, 0.35],
    ("EG05", "min_unaddressed_pairs"): [1, 2, 3, 4],
    ("EG07", "min_closures_per_analyst_hour"): [15, 20, 25, 30, 36, 40],
    ("NS05", "max_dormant_share"): [0.25, 0.30, 0.35, 0.40, 0.45, 0.50],
    ("NS08", "review_period_months"): [3, 4, 5, 6, 12],
    ("EG11", "min_spread"): [0.01, 0.02, 0.03, 0.05],
}


def _robust_z(value: float, peers: list[float], floor: float) -> tuple[float, float] | None:
    if len(peers) < 3:
        return None
    med = statistics.median(peers)
    mad = statistics.median(abs(p - med) for p in peers)
    return (value - med) / max(1.4826 * mad, floor), mad


def entity_stats(duck: DuckDBStore) -> dict[str, dict[str, Any]]:
    """The statistic each rule thresholds, per entity, computed with the rule's own SQL."""
    q = duck.query
    ents = [Entity(**r) for r in q("SELECT * FROM entity").iter_rows(named=True)]
    resolver = PeerResolver()
    portfolio_months = q("SELECT count(DISTINCT strftime(created_at, '%Y-%m')) AS m FROM alert")["m"][0]
    out: dict[str, dict[str, Any]] = {}
    fp_rates = {r["entity_id"]: (r["fp_rate"], r["n"]) for r in q(
        "SELECT entity_id, count(*) n, count(CASE WHEN disposition IN ('false_positive','benign') THEN 1 END)*1.0/count(*) fp_rate "
        "FROM alert GROUP BY entity_id").iter_rows(named=True)}
    for e in ents:
        eid = e.entity_id
        s: dict[str, Any] = {}
        human = q("SELECT count(*) t FROM alert WHERE entity_id=? AND closed_by_type='human' AND closed_at IS NOT NULL", [eid])["t"][0]
        rep = q("""SELECT coalesce(sum(n),0) r FROM (SELECT count(*) n FROM alert a JOIN closure c
                   ON a.entity_id=c.entity_id AND a.alert_id=c.ref_id
                   WHERE a.entity_id=? AND a.closed_by_type='human' AND a.closed_at IS NOT NULL
                   GROUP BY c.comment_norm_hash HAVING count(*) >= ?)""",
                [eid, int(PARAMS["EG04"]["min_hash_group_size"])])["r"][0]
        s["EG04"] = rep / max(human, 1) if rep else 0.0

        vol = q("SELECT count(*) n, count(DISTINCT asset_id) a, count(DISTINCT rule_id) r FROM alert WHERE entity_id=?", [eid])
        n, space = int(vol["n"][0]), int(vol["a"][0]) * int(vol["r"][0])
        base = int(PARAMS["EG05"]["min_repeat_count"])
        k = max(base, chance_repeat_floor(n, space, float(PARAMS["EG05"]["max_chance_pairs"]), cap=CHANCE_FLOOR_CAP_FACTOR * base))
        s["EG05"] = int(q("""SELECT count(*) c FROM (SELECT asset_id, rule_id FROM alert WHERE entity_id=?
                   GROUP BY asset_id, rule_id
                   HAVING count(*) >= ? AND count(CASE WHEN disposition IN ('false_positive','benign') THEN 1 END) = count(*)) p
                   WHERE NOT EXISTS (SELECT 1 FROM remediation m WHERE m.entity_id=? AND m.linked_asset_id=p.asset_id
                                     AND m.linked_rule_id=p.rule_id)""", [eid, k, eid])["c"][0])

        s["EG07"] = int(q("""SELECT coalesce(max(c),0) m FROM (SELECT count(*) c FROM alert WHERE entity_id=?
                   AND closed_by_type='human' AND closed_at IS NOT NULL GROUP BY closed_by, date_trunc('hour', closed_at))""",
                          [eid])["m"][0])

        ns05 = q("""SELECT r.rule_id, count(a.alert_id) f FROM detection_rule r LEFT JOIN alert a
                    ON r.entity_id=a.entity_id AND r.rule_id=a.rule_id WHERE r.entity_id=? AND r.enabled=true GROUP BY r.rule_id""", [eid])
        dormant = int((ns05["f"] == 0).sum()) if not ns05.is_empty() else 0
        s["NS05"] = (dormant / max(ns05.shape[0], 1), dormant)

        s["NS08"] = (int(q("SELECT count(DISTINCT strftime(created_at, '%Y-%m')) m FROM alert WHERE entity_id=?", [eid])["m"][0]),
                     int(portfolio_months))

        peers, _label, _weak = resolver.resolve_peers(e, ents)
        peers = peers or [x.entity_id for x in ents if x.entity_id != eid]  # BaseRule.peer_filter's fallback
        rate, total = fp_rates.get(eid, (0.0, 0))
        peer_rates = [fp_rates[p][0] for p in peers if p in fp_rates and fp_rates[p][1] >= int(PARAMS["EG11"]["min_alert_volume"])]
        tp = q("SELECT count(*) c FROM alert WHERE entity_id=? AND disposition='true_positive'", [eid])["c"][0]
        s["EG11"] = {"fp_rate": rate, "total": total, "tp": tp, "peer_rates": peer_rates}
        out[eid] = s
    return out


def flags(rule: str, stat: Any, value: float) -> bool:
    if rule == "EG04":
        return stat > value
    if rule == "EG05":
        return stat >= value
    if rule == "EG07":
        return stat >= value
    if rule == "NS05":
        share, count = stat
        return share > value and count >= int(PARAMS["NS05"]["min_dormant_rules"])
    if rule == "NS08":
        own, portfolio = stat
        return own < min(int(value), portfolio)
    if rule == "EG11":
        p = PARAMS["EG11"]
        if stat["total"] < int(p["min_alert_volume"]):
            return False
        if stat["tp"] == 0:
            return True
        z = _robust_z(stat["fp_rate"], stat["peer_rates"], value)
        return z[0] >= float(p["max_robust_z"]) if z else stat["fp_rate"] > float(p["max_fp_rate"])
    raise KeyError(rule)


def scalar(rule: str, stat: Any) -> float | None:
    if rule in ("EG04", "EG05", "EG07"):
        return float(stat)
    if rule == "NS05":
        return float(stat[0])
    if rule == "NS08":
        return float(stat[0])
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--start-seed", type=int, default=1)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    counts: dict[tuple[str, str], dict[float, dict[str, int]]] = {
        key: {v: defaultdict(int) for v in sorted(set(vals) | {float(PARAMS[key[0]][key[1]])})} for key, vals in CANDIDATES.items()}
    values: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    eg11_detail: list[dict[str, Any]] = []
    eg11_defects: list[dict[str, Any]] = []
    for seed in range(args.start_seed, args.start_seed + args.seeds):
        with tempfile.TemporaryDirectory(prefix="satsa-probe-") as tmp:
            gen = IndependentScenarioGenerator(seed)
            csv_dir, gt_path = gen.save(Path(tmp) / "gen")
            gt = json.loads(gt_path.read_text(encoding="utf-8"))
            duck = DuckDBStore(Path(tmp) / "store")
            sql = SQLiteStore(Path(tmp) / "store" / "probe.db")
            try:
                IngestionPipeline(duck, sql).ingest_directory(csv_dir)
                duck.load_all_tables()
                stats = entity_stats(duck)
            finally:
                duck.close()
                sql.close()
        defects = {(d["entity_id"], d["rule_id"]) for d in gt["defects"]}
        chance = {x["entity_id"] for x in gt["relabelled"] if x["rule_id"] == "EG11"}
        for eid, rule in sorted(defects):
            if rule == "EG11":
                st = stats[eid]["EG11"]
                z = _robust_z(st["fp_rate"], st["peer_rates"], float(PARAMS["EG11"]["min_spread"]))
                eg11_defects.append({
                    "seed": seed, "entity_id": eid, "kind": "met by chance" if eid in chance else "built",
                    "true_positives": st["tp"], "fp_rate": round(st["fp_rate"], 4),
                    "peer_rates": [round(r, 3) for r in st["peer_rates"]],
                    "peer_mad": round(z[1], 4) if z else None, "robust_z": round(z[0], 2) if z else None,
                    "flagged": {f"{v:g}": flags("EG11", st, v) for v in CANDIDATES[("EG11", "min_spread")]}})
        decoys = {(d["entity_id"], d["rule_id"]) for d in gt["decoys"]}
        for (rule, param), by_value in counts.items():
            for eid, s in stats.items():
                label = "defect" if (eid, rule) in defects else "decoy" if (eid, rule) in decoys else "other"
                for v, c in by_value.items():
                    c[label] += 1
                    c[f"{label}_flagged"] += flags(rule, s[rule], v)
                x = scalar(rule, s[rule])
                if x is not None and param == next(p for r, p in CANDIDATES if r == rule):
                    values[rule][label].append(x)
                if rule == "EG11" and label != "defect" and flags(rule, s[rule], float(PARAMS["EG11"]["min_spread"])):
                    st = s[rule]
                    z = _robust_z(st["fp_rate"], st["peer_rates"], float(PARAMS["EG11"]["min_spread"]))
                    eg11_detail.append({"seed": seed, "entity_id": eid, "label": label, "fp_rate": round(st["fp_rate"], 4),
                                        "peer_rates": [round(r, 4) for r in st["peer_rates"]],
                                        "robust_z": round(z[0], 2) if z else None, "peer_mad": round(z[1], 4) if z else None})
        print(f"seed {seed}: done", file=sys.stderr)

    print(f"# Threshold probe, seeds {args.start_seed}..{args.start_seed + args.seeds - 1}\n")
    for (rule, param), by_value in counts.items():
        current = float(PARAMS[rule][param])
        print(f"## {rule} {param} (current {current:g})\n")
        if rule in values:
            for label in ("defect", "decoy", "other"):
                xs = values[rule][label]
                if xs:
                    print(f"- {label}: n={len(xs)} min={min(xs):.3f} median={statistics.median(xs):.3f} max={max(xs):.3f}")
            print()
        print("| value | defects flagged | decoys flagged | other entities flagged |")
        print("|---|---|---|---|")
        for v, c in by_value.items():
            mark = " (current)" if v == current else ""
            print(f"| {v:g}{mark} | {c['defect_flagged']}/{c['defect']} | {c['decoy_flagged']}/{c['decoy']} | {c['other_flagged']}/{c['other']} |")
        print()
    print("## EG11 ground-truth defects, one per line\n")
    print("| Seed | Entity | Kind | True positives | FP rate | Peer rates | Peer MAD | Robust z | Flagged at min_spread |")
    print("|---:|---|---|---:|---:|---|---:|---:|---|")
    for d in eg11_defects:
        fl = ", ".join(f"{k}: {'yes' if v else 'no'}" for k, v in d["flagged"].items())
        print(f"| {d['seed']} | {d['entity_id']} | {d['kind']} | {d['true_positives']} | {d['fp_rate']:.4f} | "
              f"{d['peer_rates']} | {d['peer_mad']} | {d['robust_z']} | {fl} |")
    print()
    if eg11_detail:
        print("## EG11 flags on entities that are not EG11 defects (current min_spread)\n")
        for d in eg11_detail:
            print(f"- {d}")
    if args.json:
        payload = {"seeds": [args.start_seed, args.start_seed + args.seeds - 1],
                   "counts": {f"{r}.{p}": {str(v): dict(c) for v, c in bv.items()} for (r, p), bv in counts.items()},
                   "values": {r: dict(v) for r, v in values.items()}, "eg11_defects": eg11_defects,
                   "eg11_non_defect_flags": eg11_detail}
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
