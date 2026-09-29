"""Build a synthetic stand-in CSV for rehearsing `satsa validate --shadow-csv`.

The "examiner labels" come from the synthetic generator's ground truth
(data/generated/ground_truth.json), NOT from SAT-SA's own findings: labels
copied from the tool's findings would make rule recall 100% by construction.
This is a pipeline rehearsal, not independent evidence -- see
docs/validation.md Section 5A.

Usage:
    uv run python scripts/build_shadow_standin.py
"""

import csv
import json
import sqlite3
from pathlib import Path

from satsa.rules.registry import RuleRegistry

GROUND_TRUTH = Path("data/generated/ground_truth.json")
ALERTS_CSV = Path("data/generated/csv/alert.csv")
OUTPUT = Path("data/generated/shadow_pilot_standin.csv")
DB = Path("data/satsa.db")

MAX_ALERTS_PER_DEFECT = 5
CLEAN_ALERTS_PER_ENTITY = 5
RULE_IDS = sorted(cls.id for cls in RuleRegistry.RULE_CLASSES)


def is_alert_id(record_id: str) -> bool:
    return "-ALT-" in record_id


def build_rows(ground_truth: dict) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for defect in ground_truth["defects"]:
        ids = [str(i) for i in defect["affected_ids"]]
        alert_ids = sorted(i for i in ids if is_alert_id(i))[:MAX_ALERTS_PER_DEFECT]
        # Entity-level defects (KPI, asset, category or marker IDs) have no
        # alert to point at: one row carrying their first affected ID.
        for record_id in alert_ids or ids[:1]:
            rows.append(
                {
                    "entity_id": defect["entity_id"],
                    "record_id": record_id,
                    "rule_id": defect["rule_id"],
                    "label": "confirmed",
                }
            )

    # Clean entities cleared rule by rule: in the ground truth nothing was injected
    # there, so an examiner would find no issue for any rule. ShadowPilotAdapter
    # scores these rule-level rows for precision; a SAT-SA finding on one is a
    # false positive.
    clean = set(ground_truth["clean_entities"])
    for entity_id in sorted(clean):
        for rule_id in RULE_IDS:
            rows.append({"entity_id": entity_id, "record_id": "", "rule_id": rule_id, "label": "not_an_issue"})

    # Records from the clean entities cleared individually. These have no rule_id,
    # so they only feed the "cleared records still in the review queue" count.
    per_entity: dict[str, list[str]] = {e: [] for e in clean}
    with ALERTS_CSV.open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["entity_id"] in clean:
                per_entity[r["entity_id"]].append(r["alert_id"])
    for entity_id in sorted(clean):
        for alert_id in sorted(per_entity[entity_id])[:CLEAN_ALERTS_PER_ENTITY]:
            rows.append(
                {"entity_id": entity_id, "record_id": alert_id, "rule_id": "", "label": "not_an_issue"}
            )
    return rows


def latest_queue_records() -> tuple[str, set[tuple[str, str]]]:
    conn = sqlite3.connect(DB)
    try:
        run_id = conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()[0]
        records = {
            (e, r)
            for e, r in conn.execute(
                "SELECT entity_id, record_id FROM review_queue WHERE run_id = ?", (run_id,)
            )
        }
    finally:
        conn.close()
    return run_id, records


def main() -> None:
    ground_truth = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    rows = build_rows(ground_truth)
    with OUTPUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["entity_id", "record_id", "rule_id", "label"])
        writer.writeheader()
        writer.writerows(rows)

    confirmed = [r for r in rows if r["label"] == "confirmed"]
    run_id, queue = latest_queue_records()
    matched = [r for r in confirmed if (r["entity_id"], r["record_id"]) in queue]

    print(f"Wrote {len(rows)} rows to {OUTPUT}")
    print(f"  confirmed: {len(confirmed)}, not_an_issue: {len(rows) - len(confirmed)}")
    print(f"  latest run: {run_id} ({len(queue)} review-queue items)")
    print(f"  confirmed rows found in the review queue: {len(matched)}/{len(confirmed)}")
    for r in matched:
        print(f"    {r['entity_id']} {r['rule_id']}: {r['record_id']}")

    # The rows above cap each defect at a few IDs picked by sort order, so their
    # queue overlap depends on which IDs happen to be picked. Coverage over EVERY
    # affected ID (alerts, assets, categories, KPIs alike) is the figure that doesn't.
    print("  queue coverage of all affected IDs, per injected defect:")
    total = hits = 0
    for defect in ground_truth["defects"]:
        ids = [str(i) for i in defect["affected_ids"]]
        found = sum((defect["entity_id"], i) in queue for i in ids)
        total += len(ids)
        hits += found
        print(f"    {defect['entity_id']} {defect['rule_id']}: {found}/{len(ids)}")
    print(f"    all defects: {hits}/{total}")


if __name__ == "__main__":
    main()
