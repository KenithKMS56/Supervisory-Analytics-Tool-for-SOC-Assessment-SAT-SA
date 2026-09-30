"""Build the demo submission bundles that are uploaded by hand on the /upload page.

The synthetic 10-CSE portfolio (seed 42) is written as ZIP archives under demo_data/:

  SATSA_demo_full_submission.zip    the whole half-year in one upload
  staged/1_..., 2_..., 3_...        the same data cut into three consecutive submissions

Uploading the three staged bundles in order gives three assessment runs, which is what
the portfolio trend chart needs (an entity with fewer than two runs is not plotted).
After the third upload the stored data equals the full bundle.

One defect is added on top of the generator's own: CSE-06 closes a quarter of its alerts
with no investigation event and a trivial comment, so that EG02 fires too and every rule
in config/rules.yaml has a finding to show.

Usage:  python scripts/build_demo_upload_bundles.py [output_dir]
"""

from __future__ import annotations

import csv
import hashlib
import random
import sys
import tempfile
import zipfile
from io import StringIO
from pathlib import Path

from satsa.synth.generator import SyntheticDataGenerator

Rows = list[dict[str, str]]

STAGES = ("1_Jan-Feb_2026", "2_Mar-Apr_2026", "3_May-Jun_2026")
# Reference tables describe the entity, not a time window: every submission carries them whole.
REFERENCE_TABLES = ("entity", "asset", "detection_rule", "sla_policy", "declared_kpi")

EG02_ENTITY = "CSE-06"
EG02_SHARE = 0.25


def _read(path: Path) -> Rows:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _csv_text(rows: Rows, header: list[str]) -> str:
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def _stage_of(timestamp: str) -> int:
    """Two-month window a timestamp falls in (the data runs January to June)."""
    return min((int(timestamp[5:7]) - 1) // 2, len(STAGES) - 1)


def inject_eg02(tables: dict[str, Rows]) -> int:
    """CSE-06: a share of human closures lose their investigation step and get a trivial comment."""
    rng = random.Random(6)
    human = [
        a["alert_id"]
        for a in tables["alert"]
        if a["entity_id"] == EG02_ENTITY and a["closed_by_type"] == "human"
    ]
    picked = set(rng.sample(human, int(len(human) * EG02_SHARE)))
    tables["workflow_event"] = [
        w
        for w in tables["workflow_event"]
        if not (w["ref_type"] == "alert" and w["ref_id"] in picked and w["action"] == "investigate")
    ]
    for c in tables["closure"]:
        if c["entity_id"] == EG02_ENTITY and c["ref_id"] in picked:
            # Short, but each one different: this is missing investigation, not a template (EG04).
            c["comment_len"] = str(rng.randint(4, 20))
            c["comment_norm_hash"] = hashlib.sha256(c["ref_id"].encode()).hexdigest()[:16]
            c["comment_shingles"] = "ack,closed"
    return len(picked)


def assign_stages(tables: dict[str, Rows]) -> dict[str, list[int]]:
    """Stage of every row. Child records follow their alert or case, so no bundle has orphans
    beyond the ones the generator plants on purpose."""
    alert_stage = {a["alert_id"]: _stage_of(a["created_at"]) for a in tables["alert"]}
    case_stage = {
        link["case_id"]: alert_stage[link["alert_id"]]
        for link in tables["case_alert_link"]
        if link["alert_id"] in alert_stage
    }
    for c in tables["case"]:
        case_stage.setdefault(c["case_id"], _stage_of(c["opened_at"]))

    # Records whose alert was withheld (a planted defect) are dated by their own workflow trail.
    orphan_stage: dict[str, int] = {}
    for w in tables["workflow_event"]:
        if w["ref_type"] == "alert" and w["ref_id"] not in alert_stage:
            orphan_stage.setdefault(w["ref_id"], _stage_of(w["ts"]))

    def by_alert(ref_id: str) -> int:
        return alert_stage.get(ref_id, orphan_stage.get(ref_id, len(STAGES) - 1))

    def by_case(case_id: str) -> int:
        return case_stage.get(case_id, len(STAGES) - 1)

    return {
        "alert": [alert_stage[a["alert_id"]] for a in tables["alert"]],
        "closure": [by_alert(c["ref_id"]) for c in tables["closure"]],
        "escalation": [by_alert(e["ref_id"]) for e in tables["escalation"]],
        "workflow_event": [
            by_case(w["ref_id"]) if w["ref_type"] == "case" else by_alert(w["ref_id"])
            for w in tables["workflow_event"]
        ],
        "case": [by_case(c["case_id"]) for c in tables["case"]],
        "case_alert_link": [by_case(link["case_id"]) for link in tables["case_alert_link"]],
        "external_report": [
            case_stage.get(r["incident_id"], _stage_of(r["reported_at"])) for r in tables["external_report"]
        ],
        "remediation": [_stage_of(r["created_at"]) for r in tables["remediation"]],
        "log_source_daily": [_stage_of(r["date"]) for r in tables["log_source_daily"]],
    }


def _write_zip(path: Path, tables: dict[str, Rows], headers: dict[str, list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, rows in tables.items():
            z.writestr(f"{name}.csv", _csv_text(rows, headers[name]))


def build(out_dir: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        csv_dir, _ = SyntheticDataGenerator(seed=42, base_alerts_per_entity=1500).save_dataset(Path(tmp))
        tables = {p.stem: _read(p) for p in sorted(csv_dir.glob("*.csv"))}
    headers = {name: list(rows[0].keys()) for name, rows in tables.items()}

    n_eg02 = inject_eg02(tables)
    stages = assign_stages(tables)

    _write_zip(out_dir / "SATSA_demo_full_submission.zip", tables, headers)
    for i, label in enumerate(STAGES):
        part = {
            name: rows if name in REFERENCE_TABLES else [r for r, s in zip(rows, stages[name], strict=True) if s == i]
            for name, rows in tables.items()
        }
        _write_zip(out_dir / "staged" / f"{label}.zip", part, headers)
        print(f"{label}: " + ", ".join(f"{n}={len(r)}" for n, r in part.items()))
    print(f"EG02 planted on {n_eg02} {EG02_ENTITY} alerts. Bundles written to {out_dir}")


if __name__ == "__main__":
    build(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("demo_data"))
