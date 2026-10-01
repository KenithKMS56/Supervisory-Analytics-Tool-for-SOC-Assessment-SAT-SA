"""Golden test: ingest and assessment produce exactly the committed snapshot.

The snapshot (tests/golden/golden_findings.json) was produced by the ingest path as it was
BEFORE the Phase 5 performance work, so any optimisation of ingest must leave every stored
row, every DQ issue, every finding and every score unchanged. Four scenarios cover the paths
ingest has:

- `primary`: the original generator (seed 42), ingested twice (the re-ingest/append path),
  then assessed.
- `independent`: the independent generator (seed 7): free-text closure comments (redaction,
  hashing, shingles), different column values and entity profiles.
- `splunk`, `thehive`: product exports through their source mappings (CSV and JSON).

What is compared, per scenario:
- every canonical table, as row count plus SHA-256 of its rows sorted by all columns, read back
  from the store (so a change in Parquet layout is allowed, a change in content is not);
- DQ issues (entity, check, severity, count, and a hash of the details and samples);
- findings (entity, rule, level, severity, score, confidence, evidence count, and a hash of the
  text, peer comparison and evidence ids), entity scores, the review queue (per entity: size
  and a hash of every item) and systemic findings.

Run ids, batch ids and timestamps of the run itself are excluded; nothing else is.

To regenerate (only when a change to findings is intended, and say so in the commit):
    SATSA_UPDATE_GOLDEN=1 uv run pytest tests/test_golden_findings.py
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from satsa.ingest.mapper import SourceMapping
from satsa.ingest.pipeline import IngestionPipeline
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.synth.generator import SyntheticDataGenerator
from satsa.synth.independent import IndependentScenarioGenerator

GOLDEN = Path(__file__).resolve().parent / "golden" / "golden_findings.json"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "connectors"
MAPPINGS = Path("config/mappings")
SALT = b"satsa-golden-test-fixed-salt-32b"  # fixed, so pseudonyms are reproducible
TABLES = (
    "entity", "alert", "closure", "workflow_event", "escalation", "case", "case_alert_link", "asset",
    "log_source_daily", "detection_rule", "remediation", "external_report", "declared_kpi", "sla_policy",
)  # fmt: skip


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:16]


class Workspace:
    def __init__(self, root: Path):
        root.mkdir(parents=True)
        (root / "salt").write_bytes(SALT)
        self.duck = DuckDBStore(root / "pq")
        self.sql = SQLiteStore(root / "satsa.db")
        self.pipeline = IngestionPipeline(self.duck, self.sql, salt_file=root / "salt")

    def assess(self) -> None:
        run = AssessmentRunner(self.duck, self.sql).run_assessment(period="GOLDEN", actor="test")
        assert run["status"] == "success", run

    def snapshot(self) -> dict[str, Any]:
        self.duck.load_all_tables()
        tables = {}
        for table in TABLES:
            frame = self.duck.query(f'SELECT * FROM "{table}" ORDER BY ALL')
            tables[table] = {"rows": frame.height, "sha256": hashlib.sha256(frame.write_csv().encode()).hexdigest()}
        q = self.sql.conn.execute
        dq = sorted(
            [r["entity_id"], r["check_name"], r["severity"], r["count"], _sha([r["details"], r["sample_records_json"]])]
            for r in q("SELECT * FROM dq_issues")
        )
        evidence: dict[str, list[list[str]]] = {}
        for r in q("SELECT finding_id, record_type, record_id, details_json FROM finding_evidences"):
            evidence.setdefault(r["finding_id"], []).append([r["record_type"], r["record_id"], r["details_json"]])
        findings = sorted(
            [
                r["entity_id"], r["rule_id"], r["level"], r["severity"], round(r["score"], 9),
                round(r["confidence"], 9), len(evidence.get(r["finding_id"], [])),
                _sha([r["title"], r["rationale"], r["peer_comparison_json"], r["limitations"],
                      r["benign_explanations_json"], r["examiner_check"], sorted(evidence.get(r["finding_id"], []))]),
            ]
            for r in q("SELECT * FROM findings")
        )
        scores = sorted(
            [r["entity_id"], round(r["risk_index"], 9), r["risk_band"], r["distinct_rules_triggered"]]
            for r in q("SELECT * FROM entity_scores")
        )
        queue: dict[str, list[Any]] = {}
        for r in q("SELECT * FROM review_queue ORDER BY entity_id, record_type, record_id"):
            queue.setdefault(r["entity_id"], []).append(
                [r["record_type"], r["record_id"], r["severity"], r["score"], r["is_random"], r["selection_reason"]]
            )
        queue_summary = {entity: [len(items), _sha(items)] for entity, items in sorted(queue.items())}
        run_ids = [r[0] for r in q("SELECT run_id FROM runs")]
        systemic = sorted(
            _sha({k: v for k, v in f.items() if k not in ("run_id", "created_at", "finding_id", "systemic_id")})
            for run_id in run_ids
            for f in self.sql.get_systemic_findings(run_id)
        )
        return {
            "tables": tables, "dq_issues": dq, "findings": findings, "entity_scores": scores,
            "review_queue": queue_summary, "systemic": systemic,
        }  # fmt: skip

    def close(self) -> None:
        self.duck.close()
        self.sql.close()


def _primary(root: Path) -> dict[str, Any]:
    csv_dir, _ = SyntheticDataGenerator(seed=42, base_alerts_per_entity=1500).save_dataset(root / "generated")
    ws = Workspace(root / "ws")
    for _ in range(2):  # the second ingest exercises the append/de-duplication path
        assert ws.pipeline.ingest_directory(Path(csv_dir))["status"] == "success"
    ws.assess()
    try:
        return ws.snapshot()
    finally:
        ws.close()


def _independent(root: Path) -> dict[str, Any]:
    csv_dir, _ = IndependentScenarioGenerator(seed=7).save(root / "independent")
    ws = Workspace(root / "ws")
    assert ws.pipeline.ingest_directory(csv_dir)["status"] == "success"
    ws.assess()
    try:
        return ws.snapshot()
    finally:
        ws.close()


def _connector(source: str, entity_id: str):
    def build(root: Path) -> dict[str, Any]:
        ws = Workspace(root / "ws")
        mapping = SourceMapping(MAPPINGS / f"cse_{source}.yaml")
        result = ws.pipeline.ingest_directory(FIXTURES / source, default_entity_id=entity_id, mapping=mapping)
        assert result["status"] == "success", result
        ws.assess()
        try:
            return ws.snapshot()
        finally:
            ws.close()

    return build


SCENARIOS = {
    "primary": _primary,
    "independent": _independent,
    "splunk": _connector("splunk", "CSE-SPL"),
    "thehive": _connector("thehive", "CSE-HIVE"),
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_ingest_and_assessment_match_the_golden_snapshot(name, tmp_path):
    actual = SCENARIOS[name](tmp_path)
    golden = json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}
    if os.environ.get("SATSA_UPDATE_GOLDEN") == "1":
        golden[name] = json.loads(json.dumps(actual))
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(golden, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        pytest.skip(f"golden snapshot for {name!r} written")
    assert name in golden, f"no golden snapshot for {name!r}; see the module docstring"
    expected = golden[name]
    actual = json.loads(json.dumps(actual))  # the same JSON round trip the snapshot went through
    for section in ("tables", "dq_issues", "findings", "entity_scores", "review_queue", "systemic"):
        assert actual[section] == expected[section], f"{name}: {section} differ from the golden snapshot"


def test_the_golden_snapshot_is_not_trivial():
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert set(golden) == set(SCENARIOS)
    assert len(golden["primary"]["findings"]) >= 20
    assert len(golden["independent"]["findings"]) >= 20
    assert golden["primary"]["tables"]["alert"]["rows"] > 10_000
    assert any(t["rows"] for t in golden["splunk"]["tables"].values())
    assert any(t["rows"] for t in golden["thehive"]["tables"].values())


def test_findings_do_not_depend_on_the_order_of_submitted_rows(tmp_path):
    """The same submission with every file's rows shuffled gives the same findings, evidence,
    scores and queue. (Evidence samples used to be the first rows of an unordered query, so
    they changed with storage order, e.g. after a re-ingest.)"""
    import csv
    import random

    csv_dir, _ = SyntheticDataGenerator(seed=42, base_alerts_per_entity=600).save_dataset(tmp_path / "generated")
    shuffled = tmp_path / "shuffled"
    shuffled.mkdir()
    rng = random.Random(2026)
    for path in sorted(Path(csv_dir).glob("*.csv")):
        with open(path, encoding="utf-8", newline="") as fh:
            rows = list(csv.reader(fh))
        body = rows[1:]
        rng.shuffle(body)
        with open(shuffled / path.name, "w", encoding="utf-8", newline="") as fh:
            csv.writer(fh).writerows([rows[0], *body])
    snapshots = []
    for name, source in (("original", Path(csv_dir)), ("shuffled", shuffled)):
        ws = Workspace(tmp_path / f"ws_{name}")
        assert ws.pipeline.ingest_directory(source)["status"] == "success"
        ws.assess()
        snapshots.append(ws.snapshot())
        ws.close()
    original, reordered = snapshots
    for section in ("tables", "findings", "entity_scores", "review_queue", "systemic"):
        assert original[section] == reordered[section], f"{section} depend on the order of submitted rows"
