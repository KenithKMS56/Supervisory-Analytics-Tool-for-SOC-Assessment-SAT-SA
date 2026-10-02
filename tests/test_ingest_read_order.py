"""Reading the largest CSV first changes when it is read, nothing else.

Ingest reads the largest CSV of a canonical submission before the others, so that the brief
memory a read needs is not added to the tables already held (it set the peak at 5,000,000
alerts; see docs/benchmarks.md). Files are still processed in their usual order. These tests
ingest the same submission with the early read on and off: the ingest result, every stored
table and every DQ issue must be identical, also when the largest file cannot be read.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import satsa.ingest.pipeline as pipeline_module
from satsa.ingest.adapters import SourceAdapter
from satsa.ingest.pipeline import IngestionPipeline
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

TABLES = ("entity", "alert", "closure", "workflow_event", "case", "asset")


def _write(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def _submission(directory: Path, broken_largest: bool) -> None:
    directory.mkdir(parents=True)
    start = datetime(2026, 4, 1)
    _write(
        directory / "asset.csv",
        ["entity_id", "asset_id", "hostname"],
        [["CSE-A", f"H{i}", f"host{i}"] for i in range(5)],
    )
    _write(
        directory / "case.csv",
        ["entity_id", "case_id", "severity", "status", "owner", "opened_at"],
        [["CSE-A", f"C-{i}", "high", "open", "frank", start.isoformat()] for i in range(3)],
    )
    _write(
        directory / "closure.csv",
        ["entity_id", "ref_id", "disposition", "comment"],
        [["CSE-A", f"AL-{i:05d}", "benign", "checked"] for i in range(0, 40, 2)],
    )
    # The largest file by far, and alphabetically neither first nor last.
    events = [
        ["CSE-A" if i % 7 else "CSE-B", "alert", f"AL-{i % 60:05d}", (start + timedelta(minutes=i)).isoformat(),
         "dave", "triage"]
        for i in range(3000)
    ]  # fmt: skip
    _write(directory / "workflow_event.csv", ["entity_id", "ref_type", "ref_id", "ts", "actor", "action"], events)
    if broken_largest:
        with open(directory / "workflow_event.csv", "a", encoding="utf-8") as fh:
            fh.write("CSE-A,alert,AL-00001,2026-04-01T00:00:00,dave,triage,one,too,many\n")
    alerts = [
        {"entity_id": "CSE-A", "alert_id": f"AL-{i:05d}", "rule_id": "R1", "severity_final": "high",
         "created_at": (start + timedelta(hours=i)).isoformat(),
         "closed_at": (start + timedelta(hours=i, minutes=30 if i % 9 else -5)).isoformat(),
         "closed_by_type": "human", "closed_by": "carol", "disposition": "benign", "asset_id": f"H{i % 6}"}
        for i in range(60)
    ]  # fmt: skip
    (directory / "alert.json").write_text(json.dumps(alerts), encoding="utf-8")


def _ingest(root: Path, early: bool, broken_largest: bool, monkeypatch) -> dict[str, Any]:
    monkeypatch.setattr(pipeline_module, "READ_LARGEST_FIRST", early)
    reads: list[str] = []
    original = SourceAdapter.read_csv_frame

    def spy(path):
        reads.append(Path(path).name)
        return original(path)

    monkeypatch.setattr(SourceAdapter, "read_csv_frame", staticmethod(spy))
    _submission(root / "in", broken_largest)
    (root / "salt").write_bytes(b"read-order-test-salt-32-bytes!!!")
    duck, sql = DuckDBStore(root / "pq"), SQLiteStore(root / "satsa.db")
    try:
        result = IngestionPipeline(duck, sql, salt_file=root / "salt").ingest_directory(root / "in")
        result.pop("batch_id", None)
        duck.load_all_tables()
        return {
            "result": result,
            "reads": reads,
            "tables": {t: duck.query(f'SELECT * FROM "{t}" ORDER BY ALL').to_dicts() for t in TABLES},
            "dq": sorted(
                (r["entity_id"], r["check_name"], r["severity"], r["count"], r["sample_records_json"], r["details"])
                for r in sql.conn.execute("SELECT * FROM dq_issues")
            ),
        }
    finally:
        duck.close()
        sql.close()
        monkeypatch.undo()


@pytest.mark.parametrize("broken_largest", [False, True])
def test_reading_the_largest_csv_first_changes_nothing_else(tmp_path, monkeypatch, broken_largest):
    early = _ingest(tmp_path / "early", True, broken_largest, monkeypatch)
    plain = _ingest(tmp_path / "plain", False, broken_largest, monkeypatch)
    assert early["reads"][0] == "workflow_event.csv"
    assert plain["reads"][0] != "workflow_event.csv"
    assert sorted(early["reads"]) == sorted(plain["reads"])  # each file read once either way
    assert early["result"] == plain["result"]
    assert early["tables"] == plain["tables"]
    assert early["dq"] == plain["dq"]
    if broken_largest:
        assert early["result"]["unreadable_files"] == ["workflow_event.csv"]
        assert not early["tables"]["workflow_event"]
        assert any(check == "file_unreadable" for _, check, *_ in early["dq"])
    else:
        assert len(early["tables"]["workflow_event"]) == 3000
