"""The columnar ingest path gives exactly what the row-by-row path gives.

Two kinds of check:
- Each submission is ingested twice into fresh stores, once as shipped (columnar where it
  applies) and once with the columnar path switched off (row by row, the code that ran
  before). Every stored table, the ingest result and every DQ issue must be identical. The
  submissions are built to hit the edge cases: alias columns, header case and spacing,
  Python-only whitespace, raw closure comments with personal data, missing and invalid entity
  IDs, a default entity, empty columns.
- FrameDQ's checks are compared with DQValidator's on randomised frames.
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import polars as pl
import pytest

import satsa.ingest.pipeline as pipeline_module
from satsa.ingest.dq_checks import DQValidator, FrameDQ
from satsa.ingest.pipeline import IngestionPipeline
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

TABLES = (
    "entity", "alert", "closure", "workflow_event", "escalation", "case", "case_alert_link", "asset",
    "log_source_daily", "detection_rule", "remediation", "external_report", "declared_kpi", "sla_policy",
)  # fmt: skip
ODD_SPACE = ["", " ", "\t", "\x1c", " "]  # \x1c is whitespace to Python's str.strip() only


def _write(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def _ingest(root: Path, csv_dir: Path, default_entity: str | None, columnar: bool, monkeypatch) -> dict[str, Any]:
    used: list[str] = []
    if columnar:
        original = pipeline_module.normalise_frame

        def spy(frame, table, *args, **kwargs):
            done = original(frame, table, *args, **kwargs)
            if done is not None:
                used.append(table)
            return done

        monkeypatch.setattr(pipeline_module, "normalise_frame", spy)
    else:
        monkeypatch.setattr(pipeline_module, "normalise_frame", lambda *a, **k: None)
    root.mkdir()
    (root / "salt").write_bytes(b"columnar-equivalence-test-salt!!")
    duck, sql = DuckDBStore(root / "pq"), SQLiteStore(root / "satsa.db")
    try:
        result = IngestionPipeline(duck, sql, salt_file=root / "salt").ingest_directory(
            csv_dir, default_entity_id=default_entity
        )
        result.pop("batch_id", None)
        duck.load_all_tables()
        tables = {t: duck.query(f'SELECT * FROM "{t}" ORDER BY ALL').to_dicts() for t in TABLES}
        dq = sorted(
            (r["entity_id"], r["check_name"], r["severity"], r["count"], r["sample_records_json"], r["details"])
            for r in sql.conn.execute("SELECT * FROM dq_issues")
        )
        return {"result": result, "tables": tables, "dq": dq, "columnar_tables": sorted(used)}
    finally:
        duck.close()
        sql.close()
        monkeypatch.undo()


def _assert_same(tmp_path: Path, csv_dir: Path, monkeypatch, default_entity: str | None = None) -> dict[str, Any]:
    fast = _ingest(tmp_path / "columnar", csv_dir, default_entity, True, monkeypatch)
    slow = _ingest(tmp_path / "rows", csv_dir, default_entity, False, monkeypatch)
    assert fast["result"] == slow["result"]
    for table in TABLES:
        assert fast["tables"][table] == slow["tables"][table], f"{table} differs"
    assert fast["dq"] == slow["dq"]
    return fast


def _messy_submission(directory: Path, seed: int) -> None:
    """A small submission with every kind of irregularity the columnar path must reproduce."""
    rng = random.Random(seed)
    directory.mkdir()
    entities = ["CSE-A", "CSE-B", "cse.c_1"]
    bad = ["bad id!", "..x", "-lead", "x" * 70]

    def entity() -> str:
        roll = rng.random()
        if roll < 0.06:
            return rng.choice(ODD_SPACE)
        if roll < 0.10:
            return rng.choice(bad)
        return rng.choice(entities)

    def blank_or(value: str) -> str:
        return rng.choice(ODD_SPACE) if rng.random() < 0.15 else value

    start = datetime(2026, 4, 1)
    # Header case and spacing vary; `severity` stands in for severity_final; `owner` for closed_by.
    alert_header = [" Entity_ID", "ALERT_ID", "rule_id", "category", "severity", "asset_id", "created_at",
                    "closed_at", "Owner", "closed_by_type", "disposition", "status", "free_text_note"]  # fmt: skip
    alerts, alert_ids = [], []
    for i in range(400):
        aid = blank_or(f"AL-{i * rng.choice([1, 1, 1, 60]):05d}")
        alert_ids.append(aid)
        created = start + timedelta(minutes=rng.randint(0, 200_000))
        alerts.append([
            entity(), aid, blank_or(f"R{rng.randint(1, 9)}"), rng.choice(["Malware", "Phishing", ""]),
            blank_or(rng.choice(["High", "crit", "P3", "low", "weird"])), blank_or(f"H{rng.randint(1, 30)}"),
            created.isoformat(), (created + timedelta(minutes=rng.randint(-5, 300))).isoformat(),
            blank_or(rng.choice(["alice@example.org", "Bob", "carol"])),
            rng.choice(["human", "automation", "", " "]), blank_or(rng.choice(["FP", "true positive", "benign"])),
            blank_or(rng.choice(["Closed", "open", "resolved"])), "should be dropped",
        ])  # fmt: skip
    _write(directory / "alerts.csv", alert_header, alerts)
    closures = [
        [entity(), rng.choice(alert_ids + ["ORPHAN-1"]), rng.choice(["benign", "false_positive"]),
         rng.choice(["", "", "Checked host 10.0.0.5, mailed john.doe@corp.in", "fp " * rng.randint(1, 30), "\x1c"])]
        for _ in range(300)
    ]  # fmt: skip
    _write(directory / "closure.csv", ["entity_id", "ref_id", "disposition", "comment"], closures)
    events = [
        [entity(), rng.choice(["alert", "case", ""]), rng.choice(alert_ids), start.isoformat(),
         blank_or(rng.choice(["dave", "erin"])), rng.choice(["triage", "investigate"])]
        for _ in range(300)
    ]  # fmt: skip
    _write(directory / "workflow_event.csv", ["entity_id", "ref_type", "ref_id", "ts", "actor", "action"], events)
    _write(
        directory / "case.csv",
        ["entity_id", "case_id", "severity", "status", "owner", "opened_at"],
        [[entity(), f"C-{i}", "high", "open", blank_or("frank"), start.isoformat()] for i in range(20)],
    )
    _write(
        directory / "case_alert_link.csv",
        ["entity_id", "case_id", "alert_id"],
        [[entity(), f"C-{rng.randint(0, 25)}", rng.choice(alert_ids)] for _ in range(30)],
    )
    _write(
        directory / "asset.csv",
        ["entity_id", "hostname", "asset_type", "criticality", "monitored_flag"],
        [[rng.choice(entities), f"H{i}", "server", rng.randint(1, 4), rng.choice(["true", "false"])] for i in range(25)],
    )
    _write(
        directory / "entity.csv",
        ["entity_id", "name", "sector", "size_band", "soc_model"],
        [["CSE-A", "Alpha Power", "power", "large", "inhouse"], ["CSE-B", " ", "", "small", "mssp"]],
    )


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_messy_submission_is_stored_identically(tmp_path, monkeypatch, seed):
    _messy_submission(tmp_path / "csv", seed)
    stored = _assert_same(tmp_path, tmp_path / "csv", monkeypatch)
    assert stored["columnar_tables"] == sorted(
        ["alert", "asset", "case", "case_alert_link", "closure", "entity", "workflow_event"]
    )  # the columnar path really ran on every file
    assert stored["tables"]["alert"] and stored["tables"]["closure"]
    assert any(c["comment_norm_hash"] for c in stored["tables"]["closure"])  # raw comments were redacted
    assert not any("john.doe" in str(v) for c in stored["tables"]["closure"] for v in c.values())


def test_default_entity_and_missing_entity_column(tmp_path, monkeypatch):
    csv_dir = tmp_path / "csv"
    csv_dir.mkdir()
    _write(
        csv_dir / "alerts.csv",
        ["id", "severity_final", "created_at", "analyst"],
        [[f"N-{i}", ["high", ""][i % 2], "2026-05-01T00:00:00", ["x", ""][i % 3 == 0]] for i in range(50)],
    )
    _write(csv_dir / "asset.csv", ["entity_id", "asset_id"], [["", "H1"], ["CSE-Z", "H2"], [" ", "H3"]])
    stored = _assert_same(tmp_path, csv_dir, monkeypatch, default_entity="CSE-DEF")
    assert stored["columnar_tables"] == ["alert", "asset"]


def test_rows_without_any_entity_are_counted_not_stored(tmp_path, monkeypatch):
    csv_dir = tmp_path / "csv"
    csv_dir.mkdir()
    _write(csv_dir / "alerts.csv", ["alert_id", "severity_final"], [["A1", "high"], ["A2", "low"]])
    _write(csv_dir / "asset.csv", ["entity_id", "asset_id"], [["CSE-Q", "H1"]])
    stored = _assert_same(tmp_path, csv_dir, monkeypatch)
    assert stored["result"]["unattributed_rows"] == {"alert": 2}


# ------------------------------------------------------------------ FrameDQ vs DQValidator


def _random_frame(rng: random.Random, n: int) -> pl.DataFrame:
    def alert_id(i: int) -> Any:
        return rng.choice([f"A-{i * rng.choice([1, 1, 70]):04d}", f"A-{rng.randint(0, 5)}", "", None, "x\n12", "id-٣٤"])

    start = datetime(2026, 1, 1)
    created = [start + timedelta(hours=rng.randint(0, 900)) if rng.random() > 0.1 else None for _ in range(n)]
    closed = [c + timedelta(hours=rng.randint(-3, 10)) if c and rng.random() > 0.1 else None for c in created]
    return pl.DataFrame(
        {
            "alert_id": [alert_id(i) for i in range(n)],
            "entity_id": [rng.choice(["E", "", None]) for _ in range(n)],
            "created_at": created,
            "closed_at": closed,
            "severity_final": [rng.choice(["high", "", None]) for _ in range(n)],
            "rule_id": [rng.choice(["R1", None, ""]) for _ in range(n)],
            "asset_id": [rng.choice(["H1", "H2", "H9", None, ""]) for _ in range(n)],
            "closed_by": [rng.choice(["a", None]) for _ in range(n)],
        },
        schema_overrides={"created_at": pl.Datetime("us"), "closed_at": pl.Datetime("us")},
    )


def _dump(issues: list) -> list[dict[str, Any]]:
    return [i.model_dump() for i in issues]


@pytest.mark.parametrize("seed", range(40))
def test_frame_dq_matches_the_dict_checks(seed):
    rng = random.Random(seed)
    frame = _random_frame(rng, rng.choice([0, 5, 30, 120]))
    rows = frame.to_dicts()
    fields = ["alert_id", "entity_id", "created_at", "severity_final", "not_a_column"]
    assert _dump(FrameDQ.check_required_fields(frame, fields, "E", "alert")) == _dump(
        DQValidator.check_required_fields(rows, fields, "E", "alert")
    )
    assert _dump(FrameDQ.check_timestamp_logic(frame, "E")) == _dump(DQValidator.check_timestamp_logic(rows, "E"))
    assert _dump(FrameDQ.check_duplicate_ids(frame, "alert_id", "E", "alert")) == _dump(
        DQValidator.check_duplicate_ids(rows, "alert_id", "E", "alert")
    )
    assert _dump(FrameDQ.check_id_sequence_gaps(frame, "alert_id", "E")) == _dump(
        DQValidator.check_id_sequence_gaps(rows, "alert_id", "E")
    )
    keys = ["rule_id", "asset_id", "closed_by", "missing"]
    assert _dump(FrameDQ.check_null_rates(frame, keys, "E", "alert")) == _dump(
        DQValidator.check_null_rates(rows, keys, "E", "alert")
    )
    parents = {"H1", "H2"}
    assert _dump(
        FrameDQ.check_orphan_references(frame, pl.Series(sorted(parents)), "asset_id", "E", "alert", "asset")
    ) == _dump(DQValidator.check_orphan_references(rows, parents, "asset_id", "E", "alert", "asset"))


def test_frame_dq_handles_non_text_columns_like_the_dict_checks():
    frame = pl.DataFrame({"alert_id": [1, 2, 2, 300, None], "asset_id": [1.0, 2.0, None, 3.0, 4.0]})
    rows = frame.to_dicts()
    assert _dump(FrameDQ.check_duplicate_ids(frame, "alert_id", "E", "alert")) == _dump(
        DQValidator.check_duplicate_ids(rows, "alert_id", "E", "alert")
    )
    assert _dump(FrameDQ.check_id_sequence_gaps(frame, "alert_id", "E")) == _dump(
        DQValidator.check_id_sequence_gaps(rows, "alert_id", "E")
    )
    assert _dump(FrameDQ.check_orphan_references(frame, pl.Series(["1.0"]), "asset_id", "E", "alert", "asset")) == _dump(
        DQValidator.check_orphan_references(rows, {"1.0"}, "asset_id", "E", "alert", "asset")
    )


@pytest.mark.parametrize("seed", range(10))
def test_usable_counts_match_the_per_column_count(seed):
    """_usable_counts (all columns in one pass) equals _usable_count column by column."""
    rng = random.Random(seed)
    pool = ["", " ", "Unknown", " NULL ", "none", "unmapped", "ok", "x", "	UnMapped", None, "null!", ""]
    n = rng.randint(0, 300)
    frame = pl.DataFrame(
        {
            "text": pl.Series([rng.choice(pool) for _ in range(n)], dtype=pl.String),
            "number": pl.Series([rng.choice([1, None, 0]) for _ in range(n)], dtype=pl.Int64),
            "empty": pl.Series([None] * n, dtype=pl.Null),
        }
    )
    columns = ["text", "number", "empty", "absent"]
    expected = {c: (pipeline_module._usable_count(frame[c]) if c in frame.columns else 0) for c in columns}
    assert pipeline_module._usable_counts(frame, columns) == expected
    blank = frame["text"].str.strip_chars().str.to_lowercase().is_in(list(pipeline_module._NO_VALUE))
    assert expected["text"] == int((frame["text"].is_not_null() & ~blank).sum())
