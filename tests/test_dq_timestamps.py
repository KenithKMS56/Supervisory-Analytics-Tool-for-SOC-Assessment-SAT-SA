"""The close_before_create check runs on text timestamps (M15).

Timestamps in a CSV or JSON submission arrive as text. The check used to compare only Python
datetimes, so for those submissions it never ran. It now reads text the way the store does
(DuckDB's `TRY_CAST(... AS TIMESTAMP)` in `DuckDBStore.load_table_from_parquet`), so the alerts
it reports are exactly the alerts the rules see as closed before they were created.

The check only reads: stored rows, findings and every other DQ issue are unchanged. That is
asserted here for single submissions and, for four whole scenarios, by
`tests/test_golden_findings.py`, whose snapshot was taken before this change.
"""

from __future__ import annotations

import csv
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import polars as pl
import pytest

import satsa.ingest.pipeline as pipeline_module
from satsa.ingest.dq_checks import DQValidator, FrameDQ, _read_like_the_store
from satsa.ingest.pipeline import IngestionPipeline
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

HEADER = ["entity_id", "alert_id", "rule_id", "severity_final", "created_at", "closed_at", "closed_by_type"]
# (alert_id, created_at, closed_at, closed before created as the store reads it)
ALERTS = [
    ("A-0001", "2026-04-02T10:00:00", "2026-04-02T11:00:00", False),
    ("A-0002", "2026-04-02T10:00:00", "2026-04-01T10:00:00", True),  # a day early
    ("A-0003", "2026-04-02 10:00:00", "2026-04-02 09:59:00", True),  # a minute early, space separator
    ("A-0004", "2026-04-02T10:00:00Z", "2026-04-02T09:00:00Z", True),
    ("A-0005", "2026-04-02T10:00:00", "yesterday", False),  # unreadable: NULL in the store, not compared
    ("A-0006", "", "2026-04-01T10:00:00", False),  # no created_at
    ("A-0007", "2026-04-02T10:00:00", "", False),  # still open
    ("A-0008", "2026-04-02T10:00:00", "2026-04-02T10:00:00", False),  # closed the same instant
    # The store drops a UTC offset rather than applying it (recorded in CHANGES as M16), so
    # this reads as 10:00 created, 05:00 closed. The check reports what the rules see.
    ("A-0009", "2026-04-02T10:00:00+05:30", "2026-04-02T05:00:00Z", True),
]


def _write_submission(directory: Path, fmt: str) -> None:
    directory.mkdir(parents=True)
    rows =[dict(zip(HEADER, ["CSE-TS", aid, "R1", "high", c, d, "human"], strict=True)) for aid, c, d, _ in ALERTS]
    if fmt == "csv":
        with open(directory / "alert.csv", "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=HEADER)
            writer.writeheader()
            writer.writerows(rows)
    elif fmt == "json":
        (directory / "alert.json").write_text(json.dumps(rows), encoding="utf-8")
    else:
        (directory / "alert.json").write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")


def _ingest(root: Path, fmt: str, columnar: bool, monkeypatch) -> dict[str, Any]:
    if not columnar:
        monkeypatch.setattr(pipeline_module, "normalise_frame", lambda *a, **k: None)
    _write_submission(root / "in", fmt)
    (root / "salt").write_bytes(b"dq-timestamp-test-salt-32-bytes!")
    duck, sql = DuckDBStore(root / "pq"), SQLiteStore(root / "satsa.db")
    try:
        IngestionPipeline(duck, sql, salt_file=root / "salt").ingest_directory(root / "in")
        duck.load_all_tables()
        return {
            "stored": duck.query('SELECT * FROM alert ORDER BY ALL').to_dicts(),
            "closed_early": duck.query(
                "SELECT alert_id FROM alert WHERE closed_at < created_at ORDER BY alert_id"
            )["alert_id"].to_list(),
            "dq": {
                r["check_name"]: (r["count"], json.loads(r["sample_records_json"]), r["details"])
                for r in sql.conn.execute("SELECT * FROM dq_issues")
            },
        }
    finally:
        duck.close()
        sql.close()
        monkeypatch.undo()


@pytest.mark.parametrize(
    "fmt,columnar", [("csv", True), ("csv", False), ("json", False), ("ndjson", False)]
)
def test_text_timestamps_closed_before_creation_are_reported(tmp_path, monkeypatch, fmt, columnar):
    got = _ingest(tmp_path, fmt, columnar, monkeypatch)
    expected = [aid for aid, _, _, early in ALERTS if early]
    # The check and the store agree, alert for alert.
    assert got["closed_early"] == expected
    count, samples, details = got["dq"]["close_before_create"]
    assert count == len(expected)
    assert samples == expected  # first five in submission order; there are four
    assert details == f"{len(expected)} records exhibit close timestamp preceding create timestamp."


def test_the_fix_changes_no_stored_row_and_no_other_dq_issue(tmp_path, monkeypatch):
    """Ingest with the check as it was before (datetimes only) and as it is now: the stored
    alerts and every DQ issue other than close_before_create are identical."""
    now = _ingest(tmp_path / "now", "csv", True, monkeypatch)

    def datetimes_only(frame: pl.DataFrame, entity_id: str) -> list:
        rows = frame.select([c for c in ("created_at", "closed_at", "alert_id") if c in frame.columns]).to_dicts()
        return DQValidator.check_timestamp_logic(
            [r for r in rows if not isinstance(r.get("created_at"), str) and not isinstance(r.get("closed_at"), str)],
            entity_id,
        )

    monkeypatch.setattr(pipeline_module.FrameDQ, "check_timestamp_logic", staticmethod(datetimes_only))
    before = _ingest(tmp_path / "before", "csv", True, monkeypatch)
    assert "close_before_create" not in before["dq"]  # M15 as it was
    assert now["stored"] == before["stored"]
    assert {k: v for k, v in now["dq"].items() if k != "close_before_create"} == before["dq"]


# ------------------------------------------------------------------ frame and dict checks agree

FORMATS = [
    lambda t: t.isoformat(),
    lambda t: t.strftime("%Y-%m-%d %H:%M:%S"),
    lambda t: t.isoformat() + "Z",
    lambda t: t.isoformat() + "+05:30",
    lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.%f"),
]


def _text_frame(rng: random.Random, n: int) -> pl.DataFrame:
    def text(t: datetime | None) -> str | None:
        if t is None or rng.random() < 0.05:
            return rng.choice([None, "", "not a time", "2026-13-45T99:00:00"])
        return rng.choice(FORMATS)(t)

    start = datetime(2026, 1, 1)
    created = [start + timedelta(minutes=rng.randint(0, 90_000)) if rng.random() > 0.1 else None for _ in range(n)]
    closed = [c + timedelta(minutes=rng.randint(-30, 600)) if c and rng.random() > 0.1 else None for c in created]
    return pl.DataFrame(
        {
            "alert_id": [rng.choice([f"A-{i}", None]) for i in range(n)],
            "created_at": [text(c) for c in created],
            "closed_at": [text(d) for d in closed],
        },
        schema={"alert_id": pl.String, "created_at": pl.String, "closed_at": pl.String},
    )


def _dump(issues: list) -> list[dict[str, Any]]:
    return [i.model_dump() for i in issues]


@pytest.mark.parametrize("seed", range(30))
def test_frame_and_dict_checks_agree_on_text_timestamps(seed):
    rng = random.Random(seed)
    frame = _text_frame(rng, rng.choice([0, 5, 40, 200]))
    snapshot = frame.clone()
    rows = frame.to_dicts()
    frame_issues = FrameDQ.check_timestamp_logic(frame, "E")
    assert _dump(frame_issues) == _dump(DQValidator.check_timestamp_logic(rows, "E"))
    assert frame.equals(snapshot) and rows == frame.to_dicts()  # nothing was rewritten


def test_text_against_a_naive_datetime_column_is_compared():
    frame = pl.DataFrame(
        {
            "alert_id": ["A-1", "A-2"],
            "created_at": ["2026-04-02T10:00:00", "2026-04-02T10:00:00"],
            "closed_at": [datetime(2026, 4, 2, 9), datetime(2026, 4, 2, 11)],
        }
    )
    issues = FrameDQ.check_timestamp_logic(frame, "E")
    assert [(i.count, i.sample_records) for i in issues] == [(1, ["A-1"])]
    assert _dump(issues) == _dump(DQValidator.check_timestamp_logic(frame.to_dicts(), "E"))


def test_text_against_a_zoned_datetime_is_not_compared():
    """The store would convert a zoned column by its session time zone; neither check guesses.

    (A zoned Polars column needs the IANA time-zone database, which a Windows Python may lack,
    so the frame check is shown through the dtype test it applies.)"""
    rows = [{"alert_id": "A-1", "created_at": "2026-04-02T10:00:00", "closed_at": datetime(2026, 4, 1, tzinfo=UTC)}]
    assert DQValidator.check_timestamp_logic(rows, "E") == []
    assert not _read_like_the_store(pl.Datetime("us", "UTC"))
    assert all(_read_like_the_store(t) for t in (pl.String, pl.Null, pl.Datetime("us"), pl.Datetime("ns")))
