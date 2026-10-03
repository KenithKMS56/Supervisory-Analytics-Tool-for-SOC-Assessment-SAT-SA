"""Property tests for the ingest parser.

- Text timestamps: any date and time, written in any of the accepted ISO forms with any UTC
  offset, is stored as that instant in UTC.
- JSON: a submission as a JSON array and as NDJSON is read as the same records.
- CSV: the columnar path and the row-by-row path store the same rows and report the same DQ
  issues for generated alert files with odd headers, whitespace and entity IDs.
- Garbage: whatever bytes a submitted file holds, ingest returns a result and never raises; a
  file it cannot read is reported as unreadable.
"""

from __future__ import annotations

import csv
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import duckdb
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import satsa.ingest.pipeline as pipeline_module
from satsa.ingest.adapters import SourceAdapter
from satsa.ingest.pipeline import IngestionPipeline
from satsa.store.duckdb import DuckDBStore, text_timestamp_sql
from satsa.store.sqlite import SQLiteStore

SLOW = settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# ------------------------------------------------------------------ timestamps


@st.composite
def stamped(draw) -> tuple[str, datetime]:
    """(text, the UTC instant it denotes)."""
    moment = draw(st.datetimes(min_value=datetime(1971, 1, 1), max_value=datetime(2099, 12, 31)))
    offset_minutes = draw(st.integers(-14 * 60, 14 * 60))
    separator = draw(st.sampled_from(["T", " "]))
    fraction = draw(st.sampled_from(["none", "millis", "micros"]))
    text = moment.strftime(f"%Y-%m-%d{separator}%H:%M:%S")
    if fraction == "millis":
        moment = moment.replace(microsecond=moment.microsecond // 1000 * 1000)
        text += f".{moment.microsecond // 1000:03d}"
    elif fraction == "micros":
        text += f".{moment.microsecond:06d}"
    else:
        moment = moment.replace(microsecond=0)
    style = draw(st.sampled_from(["none", "Z", "colon", "compact", "hours"]))
    if style == "hours":
        offset_minutes -= offset_minutes % 60 if offset_minutes >= 0 else -((-offset_minutes) % 60)
    if style in ("none", "Z"):
        offset_minutes = 0
    sign = "+" if offset_minutes >= 0 else "-"
    hh, mm = divmod(abs(offset_minutes), 60)
    text += {"none": "", "Z": "Z", "colon": f"{sign}{hh:02d}:{mm:02d}", "compact": f"{sign}{hh:02d}{mm:02d}",
             "hours": f"{sign}{hh:02d}"}[style]  # fmt: skip
    return text, moment - timedelta(minutes=offset_minutes)


_CON = duckdb.connect()


@settings(max_examples=300, deadline=None)
@given(stamped())
def test_any_iso_timestamp_with_any_offset_is_stored_as_its_utc_instant(case):
    text, utc = case
    got = _CON.execute(f"SELECT {text_timestamp_sql('x')} FROM (SELECT CAST(? AS VARCHAR) AS x)", [text]).fetchone()
    assert got is not None and got[0] == utc, text


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=40))
def test_any_text_is_read_as_a_timestamp_or_as_empty_never_an_error(text):
    _CON.execute(f"SELECT {text_timestamp_sql('x')} FROM (SELECT CAST(? AS VARCHAR) AS x)", [text]).fetchone()


# ------------------------------------------------------------------ JSON

JSON_VALUES = st.one_of(
    st.none(), st.booleans(), st.integers(-(2**53), 2**53), st.text(max_size=20),
    st.floats(allow_nan=False, allow_infinity=False),
)  # fmt: skip
RECORDS = st.lists(
    st.dictionaries(st.sampled_from(["entity_id", "alert_id", "severity", "note", "count"]), JSON_VALUES, min_size=1),
    max_size=12,
)


@settings(max_examples=150, deadline=None)
@given(RECORDS)
def test_a_json_array_and_ndjson_are_read_as_the_same_records(records):
    with tempfile.TemporaryDirectory() as tmp:
        array, lines = Path(tmp) / "a.json", Path(tmp) / "b.ndjson"
        array.write_text(json.dumps(records), encoding="utf-8")
        lines.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
        assert SourceAdapter.read_json(array) == records
        assert SourceAdapter.read_json(lines) == records


# ------------------------------------------------------------------ CSV: columnar and row paths agree

ODD = ["", " ", "\t", "\x1c", " "]  # \x1c is whitespace to str.strip() only
ENTITY = st.one_of(st.sampled_from(["CSE-A", "CSE-B", "cse.c_1", " CSE-A ", "bad id!", "-x"]), st.sampled_from(ODD))
CELL = st.one_of(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=12), st.sampled_from(ODD))
SEVERITY = st.one_of(st.sampled_from(["High", "crit", "P3", "low", "weird", "CRITICAL"]), st.sampled_from(ODD))
HEADERS = st.tuples(
    st.sampled_from(["entity_id", " Entity_ID", "ENTITY_ID"]),
    st.sampled_from(["alert_id", "ALERT_ID"]),
    st.sampled_from(["severity", "severity_final", "Severity"]),
    st.sampled_from(["closed_by", "Owner"]),
)


@st.composite
def alert_csv(draw) -> tuple[list[str], list[list[str]]]:
    entity_h, alert_h, severity_h, closer_h = draw(HEADERS)
    header = [entity_h, alert_h, "rule_id", severity_h, "created_at", "closed_at", closer_h, "closed_by_type", "note"]
    start = datetime(2026, 4, 1)
    rows = []
    for i in range(draw(st.integers(1, 30))):
        created = start + timedelta(minutes=draw(st.integers(0, 50_000)))
        closed = created + timedelta(minutes=draw(st.integers(-10, 600)))
        rows.append([
            draw(ENTITY), draw(st.sampled_from([f"AL-{i:04d}", f"AL-{i % 3:04d}", ""])), draw(CELL), draw(SEVERITY),
            created.isoformat(), closed.isoformat(), draw(CELL), draw(st.sampled_from(["human", "automation", "", " "])),
            draw(CELL),
        ])  # fmt: skip
    return header, rows


def _ingest(root: Path, header: list[str], rows: list[list[str]], columnar: bool) -> dict[str, Any]:
    original = pipeline_module.normalise_frame
    used: list[str] = []

    def spy(frame, table, *args, **kwargs):
        done = original(frame, table, *args, **kwargs)
        if done is not None:
            used.append(table)
        return done

    pipeline_module.normalise_frame = spy if columnar else (lambda *a, **k: None)  # type: ignore[assignment]
    try:
        (root / "in").mkdir(parents=True)
        with open(root / "in" / "alert.csv", "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(header)
            writer.writerows(rows)
        (root / "salt").write_bytes(b"property-test-salt-32-bytes-long")
        duck, sql = DuckDBStore(root / "pq"), SQLiteStore(root / "satsa.db")
        try:
            result = IngestionPipeline(duck, sql, salt_file=root / "salt").ingest_directory(root / "in", "CSE-A")
            result.pop("batch_id", None)
            duck.load_all_tables()
            return {
                "columnar": used,
                "result": result,
                "alert": duck.query("SELECT * FROM alert ORDER BY ALL").to_dicts(),
                "dq": sorted(
                    (r["entity_id"], r["check_name"], r["count"], r["sample_records_json"], r["details"])
                    for r in sql.conn.execute("SELECT * FROM dq_issues")
                ),
            }
        finally:
            duck.close()
            sql.close()
    finally:
        pipeline_module.normalise_frame = original


@SLOW
@given(alert_csv())
def test_columnar_and_row_paths_store_the_same_alerts_and_issues(submission):
    header, rows = submission
    with tempfile.TemporaryDirectory() as tmp:
        fast = _ingest(Path(tmp) / "columnar", header, rows, columnar=True)
        slow = _ingest(Path(tmp) / "rows", header, rows, columnar=False)
    assert fast.pop("columnar") == ["alert"], "the columnar path did not run"
    assert slow.pop("columnar") == []
    assert fast == slow


# ------------------------------------------------------------------ garbage


@SLOW
@given(st.binary(max_size=400), st.sampled_from(["alert.csv", "closure.csv", "alert.json"]))
def test_any_bytes_in_a_submitted_file_give_a_result_not_a_crash(content, name):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "in").mkdir()
        (root / "in" / name).write_bytes(content)
        (root / "salt").write_bytes(b"property-test-salt-32-bytes-long")
        duck, sql = DuckDBStore(root / "pq"), SQLiteStore(root / "satsa.db")
        try:
            result = IngestionPipeline(duck, sql, salt_file=root / "salt").ingest_directory(root / "in", "CSE-A")
            checks = {r["check_name"] for r in sql.conn.execute("SELECT check_name FROM dq_issues")}
        finally:
            duck.close()
            sql.close()
    assert result["status"] in {"success", "partial", "error", "empty"}
    if name in result.get("unreadable_files", []):
        assert "file_unreadable" in checks  # reported, not dropped without trace
