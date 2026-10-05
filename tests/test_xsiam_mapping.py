"""Cortex XSIAM case export: recognised by its columns, translated by cse_cortex_xsiam.yaml.

The export below is synthetic, written to the 57 columns, encoding (Windows-1252), date form
("Oct 1st 2026 22:31:34") and quirks (multi-line descriptions, rows of empty cells, rows holding
only a pasted timer) of a real XSIAM case export. The real export is not committed: it names
people and a customer.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus

import pytest

from satsa.ingest.mapper import SourceMapping
from satsa.ingest.pipeline import IngestionPipeline, detect_source_mapping
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

MAPPINGS = Path("config/mappings")

HEADER = [
    "Last Updated", "Severity", "Score", "Case Name", "Status", "Assignee", "Critical Severity Issues",
    "High Severity Issues", "Medium Severity Issues", "Low Severity Issues", "Case ID", "Case Domain",
    "Legacy Status", "Resolution Reason", "Creation Time", "Predicted score", "Case Description", "Asset IDs",
    "Asset Groups", "Asset Names", "Asset Classes", "Asset Categories", "Asset Regions", "Asset Providers",
    "Asset Accounts", "Asset Types", "Business Application Names", "Asset Cloud Account Names",
    "Asset External Provider IDs", "Hosts Windows", "Hosts Linux", "Hosts Mac", "Hosts Android",
    "Hosts Unknown OS", "MITRE ATT&CK Tactic", "MITRE ATT&CK Technique", "Issue Categories", "WildFire Hits",
    "Total Issues", "Users", "Resolved Timestamp", "Resolution Comment", "Starred", "Case Detection Methods",
    "Issues Grouping Status", "Automated", "Last Issue Arrived At", "Tags", "Original Tags", "Assignee Email",
    "Cloud Case", "Resolution Timer", "Resolution SLA", "Case Team", "Access Mode", "Indicator IDs",
    "Investigation_time",
]  # fmt: skip


def _case(**values: str) -> list[str]:
    row = dict.fromkeys(HEADER, "")
    row.update(values)
    return [row[h] for h in HEADER]


def _export() -> bytes:
    rows = [
        HEADER,
        _case(**{
            "Case ID": "241806", "Severity": "Medium", "Status": "Resolved", "Assignee": "jane analyst",
            "Assignee Email": "jane.analyst@example.org", "Case Domain": "Security",
            "Resolution Reason": "Resolved - Known Issue", "Creation Time": "Oct 1st 2026 22:31:34",
            "Resolved Timestamp": "Oct 1st 2026 22:53:09", "Last Updated": "Oct 1st 2026 22:53:09",
            "Case Description": "Unusual traffic rate.\n        • Source IP: 10.1.2.3\n        • Host: café",
            "Resolution Comment": "Confirmed with the partner team: expected traffic.",
            "Resolution Timer": "{'total_duration': 1295, 'status': 'ended'}",
        }),
        _case(**{
            "Case ID": "241807", "Severity": "High", "Status": "Under Investigation", "Assignee": "ravi analyst",
            "Case Domain": "Security", "Creation Time": "Oct 2nd 2026 09:05:00",
        }),
        [""] * len(HEADER),  # row 4 (the description above is one row, however many lines)
        _case(Investigation_time="{'total_duration': 58, 'status': 'ended'}"),  # row 5: a pasted timer
        _case(**{
            "Case ID": "241808", "Severity": "Critical", "Status": "New", "Case Domain": "Security",
            "Creation Time": "Oct 3rd 2026 23:59:59",
        }),
    ]  # fmt: skip
    out = io.StringIO()
    csv.writer(out, lineterminator="\r\n").writerows(rows)
    return out.getvalue().encode("cp1252")


def _submission(directory: Path, name: str = "5_6192633458263600243.csv") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(_export())
    return directory


def test_the_mapping_loads():
    mapping = SourceMapping(MAPPINGS / "cse_cortex_xsiam.yaml")
    assert mapping.source == "cortex_xsiam" and mapping.entity_id is None


def test_an_xsiam_export_is_recognised_by_its_columns_whatever_its_name(tmp_path):
    mapping = detect_source_mapping(_submission(tmp_path / "in"), MAPPINGS)
    assert mapping is not None and mapping.source == "cortex_xsiam"


def test_canonical_and_mixed_submissions_are_not_taken_for_xsiam(tmp_path):
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    (canonical / "alert.csv").write_text(
        "entity_id,alert_id,created_at\nCSE-1,A-1,2026-01-01T00:00:00\n"
    )
    (canonical / "case.csv").write_text(
        "entity_id,case_id,opened_at\nCSE-1,C-1,2026-01-01T00:00:00\n"
    )
    assert detect_source_mapping(canonical, MAPPINGS) is None
    mixed = _submission(tmp_path / "mixed")
    (mixed / "alert.csv").write_text(
        "entity_id,alert_id,created_at\nCSE-1,A-1,2026-01-01T00:00:00\n"
    )
    assert detect_source_mapping(mixed, MAPPINGS) is None


@pytest.fixture
def ingested(tmp_path):
    src = _submission(tmp_path / "in")
    (tmp_path / "salt").write_bytes(b"xsiam-test-salt-32-bytes!!!!!!!!")
    duck, sql = DuckDBStore(tmp_path / "pq"), SQLiteStore(tmp_path / "s.db")
    try:
        mapping = detect_source_mapping(src, MAPPINGS)
        result = IngestionPipeline(duck, sql, salt_file=tmp_path / "salt").ingest_directory(
            src, default_entity_id="CSE-XS", mapping=mapping
        )
        duck.load_all_tables()
        cases = duck.query('SELECT * FROM "case" ORDER BY case_id').to_dicts()
        dq = {r["check_name"]: dict(r) for r in sql.conn.execute("SELECT * FROM dq_issues")}
    finally:
        duck.close()
        sql.close()
    return result, cases, dq, tmp_path


def test_cases_are_stored_in_utc_with_canonical_values(ingested):
    result, cases, _, _ = ingested
    assert result["status"] == "success"
    assert [c["case_id"] for c in cases] == ["241806", "241807", "241808"]  # text, not numbers
    first, second, third = cases
    # IST (+05:30, the mapping's utc_offset) to UTC.
    assert first["opened_at"] == datetime(2026, 10, 1, 17, 1, 34)
    assert first["closed_at"] == datetime(2026, 10, 1, 17, 23, 9)
    assert third["opened_at"] == datetime(2026, 10, 3, 18, 29, 59)
    assert [c["status"] for c in cases] == ["closed", "open", "open"]
    assert [c["severity"] for c in cases] == ["medium", "high", "critical"]
    assert first["owner"].startswith("OWNER_") and third["owner"] is None
    assert second["closed_at"] is None


def test_every_row_is_accounted_for(ingested):
    result, _, dq, _ = ingested
    (book,) = result["file_coverage"]
    assert book["rows_read"] == 4  # three cases and the pasted timer; the empty row is dropped
    assert book["stored"] == {"case": 3}
    assert book["rejected"] == {"missing case_id, opened_at for case": {"count": 1, "rows": "5"}}
    assert dq["rows_rejected"]["severity"] == "warning"
    unused = result["unused_source_columns"]["5_6192633458263600243.csv"]
    assert {
        "Resolution Reason",
        "Resolution Comment",
        "Investigation_time",
        "Assignee Email",
    } <= set(unused)


def test_nothing_personal_from_the_export_is_stored(ingested):
    _, _, _, root = ingested
    stored = b"".join(p.read_bytes() for p in (root / "pq").rglob("*.parquet"))
    for text in ("jane", "ravi", "example.org", "10.1.2.3", "partner team"):
        assert text.encode() not in stored


def test_an_upload_of_an_xsiam_export_without_a_target_entity_is_refused():
    from fastapi.testclient import TestClient

    from satsa.api.routes import app

    client = TestClient(app)
    login = client.post(
        "/login",
        data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
        follow_redirects=False,
    )
    assert login.status_code == 303
    r = client.post(
        "/upload", files={"files": ("cases.csv", _export(), "text/csv")}, follow_redirects=False
    )
    assert r.status_code == 303
    message = unquote_plus(r.headers["location"])
    assert "cortex_xsiam export" in message and "choose a target entity" in message
