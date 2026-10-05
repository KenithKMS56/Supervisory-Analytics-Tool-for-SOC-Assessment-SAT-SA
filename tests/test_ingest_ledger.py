"""Every submitted file and row is accounted for: stored, left out by the mapping, or rejected
with its reason and its row number in the file. Unrecognised files are reported, not guessed at."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from satsa.ingest.ledger import FileLedger, compress_rows
from satsa.ingest.mapper import SourceMapping
from satsa.ingest.pipeline import IngestionPipeline
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def _ingest(
    tmp_path: Path, files: dict[str, str], mapping: str | None = None, entity: str | None = None
):
    src = tmp_path / "in"
    src.mkdir()
    for name, text in files.items():
        (src / name).write_text(text, encoding="utf-8")
    source = None
    if mapping is not None:
        (tmp_path / "m.yaml").write_text(mapping, encoding="utf-8")
        source = SourceMapping(tmp_path / "m.yaml")
    (tmp_path / "salt").write_bytes(b"ledger-test-salt-32-bytes!!!!!!!")
    sql, duck = SQLiteStore(tmp_path / "s.db"), DuckDBStore(tmp_path / "d")
    try:
        result = IngestionPipeline(duck, sql, salt_file=tmp_path / "salt").ingest_directory(
            src, default_entity_id=entity, mapping=source
        )
        duck.load_all_tables()
        tables = {
            t: duck.query(f'SELECT * FROM "{t}"').to_dicts()
            for t in ("alert", "case", "case_alert_link")
        }
        dq = {r["check_name"]: dict(r) for r in sql.conn.execute("SELECT * FROM dq_issues")}
    finally:
        duck.close()
        sql.close()
    return result, tables, dq


def _file(result: dict[str, Any], name: str) -> dict[str, Any]:
    return next(f for f in result["file_coverage"] if f["file"] == name)


def test_row_ranges_are_written_compactly():
    assert compress_rows([9, 4, 5, 6, 7, 8, 15, 22, 23]) == "4-9, 15, 22-23"
    assert compress_rows([1, 3, 5, 7], limit=2) == "1, 3 and 2 more range(s)"
    assert compress_rows([]) == ""


def test_a_ledger_settles_on_a_status():
    book = FileLedger(file="a.csv", rows_read=3)
    book.store("alert", 2)
    book.reject("missing created_at for alert", 1, [4])
    book.settle()
    assert book.status == "partly stored"
    assert "1 rejected, missing created_at for alert (rows 4)" in book.summary()
    empty = FileLedger(file="b.csv")
    empty.settle()
    assert empty.status == "empty"


MAPPING = """
source: ledger_test
tables:
  - table: case
    files: ["cases*"]
    required: [case_id, opened_at]
    columns:
      case_id: "Case ID"
      opened_at: "Created"
      severity: "Severity"
"""


def test_rows_a_mapping_cannot_fill_are_reported_with_their_row_numbers(tmp_path):
    cases = (
        "Case ID,Created,Severity\n"  # row 1
        "C-1,2026-01-01T00:00:00,High\n"  # 2
        "\n"  # 3: blank, dropped by the sanitiser
        ",2026-01-02T00:00:00,Low\n"  # 4: no case id
        "C-3,,Low\n"  # 5: no creation time
        "C-4,2026-01-04T00:00:00,Low\n"  # 6
        ",,\n"  # 7: blank
        ",not a date,Low\n"  # 8: neither
    )
    result, tables, dq = _ingest(tmp_path, {"cases.csv": cases}, MAPPING, "CSE-L")
    assert result["status"] == "success"
    assert sorted(r["case_id"] for r in tables["case"]) == ["C-1", "C-4"]
    book = _file(result, "cases.csv")
    assert book["status"] == "partly stored"
    assert book["rows_read"] == 5 and book["stored"] == {"case": 2}
    assert book["rejected"] == {
        "missing case_id for case": {"count": 1, "rows": "4"},
        "missing case_id, opened_at for case": {"count": 1, "rows": "8"},
        "missing opened_at for case": {"count": 1, "rows": "5"},
    }
    issue = dq["rows_rejected"]
    assert issue["severity"] == "error"  # 3 of the file's 5 rows
    assert issue["count"] == 3
    assert "cases.csv" in issue["details"] and "rows 5" in issue["details"]


def test_a_few_rejected_rows_are_a_warning(tmp_path):
    rows = "".join(f"C-{i},2026-01-01T00:00:00,Low\n" for i in range(9))
    result, _, dq = _ingest(
        tmp_path,
        {"cases.csv": "Case ID,Created,Severity\n" + rows + "C-9,,Low\n"},
        MAPPING,
        "CSE-L",
    )
    assert _file(result, "cases.csv")["rejected"] == {
        "missing opened_at for case": {"count": 1, "rows": "11"}
    }
    assert dq["rows_rejected"]["severity"] == "warning"


def test_a_row_another_table_took_is_not_rejected(tmp_path):
    mapping = """
source: ledger_test
tables:
  - table: alert
    files: ["alerts*"]
    required: [alert_id]
    columns:
      alert_id: id
      created_at: created
  - table: case_alert_link
    files: ["alerts*"]
    required: [case_id, alert_id]
    columns:
      case_id: case
      alert_id: id
"""
    alerts = "id,created,case\nA-1,2026-01-01T00:00:00,C-1\nA-2,2026-01-01T00:00:00,\n,2026-01-01T00:00:00,C-3\n"
    result, _, dq = _ingest(tmp_path, {"alerts.csv": alerts}, mapping, "CSE-L")
    book = _file(result, "alerts.csv")
    assert book["stored"] == {"alert": 2, "case_alert_link": 1}
    # A-2 has no case: not for the link table, but stored as an alert.
    assert book["filtered"] == {"case_alert_link": 1}
    # Row 4 has no alert id: no table took it, and it is reported once.
    assert book["rejected"] == {"missing alert_id for alert": {"count": 1, "rows": "4"}}
    assert dq["rows_rejected"]["count"] == 1


def test_a_file_nothing_identifies_is_reported_not_stored_as_alerts(tmp_path):
    files = {
        "alert.csv": "entity_id,alert_id,created_at,severity_final\nCSE-L,A-1,2026-01-01T00:00:00,high\n",
        "notes.csv": "note,author,when\nchecked the firewall,priya,yesterday\n",
    }
    result, tables, dq = _ingest(tmp_path, files)
    assert result["status"] == "success"
    assert [r["alert_id"] for r in tables["alert"]] == ["A-1"]
    assert result["unrecognised_files"] == ["notes.csv"]
    assert _file(result, "notes.csv")["status"] == "not recognised"
    assert dq["file_not_recognised"]["severity"] == "warning"
    assert "notes.csv" in dq["file_not_recognised"]["details"]


def test_a_submission_of_only_unrecognised_files_says_why_nothing_was_stored(tmp_path):
    result, _, _ = _ingest(tmp_path, {"notes.csv": "note,author\nhello,priya\n"}, entity="CSE-L")
    assert result["status"] == "error"
    assert "notes.csv: not recognised" in result["message"]
    assert result["file_coverage"][0]["status"] == "not recognised"


def test_canonical_rows_without_an_entity_are_numbered(tmp_path):
    alerts = (
        "entity_id,alert_id,created_at,severity_final\n"
        "CSE-L,A-1,2026-01-01T00:00:00,high\n"
        ",A-2,2026-01-01T00:00:00,low\n"
        "bad id!,A-3,2026-01-01T00:00:00,low\n"
    )
    result, tables, dq = _ingest(tmp_path, {"alert.csv": alerts})
    assert [r["alert_id"] for r in tables["alert"]] == ["A-1"]
    book = _file(result, "alert.csv")
    assert book["rejected"] == {
        "invalid entity_id": {"count": 1, "rows": "4"},
        "no entity_id": {"count": 1, "rows": "3"},
    }
    # Their own DQ checks report them; rows_rejected is for rows a mapping could not fill.
    assert {"missing_entity_id", "invalid_entity_id"} <= set(dq) and "rows_rejected" not in dq


def test_json_rows_are_named_by_record(tmp_path):
    alerts = (
        '[{"entity_id": "CSE-L", "alert_id": "A-1"}, {"entity_id": "no good!", "alert_id": "A-2"}]'
    )
    result, _, _ = _ingest(tmp_path, {"alert.json": alerts})
    book = _file(result, "alert.json")
    assert book["row_label"] == "record"
    assert book["rejected"] == {"invalid entity_id": {"count": 1, "rows": "2"}}
    assert "records 2" in book["summary"]


def test_a_clean_submission_stores_every_row(tmp_path):
    files = {
        "alert.csv": "entity_id,alert_id,created_at\nCSE-L,A-1,2026-01-01T00:00:00\nCSE-L,A-2,2026-01-02T00:00:00\n"
    }
    result, _, _ = _ingest(tmp_path, files)
    assert result["file_coverage"] == [
        {
            "file": "alert.csv",
            "status": "ingested",
            "rows_read": 2,
            "row_label": "row",
            "stored": {"alert": 2},
            "filtered": {},
            "rejected": {},
            "note": "",
            "summary": "alert.csv: 2 row(s) read, 2 into alert",
        }
    ]
