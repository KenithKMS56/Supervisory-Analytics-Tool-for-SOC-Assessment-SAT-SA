"""Sanitising of submitted files: encodings, separators, ragged rows, Excel, JSON, value parsers."""

import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import polars as pl
import pytest

from satsa.ingest import sanitise
from satsa.ingest.mapper import MappingError, SourceMapping, parse_source_timestamp
from satsa.ingest.sanitise import (
    UnreadableFile,
    clean_headers,
    collect_reports,
    header_key,
    parse_bool,
    parse_datetime_text,
    parse_literal,
    parse_number,
    read_delimited,
    read_excel,
    read_header,
    read_json_records,
    sniff_delimiter,
)

# --------------------------------------------------------------------------- delimited text


def test_a_clean_canonical_csv_is_read_exactly_as_before(tmp_path):
    path = tmp_path / "alert.csv"
    path.write_text(
        "entity_id,alert_id,criticality,created_at\nE1,A1,3,2026-01-05T09:00:00\nE1,A2,4,\n"
    )
    table = read_delimited(path)
    assert table.frame.equals(pl.read_csv(path, infer_schema_length=1000))
    assert not table.report.noteworthy


def test_windows_1252_text_from_excel_is_decoded(tmp_path):
    path = tmp_path / "cases.csv"
    path.write_bytes("Case ID,Description\n1,• Source IP: 10.0.0.1 – café\n".encode("cp1252"))
    table = read_delimited(path)
    assert table.frame["Description"][0] == "• Source IP: 10.0.0.1 – café"
    assert table.report.encoding == "windows-1252"
    assert "read as windows-1252 text" in table.report.notes()


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-8-sig"])
def test_utf16_and_byte_order_marks(tmp_path, encoding):
    path = tmp_path / "a.csv"
    path.write_bytes("alert_id,severity\nA1,high\n".encode(encoding))
    table = read_delimited(path)
    assert table.frame.columns == ["alert_id", "severity"]
    assert table.frame.to_dicts() == [{"alert_id": "A1", "severity": "high"}]


@pytest.mark.parametrize(("sep", "name"), [(";", "semicolon"), ("\t", "tab"), ("|", "pipe")])
def test_other_separators_are_detected(tmp_path, sep, name):
    path = tmp_path / "a.csv"
    path.write_text(
        sep.join(["alert_id", "score", "note"]) + "\n" + sep.join(["A1", "1,5", '"x, y"']) + "\n"
    )
    table = read_delimited(path)
    assert table.frame.columns == ["alert_id", "score", "note"]
    assert table.frame.row(0) == ("A1", "1,5", "x, y")
    assert f"{name}-separated" in table.report.notes()


def test_a_tsv_file_is_tab_separated_whatever_its_sample_says(tmp_path):
    path = tmp_path / "a.tsv"
    path.write_text("alert_id\tnote\nA1\ta,b,c\n")
    assert read_delimited(path).frame.row(0) == ("A1", "a,b,c")


def test_sniffing_prefers_the_separator_that_gives_consistent_rows():
    sample = "id;amount;note\n1;1,5;a\n2;2,25;b\n3;3;c\n"
    assert sniff_delimiter(sample) == ";"
    assert sniff_delimiter("single_column\nvalue\n") == ","


def test_blank_rows_anywhere_are_dropped_and_counted(tmp_path):
    path = tmp_path / "a.csv"
    path.write_text("alert_id,severity\n\nA1,high\n,\n  ,   \nA2,low\n,,\n")
    table = read_delimited(path)
    assert table.frame["alert_id"].to_list() == ["A1", "A2"]
    assert table.report.blank_rows_dropped >= 2


def test_ragged_rows_are_padded_or_truncated_and_reported(tmp_path):
    path = tmp_path / "a.csv"
    path.write_text("a,b,c\n1,2,3\n4,5\n6,7,8,9\n10,11,12,\n")
    table = read_delimited(path)
    assert table.frame.to_dicts() == [
        {"a": 1, "b": 2, "c": 3},
        {"a": 4, "b": 5, "c": None},
        {"a": 6, "b": 7, "c": 8},
        {"a": 10, "b": 11, "c": 12},
    ]
    assert table.report.short_rows_padded == 1
    # A trailing empty cell loses nothing; a real extra value is reported as not read.
    assert table.report.long_rows_truncated == 1
    assert table.report.data_lost


def test_a_column_whose_type_changes_after_row_1000_does_not_fail(tmp_path):
    path = tmp_path / "a.csv"
    path.write_text("id,value\n" + "".join(f"{i},{i}\n" for i in range(1500)) + "1500,n/a\n")
    frame = read_delimited(path).frame
    assert frame.height == 1501 and frame["value"][-1] == "n/a"


def test_quoted_newlines_and_nul_bytes(tmp_path):
    path = tmp_path / "a.csv"
    path.write_bytes(b'id,description\n1,"line one\nline two"\n2,bad\x00byte\n')
    frame = read_delimited(path).frame
    assert frame["description"][0] == "line one\nline two"
    assert frame["description"][1].replace("\x00", "") == "badbyte"
    # On the careful path (here forced by Windows-1252 text) NULs are removed: csv cannot read them.
    path.write_bytes(b"id,description\n1,caf\xe9\n2,bad\x00byte\n")
    assert read_delimited(path).frame["description"].to_list() == ["café", "badbyte"]


def test_blank_and_repeated_headers_are_renamed():
    names, renamed, collisions = clean_headers(
        ["﻿Alert ID", "", "Severity", "severity", " alert_id "]
    )
    assert names == ["Alert ID", "column_2", "Severity", "severity_2", "alert_id"]
    assert renamed == {"": "column_2", "severity": "severity_2"}
    assert collisions == ["Alert ID / alert_id"]


def test_header_key_compares_headers_as_people_write_them():
    assert (
        header_key(" Alert ID ") == header_key("alert_id") == header_key("ALERT-ID") == "alert_id"
    )
    assert header_key("MITRE ATT&CK Tactic") == "mitre_att_ck_tactic"
    assert header_key("Sévérité") == "sévérité"


def test_read_header_of_a_header_only_file(tmp_path):
    path = tmp_path / "escalation.csv"
    path.write_bytes("﻿esc_id;ref_id;escalated_at\n".encode())
    assert read_header(path) == ["esc_id", "ref_id", "escalated_at"]


def test_reports_are_collected_per_block(tmp_path):
    clean, messy = tmp_path / "clean.csv", tmp_path / "messy.csv"
    clean.write_text("a,b\n1,2\n")
    messy.write_text("a;b\n1;2\n\n")
    with collect_reports() as reports:
        read_delimited(clean)
        read_delimited(messy)
    assert [r.file for r in reports] == ["clean.csv", "messy.csv"]
    assert [r.noteworthy for r in reports] == [False, True]
    assert sanitise.collected() == []


# --------------------------------------------------------------------------- Excel


def _xlsx(
    path: Path,
    rows_xml: str,
    shared: list[str],
    styles_xml: str = "",
    date1904: bool = False,
    shared_xml: str = "",
) -> Path:
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(
            "xl/workbook.xml",
            f'<workbook xmlns="{main}" xmlns:r="{rel}">'
            + ('<workbookPr date1904="1"/>' if date1904 else "")
            + '<sheets><sheet name="Cases" sheetId="1" r:id="rId1"/></sheets></workbook>',
        )
        z.writestr(
            "xl/_rels/workbook.xml.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        )
        z.writestr(
            "xl/sharedStrings.xml",
            shared_xml
            or f'<sst xmlns="{main}">' + "".join(f"<si><t>{s}</t></si>" for s in shared) + "</sst>",
        )
        if styles_xml:
            z.writestr("xl/styles.xml", f'<styleSheet xmlns="{main}">{styles_xml}</styleSheet>')
        z.writestr(
            "xl/worksheets/sheet1.xml",
            f'<worksheet xmlns="{main}"><sheetData>{rows_xml}</sheetData></worksheet>',
        )
    return path


def test_an_excel_workbook_is_read_with_the_standard_library(tmp_path):
    styles = (
        '<numFmts><numFmt numFmtId="164" formatCode="dd/mm/yyyy hh:mm"/></numFmts>'
        '<cellXfs><xf numFmtId="0"/><xf numFmtId="164"/><xf numFmtId="14"/></cellXfs>'
    )
    rows = (
        '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c>'
        '<c r="D1" t="s"><v>3</v></c><c r="E1" t="s"><v>4</v></c></row>'
        '<row r="2"/>'  # blank row
        '<row r="3"><c r="A3"><v>241806</v></c><c r="B3" s="1"><v>46296.5</v></c>'
        '<c r="C3" t="b"><v>1</v></c><c r="E3" t="inlineStr"><is><t>Known Issue</t></is></c></row>'
        '<row r="4"><c r="A4"><v>241807</v></c><c r="B4" s="2"><v>46296</v></c><c r="D4"><v>0.25</v></c></row>'
    )
    path = _xlsx(
        tmp_path / "cases.xlsx",
        rows,
        ["Case ID", "Creation Time", "Automated", "Score", "Resolution Reason"],
        styles,
    )
    table = read_excel(path)
    assert table.frame.columns == [
        "Case ID",
        "Creation Time",
        "Automated",
        "Score",
        "Resolution Reason",
    ]
    assert table.frame.to_dicts() == [
        {
            "Case ID": 241806,
            "Creation Time": "2026-10-01 12:00:00",
            "Automated": True,
            "Score": None,
            "Resolution Reason": "Known Issue",
        },
        {
            "Case ID": 241807,
            "Creation Time": "2026-10-01",
            "Automated": None,
            "Score": 0.25,
            "Resolution Reason": None,
        },
    ]
    assert table.report.sheet == "Cases" and table.report.blank_rows_dropped == 1
    assert read_header(path)[0] == "Case ID"


def test_a_workbook_part_with_a_doctype_is_refused(tmp_path):
    path = _xlsx(
        tmp_path / "bad.xlsx", "<row/>", [], shared_xml='<!DOCTYPE x [<!ENTITY a "aaaa">]><sst/>'
    )
    with pytest.raises(UnreadableFile):
        read_excel(path)


def test_a_file_named_xlsx_that_is_not_a_workbook_is_unreadable(tmp_path):
    path = tmp_path / "fake.xlsx"
    path.write_text("alert_id\nA1\n")
    with pytest.raises(UnreadableFile):
        read_excel(path)


# --------------------------------------------------------------------------- JSON


def test_json_shapes(tmp_path):
    cases = {
        "array.json": json.dumps([{"id": 1}, {"id": 2}]),
        "envelope.json": json.dumps({"total": 2, "data": [{"id": 1}, {"id": 2}]}),
        "single.json": json.dumps({"id": 1, "tags": ["a"]}, indent=2),
        "lines.ndjson": '{"id": 1}\n\n{"id": 2}\n',
    }
    for name, text in cases.items():
        (tmp_path / name).write_bytes(("﻿" + text).encode())
    assert read_json_records(tmp_path / "array.json") == [{"id": 1}, {"id": 2}]
    assert read_json_records(tmp_path / "envelope.json") == [{"id": 1}, {"id": 2}]
    assert read_json_records(tmp_path / "single.json") == [{"id": 1, "tags": ["a"]}]
    assert read_json_records(tmp_path / "lines.ndjson") == [{"id": 1}, {"id": 2}]


def test_bad_ndjson_lines_are_skipped_and_counted(tmp_path):
    path = tmp_path / "alerts.ndjson"
    path.write_text('{"id": 1}\nnot json\n[1, 2]\n{"id": 2}\n')
    with collect_reports() as reports:
        assert read_json_records(path) == [{"id": 1}, {"id": 2}]
    assert reports[0].records_skipped == 2 and reports[0].data_lost


def test_a_file_with_no_json_at_all_is_unreadable(tmp_path):
    path = tmp_path / "x.json"
    path.write_text("alert_id,severity\nA1,high\n")
    with pytest.raises(UnreadableFile):
        read_json_records(path)


# --------------------------------------------------------------------------- value parsers


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Oct 1st 2026 22:53:09", datetime(2026, 10, 1, 22, 53, 9)),
        ("October 22nd, 2026", datetime(2026, 10, 22)),
        ("1 Oct 2026", datetime(2026, 10, 1)),
        ("01-Oct-2026 09:15", datetime(2026, 10, 1, 9, 15)),
        ("Oct 1, 2026 10:53:09 PM", datetime(2026, 10, 1, 22, 53, 9)),
        ("2026-10-01 22:53:09", datetime(2026, 10, 1, 22, 53, 9)),
        ("2026/10/01 22:53", datetime(2026, 10, 1, 22, 53)),
        ("2026-10-01T22:53:09Z", datetime(2026, 10, 1, 22, 53, 9, tzinfo=UTC)),
        ("2026-10-01 22:53:09 UTC", datetime(2026, 10, 1, 22, 53, 9, tzinfo=UTC)),
        ("Thu Oct  1 22:53:09 2026", datetime(2026, 10, 1, 22, 53, 9)),
        ("13/04/2026 10:00", datetime(2026, 4, 13, 10, 0)),  # day-first, unambiguous
        ("04/13/2026", datetime(2026, 4, 13)),  # month-first, unambiguous
        ("1790000000", datetime.fromtimestamp(1790000000, tz=UTC)),
        ("1790000000000", datetime.fromtimestamp(1790000000, tz=UTC)),
    ],
)
def test_common_timestamp_forms_are_parsed(text, expected):
    assert parse_datetime_text(text) == expected


@pytest.mark.parametrize(
    "text", ["03/04/2026", "garbage", "", "12345", "99999999999", "2026-13-45"]
)
def test_ambiguous_or_meaningless_timestamps_give_none(text):
    assert parse_datetime_text(text) is None


def test_bool_number_and_literal_parsers():
    assert [parse_bool(v) for v in ("Yes", "no", "TRUE", "0", "On", "maybe", None)] == [
        True,
        False,
        True,
        False,
        True,
        None,
        None,
    ]
    assert parse_number("1,234,567.5") == 1234567.5
    assert parse_number("12,34,567") == 1234567
    assert parse_number(" 42 ") == 42
    assert parse_number("1,5") is None  # a decimal comma is not a thousands separator
    assert parse_number("nan") is None and parse_number(True) is None
    assert parse_literal("{'total_duration': 1295, 'status': 'ended'}") == {
        "total_duration": 1295,
        "status": "ended",
    }
    assert parse_literal("['TA0001 - Initial Access', 'TA0040 - Impact']") == [
        "TA0001 - Initial Access",
        "TA0040 - Impact",
    ]
    assert parse_literal("__import__('os').system('x')") == "__import__('os').system('x')"
    assert parse_literal("{'a': __import__('os')}") == "{'a': __import__('os')}"


# --------------------------------------------------------------------------- mapper integration


def test_a_mapping_reads_ordinal_dates_and_values_inside_literals(tmp_path):
    mapping_path = tmp_path / "m.yaml"
    mapping_path.write_text(
        """
source: xsiam_test
timestamp_format: "%Y-%m-%d %H:%M:%S"
tables:
  - table: case
    files: ["cases*"]
    required: [case_id, opened_at]
    columns:
      case_id: "Case ID"
      opened_at: "Creation Time"
      closed_at: "Resolved Timestamp"
      severity: Severity
      status: Status
      resolution_seconds: {column: "Resolution Timer", extract: total_duration, transform: number}
      automated: {column: Automated, transform: boolean}
""",
        encoding="utf-8",
    )
    mapping = SourceMapping(mapping_path)
    spec = mapping.specs_for_file("cases_oct")[0]
    raw = [
        {
            "Case ID": "241806",
            "Creation Time": "Oct 1st 2026 22:31:34",
            "Resolved Timestamp": "Oct 1st 2026 22:53:09",
            "Severity": "Medium",
            "Status": "Resolved",
            "Resolution Timer": "{'total_duration': 1295, 'status': 'ended'}",
            "Automated": "No",
        },
        # The XSIAM export's near-empty rows: no case id, so dropped and counted.
        {
            "Case ID": None,
            "Creation Time": None,
            "Resolution Timer": "{'total_duration': 4526, 'status': 'ended'}",
        },
    ]
    mapped = mapping.map_rows(raw, spec, "CSE-01")
    assert mapped.dropped_missing_required == 1
    row = mapped.rows[0]
    assert row["opened_at"] == datetime(2026, 10, 1, 22, 31, 34)
    assert row["closed_at"] == datetime(2026, 10, 1, 22, 53, 9)
    assert row["resolution_seconds"] == 1295
    assert row["automated"] is False
    assert (row["closed_at"] - row["opened_at"]).total_seconds() == row["resolution_seconds"]


def test_an_unknown_transform_is_a_mapping_error(tmp_path):
    path = tmp_path / "m.yaml"
    path.write_text(
        "tables:\n  - table: alert\n    files: [a]\n    columns:\n      alert_id: {column: id, transform: shout}\n"
    )
    with pytest.raises(MappingError, match="transform 'shout'"):
        SourceMapping(path)


def test_a_declared_format_still_wins_and_ambiguity_is_not_guessed():
    assert parse_source_timestamp("03/04/2026", "%d/%m/%Y") == datetime(2026, 4, 3)
    assert parse_source_timestamp("03/04/2026", "iso") is None
    assert parse_source_timestamp("Oct 1st 2026 22:53:09", "%Y-%m-%d %H:%M:%S") == datetime(
        2026, 10, 1, 22, 53, 9
    )


# --------------------------------------------------------------------------- pipeline integration


def _ingest(tmp_path, files: dict[str, bytes]):
    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    src = tmp_path / "in"
    src.mkdir()
    for name, data in files.items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_bytes(data)
    (tmp_path / "salt").write_bytes(b"sanitise-test-salt-32-bytes!!!!!")
    sql, duck = SQLiteStore(tmp_path / "s.db"), DuckDBStore(tmp_path / "d")
    try:
        result = IngestionPipeline(duck, sql, salt_file=tmp_path / "salt").ingest_directory(src)
        duck.load_all_tables()
        alerts = duck.query(
            'SELECT alert_id, severity_final FROM "alert" ORDER BY alert_id'
        ).to_dicts()
        dq = {
            r["check_name"]: r["details"]
            for r in sql.conn.execute("SELECT check_name, details FROM dq_issues")
        }
    finally:
        duck.close()
        sql.close()
    return result, alerts, dq


def test_a_messy_alert_export_is_ingested_and_its_tidying_reported(tmp_path):
    messy = (
        "Entity ID;Alert ID;Rule ID;Created At;Severity Final\r\n"
        "\r\n"
        "CSE-09;A-1;R1;2026-01-05T09:00:00;High\r\n"
        ";;;;\r\n"
        "CSE-09;A-2;R2;2026-01-05T10:00:00;Low;stray•cell\r\n"
    ).encode("cp1252")
    result, alerts, dq = _ingest(
        tmp_path,
        {"Alerts.CSV": messy, "__MACOSX/._Alerts.CSV": b"\x00\x05junk", "~$book.xlsx": b"lock"},
    )
    assert result["status"] == "success"
    assert alerts == [
        {"alert_id": "A-1", "severity_final": "high"},
        {"alert_id": "A-2", "severity_final": "low"},
    ]
    (report,) = result["file_sanitising"]
    assert report["file"] == "Alerts.CSV"
    assert report["encoding"] == "windows-1252" and report["delimiter"] == ";"
    assert report["blank_rows_dropped"] == 2 and report["long_rows_truncated"] == 1
    assert "file_partly_read" in dq and "Alerts.CSV" in dq["file_partly_read"]
    assert result["unreadable_files"] == []


def test_an_excel_alert_file_is_ingested(tmp_path):
    rows = (
        '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c>'
        '<c r="D1" t="s"><v>3</v></c></row>'
        '<row r="2"><c r="A2" t="s"><v>4</v></c><c r="B2" t="s"><v>5</v></c><c r="C2" t="s"><v>6</v></c>'
        '<c r="D2" t="s"><v>7</v></c></row>'
    )
    path = _xlsx(
        tmp_path / "alerts.xlsx",
        rows,
        [
            "entity_id",
            "alert_id",
            "created_at",
            "severity_final",
            "CSE-10",
            "X-1",
            "2026-02-01T08:00:00",
            "critical",
        ],
    )
    result, alerts, _ = _ingest(tmp_path, {"alerts.xlsx": path.read_bytes()})
    assert result["status"] == "success"
    assert alerts == [{"alert_id": "X-1", "severity_final": "critical"}]


# --------------------------------------------------------------------------- row numbers


def test_rows_are_numbered_as_the_file_shows_them_past_blank_rows(tmp_path):
    path = tmp_path / "a.csv"
    path.write_text("alert_id,n\nA1,1\n\nA2,2\n,\nA3,3\n")
    table = read_delimited(path)
    assert table.frame["alert_id"].to_list() == ["A1", "A2", "A3"]
    assert table.report.source_rows([0, 1, 2]) == [2, 4, 6]


def test_row_numbers_count_blank_lines_above_the_header(tmp_path):
    path = tmp_path / "a.csv"
    path.write_bytes("\n\nid,name\n1,caf\xe9\n\n2,b\n".encode("latin-1"))  # not UTF-8: careful path
    table = read_delimited(path)
    assert table.report.encoding == "windows-1252"
    assert table.report.source_rows([0, 1]) == [4, 6]


def test_excel_rows_keep_their_sheet_numbers(tmp_path):
    rows = (
        '<row r="1"><c r="A1" t="s"><v>0</v></c></row>'
        '<row r="3"><c r="A3" t="s"><v>1</v></c></row>'  # Excel left row 2 out
        '<row r="4"><c r="A4" s="0"/></row>'  # formatting only
        '<row r="7"><c r="A7" t="s"><v>2</v></c></row>'
        '<row r="1048576"><c r="A1048576" s="0"/></row>'  # formatting at the sheet's end
    )
    table = read_excel(_xlsx(tmp_path / "a.xlsx", rows, ["Case ID", "C-1", "C-2"]))
    assert table.frame["Case ID"].to_list() == ["C-1", "C-2"]
    assert table.report.source_rows([0, 1]) == [3, 7]
    assert table.report.blank_rows_dropped == 4  # rows 2, 4, 5 and 6, not the million after


def test_json_records_and_ndjson_lines_are_numbered(tmp_path):
    (tmp_path / "a.json").write_text('[{"a": 1}, 3, {"a": 2}]')
    (tmp_path / "b.ndjson").write_text('{"a": 1}\n\nnot json\n{"a": 2}\n5\n{"a": 3}\n')
    with collect_reports() as reports:
        assert len(read_json_records(tmp_path / "a.json")) == 2
        assert len(read_json_records(tmp_path / "b.ndjson")) == 3
    array, lines = reports
    assert (array.row_label, array.source_rows([0, 1])) == ("record", [1, 3])
    assert (lines.row_label, lines.source_rows([0, 1, 2])) == ("line", [1, 4, 6])
    assert lines.records_skipped == 2  # "not json" and 5; the blank line is not a record
