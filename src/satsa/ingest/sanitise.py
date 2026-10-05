"""Sanitising of submitted files, before any table or column is identified.

Every CSE exports differently: Windows-1252 or UTF-16 text, semicolon or tab separators, a
byte-order mark in the first header, blank lines, rows with a cell too many, a column that holds
numbers for 1,000 rows and text after that, Excel workbooks, JSON wrapped in an envelope. None
of that says anything about the SOC, so none of it should make a file unreadable.

This module reads such a file into a frame of rows under clean, unique headers and records what
it had to do (`SanitiseReport`). It never decides what a column means: that is the job of the
canonical layout or of a source mapping (`mapper.py`).

A clean canonical CSV (UTF-8, comma-separated, rectangular) takes the fast path and is read
exactly as before. Anything else is decoded, re-parsed with Python's csv module and handed to
Polars as clean UTF-8 CSV, so column types are inferred the same way in both paths.

The value parsers at the end (`parse_datetime_text`, `parse_bool`, `parse_number`,
`parse_literal`) are used by source mappings for exports whose values are not in one fixed
format.
"""

from __future__ import annotations

import ast
import codecs
import contextvars
import csv
import io
import json
import math
import re
import unicodedata
import zipfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import polars as pl

# Bytes looked at to choose the encoding and the separator.
SAMPLE_BYTES = 64 * 1024
DELIMITERS = (",", ";", "\t", "|")
DELIMITER_NAMES = {",": "comma", ";": "semicolon", "\t": "tab", "|": "pipe"}
# A cell larger than this is not data a rule reads; Python's csv default (128 KiB) is too small
# for some exports' description fields.
CSV_FIELD_LIMIT = 16 * 1024 * 1024
# Workbook parts are decompressed in memory: a crafted file must not expand without bound.
XLSX_MAX_UNCOMPRESSED = 1024 * 1024 * 1024
XLSX_MAX_RATIO = 200
# Python-literal cells (`{'total_duration': 1295}`) longer than this are not evaluated.
LITERAL_MAX_CHARS = 100_000

TABULAR_SUFFIXES = (".csv", ".tsv")
EXCEL_SUFFIXES = (".xlsx",)
JSON_SUFFIXES = (".json", ".ndjson")
SUPPORTED_SUFFIXES = TABULAR_SUFFIXES + EXCEL_SUFFIXES + JSON_SUFFIXES


class UnreadableFile(ValueError):
    """The file is not a table in any form this module reads."""


@dataclass
class SanitiseReport:
    """What was done to one file to read it. `noteworthy` is False for a clean canonical CSV."""

    file: str
    encoding: str = "utf-8"
    delimiter: str | None = None
    rows: int = 0
    blank_rows_dropped: int = 0
    short_rows_padded: int = 0
    long_rows_truncated: int = 0
    headers_renamed: dict[str, str] = field(default_factory=dict)
    header_collisions: list[str] = field(default_factory=list)
    records_skipped: int = 0  # JSON lines or array items that are not an object
    types_read_as_text: bool = False
    sheet: str | None = None
    # Where each row read came from, so a rejected row can be named as the file shows it: the
    # file's own number of the first data row ("row" 2 under a header, as a spreadsheet counts;
    # JSON "record" or NDJSON "line" 1), and the data positions dropped before the frame.
    path: str | None = field(default=None, repr=False)
    row_label: str = field(default="row", repr=False)
    first_row: int = field(default=2, repr=False)
    dropped_positions: list[int] = field(default_factory=list, repr=False)

    def source_rows(self, positions: Iterable[int]) -> list[int]:
        """The file's numbers for rows at these positions of the frame read, in order."""
        dropped = self.dropped_positions
        out, skipped = [], 0
        for position in sorted(positions):
            while skipped < len(dropped) and dropped[skipped] <= position + skipped:
                skipped += 1
            out.append(self.first_row + position + skipped)
        return out

    @property
    def noteworthy(self) -> bool:
        return bool(self.notes())

    @property
    def data_lost(self) -> bool:
        """Something in the file was not read (as opposed to tidied)."""
        return bool(self.long_rows_truncated or self.records_skipped)

    def notes(self) -> list[str]:
        out: list[str] = []
        if self.encoding not in ("utf-8", "ascii"):
            out.append(f"read as {self.encoding} text")
        if self.delimiter not in (None, ","):
            out.append(f"{DELIMITER_NAMES.get(self.delimiter, repr(self.delimiter))}-separated")
        if self.sheet:
            out.append(f"Excel sheet '{self.sheet}'")
        if self.blank_rows_dropped:
            out.append(f"{self.blank_rows_dropped} blank row(s) dropped")
        if self.short_rows_padded:
            out.append(
                f"{self.short_rows_padded} row(s) had fewer cells than the header (filled as empty)"
            )
        if self.long_rows_truncated:
            out.append(
                f"{self.long_rows_truncated} row(s) had more cells than the header; the extra cells were not read"
            )
        if self.headers_renamed:
            pairs = ", ".join(
                f"{k or '(blank)'!r} -> {v!r}" for k, v in self.headers_renamed.items()
            )
            out.append(f"headers renamed: {pairs}")
        if self.header_collisions:
            out.append(f"columns that read as the same name: {', '.join(self.header_collisions)}")
        if self.records_skipped:
            out.append(f"{self.records_skipped} record(s) skipped: not a JSON object")
        if self.types_read_as_text:
            out.append("column types could not be inferred; every column read as text")
        return out

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        for internal in ("path", "row_label", "first_row", "dropped_positions"):
            del out[internal]
        out["notes"] = self.notes()
        return out


@dataclass
class SanitisedTable:
    frame: pl.DataFrame
    report: SanitiseReport


# --------------------------------------------------------------------------- report collection

_collector: contextvars.ContextVar[list[SanitiseReport] | None] = contextvars.ContextVar(
    "satsa_sanitise_reports", default=None
)


@contextmanager
def collect_reports() -> Iterator[list[SanitiseReport]]:
    """Gather the reports of every file read inside the block (per thread / task)."""
    reports: list[SanitiseReport] = []
    token = _collector.set(reports)
    try:
        yield reports
    finally:
        _collector.reset(token)


def collected() -> list[SanitiseReport]:
    """Reports gathered so far by the innermost `collect_reports` (empty outside one)."""
    return list(_collector.get() or [])


def _record(report: SanitiseReport) -> None:
    sink = _collector.get()
    if sink is not None:
        sink.append(report)


def report_key(path: Path | str) -> str:
    """How a report names its file: the absolute path, so two `alert.csv` in a batch differ."""
    return str(Path(path).absolute())


def report_for(path: Path | str) -> SanitiseReport | None:
    """The latest report collected for this file, if it was read inside `collect_reports`."""
    key = report_key(path)
    return next((r for r in reversed(_collector.get() or []) if r.path == key), None)


# --------------------------------------------------------------------------- text and headers


def detect_bom_encoding(head: bytes) -> str | None:
    """Encoding announced by a byte-order mark, or plainly visible as UTF-16 without one."""
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if head.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return "utf-32"
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16"
    sample = head[:2048]
    if len(sample) >= 4:
        even_nuls = sample[0::2].count(0) / len(sample[0::2])
        odd_nuls = sample[1::2].count(0) / len(sample[1::2])
        # ASCII text in UTF-16 has a zero in every other byte.
        if odd_nuls > 0.4 and even_nuls < 0.05:
            return "utf-16-le"
        if even_nuls > 0.4 and odd_nuls < 0.05:
            return "utf-16-be"
    return None


def decode_bytes(raw: bytes) -> tuple[str, str]:
    """Text of a file and the name of the encoding it was read as.

    UTF-8 is tried strictly first. Windows-1252 is what Excel on Windows writes for "CSV";
    Latin-1 maps every byte, so decoding never fails. NUL characters are removed (the csv
    module cannot read them and no SOC field contains one).
    """
    announced = detect_bom_encoding(raw[:4096])
    if announced:
        text = raw.decode(announced, errors="replace")
        name = {"utf-8-sig": "utf-8 (with byte-order mark)"}.get(announced, announced)
    else:
        try:
            text, name = raw.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            try:
                text, name = raw.decode("cp1252"), "windows-1252"
            except UnicodeDecodeError:
                text, name = raw.decode("latin-1"), "latin-1"
    return text.lstrip("﻿").replace("\x00", ""), name


def sniff_delimiter(sample: str, truncated: bool = False) -> str:
    """The separator that splits the sample into the most consistent rows of 2+ cells.

    Each candidate parses the sample with quoting honoured; the score is the share of rows
    as wide as the header, then the header's width. Comma wins ties and is the default for a
    one-column file.
    """
    best, best_score = ",", (0.0, 0)
    for delim in DELIMITERS:
        try:
            rows = [
                r
                for r in csv.reader(io.StringIO(sample, newline=""), delimiter=delim)
                if _non_blank(r)
            ]
        except csv.Error:
            continue
        if truncated and len(rows) > 1:
            rows = rows[:-1]  # the sample may end inside a record
        rows = rows[:200]
        if not rows or len(rows[0]) < 2:
            continue
        width = len(rows[0])
        score = (sum(1 for r in rows if len(r) == width) / len(rows), width)
        if score > best_score:
            best, best_score = delim, score
    return best


def header_key(name: Any) -> str:
    """The comparison form of a header: "Alert ID", "alert_id" and "alert-id" all give `alert_id`."""
    text = unicodedata.normalize("NFKC", str(name)).lower()
    return re.sub(r"[\W_]+", "_", text).strip("_")


def clean_headers(names: list[Any]) -> tuple[list[str], dict[str, str], list[str]]:
    """Trimmed, non-blank, unique headers; what was renamed; which names collide as keys.

    A blank header becomes `column_<n>`. A repeated header (ignoring case) gets `_2`, `_3`.
    Distinct headers with the same comparison key ("Alert ID" and "alert_id") are kept and
    listed, since only one of them can feed a canonical column.
    """
    out: list[str] = []
    renamed: dict[str, str] = {}
    seen: set[str] = set()
    for i, raw in enumerate(names):
        original = "" if raw is None else str(raw)
        name = original.replace("﻿", "").strip().strip('"').strip()
        if not name:
            name = f"column_{i + 1}"
        base, n = name, 2
        while name.lower() in seen:
            name, n = f"{base}_{n}", n + 1
        seen.add(name.lower())
        if name != original:
            renamed[original] = name
        out.append(name)
    keys: dict[str, list[str]] = {}
    for name in out:
        keys.setdefault(header_key(name), []).append(name)
    collisions = [" / ".join(group) for group in keys.values() if len(group) > 1]
    # BOM and surrounding-space removal is routine; only report renames a person would notice.
    renamed = {
        k: v for k, v in renamed.items() if k.replace("﻿", "").strip().strip('"').strip() != v
    }
    return out, renamed, collisions


def _non_blank(cells: list[str]) -> bool:
    return any(c.strip() for c in cells)


# --------------------------------------------------------------------------- frames


def _polars_read(source: Path | io.BytesIO, separator: str, report: SanitiseReport) -> pl.DataFrame:
    """Polars' CSV read, falling back to a full-file type scan, then to all-text columns."""
    attempts: list[dict[str, Any]] = [{"infer_schema_length": 1000}, {"infer_schema_length": None}]
    last: Exception | None = None
    for kwargs in attempts:
        if isinstance(source, io.BytesIO):
            source.seek(0)
        try:
            return pl.read_csv(source, separator=separator, **kwargs)
        except pl.exceptions.ComputeError as exc:
            last = exc
    if isinstance(source, io.BytesIO):
        source.seek(0)
    try:
        frame = pl.read_csv(source, separator=separator, infer_schema=False)
    except pl.exceptions.ComputeError:
        raise last or UnreadableFile("not a delimited text file") from None
    report.types_read_as_text = True
    return frame


def drop_blank_rows(frame: pl.DataFrame) -> tuple[pl.DataFrame, list[int]]:
    """The frame without rows whose every cell is empty or whitespace, and where they were."""
    if frame.width == 0 or frame.height == 0:
        return frame, []

    def empty(name: str, dtype: pl.DataType) -> pl.Expr:
        cond = pl.col(name).is_null()
        if dtype == pl.String:
            cond = cond | (pl.col(name).str.strip_chars() == "")
        return cond

    # Shortcut: a column with a real value in every row means no row is blank. An export
    # nearly always has one (its id), so a large clean file costs one column scan, not all.
    nulls = frame.null_count().row(0)
    for (name, dtype), n_null in zip(frame.schema.items(), nulls, strict=True):
        if n_null == 0 and (
            dtype != pl.String or not frame.select(empty(name, dtype).any()).item()
        ):
            return frame, []
    conditions = [empty(name, dtype) for name, dtype in frame.schema.items()]
    blank = pl.all_horizontal(conditions)
    positions = frame.select(blank.arg_true())
    if positions.height == 0:
        return frame, []
    return frame.filter(~blank), positions.to_series().to_list()


def _frame_from_records(
    header: list[Any], records: Iterator[list[Any]], report: SanitiseReport
) -> pl.DataFrame:
    """Clean headers and rectangular, non-blank rows, typed the way the fast path types them."""
    names, renamed, collisions = clean_headers(header)
    report.headers_renamed, report.header_collisions = renamed, collisions
    width = len(names)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(names)
    for position, row in enumerate(records):
        cells = ["" if c is None else str(c) for c in row]
        if not _non_blank(cells):
            report.blank_rows_dropped += 1
            report.dropped_positions.append(position)
            continue
        if len(cells) < width:
            report.short_rows_padded += 1
            cells += [""] * (width - len(cells))
        elif len(cells) > width:
            if _non_blank(cells[width:]):
                report.long_rows_truncated += 1
            cells = cells[:width]
        writer.writerow(cells)
    frame = _polars_read(io.BytesIO(out.getvalue().encode("utf-8")), ",", report)
    report.rows = frame.height
    return frame


def read_delimited(path: Path | str) -> SanitisedTable:
    """A CSV/TSV file in any common encoding and separator."""
    path = Path(path)
    report = SanitiseReport(file=path.name, path=report_key(path))
    if not path.exists():
        return SanitisedTable(pl.DataFrame(), report)
    with open(path, "rb") as f:
        head = f.read(SAMPLE_BYTES)
    truncated = path.stat().st_size > len(head)

    if detect_bom_encoding(head) not in (None, "utf-8-sig"):
        return _read_delimited_slow(path, report)
    sample = head.decode("utf-8", errors="ignore").lstrip("﻿")
    delimiter = "\t" if path.suffix.lower() == ".tsv" else sniff_delimiter(sample, truncated)
    report.delimiter = delimiter
    try:
        frame = _polars_read(path, delimiter, report)
    except Exception:  # noqa: BLE001 - invalid UTF-8, ragged rows, stray quotes: the careful path
        return _read_delimited_slow(path, report)

    header = next(csv.reader(io.StringIO(sample, newline=""), delimiter=delimiter), None)
    original = header if header is not None and len(header) == frame.width else frame.columns
    names, renamed, collisions = clean_headers(original)
    if names != frame.columns:
        frame = frame.rename(dict(zip(frame.columns, names, strict=True)))
    report.headers_renamed, report.header_collisions = renamed, collisions
    frame, report.dropped_positions = drop_blank_rows(frame)
    report.blank_rows_dropped = len(report.dropped_positions)
    report.rows = frame.height
    _record(report)
    return SanitisedTable(frame, report)


def _read_delimited_slow(path: Path, report: SanitiseReport) -> SanitisedTable:
    text, report.encoding = decode_bytes(path.read_bytes())
    report.delimiter = (
        "\t"
        if path.suffix.lower() == ".tsv"
        else sniff_delimiter(text[:SAMPLE_BYTES], len(text) > SAMPLE_BYTES)
    )
    previous_limit = csv.field_size_limit()
    csv.field_size_limit(max(previous_limit, CSV_FIELD_LIMIT))
    try:
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=report.delimiter)
        header = next(reader, None)
        while header is not None and not _non_blank(header):
            header = next(reader, None)  # blank lines above the header
            report.first_row += 1
        if header is None:
            frame = pl.DataFrame()
        else:
            frame = _frame_from_records(header, reader, report)
    except csv.Error as exc:
        raise UnreadableFile(f"{path.name}: {exc}") from None
    finally:
        csv.field_size_limit(previous_limit)
    _record(report)
    return SanitisedTable(frame, report)


def read_header(path: Path | str) -> list[str]:
    """Clean header of a delimited or Excel file without reading its rows (empty if none)."""
    path = Path(path)
    if path.suffix.lower() in EXCEL_SUFFIXES:
        try:
            rows = _xlsx_rows(path)
            header = next((r for r in rows if _non_blank(r)), [])
        except (UnreadableFile, zipfile.BadZipFile, KeyError, ElementTree.ParseError):
            return []
        return clean_headers(header)[0] if header else []
    with open(path, "rb") as f:
        head = f.read(SAMPLE_BYTES)
    text, _ = decode_bytes(head)
    delimiter = "\t" if path.suffix.lower() == ".tsv" else sniff_delimiter(text, True)
    for row in csv.reader(io.StringIO(text, newline=""), delimiter=delimiter):
        if _non_blank(row):
            return clean_headers(row)[0]
    return []


# --------------------------------------------------------------------------- JSON

_NO_RECORD = object()  # an NDJSON line that is blank or not JSON


def read_json_records(path: Path | str) -> list[dict[str, Any]]:
    """Objects of a JSON array, a single object, an envelope `{"data": [...]}` or NDJSON.

    In NDJSON a line that is not valid JSON, or not an object, is skipped and counted; a file
    in which no line is valid JSON is unreadable.
    """
    path = Path(path)
    report = SanitiseReport(file=path.name, path=report_key(path), row_label="record", first_row=1)
    if not path.exists():
        return []
    text, report.encoding = decode_bytes(path.read_bytes())
    if not text.strip():
        _record(report)
        return []
    # One entry per record (JSON) or line (NDJSON) of the file, so positions are the file's.
    records: list[Any]
    try:
        records = _unwrap(json.loads(text))
    except json.JSONDecodeError:
        report.row_label = "line"
        records = []
        for line in text.splitlines():
            if not line.strip():
                records.append(_NO_RECORD)
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(_NO_RECORD)
                report.records_skipped += 1
        if all(r is _NO_RECORD for r in records):
            raise UnreadableFile(f"{path.name}: not JSON") from None
    objects = []
    for position, record in enumerate(records):
        if isinstance(record, dict):
            objects.append(record)
            continue
        report.dropped_positions.append(position)
        if record is not _NO_RECORD:
            report.records_skipped += 1
    report.rows = len(objects)
    _record(report)
    return objects


def _unwrap(data: Any) -> list[Any]:
    """Records of a parsed JSON document: a list, or an object's only list of objects."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        lists = [
            v
            for v in data.values()
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v)
        ]
        if len(lists) == 1:
            return lists[0]
        return [data]
    return [data]


# --------------------------------------------------------------------------- Excel (.xlsx)

_NS = {
    "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
}
# Built-in number formats that display a date or time (ECMA-376 18.8.30).
_BUILTIN_DATE_FORMATS = frozenset({14, 15, 16, 17, 18, 19, 20, 21, 22, 45, 46, 47})


def _xml_part(z: zipfile.ZipFile, name: str) -> ElementTree.Element:
    data = z.read(name)
    # Entity declarations live in a DOCTYPE; a workbook part never needs one.
    if b"<!DOCTYPE" in data[:4096] or b"<!ENTITY" in data[:4096]:
        raise UnreadableFile(f"workbook part {name} declares a DOCTYPE")
    return ElementTree.fromstring(data)


def _check_zip(z: zipfile.ZipFile) -> None:
    total = 0
    for info in z.infolist():
        total += info.file_size
        if (
            info.compress_size
            and info.file_size / info.compress_size > XLSX_MAX_RATIO
            and info.file_size > 10_000_000
        ):
            raise UnreadableFile(f"workbook part {info.filename} expands too far")
    if total > XLSX_MAX_UNCOMPRESSED:
        raise UnreadableFile("workbook is too large to read")


def _is_date_format(code: str) -> bool:
    code = re.sub(r'"[^"]*"|\[[^\]]*\]|\\.', "", code.lower())
    return bool(re.search(r"[dmyhs]", code)) and "general" not in code


def _first_sheet(z: zipfile.ZipFile) -> tuple[str, str]:
    """(sheet name, part path) of the workbook's first sheet."""
    workbook = _xml_part(z, "xl/workbook.xml")
    sheet = workbook.find("m:sheets/m:sheet", _NS)
    if sheet is None:
        raise UnreadableFile("workbook has no sheet")
    rel_id = sheet.get(f"{{{_NS['r']}}}id")
    target = "worksheets/sheet1.xml"
    if "xl/_rels/workbook.xml.rels" in z.namelist():
        for rel in _xml_part(z, "xl/_rels/workbook.xml.rels").findall("rel:Relationship", _NS):
            if rel.get("Id") == rel_id:
                target = rel.get("Target", target)
    path = target.lstrip("/") if target.startswith("/") else f"xl/{target}"
    return sheet.get("name", "Sheet1"), path.replace("xl/xl/", "xl/")


def _xlsx_rows(path: Path, report: SanitiseReport | None = None) -> Iterator[list[str]]:
    with zipfile.ZipFile(path) as z:
        _check_zip(z)
        names = set(z.namelist())
        workbook = _xml_part(z, "xl/workbook.xml")
        pr = workbook.find("m:workbookPr", _NS)
        epoch = (
            datetime(1904, 1, 1)
            if pr is not None and pr.get("date1904") in ("1", "true")
            else datetime(1899, 12, 30)
        )

        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            for si in _xml_part(z, "xl/sharedStrings.xml").findall("m:si", _NS):
                shared.append("".join(t.text or "" for t in si.iter(f"{{{_NS['m']}}}t")))

        date_styles: set[int] = set()
        if "xl/styles.xml" in names:
            styles = _xml_part(z, "xl/styles.xml")
            custom = {
                int(nf.get("numFmtId", "0")): nf.get("formatCode", "")
                for nf in styles.findall("m:numFmts/m:numFmt", _NS)
            }
            for i, xf in enumerate(styles.findall("m:cellXfs/m:xf", _NS)):
                fmt = int(xf.get("numFmtId", "0"))
                if fmt in _BUILTIN_DATE_FORMATS or (fmt in custom and _is_date_format(custom[fmt])):
                    date_styles.add(i)

        sheet_name, sheet_path = _first_sheet(z)
        if report is not None:
            report.sheet = sheet_name
        sheet = _xml_part(z, sheet_path)
        # A row's position is its number in the sheet: the empty rows Excel leaves out (or
        # stores only for their formatting) are yielded empty before the next row with a value,
        # and not at all after the last one.
        yielded = 0
        for row in sheet.iterfind("m:sheetData/m:row", _NS):
            declared = row.get("r", "")
            number = int(declared) if declared.isdigit() else yielded + 1
            cells: dict[int, str] = {}
            for c in row.findall("m:c", _NS):
                col = _column_index(c.get("r", "")) if c.get("r") else len(cells)
                cells[col] = _cell_text(c, shared, date_styles, epoch)
            values = [cells.get(i, "") for i in range(max(cells) + 1)] if cells else []
            if not _non_blank(values):
                continue
            while yielded + 1 < number:
                yielded += 1
                yield []
            yielded += 1
            yield values


def _column_index(ref: str) -> int:
    letters = re.match(r"[A-Za-z]+", ref)
    n = 0
    for ch in (letters.group(0) if letters else "A").upper():
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _cell_text(
    c: ElementTree.Element, shared: list[str], date_styles: set[int], epoch: datetime
) -> str:
    kind = c.get("t", "n")
    if kind == "inlineStr":
        return "".join(t.text or "" for t in c.iter(f"{{{_NS['m']}}}t"))
    v = c.find("m:v", _NS)
    raw = v.text if v is not None and v.text is not None else ""
    if kind == "s":
        try:
            return shared[int(raw)]
        except (ValueError, IndexError):
            return ""
    if kind == "b":
        return "TRUE" if raw == "1" else "FALSE"
    if kind == "e" or raw == "":
        return ""
    if kind == "n":
        try:
            number = float(raw)
        except ValueError:
            return raw
        if int(c.get("s", "0")) in date_styles:
            moment = epoch + timedelta(days=number)
            moment = moment.replace(microsecond=round(moment.microsecond / 1000) * 1000 % 1_000_000)
            return moment.isoformat(sep=" ") if number % 1 else moment.date().isoformat()
        return str(int(number)) if number.is_integer() and abs(number) < 2**53 else raw
    return raw  # str (formula result) and anything else


def read_excel(path: Path | str) -> SanitisedTable:
    """The first sheet of an .xlsx workbook, read with the standard library only."""
    path = Path(path)
    report = SanitiseReport(file=path.name, encoding="utf-8", delimiter=None, path=report_key(path))
    try:
        rows = _xlsx_rows(path, report)
        header = next(rows, None)
        while header is not None and not _non_blank(header):
            header = next(rows, None)
            report.first_row += 1
        frame = pl.DataFrame() if header is None else _frame_from_records(header, rows, report)
    except (zipfile.BadZipFile, KeyError, ElementTree.ParseError) as exc:
        raise UnreadableFile(f"{path.name}: not a readable .xlsx workbook ({exc})") from None
    _record(report)
    return SanitisedTable(frame, report)


# --------------------------------------------------------------------------- value parsers

_ORDINAL = re.compile(r"\b(\d{1,2})(st|nd|rd|th)\b", re.IGNORECASE)
_UTC_SUFFIX = re.compile(r"\s*(utc|gmt|z)$", re.IGNORECASE)
_TIMES = ("%H:%M:%S.%f", "%H:%M:%S", "%H:%M", "%I:%M:%S %p", "%I:%M %p", "%I:%M:%S%p", "%I:%M%p")
_NAMED_DATES = (
    "%b %d %Y",
    "%B %d %Y",
    "%d %b %Y",
    "%d %B %Y",
    "%d-%b-%Y",
    "%d-%B-%Y",
    "%Y-%b-%d",
    "%a %b %d %Y",
)
_YMD_DATES = ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%Y%m%d")
# Numeric dates where day and month can trade places: parsed only when the reading is unique.
_DMY_DATES = ("%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y")
_MDY_DATES = ("%m/%d/%Y", "%m-%d-%Y", "%m.%d.%Y")
_EPOCH_RANGE = (
    datetime(1990, 1, 1, tzinfo=UTC).timestamp(),
    datetime(2100, 1, 1, tzinfo=UTC).timestamp(),
)


def _with_times(dates: tuple[str, ...]) -> list[str]:
    return [f"{d} {t}" for d in dates for t in _TIMES] + list(dates)


_UNAMBIGUOUS_FORMATS = (
    _with_times(_NAMED_DATES)
    + _with_times(_YMD_DATES)
    + [f"{d}T{t}" for d in _YMD_DATES for t in _TIMES[:3]]
)
_DMY_FORMATS = _with_times(_DMY_DATES)
_MDY_FORMATS = _with_times(_MDY_DATES)


def _try_formats(text: str, formats: list[str]) -> datetime | None:
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_datetime_text(value: Any) -> datetime | None:
    """A timestamp written in any common way, or None.

    Handles ISO 8601 (with or without offset), "Oct 1st 2026 22:53:09", "1 Oct 2026",
    "Oct 1, 2026 10:53 PM", ctime, a trailing "UTC"/"Z", and epoch seconds or milliseconds
    (10 or 13 digits, 1990-2100). A numeric date that reads differently day-first and
    month-first ("03/04/2026") is ambiguous and gives None: a source mapping states the format
    for such exports. The result is timezone-aware only when the text carries an offset.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{10}(\.\d+)?|\d{13}", text):
        seconds = float(text) / (1000.0 if len(text) == 13 else 1.0)
        if _EPOCH_RANGE[0] <= seconds <= _EPOCH_RANGE[1]:
            return datetime.fromtimestamp(seconds, tz=UTC)
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        pass
    utc = bool(_UTC_SUFFIX.search(text))
    cleaned = _UTC_SUFFIX.sub("", text)
    cleaned = _ORDINAL.sub(r"\1", cleaned)
    cleaned = re.sub(r"\s*,\s*", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    parsed = _try_formats(cleaned, _UNAMBIGUOUS_FORMATS)
    if parsed is None:
        day_first = _try_formats(cleaned, _DMY_FORMATS)
        month_first = _try_formats(cleaned, _MDY_FORMATS)
        if day_first and month_first and day_first != month_first:
            return None
        parsed = day_first or month_first
    if parsed is None:
        # ctime: "Thu Oct  1 22:53:09 2026"
        parsed = _try_formats(cleaned, ["%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Y"])
    if parsed is None:
        return None
    return parsed.replace(tzinfo=UTC) if utc else parsed


_TRUE = frozenset({"true", "t", "yes", "y", "1", "on"})
_FALSE = frozenset({"false", "f", "no", "n", "0", "off"})


def parse_bool(value: Any) -> bool | None:
    """Yes/No, True/False, Y/N, 1/0, On/Off (any case); None for anything else."""
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


_GROUPED_WESTERN = re.compile(r"-?\d{1,3}(,\d{3})+(\.\d+)?")
_GROUPED_INDIAN = re.compile(r"-?\d{1,2}(,\d{2})+,\d{3}(\.\d+)?")


def parse_number(value: Any) -> int | float | None:
    """A number, allowing thousands separators (1,234,567 and 12,34,567) and spaces; else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    if value is None:
        return None
    text = str(value).strip().replace(" ", "").replace(" ", "").replace("_", "")
    if _GROUPED_WESTERN.fullmatch(text) or _GROUPED_INDIAN.fullmatch(text):
        text = text.replace(",", "")
    try:
        return int(text)
    except ValueError:
        pass
    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def parse_literal(value: Any) -> Any:
    """A JSON or Python literal written in a cell (`{'total_duration': 1295}`, `['TA0001']`).

    Python literals are evaluated with `ast.literal_eval`, which builds values and never runs
    code. Anything that is not a dict or list literal is returned unchanged.
    """
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in "[{" or len(text) > LITERAL_MAX_CHARS:
        return value
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return value
