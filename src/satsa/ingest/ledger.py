"""What became of every submitted file and every row in it.

A row that cannot be stored (no entity, a required field the mapping cannot fill) is not kept:
its other cells may hold names, comments or addresses that the pipeline only ever stores
pseudonymised or redacted. What is kept is where it was: the file, the reason and the row as
the file numbers it (a spreadsheet's row, a JSON record or an NDJSON line), so the entity can
correct its export and submit again. Nothing is left out of the count, so a supervisor can see
how much of a submission the assessment actually rests on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Row numbers kept per reason; the count is always exact.
ROW_SAMPLE = 1000
# Ranges spelled out in a summary before "and N more".
RANGES_SHOWN = 12


def compress_rows(rows: list[int], limit: int = RANGES_SHOWN) -> str:
    """'4-9, 15, 22-26' for [4..9, 15, 22..26], with at most `limit` ranges spelled out."""
    ranges: list[tuple[int, int]] = []
    for n in sorted(set(rows)):
        if ranges and n == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], n)
        else:
            ranges.append((n, n))
    text = ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges[:limit])
    if len(ranges) > limit:
        text += f" and {len(ranges) - limit} more range(s)"
    return text


@dataclass
class Rejected:
    """Rows set aside for one reason: an exact count, and the first ROW_SAMPLE row numbers."""

    count: int = 0
    rows: list[int] = field(default_factory=list)

    def add(self, count: int, rows: list[int]) -> None:
        self.count += count
        self.rows.extend(rows[: max(0, ROW_SAMPLE - len(self.rows))])

    def where(self, label: str) -> str:
        if not self.rows:
            return ""
        shown = compress_rows(self.rows)
        more = " (first ones listed)" if self.count > len(self.rows) else ""
        return f"{label}s {shown}{more}"


@dataclass
class FileLedger:
    """One submitted file: rows read, stored per table, filtered out on purpose, set aside."""

    file: str
    status: str = "ingested"
    rows_read: int = 0
    row_label: str = "row"
    stored: dict[str, int] = field(default_factory=dict)
    # Rows the mapping leaves out of a table on purpose: its `where:` excludes them, or they
    # lack a field that table requires but another table of the file took them.
    filtered: dict[str, int] = field(default_factory=dict)
    rejected: dict[str, Rejected] = field(default_factory=dict)
    note: str = ""

    def store(self, table: str, rows: int) -> None:
        self.stored[table] = self.stored.get(table, 0) + rows

    def reject(self, reason: str, count: int, rows: list[int]) -> None:
        if count:
            self.rejected.setdefault(reason, Rejected()).add(count, rows)
            # Reasons in a fixed order, however the rows reached them.
            self.rejected = dict(sorted(self.rejected.items()))

    @property
    def rejected_count(self) -> int:
        return sum(r.count for r in self.rejected.values())

    def settle(self) -> None:
        """The status once every row is accounted for."""
        if self.status != "ingested":
            return
        if self.rows_read == 0:
            self.status = "empty"
        elif self.rejected and not any(self.stored.values()):
            self.status = "nothing stored"
        elif self.rejected:
            self.status = "partly stored"

    def summary(self) -> str:
        """One line a person can act on."""
        if self.status in ("unreadable", "not recognised", "not mapped"):
            return f"{self.file}: {self.status}" + (f" ({self.note})" if self.note else "")
        if self.status == "empty":
            return f"{self.file}: no data rows"
        stored = ", ".join(f"{n} into {t}" for t, n in self.stored.items() if n) or "none stored"
        parts = [f"{self.file}: {self.rows_read} {self.row_label}(s) read, {stored}"]
        for table, n in self.filtered.items():
            if n:
                parts.append(f"{n} not for {table} (by the mapping)")
        for reason, rejected in self.rejected.items():
            where = rejected.where(self.row_label)
            parts.append(f"{rejected.count} rejected, {reason}" + (f" ({where})" if where else ""))
        return "; ".join(parts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "status": self.status,
            "rows_read": self.rows_read,
            "row_label": self.row_label,
            "stored": dict(self.stored),
            "filtered": {t: n for t, n in self.filtered.items() if n},
            "rejected": {
                reason: {"count": r.count, "rows": compress_rows(r.rows, limit=10**9)}
                for reason, r in self.rejected.items()
            },
            "note": self.note,
            "summary": self.summary(),
        }
