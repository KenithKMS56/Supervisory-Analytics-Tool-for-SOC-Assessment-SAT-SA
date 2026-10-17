"""Which data an assessment reads: one selection service for the runner, CLI, API and history.

An assessment covers an explicit window of operational time, [start, end), and reads the
submitted data as it was known at a point in the publication sequence (`max_pub_seq`, the
"source snapshot"). Both are recorded in the run, so the same assessment can be replayed later
even after corrections arrive.

Per-table rules (a blanket date filter on every table would be wrong):

- `alert`: created in the window. Anything that happened to it at or after `end`
  (acknowledgement, first touch, closure) is not yet known at `end`: those fields are cleared and
  a closure after `end` leaves the alert open.
- `case`: carried into the window: opened before `end` and not closed before `start` (the
  backlog). A closure at or after `end` leaves it open.
- `case_alert_link`, `closure`: belong to a selected alert or case (a closure only if the
  parent's closure falls inside the selection).
- `workflow_event`, `escalation`: before `end`, and inside the window or about a selected
  alert/case. An escalation acknowledged at or after `end` is unacknowledged at `end`.
- `remediation`: open at some point in the window; a closure at or after `end` is cleared.
- `external_report`: filed before `end`.
- `log_source_daily`: days inside the window.
- `declared_kpi`: rows whose own period overlaps the window (or names no parseable period).
- `detection_rule`: a `last_fired` at or after `end` is cleared (not known at `end`).
- `asset`, `entity`, `sla_policy`: the latest version known in the source snapshot (inventory
  has no effective dates yet; see docs/data_contract.md).

Rows with no timestamp in a time-anchored table cannot be placed in a period: they are left
out of a windowed assessment and counted in the run manifest (`undated_excluded`).

`mode="all_submitted"` is the explicit cumulative mode: no lower bound, every record known,
nothing masked. It is what an assessment without a period uses, and it says so.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

from satsa.store.duckdb import DuckDBStore

PERIOD_LABEL_RE = re.compile(r"^(?P<year>\d{4})(?:-(?:Q(?P<q>[1-4])|H(?P<h>[12])|(?P<m>0[1-9]|1[0-2])))?$")

WINDOWED = "window"
CUMULATIVE = "cumulative"  # no lower bound, masked at `end` (trend history)
ALL_SUBMITTED = "all_submitted"  # every record, unmasked: explicit, never implied by a period


@dataclass(frozen=True)
class AssessmentWindow:
    """The operational time an assessment covers and the source snapshot it reads."""

    mode: str = ALL_SUBMITTED
    start: datetime | None = None
    end: datetime | None = None  # exclusive
    max_pub_seq: int | None = None  # source snapshot: published batches up to this sequence
    label: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in (WINDOWED, CUMULATIVE, ALL_SUBMITTED):
            raise ValueError(f"unknown selection mode {self.mode!r}")
        if self.mode == WINDOWED and (self.start is None or self.end is None):
            raise ValueError("a windowed assessment needs a start and an end")
        if self.mode == CUMULATIVE and self.end is None:
            raise ValueError("a cumulative assessment needs an end")
        if self.start is not None and self.end is not None and self.start >= self.end:
            raise ValueError("the window must end after it starts")

    @property
    def masks(self) -> bool:
        return self.mode in (WINDOWED, CUMULATIVE)

    def describe(self) -> str:
        if self.mode == ALL_SUBMITTED:
            return "all submitted data (cumulative, no period filter)"
        start = self.start.date().isoformat() if self.start else "beginning"
        assert self.end is not None
        last = (self.end - timedelta(microseconds=1)).date().isoformat()
        return f"{start} to {last} inclusive" + (" (cumulative)" if self.mode == CUMULATIVE else "")

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["start"] = self.start.isoformat() if self.start else None
        d["end_exclusive"] = self.end.isoformat() if self.end else None
        d.pop("end")
        d["description"] = self.describe()
        return d


def period_bounds(label: str) -> tuple[datetime, datetime] | None:
    """[start, end) of a review-period label: `2026`, `2026-Q1`, `2026-H2` or `2026-03` (UTC)."""
    m = PERIOD_LABEL_RE.match(label.strip())
    if not m:
        return None
    year = int(m["year"])
    if m["q"]:
        first, months = (int(m["q"]) - 1) * 3 + 1, 3
    elif m["h"]:
        first, months = (int(m["h"]) - 1) * 6 + 1, 6
    elif m["m"]:
        first, months = int(m["m"]), 1
    else:
        first, months = 1, 12
    start = datetime(year, first, 1)
    end_month = first + months
    end = datetime(year + (end_month - 1) // 12, (end_month - 1) % 12 + 1, 1)
    return start, end


def window_for_period(label: str | None, max_pub_seq: int | None = None) -> AssessmentWindow:
    """The window a period label names; an absent or non-period label means all submitted data."""
    bounds = period_bounds(label) if label else None
    if bounds is None:
        return AssessmentWindow(mode=ALL_SUBMITTED, max_pub_seq=max_pub_seq, label=label)
    return AssessmentWindow(mode=WINDOWED, start=bounds[0], end=bounds[1], max_pub_seq=max_pub_seq, label=label)


def apply_window(store: DuckDBStore, window: AssessmentWindow) -> dict[str, Any]:
    """Restrict the store's loaded tables to the window, in place. Returns what was excluded."""
    report: dict[str, Any] = {"mode": window.mode, "excluded_rows": {}, "undated_excluded": {}, "masked": {}}
    if not window.masks:
        return report
    end = window.end
    assert end is not None  # masks implies an end (see AssessmentWindow.__post_init__)
    start = window.start
    lower = start is not None

    def count(sql: str, params: list[Any]) -> int:
        df = store.query(sql, params)
        return int(df.row(0)[0]) if not df.is_empty() else 0

    def delete(table: str, where: str, params: list[Any]) -> None:
        q = f'"{table}"'
        n = count(f"SELECT count(*) FROM {q} WHERE {where}", params)
        if n:
            store.execute(f"DELETE FROM {q} WHERE {where}", params)
            report["excluded_rows"][table] = report["excluded_rows"].get(table, 0) + n

    def undated(table: str, column: str) -> None:
        q = f'"{table}"'
        n = count(f"SELECT count(*) FROM {q} WHERE {column} IS NULL", [])
        if n:
            store.execute(f"DELETE FROM {q} WHERE {column} IS NULL")
            report["undated_excluded"][table] = n

    def mask(table: str, column: str, also: dict[str, Any] | None = None) -> None:
        q = f'"{table}"'
        n = count(f"SELECT count(*) FROM {q} WHERE {column} >= ?", [end])
        if not n:
            return
        sets = [f"{column} = NULL"] + [f'"{c}" = {v}' for c, v in (also or {}).items()]
        store.execute(f"UPDATE {q} SET {', '.join(sets)} WHERE {column} >= ?", [end])
        report["masked"][f"{table}.{column}"] = n

    # Alerts created in the window.
    undated("alert", "created_at")
    delete("alert", "created_at >= ?" + (" OR created_at < ?" if lower else ""), [end, start] if lower else [end])
    mask(
        "alert",
        "closed_at",
        {"closed_by": "NULL", "closed_by_type": "NULL", "disposition": "NULL", "playbook_id": "NULL", "status": "'open'"},
    )
    mask("alert", "acknowledged_at")
    mask("alert", "first_touch_at")

    # Cases carried into the window.
    undated("case", "opened_at")
    delete(
        "case",
        "opened_at >= ?" + (" OR (closed_at IS NOT NULL AND closed_at < ?)" if lower else ""),
        [end, start] if lower else [end],
    )
    mask("case", "closed_at", {"status": "'open'"})

    sel = (
        "(ref_id IN (SELECT alert_id FROM alert) OR ref_id IN (SELECT case_id FROM \"case\"))"
    )
    delete(
        "case_alert_link",
        "case_id NOT IN (SELECT case_id FROM \"case\") AND alert_id NOT IN (SELECT alert_id FROM alert)",
        [],
    )
    # A closure belongs to a parent closed inside the selection.
    delete(
        "closure",
        "ref_id NOT IN (SELECT alert_id FROM alert WHERE closed_at IS NOT NULL) "
        "AND ref_id NOT IN (SELECT case_id FROM \"case\" WHERE closed_at IS NOT NULL)",
        [],
    )
    for table, ts in (("workflow_event", "ts"), ("escalation", "escalated_at")):
        cond = f"({ts} IS NULL AND NOT {sel}) OR {ts} >= ?"
        params: list[Any] = [end]
        if lower:
            cond += f" OR ({ts} < ? AND NOT {sel})"
            params.append(start)
        delete(table, cond, params)
    mask("escalation", "acknowledged_at")

    delete(
        "remediation",
        "created_at IS NULL OR created_at >= ?" + (" OR (closed_at IS NOT NULL AND closed_at < ?)" if lower else ""),
        [end, start] if lower else [end],
    )
    mask("remediation", "closed_at")
    delete("external_report", "reported_at IS NULL OR reported_at >= ?", [end])

    undated("log_source_daily", "date")
    delete(
        "log_source_daily",
        "date >= CAST(? AS DATE)" + (" OR date < CAST(? AS DATE)" if lower else ""),
        [end, start] if lower else [end],
    )
    mask("detection_rule", "last_fired")

    # Declared KPIs: keep rows whose own period overlaps the window.
    kpis = store.query("SELECT DISTINCT period FROM declared_kpi WHERE period IS NOT NULL")
    drop = []
    for label in kpis["period"].to_list() if not kpis.is_empty() else []:
        bounds = period_bounds(str(label))
        if bounds is None:
            continue
        if bounds[1] <= (start or bounds[0]) or bounds[0] >= end:
            drop.append(label)
    if drop:
        delete("declared_kpi", f"period IN ({', '.join('?' for _ in drop)})", drop)
    return report
