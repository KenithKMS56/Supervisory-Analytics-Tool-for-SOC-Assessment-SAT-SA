"""Genuine multi-period historical re-scoring for the portfolio trend chart.

The portfolio dashboard used to plot a "risk trajectory" trend by multiplying
an entity's CURRENT risk_index by hardcoded constants (0.82, 0.94, 1.25, ...)
with a couple of entities' points hardcoded outright. That was fabricated
data labeled with real-looking period names.

This module replaces that fabrication with a real (if approximate) mechanism:
it takes the alert/case data that has actually been ingested, splits its
observed timeline into N chronological windows, and re-runs the same
deterministic rule engine against each window's real data subset. Each
window produces a genuine EntityScore, persisted exactly like any other
assessment run and tagged with a period label derived from that window's
calendar quarter. The portfolio route then queries these real historical
runs (see `satsa.api.routes.view_portfolio`) instead of synthesizing points.

Each window is a cumulative selection (satsa.scoring.selection, mode `cumulative`): every
record created before the window's cutoff, as it was known at the cutoff -- a closure,
acknowledgement or escalation acknowledgement after the cutoff is masked, so an alert closed
later is open at the cutoff. The same selection service is used by every assessment, so these
points use exactly the rules a period assessment uses (docs/analytics_methodology.md).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from satsa.scoring.runner import AssessmentRunner
from satsa.scoring.selection import CUMULATIVE, AssessmentWindow
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def period_label_for(dt: datetime) -> str:
    """Derive a calendar-quarter period label (e.g. '2026-Q1') from a real timestamp."""
    quarter = (dt.month - 1) // 3 + 1
    return f"{dt.year}-Q{quarter}"


def _as_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    to_pydatetime = getattr(value, "to_pydatetime", None)
    if to_pydatetime:
        return to_pydatetime()
    return None


def seed_historical_periods(
    data_dir: str | Any,
    sqlite_store: SQLiteStore,
    n_periods: int = 3,
    actor: str = "system",
) -> list[dict[str, Any]]:
    """Compute and persist N genuine historical assessment runs.

    Splits the already-ingested alert timeline into `n_periods` chronological
    windows (earliest to latest) and runs the real deterministic rule and
    scoring engine against each window's actual data subset. Returns the
    list of run results (same shape as `AssessmentRunner.run_assessment`),
    each additionally tagged with its computed `period` label.

    Returns an empty list if there is no alert data to window (e.g. an empty
    deployment) -- it never fabricates points to fill the gap.
    """
    data_dir_str = str(data_dir)
    results: list[dict[str, Any]] = []

    probe = DuckDBStore(data_dir_str)
    probe.load_all_tables()
    range_df = probe.query("SELECT min(created_at) as min_ts, max(created_at) as max_ts FROM alert")
    probe.close()

    if range_df.is_empty() or range_df["min_ts"][0] is None:
        return results

    min_ts = _as_datetime(range_df["min_ts"][0])
    max_ts = _as_datetime(range_df["max_ts"][0])
    if min_ts is None or max_ts is None:
        return results

    total_seconds = (max_ts - min_ts).total_seconds()
    if total_seconds <= 0 or n_periods < 1:
        return results

    window_seconds = total_seconds / n_periods
    used_labels: dict[str, int] = {}

    store = DuckDBStore(data_dir_str)
    snapshot = store.catalog.max_pub_seq()  # every window reads the same published data
    try:
        for i in range(n_periods):
            cutoff = min_ts + timedelta(seconds=window_seconds * (i + 1))
            base_label = period_label_for(cutoff)
            # A short dataset window can put two chronologically-distinct cutoffs
            # in the same real calendar quarter (e.g. a 6-month dataset split
            # into 3 periods puts windows 2 and 3 both in the same quarter).
            # Disambiguate with a real cutoff-date suffix rather than silently
            # producing two identically-labeled x-axis points.
            if base_label in used_labels:
                used_labels[base_label] += 1
                period_label = f"{base_label} (as of {cutoff.date().isoformat()})"
            else:
                used_labels[base_label] = 1
                period_label = base_label
            # Records at or before the cutoff (the window's end is exclusive).
            window = AssessmentWindow(
                mode=CUMULATIVE,
                end=cutoff + timedelta(microseconds=1),
                max_pub_seq=snapshot,
                label=period_label,
            )
            res = AssessmentRunner(store, sqlite_store).run_assessment(
                period=period_label,
                actor=actor,
                record_data_gaps=False,
                reference_date=cutoff,
                window=window,
            )
            res["period"] = period_label
            results.append(res)
    finally:
        store.close()

    return results
