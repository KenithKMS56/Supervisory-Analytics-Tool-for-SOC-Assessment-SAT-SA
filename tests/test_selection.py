"""The assessment selection service (satsa.scoring.selection): period labels, window boundaries,
masking of what happened after the window, and record versions."""

from __future__ import annotations

from datetime import datetime

import polars as pl
import pytest

from satsa.scoring.selection import (
    ALL_SUBMITTED,
    CUMULATIVE,
    WINDOWED,
    AssessmentWindow,
    apply_window,
    period_bounds,
    window_for_period,
)
from satsa.store.duckdb import DuckDBStore


@pytest.mark.parametrize(
    ("label", "start", "end"),
    [
        ("2026", datetime(2026, 1, 1), datetime(2027, 1, 1)),
        ("2026-Q1", datetime(2026, 1, 1), datetime(2026, 4, 1)),
        ("2026-Q4", datetime(2026, 10, 1), datetime(2027, 1, 1)),
        ("2026-H2", datetime(2026, 7, 1), datetime(2027, 1, 1)),
        ("2026-02", datetime(2026, 2, 1), datetime(2026, 3, 1)),
        ("2026-12", datetime(2026, 12, 1), datetime(2027, 1, 1)),
    ],
)
def test_period_labels_name_half_open_windows(label, start, end):
    assert period_bounds(label) == (start, end)
    window = window_for_period(label)
    assert (window.mode, window.start, window.end) == (WINDOWED, start, end)


@pytest.mark.parametrize("label", [None, "", "GOLDEN", "STRESS", "2026-Q5", "2026-13", "26-Q1"])
def test_a_label_that_names_no_period_assesses_all_submitted_data_and_says_so(label):
    window = window_for_period(label)
    assert window.mode == ALL_SUBMITTED
    assert window.describe() == "all submitted data (cumulative, no period filter)"


def test_windows_must_be_well_formed():
    with pytest.raises(ValueError):
        AssessmentWindow(mode=WINDOWED, start=datetime(2026, 4, 1), end=datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        AssessmentWindow(mode=WINDOWED, start=datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        AssessmentWindow(mode=CUMULATIVE)
    assert window_for_period("2026-Q1").describe() == "2026-01-01 to 2026-03-31 inclusive"


def _store(tmp_path) -> DuckDBStore:
    store = DuckDBStore(tmp_path)
    store.execute(
        """
        INSERT INTO alert (entity_id, alert_id, created_at, acknowledged_at, closed_at, closed_by, disposition, status)
        VALUES
          ('E1', 'LAST-SECOND', '2026-03-31 23:59:59', NULL, NULL, NULL, NULL, 'open'),
          ('E1', 'NEXT-QUARTER', '2026-04-01 00:00:00', NULL, NULL, NULL, NULL, 'open'),
          ('E1', 'BEFORE', '2025-12-31 23:59:59', NULL, NULL, NULL, NULL, 'open'),
          ('E1', 'CLOSED-LATER', '2026-03-30 10:00:00', '2026-04-02 09:00:00', '2026-04-03 09:00:00',
                 'ANALYST-1', 'true_positive', 'closed'),
          ('E1', 'CLOSED-INSIDE', '2026-03-01 10:00:00', '2026-03-01 10:05:00', '2026-03-01 11:00:00',
                 'ANALYST-1', 'false_positive', 'closed'),
          ('E1', 'UNDATED', NULL, NULL, NULL, NULL, NULL, 'open')
        """
    )
    store.execute(
        """
        INSERT INTO "case" (entity_id, case_id, opened_at, closed_at, status) VALUES
          ('E1', 'BACKLOG', '2025-11-01 00:00:00', NULL, 'open'),
          ('E1', 'CLOSED-BEFORE', '2025-11-01 00:00:00', '2025-12-01 00:00:00', 'closed'),
          ('E1', 'OPENED-AFTER', '2026-04-05 00:00:00', NULL, 'open')
        """
    )
    store.execute(
        "INSERT INTO closure (entity_id, ref_id, disposition) VALUES ('E1', 'CLOSED-LATER', 'true_positive'), "
        "('E1', 'CLOSED-INSIDE', 'false_positive')"
    )
    return store


def test_a_quarter_selects_by_creation_time_and_masks_what_happened_after_it(tmp_path):
    store = _store(tmp_path)
    report = apply_window(store, window_for_period("2026-Q1"))
    alerts = {
        r[0]: r[1:]
        for r in store.query("SELECT alert_id, closed_at, acknowledged_at, closed_by, disposition, status FROM alert").rows()
    }
    cases = store.query('SELECT case_id, status FROM "case" ORDER BY case_id').rows()
    closures = store.query("SELECT ref_id FROM closure").rows()
    store.close()

    assert set(alerts) == {"LAST-SECOND", "CLOSED-LATER", "CLOSED-INSIDE"}
    # Closed after the quarter: at the end of Q1 it was open and unacknowledged.
    assert alerts["CLOSED-LATER"] == (None, None, None, None, "open")
    assert alerts["CLOSED-INSIDE"][3:] == ("false_positive", "closed")
    assert cases == [("BACKLOG", "open")]  # the backlog is carried in; closed-before and opened-after are not
    assert closures == [("CLOSED-INSIDE",)]
    assert report["undated_excluded"] == {"alert": 1}
    assert report["masked"]["alert.closed_at"] == 1


def test_all_submitted_changes_nothing(tmp_path):
    store = _store(tmp_path)
    before = store.query("SELECT * FROM alert ORDER BY alert_id")
    report = apply_window(store, window_for_period(None))
    after = store.query("SELECT * FROM alert ORDER BY alert_id")
    store.close()
    assert report["excluded_rows"] == {} and before.equals(after)


def test_a_cumulative_window_has_no_lower_bound(tmp_path):
    store = _store(tmp_path)
    apply_window(store, AssessmentWindow(mode=CUMULATIVE, end=datetime(2026, 4, 1)))
    ids = set(store.query("SELECT alert_id FROM alert")["alert_id"].to_list())
    store.close()
    assert ids == {"BEFORE", "LAST-SECOND", "CLOSED-LATER", "CLOSED-INSIDE"}


def test_a_correction_in_a_later_batch_replaces_the_record_and_one_batch_keeps_its_own_rows(tmp_path):
    store = DuckDBStore(tmp_path)
    store.write_partitioned_parquet(
        "alert",
        pl.DataFrame({"entity_id": ["E1"] * 3, "alert_id": ["A1", "A2", "A2"], "status": ["open", "open", "closed"]}),
    )
    first = sorted(store.query("SELECT alert_id, status FROM alert").rows())
    store.write_partitioned_parquet("alert", pl.DataFrame({"entity_id": ["E1"], "alert_id": ["A1"], "status": ["closed"]}))
    second = sorted(store.query("SELECT alert_id, status FROM alert").rows())
    store.close()
    # Two rows of A2 in one submission are both kept (ingestion reports the duplicate id).
    assert first == [("A1", "open"), ("A2", "closed"), ("A2", "open")]
    # The later batch's A1 replaces the earlier version instead of being counted beside it.
    assert second == [("A1", "closed"), ("A2", "closed"), ("A2", "open")]
