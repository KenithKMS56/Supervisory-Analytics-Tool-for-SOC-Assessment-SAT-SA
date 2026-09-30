"""Tests that the portfolio trend chart uses REAL historical run data, never fabricated points."""

from fastapi.testclient import TestClient

from satsa.api.routes import _build_real_trend_series, app
from satsa.scoring.history import period_label_for, seed_historical_periods
from satsa.store.sqlite import SQLiteStore

client = TestClient(app)


def test_trend_series_never_contains_hardcoded_fabricated_points():
    """The old implementation hardcoded CSE-02 -> [32.0, 49.5, curr] and CSE-06 -> [59.0, 58.0, curr]
    and multiplied every other entity's current risk_index by constants (0.82, 0.94, 1.25, 1.10).
    None of that fabrication logic should remain reachable from the route.
    """
    resp = client.get("/")
    assert resp.status_code == 200
    # The fabricated hardcoded quarter labels must be gone.
    assert "2025-Q3 (Baseline)" not in resp.text
    assert "2025-Q4 (Interim)" not in resp.text
    assert "2026-Q1 (Current)" not in resp.text


def test_insufficient_history_reported_not_synthesized():
    """An entity with 0 or 1 real historical runs must be marked insufficient_history
    with an empty data list -- never padded with interpolated/synthesized values.
    """
    store = SQLiteStore("data/satsa.db")
    cur = store.conn.cursor()

    # An entity id that has never had any run at all.
    _periods, series, _has_data = _build_real_trend_series(cur, ["CSE-ZZ-NONEXISTENT"], [])
    store.close()

    assert len(series) == 1
    assert series[0]["insufficient_history"] is True
    assert series[0]["data"] == []


def test_period_label_derivation_is_real_not_hardcoded():
    from datetime import datetime

    assert period_label_for(datetime(2026, 1, 15)) == "2026-Q1"
    assert period_label_for(datetime(2026, 4, 1)) == "2026-Q2"
    assert period_label_for(datetime(2025, 11, 30)) == "2025-Q4"


def test_seed_historical_periods_produces_real_distinct_runs():
    store = SQLiteStore("data/satsa.db")
    cur = store.conn.cursor()
    cur.execute("SELECT count(*) FROM runs")
    before_count = cur.fetchone()[0]

    run_ids: list[str] = []
    try:
        results = seed_historical_periods("data", store, n_periods=3, actor="test-suite")
        assert len(results) == 3
        # Each seeded period must have produced a genuinely distinct run_id.
        run_ids = [r["run_id"] for r in results]
        assert len(set(run_ids)) == 3

        cur.execute("SELECT count(*) FROM runs")
        after_count = cur.fetchone()[0]
        assert after_count == before_count + 3

        # Now the portfolio trend should have real multi-period data for at least
        # one of the top entities.
        cur.execute("SELECT entity_id FROM entity_scores WHERE run_id = ?", (run_ids[-1],))
        entity_ids = [r["entity_id"] for r in cur.fetchall()]
        assert entity_ids
        _periods, series, has_data = _build_real_trend_series(cur, entity_ids[:3], [])
        assert has_data is True
        assert any(not s["insufficient_history"] for s in series)
    finally:
        for rid in run_ids:
            cur.execute("DELETE FROM runs WHERE run_id = ?", (rid,))
            cur.execute("DELETE FROM entity_scores WHERE run_id = ?", (rid,))
            cur.execute("DELETE FROM domain_scores WHERE run_id = ?", (rid,))
            cur.execute("DELETE FROM findings WHERE run_id = ?", (rid,))
            cur.execute("DELETE FROM review_queue WHERE run_id = ?", (rid,))
        store.conn.commit()
        store.close()


def test_seed_historical_periods_empty_store_returns_no_fabrication():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        empty_store = SQLiteStore(Path(tmpdir) / "empty.db")
        results = seed_historical_periods(Path(tmpdir) / "no_data", empty_store, n_periods=3)
        empty_store.close()
        assert results == []


def test_historical_periods_assess_their_own_window_not_the_full_dataset():
    """Each seeded period must see only the data up to its cutoff. run_assessment used to
    reload every table from Parquet, undoing the truncation: all periods were the full run
    under different labels. CSE-05's critical asset goes silent on 10 March, so NS01 must be
    absent from the first window (which ends around 1 March) and present in the last."""
    store = SQLiteStore("data/satsa.db")
    cur = store.conn.cursor()
    dq_before = cur.execute("SELECT issue_id, details FROM dq_issues ORDER BY issue_id").fetchall()
    run_ids: list[str] = []
    try:
        results = seed_historical_periods("data", store, n_periods=3, actor="test-suite")
        run_ids = [r["run_id"] for r in results]

        def rules(run_id: str, entity_id: str) -> set[str]:
            rows = cur.execute(
                "SELECT rule_id FROM findings WHERE run_id = ? AND entity_id = ?", (run_id, entity_id)
            ).fetchall()
            return {r["rule_id"] for r in rows}

        first, last = run_ids[0], run_ids[-1]
        assert "NS01" not in rules(first, "CSE-05") and "NS01" in rules(last, "CSE-05")
        # A partial window is not an incomplete submission: clean entities stay clean.
        assert rules(first, "CSE-01") == set() and rules(last, "CSE-01") == set()
        indices = [
            cur.execute(
                "SELECT risk_index FROM entity_scores WHERE run_id = ? AND entity_id = 'CSE-02'", (rid,)
            ).fetchone()["risk_index"]
            for rid in run_ids
        ]
        assert len(set(indices)) > 1, "every period has the same risk index: windows are not applied"
        # Historical runs must not rewrite the DQ view, which describes the current submission.
        dq_after = cur.execute("SELECT issue_id, details FROM dq_issues ORDER BY issue_id").fetchall()
        assert [tuple(r) for r in dq_after] == [tuple(r) for r in dq_before]
    finally:
        for rid in run_ids:
            for table in ("runs", "entity_scores", "domain_scores", "findings", "review_queue"):
                cur.execute(f"DELETE FROM {table} WHERE run_id = ?", (rid,))
        store.conn.commit()
        store.close()
