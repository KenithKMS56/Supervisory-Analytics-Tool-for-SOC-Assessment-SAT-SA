"""Tests for validation harness and ground-truth evaluation."""

from pathlib import Path

from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.validate.harness import (
    ShadowPilotAdapter,
    ValidationHarness,
    assign_ranks,
    compute_spearman_rank_corr,
)


def test_spearman_rank_corr():
    # Identical ranks -> 1.0
    r1 = [1.0, 2.0, 3.0, 4.0, 5.0]
    r2 = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert compute_spearman_rank_corr(r1, r2) == 1.0

    # Inverted ranks -> -1.0
    r3 = [5.0, 4.0, 3.0, 2.0, 1.0]
    assert compute_spearman_rank_corr(r1, r3) == -1.0


def test_assign_ranks():
    vals = [100.0, 50.0, 50.0, 10.0]
    ranks = assign_ranks(vals, reverse=True)
    # Highest is 100 -> rank 1.0; next two are 50.0 -> average of 2 and 3 = 2.5; 10.0 -> 4.0
    assert ranks[0] == 1.0
    assert ranks[1] == 2.5
    assert ranks[2] == 2.5
    assert ranks[3] == 4.0


def test_validation_harness(tmp_path: Path):
    duckdb_store = DuckDBStore("data")
    duckdb_store.load_all_tables()
    sqlite_store = SQLiteStore("data/satsa.db")

    harness = ValidationHarness(duckdb_store, sqlite_store, "data/generated/ground_truth.json")
    results = harness.run_full_validation()

    assert "entity_ranking" in results
    assert results["entity_ranking"]["precision_at_k"] == 1.0
    assert results["entity_ranking"]["recall_at_k"] == 1.0

    assert "rule_detection" in results
    assert results["rule_detection"]["overall_recall"] >= 0.9

    assert "review_effort_lift" in results
    assert "1%" in results["review_effort_lift"]["budgets"]
    assert results["review_effort_lift"]["budgets"]["1%"]["lift_factor"] > 1.0

    assert "stability" in results
    assert results["stability"]["is_stable"] is True

    # Report generation
    md_file = tmp_path / "test_report.md"
    html_file = tmp_path / "test_report.html"
    res_md, res_html = harness.generate_report(md_file, html_file)
    assert res_md.exists()
    assert res_html.exists()

    duckdb_store.close()
    sqlite_store.close()


def test_shadow_pilot_adapter(tmp_path: Path):
    sqlite_store = SQLiteStore("data/satsa.db")
    adapter = ShadowPilotAdapter(sqlite_store)

    # Write temporary shadow pilot CSV
    csv_file = tmp_path / "shadow_reviews.csv"
    csv_file.write_text(
        "entity_id,record_id,rule_id,label\n"
        "CSE-02,,EG10,confirmed\n"
        "CSE-03,CSE03-ALT-000001,EG01,confirmed\n"
        "CSE-05,,NS01,confirmed\n",
        encoding="utf-8",
    )

    reviews = adapter.load_manual_reviews(csv_file)
    assert len(reviews) == 3

    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1")
    run_row = cur.fetchone()
    run_id = run_row["run_id"] if run_row else ""

    res = adapter.evaluate_shadow_pilot(reviews, run_id)
    assert res["status"] == "success"
    assert res["total_confirmed_issues"] == 3
    assert res["rule_finding_recall"] == 1.0

    sqlite_store.close()
