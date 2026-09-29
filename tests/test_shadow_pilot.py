"""Shadow pilot: the /shadow-pilot page, stored results, and their place in the validation report."""

from urllib.parse import unquote_plus

import pytest
from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.store.sqlite import SQLiteStore
from satsa.validate.harness import ShadowPilotAdapter, shadow_html, shadow_markdown


@pytest.fixture
def analyst():
    c = TestClient(app)
    r = c.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"}, follow_redirects=False)
    assert r.status_code == 303 and "error" not in r.headers["location"]
    return c


@pytest.fixture
def latest_finding():
    store = SQLiteStore("data/satsa.db")
    run_id = store.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()[0]
    row = store.conn.execute(
        "SELECT entity_id, rule_id FROM findings WHERE run_id = ? LIMIT 1", (run_id,)
    ).fetchone()
    store.close()
    assert row, "bootstrapped data required"
    return run_id, row["entity_id"], row["rule_id"]


def test_adapter_reports_each_confirmed_row(tmp_path, latest_finding):
    run_id, entity_id, rule_id = latest_finding
    csv_file = tmp_path / "wp.csv"
    csv_file.write_text(
        "entity_id,record_id,rule_id,label\n"
        f"{entity_id},,{rule_id},confirmed\n"
        "CSE-99,,EG99,confirmed\n"
        "CSE-01,X,,not_an_issue\n",
        encoding="utf-8",
    )
    store = SQLiteStore("data/satsa.db")
    adapter = ShadowPilotAdapter(store)
    res = adapter.evaluate_shadow_pilot(adapter.load_manual_reviews(csv_file), run_id)
    store.close()
    assert res["run_id"] == run_id
    assert (res["total_manual_reviews"], res["total_confirmed_issues"], res["matched_findings"]) == (3, 2, 1)
    assert [r["in_findings"] for r in res["rows"]] == [True, False]


def test_stored_results_round_trip(tmp_path):
    store = SQLiteStore(tmp_path / "s.db")
    result = {"status": "success", "total_manual_reviews": 1}
    store.save_shadow_result("RUN-A", "analyst", "a.csv", result)
    store.save_shadow_result("RUN-B", "analyst", "b.csv", result)
    assert [r["source_name"] for r in store.list_shadow_results()] == ["b.csv", "a.csv"]
    only_a = store.list_shadow_results("RUN-A")
    assert len(only_a) == 1 and only_a[0]["result"] == result
    store.close()


def test_report_sections_show_result_and_escape_it():
    stored = {
        "source_name": "<script>x</script>.csv",
        "created_at": "2026-09-29T00:00:00+00:00",
        "actor": "analyst",
        "result": {
            "total_manual_reviews": 3,
            "total_confirmed_issues": 2,
            "rule_finding_recall": 0.5,
            "queue_record_recall": 0.0,
            "matched_findings": 1,
            "matched_queue": 0,
            "rows": [
                {"entity_id": "CSE-01", "record_id": "", "rule_id": "EG01", "in_findings": True, "in_queue": False},
                {"entity_id": "CSE-02", "record_id": "R1", "rule_id": "EG02", "in_findings": False, "in_queue": False},
            ],
        },
    }
    md = "\n".join(shadow_markdown(stored))
    assert "50.0% (1/2)" in md and "CSE-02 / EG02 (record R1)" in md
    html = shadow_html(stored)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "No shadow-pilot evaluation" in shadow_markdown(None)[0]


def test_page_upload_evaluates_and_saves(analyst, latest_finding):
    _, entity_id, rule_id = latest_finding
    csv_bytes = f"entity_id,record_id,rule_id,label\n{entity_id},,{rule_id},confirmed\n".encode()
    r = analyst.post(
        "/shadow-pilot",
        files={"workpaper": ("pilot_test_workpaper.csv", csv_bytes, "text/csv")},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "finding recall 100.0%" in unquote_plus(r.headers["location"])
    page = analyst.get("/shadow-pilot").text
    assert "pilot_test_workpaper.csv" in page and "Reproduced" in page


def test_page_rejects_workpaper_missing_columns(analyst):
    r = analyst.post(
        "/shadow-pilot",
        files={"workpaper": ("bad.csv", b"entity_id,rule_id\nCSE-01,EG01\n", "text/csv")},
        follow_redirects=False,
    )
    assert "missing column(s): label, record_id" in unquote_plus(r.headers["location"])


def test_examiner_cannot_open_shadow_pilot():
    c = TestClient(app)
    c.post("/login", data={"username": "examiner", "password": "ChangeMe-Examiner#2026"})
    assert c.get("/shadow-pilot", follow_redirects=False).status_code == 403
    assert 'href="/shadow-pilot"' not in c.get("/portfolio").text
