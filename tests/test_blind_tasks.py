"""Blind review as assigned tasks (satsa.cases.blind; docs/product_brief.md section 8).

Acceptance: blind-task responses contain no leaked scores; tasks are assigned and worked only by
their examiner; samples mix flagged, random and control entities reproducibly, with provenance;
the reveal time is recorded.
"""

from __future__ import annotations

import re

import pytest
from case_fixtures import PASSPHRASE, add_result, add_run, make_store
from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.cases import blind
from satsa.cases.workflow import CaseForbidden, CaseInvalid, InvalidTransition
from satsa.store.sqlite import SQLiteStore


def _login(name: str, password: str) -> TestClient:
    c = TestClient(app)
    r = c.post("/login", data={"username": name, "password": password}, follow_redirects=False)
    assert r.status_code == 303 and "error" not in r.headers["location"], name
    return c


@pytest.fixture(scope="module")
def shared():
    store = SQLiteStore("data/satsa.db")
    if not store.conn.execute("SELECT 1 FROM identities WHERE username = 'examiner2'").fetchone():
        store.create_user("examiner2", "examiner", PASSPHRASE)
    run_id = store.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()[0]
    yield store, run_id
    store.close()


def _tasks(store, sample_id):
    return [dict(r) for r in store.conn.execute(
        "SELECT * FROM blind_tasks WHERE sample_id = ? ORDER BY position", (sample_id,))]


def test_a_sample_mixes_flagged_control_and_random_entities_reproducibly(shared):
    store, run_id = shared
    a = blind.create_sample(store, run_id, "analyst", "analyst", "examiner", 2, 2, 2, seed=1234)
    b = blind.create_sample(store, run_id, "analyst", "analyst", "examiner", 2, 2, 2, seed=1234)
    ta, tb = _tasks(store, a["sample_id"]), _tasks(store, b["sample_id"])
    assert [t["entity_id"] for t in ta] == [t["entity_id"] for t in tb], "same seed, same draw and order"
    assert len({t["entity_id"] for t in ta}) == len(ta) == 6
    assert a["drawn"] == {"flagged": 2, "random": 2, "control": 2}

    scores = {r["entity_id"]: dict(r) for r in store.conn.execute(
        "SELECT entity_id, risk_index, risk_band, classification_status FROM entity_scores WHERE run_id = ?", (run_id,))}
    classified = sorted((s for s in scores.values() if s["classification_status"] != "insufficient_evidence"),
                        key=lambda s: (-s["risk_index"], s["entity_id"]))
    flagged = {t["entity_id"] for t in ta if t["sample_kind"] == "flagged"}
    assert flagged == {s["entity_id"] for s in classified[:2]}
    for t in ta:
        if t["sample_kind"] == "control":
            assert scores[t["entity_id"]]["risk_band"].startswith("Low")
        assert '"seed": 1234' in t["provenance_json"] and run_id in t["provenance_json"]
    # Shuffled: the kinds are not in drawing order (flagged, control, random) for this seed.
    assert [t["sample_kind"] for t in ta] != ["flagged"] * 2 + ["control"] * 2 + ["random"] * 2


def test_who_may_draw_and_be_assigned_a_sample(shared):
    store, run_id = shared
    with pytest.raises(CaseForbidden):
        blind.create_sample(store, run_id, "examiner", "examiner", "examiner2", 1, 0, 0)
    with pytest.raises(CaseInvalid, match="not an active examiner"):
        blind.create_sample(store, run_id, "analyst", "analyst", "analyst", 1, 0, 0)
    with pytest.raises(CaseInvalid):
        blind.create_sample(store, run_id, "analyst", "analyst", "examiner", 0, 0, 0)
    with pytest.raises(CaseInvalid):
        blind.create_sample(store, run_id, "analyst", "analyst", "examiner", 51, 0, 0)
    examiner = _login("examiner", "ChangeMe-Examiner#2026")
    resp = examiner.post("/blind-review/samples", data={"run_id": run_id, "assignee": "examiner", "flagged": 1})
    assert resp.status_code == 403


def test_a_task_serves_nothing_scored_until_its_examiner_reveals_it(shared):
    store, run_id = shared
    sample = blind.create_sample(store, run_id, "analyst", "analyst", "examiner", 1, 0, 0, seed=5)
    [task] = _tasks(store, sample["sample_id"])
    score = store.conn.execute("SELECT risk_index, risk_band FROM entity_scores WHERE run_id = ? AND entity_id = ?",
                               (run_id, task["entity_id"])).fetchone()
    rule_ids = {r[0] for r in store.conn.execute(
        "SELECT rule_id FROM findings WHERE run_id = ? AND entity_id = ?", (run_id, task["entity_id"]))}
    assert rule_ids, "a flagged entity has findings"

    def leaks(html: str) -> list[str]:
        found = [s for s in (score["risk_band"], f"index {score['risk_index']}", "Why this entity",
                             "System assessment", "Agreement:") if s in html]
        found += [r for r in rule_ids if re.search(rf"\b{r}\b", html)]
        return found

    examiner = _login("examiner", "ChangeMe-Examiner#2026")
    url = f"/blind-review/tasks/{task['task_id']}"
    page = examiner.get(url)
    assert page.status_code == 200 and "Your independent judgement" in page.text
    assert leaks(page.text) == []
    assert leaks(examiner.get("/blind-review").text) == []
    submitted = examiner.post(f"{url}/submit", data={
        "examiner_concern": "Critical", "examiner_priority": "P1", "examiner_recommendation": "Formal Inquiry",
        "examiner_notes": "Silent critical assets and fast closures."}, follow_redirects=True)
    assert submitted.status_code == 200 and leaks(submitted.text) == []  # still hidden after submitting
    again = examiner.post(f"{url}/submit", data={
        "examiner_concern": "Low", "examiner_priority": "P1", "examiner_recommendation": "Satisfactory",
        "examiner_notes": "second try"})
    assert again.status_code == 409  # a blind judgement is made once

    revealed = examiner.post(f"{url}/reveal", follow_redirects=True).text
    assert score["risk_band"] in revealed and "Why this entity" in revealed and "<strong>flagged</strong>" in revealed
    row = store.conn.execute("SELECT submitted_at, revealed_at, system_risk_band, concordance_score "
                             "FROM blind_tasks WHERE task_id = ?", (task["task_id"],)).fetchone()
    assert row["submitted_at"] < row["revealed_at"] and row["system_risk_band"] == score["risk_band"]
    assert row["concordance_score"] is not None


def test_only_the_assigned_examiner_works_a_task(shared):
    store, run_id = shared
    sample = blind.create_sample(store, run_id, "analyst", "analyst", "examiner", 0, 1, 0, seed=9)
    [task] = _tasks(store, sample["sample_id"])
    url = f"/blind-review/tasks/{task['task_id']}"
    other = _login("examiner2", PASSPHRASE)
    assert other.get(url).status_code == 403
    assert other.post(f"{url}/submit", data={"examiner_concern": "Low", "examiner_priority": "P1",
                                             "examiner_recommendation": "Satisfactory",
                                             "examiner_notes": "not mine"}).status_code == 403
    assert task["task_id"] not in other.get("/blind-review").text
    analyst = _login("analyst", "ChangeMe-Analyst#2026")
    assert analyst.get(url).status_code == 403
    examiner = _login("examiner", "ChangeMe-Examiner#2026")
    assert examiner.post(f"{url}/reveal").status_code == 409  # judge first, then reveal
    with pytest.raises(InvalidTransition):
        blind.reveal(store, task["task_id"], "examiner", "examiner")


def test_an_unclassified_entity_has_no_agreement_score(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = make_store(tmp_path)
    try:
        add_run(store, "RUN-X", "2026-04-02T00:00:00+00:00")
        add_result(store, "RUN-X", "insufficient_evidence", band="Insufficient evidence",
                   classification="insufficient_evidence", risk_index=0.0, coverage=0.1)
        sample = blind.create_sample(store, "RUN-X", "analyst", "analyst", "examiner", 0, 1, 0, seed=3)
        [task] = _tasks(store, sample["sample_id"])
        blind.submit(store, task["task_id"], "examiner", "examiner", "Low", "Routine", "Satisfactory", "Looks fine.")
        row = store.conn.execute("SELECT concordance_score, system_classification FROM blind_tasks").fetchone()
        assert row["concordance_score"] is None and row["system_classification"] == "insufficient_evidence"
    finally:
        store.close()
