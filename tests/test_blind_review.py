"""Blinded-review agreement (concordance) between the examiner's concern and the system band.

The score is 100 when the examiner's blind judgement matches the system's band and drops 25
points per band of disagreement. It was computed from a lookup table whose keys ("Elevated
Concern", "High Concern") matched no real band label, so every High or Critical entity was
silently treated as Low.
"""

import pytest
from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.store.sqlite import SQLiteStore


@pytest.fixture
def examiner():
    c = TestClient(app)
    r = c.post(
        "/login", data={"username": "examiner", "password": "ChangeMe-Examiner#2026"}, follow_redirects=False
    )
    assert r.status_code == 303 and "error" not in r.headers["location"]
    return c


def _latest_run(store: SQLiteStore) -> str:
    return store.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()[0]


def _entity_in_band(prefix: str) -> str:
    store = SQLiteStore("data/satsa.db")
    row = store.conn.execute(
        "SELECT entity_id FROM entity_scores WHERE run_id = ? AND risk_band LIKE ? ORDER BY entity_id LIMIT 1",
        (_latest_run(store), f"{prefix}%"),
    ).fetchone()
    store.close()
    assert row, f"bootstrapped data has no entity in the {prefix} band"
    return row["entity_id"]


def _task_for(entity_id: str) -> str:
    """A fresh blind task on `entity_id` for the examiner: a sample of every classified entity,
    drawn by the analyst (a blind judgement is made once per task)."""
    from satsa.cases.blind import create_sample

    store = SQLiteStore("data/satsa.db")
    try:
        sample = create_sample(store, _latest_run(store), "analyst", "analyst", "examiner", 50, 0, 0, seed=11)
        row = store.conn.execute(
            "SELECT task_id FROM blind_tasks WHERE sample_id = ? AND entity_id = ?", (sample["sample_id"], entity_id)
        ).fetchone()
    finally:
        store.close()
    assert row, f"{entity_id} is not among the run's classified entities"
    return row["task_id"]


def _submit(client: TestClient, entity_id: str, concern: str) -> float:
    task_id = _task_for(entity_id)
    resp = client.post(
        f"/blind-review/tasks/{task_id}/submit",
        data={
            "examiner_concern": concern,
            "examiner_priority": "P2",
            "examiner_recommendation": "Formal Audit",
            "examiner_notes": f"concordance test ({concern})",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    store = SQLiteStore("data/satsa.db")
    row = store.conn.execute("SELECT concordance_score FROM blind_tasks WHERE task_id = ?", (task_id,)).fetchone()
    store.close()
    return float(row["concordance_score"])


def test_examiner_matching_a_high_band_entity_scores_full_agreement(examiner):
    """The form's "Elevated" is the examiner's word for the system's "High" band."""
    entity_id = _entity_in_band("High")
    assert _submit(examiner, entity_id, "Elevated") == 100.0
    assert _submit(examiner, entity_id, "Critical") == 75.0
    assert _submit(examiner, entity_id, "Low") == 50.0


def test_low_band_entity_is_still_scored_correctly(examiner):
    entity_id = _entity_in_band("Low")
    assert _submit(examiner, entity_id, "Low") == 100.0
    assert _submit(examiner, entity_id, "Critical") == 25.0


@pytest.mark.parametrize(
    ("concern", "band", "expected"),
    [
        ("Low", "Low Supervisory Concern", 100.0),
        ("Moderate", "Moderate Supervisory Concern", 100.0),
        ("Elevated", "High Supervisory Concern", 100.0),
        ("Critical", "Critical Supervisory Concern", 100.0),
        ("Low", "Critical Supervisory Concern", 25.0),
        ("Critical", "Low Supervisory Concern", 25.0),
        ("Moderate", "High Supervisory Concern", 75.0),
    ],
)
def test_concordance_table(concern, band, expected):
    from satsa.scoring.scorer import blind_review_concordance

    assert blind_review_concordance(concern, band) == expected


def test_concordance_rejects_values_it_cannot_place():
    from satsa.scoring.scorer import blind_review_concordance

    with pytest.raises(ValueError, match="examiner concern"):
        blind_review_concordance("Severe", "High Supervisory Concern")
    with pytest.raises(ValueError, match="risk band"):
        blind_review_concordance("Low", "Elevated Concern")
