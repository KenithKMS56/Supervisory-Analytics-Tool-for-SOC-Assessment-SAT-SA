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


def _entity_in_band(prefix: str) -> str:
    store = SQLiteStore("data/satsa.db")
    run_id = store.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()[0]
    row = store.conn.execute(
        "SELECT entity_id FROM entity_scores WHERE run_id = ? AND risk_band LIKE ? ORDER BY entity_id LIMIT 1",
        (run_id, f"{prefix}%"),
    ).fetchone()
    store.close()
    assert row, f"bootstrapped data has no entity in the {prefix} band"
    return row["entity_id"]


def _submit(client: TestClient, entity_id: str, concern: str) -> float:
    resp = client.post(
        "/blind-review/submit",
        data={
            "entity_id": entity_id,
            "examiner_concern": concern,
            "examiner_priority": "High",
            "examiner_recommendation": "On-site review",
            "examiner_notes": f"concordance test ({concern})",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    store = SQLiteStore("data/satsa.db")
    row = store.conn.execute(
        "SELECT concordance_score FROM blind_reviews WHERE entity_id = ? AND examiner_concern = ? "
        "ORDER BY created_at DESC LIMIT 1",
        (entity_id, concern),
    ).fetchone()
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
