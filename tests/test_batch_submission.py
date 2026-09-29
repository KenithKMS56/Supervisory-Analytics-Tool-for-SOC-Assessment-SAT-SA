"""POST /api/v1/submissions: periodic batch submission, one per entity and period.

The PS excludes continuously collecting logs/telemetry from CSEs, so the JSON
endpoint must behave like the file upload -- a periodic batch -- and must refuse
to accept the same entity/period twice (which would turn it into a feed).
"""

import shutil
import uuid
from pathlib import Path
from urllib.parse import unquote_plus

import pytest
from fastapi.testclient import TestClient

from satsa.api.routes import app


@pytest.fixture
def analyst():
    c = TestClient(app)
    r = c.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
               follow_redirects=False)
    assert r.status_code == 303
    return c


@pytest.fixture
def entity_id():
    eid = f"ZZAPI-{uuid.uuid4().hex[:8].upper()}"
    yield eid
    for part in Path("data/parquet").glob(f"*/entity_id={eid}"):
        shutil.rmtree(part, ignore_errors=True)


def _batch(eid: str, period: str = "2026-Q2", **extra):
    return {
        "entity_id": eid,
        "period": period,
        "alerts": [{"alert_id": f"{eid}-A1", "severity_final": "high", "closed_by_type": "human"}],
        "run_assessment_now": False,
        **extra,
    }


def test_first_submission_accepted_repeat_rejected(analyst, entity_id):
    first = analyst.post("/api/v1/submissions", json=_batch(entity_id))
    assert first.status_code == 200, first.text
    assert first.json()["ingested_counts"] == {"alerts": 1}
    assert (Path("data/parquet/alert") / f"entity_id={entity_id}").is_dir()

    again = analyst.post("/api/v1/submissions", json=_batch(entity_id))
    assert again.status_code == 409
    assert "already been submitted" in again.json()["detail"]

    # A different period for the same entity is a new periodic batch.
    next_period = analyst.post("/api/v1/submissions", json=_batch(entity_id, period="2026-Q3"))
    assert next_period.status_code == 200


@pytest.mark.parametrize("period", ["2026", "2026-Q5", "now", "2026-13", "2026-Q1; DROP"])
def test_period_must_be_a_review_period(analyst, entity_id, period):
    assert analyst.post("/api/v1/submissions", json=_batch(entity_id, period=period)).status_code == 422


def test_rejected_batch_stores_nothing(analyst, entity_id):
    bad = _batch(entity_id)
    bad["alerts"][0]["entity_id"] = "../../escape"
    assert analyst.post("/api/v1/submissions", json=bad).status_code == 400
    assert not list(Path("data/parquet").glob(f"*/entity_id={entity_id}"))
    # The slot was never claimed, so a corrected batch is still accepted.
    assert analyst.post("/api/v1/submissions", json=_batch(entity_id)).status_code == 200


def test_old_telemetry_path_is_gone(analyst, entity_id):
    assert analyst.post("/api/v1/telemetry/ingest", json=_batch(entity_id)).status_code == 404


def test_docstring_describes_periodic_batch_only():
    from satsa.api.routes import api_batch_submission

    doc = api_batch_submission.__doc__.lower()
    assert "periodic batch" in doc
    assert "not a streaming or event-driven feed" in doc
    for banned in ("webhook", "soar playbook", "real-time"):
        assert banned not in doc


def test_new_entity_is_registered_and_visible_in_ui(analyst, entity_id):
    """A CSE first seen in a batch must be registered, or the assessment and
    every UI view skip it while the API reports the batch as stored."""
    assert analyst.post("/api/v1/submissions", json=_batch(entity_id)).status_code == 200
    assert analyst.get(f"/entity/{entity_id}").status_code == 200
    alerts = analyst.get(f"/alerts?entity={entity_id}")
    assert f"{entity_id}-A1" in alerts.text


def test_upload_without_entity_id_is_rejected(analyst):
    """Rows attributable to no CSE are refused, not written outside the entity partitions."""
    alert_root = Path("data/parquet/alert/data.parquet")
    before = alert_root.stat().st_mtime_ns if alert_root.exists() else None
    csv = b"alertid,timestamp,severity\nNOENT-1,2026-04-01T10:00:00Z,3\n"
    r = analyst.post(
        "/upload", files={"files": ("alerts.csv", csv, "text/csv")}, follow_redirects=False
    )
    assert r.status_code == 303
    assert "no entity_id" in unquote_plus(r.headers["location"])
    assert (alert_root.stat().st_mtime_ns if alert_root.exists() else None) == before
