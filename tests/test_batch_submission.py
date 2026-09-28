"""POST /api/v1/submissions: periodic batch submission, one per entity and period.

The PS excludes continuously collecting logs/telemetry from CSEs, so the JSON
endpoint must behave like the file upload -- a periodic batch -- and must refuse
to accept the same entity/period twice (which would turn it into a feed).
"""

import shutil
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from satsa.api.routes import app


@pytest.fixture
def supervisor():
    c = TestClient(app)
    r = c.post("/login", data={"username": "supervisor", "password": "ChangeMe-Supervisor#2026"},
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


def test_first_submission_accepted_repeat_rejected(supervisor, entity_id):
    first = supervisor.post("/api/v1/submissions", json=_batch(entity_id))
    assert first.status_code == 200, first.text
    assert first.json()["ingested_counts"] == {"alerts": 1}
    assert (Path("data/parquet/alert") / f"entity_id={entity_id}").is_dir()

    again = supervisor.post("/api/v1/submissions", json=_batch(entity_id))
    assert again.status_code == 409
    assert "already been submitted" in again.json()["detail"]

    # A different period for the same entity is a new periodic batch.
    next_period = supervisor.post("/api/v1/submissions", json=_batch(entity_id, period="2026-Q3"))
    assert next_period.status_code == 200


@pytest.mark.parametrize("period", ["2026", "2026-Q5", "now", "2026-13", "2026-Q1; DROP"])
def test_period_must_be_a_review_period(supervisor, entity_id, period):
    assert supervisor.post("/api/v1/submissions", json=_batch(entity_id, period=period)).status_code == 422


def test_rejected_batch_stores_nothing(supervisor, entity_id):
    bad = _batch(entity_id)
    bad["alerts"][0]["entity_id"] = "../../escape"
    assert supervisor.post("/api/v1/submissions", json=bad).status_code == 400
    assert not list(Path("data/parquet").glob(f"*/entity_id={entity_id}"))
    # The slot was never claimed, so a corrected batch is still accepted.
    assert supervisor.post("/api/v1/submissions", json=_batch(entity_id)).status_code == 200


def test_old_telemetry_path_is_gone(supervisor, entity_id):
    assert supervisor.post("/api/v1/telemetry/ingest", json=_batch(entity_id)).status_code == 404


def test_docstring_describes_periodic_batch_only():
    from satsa.api.routes import api_batch_submission

    doc = api_batch_submission.__doc__.lower()
    assert "periodic batch" in doc
    assert "not a streaming or event-driven feed" in doc
    for banned in ("webhook", "soar playbook", "real-time"):
        assert banned not in doc
