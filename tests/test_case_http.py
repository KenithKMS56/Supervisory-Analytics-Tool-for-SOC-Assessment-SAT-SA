"""The examiner workflow through the web app: forms, packages, the JSON API and their refusals.

Runs against its own small deployment (tests/case_fixtures.py) in a temporary directory, so the
next-period evidence is exactly what each step needs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from case_fixtures import PASSPHRASE, Q2, add_result, add_run, make_store, seed_q1_concern
from fastapi.testclient import TestClient
from test_cases import response_zip

from satsa.api.routes import app


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = make_store(tmp_path)
    finding = seed_q1_concern(store)
    store.close()
    clients = {}
    for name, password in (("examiner", "ChangeMe-Examiner#2026"), ("examiner2", PASSPHRASE),
                           ("analyst", "ChangeMe-Analyst#2026")):
        c = TestClient(app)
        r = c.post("/login", data={"username": name, "password": password}, follow_redirects=False)
        assert r.status_code == 303 and "error" not in r.headers["location"], name
        clients[name] = c
    return clients, finding


def _version(client, case_id) -> int:
    return int(client.get(f"/api/v1/cases/{case_id}").json()["case"]["version"])


def _act(client, case_id, action, expect=303, **data):
    data = {"action": action, "expected_version": _version(client, case_id), "rationale": "reasons", **data}
    resp = client.post(f"/cases/{case_id}/actions", data=data, follow_redirects=False)
    assert resp.status_code == expect, (action, resp.status_code, resp.text[:300])
    return resp


def test_a_case_is_worked_end_to_end_in_the_browser(site):
    clients, finding = site
    ex, ex2, analyst = clients["examiner"], clients["examiner2"], clients["analyst"]

    page = ex.get(f"/finding/{finding}").text
    assert "Open supervisory case" in page
    resp = ex.post("/cases", data={"finding_id": finding, "rationale": "Looks real."}, follow_redirects=False)
    assert resp.status_code == 303
    case_id = resp.headers["location"].rsplit("/", 1)[-1]
    assert re.fullmatch(r"CASE-[0-9A-F]{12}", case_id)
    assert case_id in ex.get(f"/finding/{finding}").text  # the finding page now points at the case
    assert case_id in analyst.get("/cases").text  # analysts can read cases ...
    assert "No action is open to you" in analyst.get(f"/cases/{case_id}").text
    assert analyst.post("/cases", data={"finding_id": finding}).status_code == 403  # ... but not act
    assert analyst.post(f"/cases/{case_id}/actions",
                        data={"action": "assign", "expected_version": 1, "owner": "analyst"}).status_code == 403

    _act(ex, case_id, "assign", owner="examiner", due_date="2026-05-31", rationale="")
    _act(ex, case_id, "request_explanation", due_date="2026-05-15", rationale="Explain the off-shift delays.")
    request = ex.post(f"/cases/{case_id}/request-package")
    assert request.status_code == 200 and request.headers["content-type"] == "application/zip"
    assert ex2.post(f"/cases/{case_id}/request-package").status_code == 403  # not the owner
    upload = ex.post(f"/cases/{case_id}/response-package",
                     data={"expected_version": _version(ex, case_id)},
                     files={"package": ("response.zip", response_zip(request.content,
                                                                     attachments={"rota.pdf": b"%PDF"}),
                                        "application/zip")},
                     follow_redirects=False)
    assert upload.status_code == 303, upload.text[:300]

    # A stale form is refused with the case page and nothing recorded.
    stale = ex.post(f"/cases/{case_id}/actions", data={
        "action": "decide", "expected_version": 1, "outcome": "dismissed", "rationale": "stale"})
    assert stale.status_code == 409 and "changed since you loaded" in stale.text
    _act(ex2, case_id, "decide", expect=403, outcome="confirmed")  # only the owner decides
    _act(ex, case_id, "decide", outcome="confirmed", rationale="The response confirms the gap.")
    _act(ex, case_id, "require_corrective_action", description="Staff the night shift.",
         action_owner="CSE SOC manager", due_date="2026-06-30", verification_criteria="Q2 acknowledgement in range.")
    _act(ex, case_id, "submit_for_verification", rationale="New rota from 1 April.")

    # No later period yet: verification cannot pass.
    refused = _act(ex2, case_id, "verify", expect=409, result="passed", reassessment_run_id="RUN-Q1")
    assert "cannot be verified" in refused.text
    store = make_store(Path.cwd())
    add_run(store, "RUN-Q2", "2026-07-02T00:00:00+00:00", window=Q2, period="2026-Q2")
    add_result(store, "RUN-Q2", "assessed_clear")
    store.close()
    page = ex2.get(f"/cases/{case_id}").text
    assert "Next-period evidence" in page and "<strong>Yes</strong>" in page
    _act(ex, case_id, "verify", expect=403, result="passed", reassessment_run_id="RUN-Q2")  # owner can't sign off
    _act(ex2, case_id, "verify", result="passed", reassessment_run_id="RUN-Q2", rationale="Q2 is clear.")

    body = ex.get(f"/api/v1/cases/{case_id}").json()
    assert body["case"]["state"] == "closed" and body["allowed_actions"] == ["reopen"]
    assert [e["action"] for e in body["events"]] == [
        "open", "assign", "request_explanation", "record_response", "decide", "require_corrective_action",
        "submit_for_verification", "verify"]
    [att] = body["attachments"]
    download = analyst.get(f"/cases/{case_id}/attachments/{att['attachment_id']}")
    assert download.content == b"%PDF" and download.headers["x-content-type-options"] == "nosniff"
    assert "attachment" in download.headers["content-disposition"]


def test_the_json_api_enforces_the_same_rules(site):
    clients, finding = site
    ex, ex2, analyst = clients["examiner"], clients["examiner2"], clients["analyst"]
    created = ex.post("/api/v1/cases", json={"finding_id": finding})
    assert created.status_code == 201 and created.json()["created"]
    case_id = created.json()["case"]["case_id"]
    assert ex.post("/api/v1/cases", json={"finding_id": finding}).status_code == 200  # linked, not duplicated
    assert analyst.post("/api/v1/cases", json={"finding_id": finding}).status_code == 403

    def move(client, action, version, **fields):
        return client.post(f"/api/v1/cases/{case_id}/transitions",
                           json={"action": action, "expected_version": version, "rationale": "r", "fields": fields})

    ok = move(ex, "assign", 1, owner="examiner")
    assert ok.status_code == 200 and ok.json()["case"]["state"] == "assigned"
    conflict = move(ex, "decide", 1, outcome="dismissed")
    assert conflict.status_code == 409 and conflict.json()["error"] == "VersionConflict"
    v = ok.json()["case"]["version"]
    assert move(ex2, "decide", v, outcome="dismissed").json()["error"] == "CaseForbidden"
    assert move(ex, "verify", v, result="passed").json()["error"] == "InvalidTransition"
    assert move(ex, "decide", v, outcome="maybe").status_code == 422
    assert move(analyst, "decide", v, outcome="dismissed").status_code == 403
    assert ex.get("/api/v1/cases/CASE-FFFFFFFFFFFF").status_code == 404
    assert [c["case_id"] for c in analyst.get("/api/v1/cases", params={"state": "open"}).json()] == [case_id]
