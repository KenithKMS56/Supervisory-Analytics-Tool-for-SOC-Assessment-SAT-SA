"""Entity context, portfolio attention and run-pinned reports through the web app (brief §7, §9).

Runs against a private copy of the session deployment, so the maintenance windows, exceptions
and decisions it records never reach the database the rest of the suite reads.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import re

import pytest
from case_fixtures import PASSPHRASE
from deploy_utils import copy_deployment
from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.store.sqlite import SQLiteStore


@pytest.fixture
def site(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    store = SQLiteStore("data/satsa.db")
    try:
        if not store.conn.execute("SELECT 1 FROM identities WHERE username = 'examiner2'").fetchone():
            store.create_user("examiner2", "examiner", PASSPHRASE)
        ids = dict(store.conn.execute(
            "SELECT f.entity_id, f.finding_id, f.run_id FROM findings f WHERE f.run_id = "
            "(SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1) ORDER BY f.score DESC LIMIT 1"
        ).fetchone())
    finally:
        store.close()
    clients = {}
    for name, password in (("examiner", "ChangeMe-Examiner#2026"), ("examiner2", PASSPHRASE),
                           ("analyst", "ChangeMe-Analyst#2026")):
        c = TestClient(app)
        r = c.post("/login", data={"username": name, "password": password}, follow_redirects=False)
        assert r.status_code == 303 and "error" not in r.headers["location"], name
        clients[name] = c
    return clients, ids


def _ok(resp, expect=303):
    assert resp.status_code == expect, (resp.status_code, resp.text[:300])
    return resp


def test_maintenance_is_requested_approved_and_revoked_through_the_entity_page(site):
    clients, ids = site
    ent = ids["entity_id"]
    analyst, ex, ex2 = clients["analyst"], clients["examiner"], clients["examiner2"]
    form = {"starts_on": "2026-02-01", "ends_on": "2026-02-03", "reason": "SIEM upgrade",
            "evidence_ref": "CHG-1042", "asset_id": ""}
    _ok(analyst.post(f"/entity/{ent}/maintenance", data=form, follow_redirects=False))
    page = ex.get(f"/entity/{ent}").text
    window_id = re.search(r"MW-[A-F0-9]{12}", page).group(0)
    assert "awaiting approval" in page and "Assessment context" in page
    # Analysts record but never approve; an examiner approves.
    assert analyst.post(f"/entity/{ent}/maintenance/{window_id}/approve", follow_redirects=False).status_code == 403
    _ok(ex.post(f"/entity/{ent}/maintenance/{window_id}/approve", follow_redirects=False))
    assert "in force" in ex2.get(f"/entity/{ent}").text
    # Approving twice, or for another entity, is refused.
    assert ex2.post(f"/entity/{ent}/maintenance/{window_id}/approve").status_code == 409
    assert ex2.post(f"/entity/CSE-99/maintenance/{window_id}/approve").status_code == 404
    _ok(ex2.post(f"/entity/{ent}/maintenance/{window_id}/revoke", data={"reason": "wrong dates"},
                 follow_redirects=False))
    assert "revoked" in ex.get(f"/entity/{ent}").text
    bad = {**form, "ends_on": "2026-01-01"}
    assert analyst.post(f"/entity/{ent}/maintenance", data=bad).status_code == 400
    assert analyst.post(f"/entity/{ent}/maintenance", data={**form, "asset_id": "../../etc"}).status_code == 400


def test_an_exception_needs_a_second_examiner_and_shows_on_the_finding(site):
    clients, ids = site
    ent, ex, ex2, analyst = ids["entity_id"], clients["examiner"], clients["examiner2"], clients["analyst"]
    rule = ids["finding_id"].split("-")[1]
    expires = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=90)).isoformat()
    form = {"rule_id": rule, "scope": "night staffing", "reason": "8x5 SOC approved by the board",
            "evidence_ref": "BOARD-MIN-7", "expires_on": expires}
    assert analyst.post(f"/entity/{ent}/exceptions", data=form).status_code == 403
    assert ex.post(f"/entity/{ent}/exceptions", data={**form, "rule_id": "ZZ99"}).status_code == 400
    _ok(ex.post(f"/entity/{ent}/exceptions", data=form, follow_redirects=False))
    xid = re.search(r"EXC-[A-F0-9]{12}", ex.get(f"/entity/{ent}").text).group(0)
    assert ex.post(f"/entity/{ent}/exceptions/{xid}/approve").status_code == 400  # the requester
    _ok(ex2.post(f"/entity/{ent}/exceptions/{xid}/approve", follow_redirects=False))

    # Applicability: examiners only, with a reason; it appears with its status and can be revoked.
    assert analyst.post(f"/entity/{ent}/applicability", data={"rule_id": "NS07", "reason": "x"}).status_code == 403
    assert ex.post(f"/entity/{ent}/applicability", data={"rule_id": "NS07", "reason": " "}).status_code == 400
    _ok(ex.post(f"/entity/{ent}/applicability", data={"rule_id": "NS07", "reason": "No reporting duty"},
                follow_redirects=False))
    page = ex.get(f"/entity/{ent}").text
    decision = re.search(r"APD-[a-f0-9]{12}", page).group(0)
    assert "No reporting duty" in page
    _ok(ex2.post(f"/entity/{ent}/applicability/{decision}/revoke", data={"reason": "duty applies"},
                 follow_redirects=False))
    assert ex2.post(f"/entity/{ent}/applicability/{decision}/revoke", data={"reason": "again"}).status_code == 409


def test_the_finding_page_shows_evidence_support_and_the_recorded_cohort(site):
    clients, ids = site
    page = clients["examiner"].get(f"/finding/{ids['finding_id']}").text
    assert "Evidence support" in page and "Statistical Confidence" not in page
    assert "not the probability that the finding is correct" in page
    assert 'id="peer-cohort"' in page


def test_the_portfolio_says_why_evidence_and_next_action_and_filters(site):
    clients, ids = site
    ex = clients["examiner"]
    page = ex.get("/portfolio").text
    for heading in ("Why it needs attention", "Next action", "Evidence"):
        assert heading in page
    assert re.search(r"(Assessable|Partially assessable|Insufficient evidence); \d+ of \d+ applicable rules", page)
    narrowed = ex.get("/portfolio", params={"q": ids["entity_id"]}).text
    assert "Showing 1 of" in narrowed
    none = ex.get("/portfolio", params={"q": "no-such-entity-anywhere"}).text
    assert "No entity matches these filters." in none
    assert ex.get("/portfolio", params={"band": "<script>", "sort": "nonsense"}).status_code == 200
    assert ex.get("/portfolio", params={"run_id": "RUN-20990101000000000000-deadbeef"}).status_code == 404

    # Saved views belong to their owner.
    r = _ok(ex.post("/portfolio/views", data={"name": "Critical only", "band": "critical"}, follow_redirects=False))
    assert "band=critical" in r.headers["location"]
    assert "Critical only" in ex.get("/portfolio").text
    assert "Critical only" not in clients["examiner2"].get("/portfolio").text
    assert ex.post("/portfolio/views", data={"name": "<b>x</b>"}).status_code == 400
    view_id = re.search(r"VIEW-[A-F0-9]{12}", ex.get("/portfolio").text).group(0)
    _ok(clients["examiner2"].post(f"/portfolio/views/{view_id}/delete", follow_redirects=False))  # not theirs
    assert "Critical only" in ex.get("/portfolio").text
    _ok(ex.post(f"/portfolio/views/{view_id}/delete", follow_redirects=False))
    assert "Critical only" not in ex.get("/portfolio").text


def test_reports_follow_the_selected_run_and_carry_its_coverage(site):
    clients, ids = site
    analyst = clients["analyst"]
    store = SQLiteStore("data/satsa.db")
    try:
        runs = [r[0] for r in store.conn.execute("SELECT run_id FROM runs ORDER BY created_at")]
        counts = {rid: store.conn.execute("SELECT count(*) FROM findings WHERE run_id = ?", (rid,)).fetchone()[0]
                  for rid in runs}
    finally:
        store.close()
    latest = runs[-1]
    rows = list(csv.DictReader(io.StringIO(analyst.get("/reports/export/findings-csv").text)))
    assert {r["run_id"] for r in rows} == {latest} and len(rows) == counts[latest]  # one run, as the UI
    assert all(r["entity_evidence_coverage"] for r in rows)
    pinned = analyst.get("/reports/export/findings-csv", params={"run_id": runs[0]})
    pinned_rows = list(csv.DictReader(io.StringIO(pinned.text)))
    assert {r["run_id"] for r in pinned_rows} <= {runs[0]} and len(pinned_rows) == counts[runs[0]]
    assert runs[0] in pinned.headers["content-disposition"]
    html = analyst.get(f"/reports/entity/{ids['entity_id']}/html", params={"run_id": latest}).text
    assert 'id="evidence-coverage"' in html and latest in html and "Peer comparison:" in html
    assert analyst.get("/reports/portfolio/html", params={"run_id": "RUN-20990101000000000000-deadbeef"}).status_code == 404
    assert analyst.get("/reports/portfolio/html", params={"run_id": "../../x"}).status_code == 400


def test_report_html_escapes_stored_text(site):
    """A finding title is built partly from submitted values; the report must not render it as HTML."""
    clients, ids = site
    store = SQLiteStore("data/satsa.db")
    try:
        with store.transaction():
            store.conn.execute("UPDATE findings SET title = '<img src=x onerror=alert(1)>' WHERE finding_id = ?",
                               (ids["finding_id"],))
    finally:
        store.close()
    html = clients["examiner"].get(f"/reports/entity/{ids['entity_id']}/html", params={"run_id": ids["run_id"]}).text
    assert "<img src=x" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html


def test_the_entities_api_returns_one_run_with_its_evidence_coverage(site):
    clients, ids = site
    rows = clients["examiner"].get("/api/v1/entities").json()
    assert rows and len({r["entity_id"] for r in rows}) == len(rows)  # one row per entity, not per run
    assert {r["run_id"] for r in rows} == {ids["run_id"]}
    assert all(r["classification_status"] and r["evidence"] for r in rows)
    assert clients["examiner"].get("/api/v1/entities", params={"run_id": "bad id"}).status_code == 400
