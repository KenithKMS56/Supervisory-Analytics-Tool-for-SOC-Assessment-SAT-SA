"""Access-control deny paths and secure defaults of Phase 2 (docs/product_brief.md section 10):
service credentials for the submission API, the session idle timeout, CSV formula injection, and
entity retirement that never erases evidence. All on a private copy of the deployment."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json

import pytest
from deploy_utils import copy_deployment
from fastapi.testclient import TestClient

from satsa.api import routes
from satsa.auth import service_credentials
from satsa.csv_safe import safe_cell
from satsa.jobs.worker import run_jobs
from satsa.scoring.replay import replay_run
from satsa.store.catalog import Catalog
from satsa.store.sqlite import SQLiteStore


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    return root


def _store() -> SQLiteStore:
    return SQLiteStore("data/satsa.db")


def _analyst() -> TestClient:
    client = TestClient(routes.app)
    r = client.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                    follow_redirects=False)
    assert r.status_code == 303
    return client


def _batch(entity: str, period: str, alert_id: str) -> dict:
    return {"entity_id": entity, "period": period, "run_assessment_now": False,
            "alerts": [{"alert_id": alert_id, "created_at": f"{period[:4]}-07-02T10:00:00Z", "severity_final": "high"}]}


# ---------------------------------------------------------------- service credentials


def test_a_service_credential_submits_only_for_its_entities(deployment):
    store = _store()
    try:
        token, record = service_credentials.issue(store, name="CSE-01 connector", entities=["CSE-01"],
                                                  expires_days=30, created_by="test")
    finally:
        store.close()
    client = TestClient(routes.app)  # no session cookie at all
    auth = {"Authorization": f"Bearer {token}"}

    ok = client.post("/api/v1/submissions", json=_batch("CSE-01", "2026-Q3", "SC-1"), headers=auth)
    assert ok.status_code == 200, ok.text
    assert ok.json()["batch_id"]
    denied = client.post("/api/v1/submissions", json=_batch("CSE-02", "2026-Q3", "SC-2"), headers=auth)
    assert denied.status_code == 403 and "CSE-02" in denied.json()["detail"]

    store = _store()
    try:
        audit = [(r["action"], json.loads(r["details_json"])) for r in store.conn.execute(
            "SELECT action, details_json FROM audit_log WHERE action LIKE 'service_credential_%' ORDER BY rowid")]
        dump = "\n".join(str(tuple(r)) for r in store.conn.execute("SELECT * FROM service_credentials"))
        submitted_by = Catalog("data").batch(ok.json()["batch_id"])["submitted_by"]
    finally:
        store.close()
    assert [a for a, _ in audit] == ["service_credential_issued", "service_credential_used", "service_credential_refused"]
    assert all(record["credential_id"] == d.get("credential_id") for _, d in audit)
    assert token.split("_")[-1] not in dump, "the secret itself must never be stored"
    assert token not in json.dumps(audit)
    assert submitted_by == "service:CSE-01 connector"


def test_revoked_expired_and_forged_credentials_are_refused_at_once(deployment):
    store = _store()
    try:
        token, record = service_credentials.issue(store, name="short-lived", entities=["CSE-01"],
                                                  expires_days=1, created_by="test")
    finally:
        store.close()
    client = TestClient(routes.app)

    def submit(tok: str, alert: str) -> int:
        return client.post("/api/v1/submissions", json=_batch("CSE-01", "2026-Q4", alert),
                           headers={"Authorization": f"Bearer {tok}"}).status_code

    forged = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    assert submit(forged, "F-1") == 401
    assert submit("satsa_sc_0000000000000000_" + "x" * 43, "F-2") == 401
    store = _store()
    try:
        with store.transaction():
            store.conn.execute("UPDATE service_credentials SET expires_at = ? WHERE credential_id = ?",
                               ("2000-01-01T00:00:00+00:00", record["credential_id"]))
    finally:
        store.close()
    assert submit(token, "E-1") == 401, "expired"
    store = _store()
    try:
        with store.transaction():
            store.conn.execute("UPDATE service_credentials SET expires_at = ? WHERE credential_id = ?",
                               ("2999-01-01T00:00:00+00:00", record["credential_id"]))
        assert service_credentials.revoke(store, record["credential_id"], "test")
    finally:
        store.close()
    assert submit(token, "R-1") == 401, "revoked"


def test_credentials_are_limited_in_scope_and_lifetime():
    with pytest.raises(service_credentials.CredentialError, match="expire within"):
        service_credentials.issue(None, name="x-long", entities=["CSE-01"], expires_days=3650, created_by="t")  # type: ignore[arg-type]
    with pytest.raises(service_credentials.CredentialError, match="valid entity"):
        service_credentials.issue(None, name="x-none", entities=[], expires_days=30, created_by="t")  # type: ignore[arg-type]
    with pytest.raises(service_credentials.CredentialError, match="scope"):
        service_credentials.issue(None, name="x-admin", entities=["CSE-01"], expires_days=30, created_by="t",  # type: ignore[arg-type]
                                  scopes=("admin",))


def test_an_oversized_submission_is_refused_before_it_is_read(deployment, monkeypatch):
    monkeypatch.setattr(routes, "MAX_API_BODY_BYTES", 1024)
    client = TestClient(routes.app)
    big = _batch("CSE-01", "2026-Q3", "BIG-1")
    big["alerts"] = big["alerts"] * 50
    assert client.post("/api/v1/submissions", json=big).status_code == 413


def test_the_api_without_any_credential_is_refused(deployment):
    assert TestClient(routes.app).post("/api/v1/submissions", json=_batch("CSE-01", "2026-Q3", "N-1")).status_code == 401


# ---------------------------------------------------------------- sessions


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def test_an_idle_session_ends(deployment, monkeypatch):
    monkeypatch.setenv("SATSA_SESSION_IDLE_MINUTES", "30")
    store = _store()
    try:
        token = store.create_session("analyst", "analyst")
        assert store.get_session(token) is not None
        an_hour_ago = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)).isoformat()
        with store.transaction():
            store.conn.execute("UPDATE sessions SET created_at = ?, last_seen_at = ? WHERE session_hash = ?",
                               (an_hour_ago, an_hour_ago, _hash(token)))
        assert store.get_session(token) is None, "idle for an hour"
        assert store.conn.execute("SELECT count(*) FROM sessions WHERE session_hash = ?",
                                  (_hash(token),)).fetchone()[0] == 0

        active = store.create_session("analyst", "analyst")
        ten_minutes_ago = (dt.datetime.now(dt.UTC) - dt.timedelta(minutes=10)).isoformat()
        with store.transaction():
            store.conn.execute("UPDATE sessions SET last_seen_at = ? WHERE session_hash = ?",
                               (ten_minutes_ago, _hash(active)))
        assert store.get_session(active) is not None
        # The shared deployment holds other sessions too: read this one's row.
        seen = store.conn.execute("SELECT last_seen_at FROM sessions WHERE session_hash = ?",
                                  (_hash(active),)).fetchone()[0]
        assert seen > ten_minutes_ago, "use refreshes the idle clock"
    finally:
        store.close()


def test_an_idle_admin_session_ends_too(deployment):
    store = _store()
    try:
        token = store.create_admin_session("nciipc_admin", "NCIIPC Super Administrator")
        old = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=2)).isoformat()
        with store.transaction():
            store.conn.execute("UPDATE admin_sessions SET created_at = ?, last_seen_at = ?", (old, old))
        assert store.get_admin_session(token) is None
    finally:
        store.close()


# ---------------------------------------------------------------- CSV injection


def test_formula_like_text_is_exported_as_text():
    assert safe_cell("=HYPERLINK(\"http://x\",\"y\")") == "'=HYPERLINK(\"http://x\",\"y\")"
    assert safe_cell("+1-2") == "'+1-2" and safe_cell("@SUM(A1)") == "'@SUM(A1)" and safe_cell("\t=1") == "'\t=1"
    assert safe_cell(-3.5) == -3.5 and safe_cell("CSE-01") == "CSE-01"


def test_the_queue_export_neutralises_a_formula_in_submitted_text(deployment):
    store = _store()
    try:
        run_id = store.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()[0]
        with store.transaction():
            store.conn.execute(
                "UPDATE review_queue SET record_id = ? WHERE queue_id = (SELECT queue_id FROM review_queue "
                "WHERE run_id = ? LIMIT 1)", ("=cmd|' /C calc'!A0", run_id))
    finally:
        store.close()
    text = _analyst().get("/api/v1/export/queue.csv").text
    cells = [c for row in csv.reader(io.StringIO(text)) for c in row]
    assert "'=cmd|' /C calc'!A0" in cells
    assert not any(c.startswith("=") for c in cells)


# ---------------------------------------------------------------- retirement


def test_retiring_an_entity_keeps_its_evidence_and_replays(deployment):
    store = _store()
    try:
        before = {t: store.conn.execute(f"SELECT count(*) FROM {t} WHERE entity_id = 'CSE-03'").fetchone()[0]
                  for t in ("findings", "entity_scores", "domain_scores", "review_queue")}
    finally:
        store.close()
    assert before["entity_scores"] > 0
    client = _analyst()
    r = client.post("/upload/delete-entity/CSE-03", follow_redirects=False)
    assert r.status_code == 303 and "retired" in r.headers["location"]
    store = _store()
    try:
        after = {t: store.conn.execute(f"SELECT count(*) FROM {t} WHERE entity_id = 'CSE-03'").fetchone()[0]
                 for t in before}
        job_id = store.conn.execute("SELECT job_id FROM jobs WHERE kind = 'assessment' AND state = 'queued'").fetchone()[0]
    finally:
        store.close()
    assert after == before, "retiring erased evidence"
    catalog = Catalog("data")
    try:
        assert catalog.verify() == [], "published files were removed"
    finally:
        catalog.close()

    (job,) = run_jobs(job_id)
    assert job["state"] == "succeeded", job
    run_id = job["result"]["run_id"]
    store = _store()
    try:
        scored = {r[0] for r in store.conn.execute("SELECT entity_id FROM entity_scores WHERE run_id = ?", (run_id,))}
        selection = json.loads(store.conn.execute("SELECT selection_json FROM runs WHERE run_id = ?",
                                                  (run_id,)).fetchone()[0])
        assert "CSE-03" not in scored and len(scored) >= 5
        assert selection["retired_entities"] == ["CSE-03"]
        # Reinstated later: the retired run still replays as it was assessed.
        assert store.reinstate_entity("CSE-03", "test")
        report = replay_run(run_id, "data", store)
    finally:
        store.close()
    assert report["results_match"] and report["fingerprint_match"], report["differences"]
    assert "Already" not in client.post("/upload/delete-entity/CSE-03", follow_redirects=False).headers["location"]
