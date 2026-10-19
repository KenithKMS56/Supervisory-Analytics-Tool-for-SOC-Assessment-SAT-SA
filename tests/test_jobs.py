"""Durable jobs (docs/product_brief.md section 9): imports and assessments run in a worker, keep
their state across restarts, recover from a dead worker without duplicating work, and can be
cancelled. Every test runs on a private copy of the deployment (tests/deploy_utils.py)."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import unquote_plus

import pytest
from deploy_utils import copy_deployment
from fastapi.testclient import TestClient

from satsa.jobs import handlers
from satsa.jobs.queue import JobQueue, fingerprint, iso, utc_now
from satsa.jobs.worker import JobCancelled, JobContext, Worker, run_jobs
from satsa.store.catalog import Catalog
from satsa.store.sqlite import SQLiteStore

ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    # The copy starts with an empty queue: a job an earlier test left queued in the shared
    # database belongs to that test, and would be claimed (or counted) here otherwise.
    store = SQLiteStore("data/satsa.db")
    try:
        with store.transaction():
            store.conn.execute("DELETE FROM jobs")
    finally:
        store.close()
    return root


def _enqueue(kind: str = "assessment", params: dict | None = None, **kw) -> dict:
    store = SQLiteStore("data/satsa.db")
    try:
        return JobQueue(store).enqueue(kind, params if params is not None else {"period": "2026-Q1"}, "analyst", **kw)
    finally:
        store.close()


def _job(job_id: str) -> dict:
    store = SQLiteStore("data/satsa.db")
    try:
        job = JobQueue(store).get(job_id)
        assert job is not None
        return job
    finally:
        store.close()


def _count(sql: str, *args) -> int:
    store = SQLiteStore("data/satsa.db")
    try:
        return int(store.conn.execute(sql, args).fetchone()[0])
    finally:
        store.close()


def _expire_lease(job_id: str) -> None:
    store = SQLiteStore("data/satsa.db")
    try:
        with store.transaction():
            store.conn.execute("UPDATE jobs SET lease_until = ? WHERE job_id = ?",
                               (iso(utc_now().replace(year=2000)), job_id))
    finally:
        store.close()


def test_a_queued_job_survives_a_restart_and_a_worker_process_runs_it(deployment):
    job = _enqueue()
    assert job["state"] == "queued" and not job["deduplicated"]
    # Nothing in memory: a separate process, started later, finds and runs it.
    done = subprocess.run([sys.executable, "-m", "satsa.cli", "worker", "--once"], cwd=deployment, env=ENV,
                          capture_output=True, text=True, check=False, timeout=600)
    assert done.returncode == 0, done.stderr[-2000:]
    finished = _job(job["job_id"])
    assert finished["state"] == "succeeded", finished
    assert finished["result"]["run_id"] == f"RUN-{job['job_id']}"
    assert _count("SELECT count(*) FROM runs WHERE run_id = ?", finished["result"]["run_id"]) == 1
    assert finished["attempts"] == 1 and finished["heartbeat_at"] and finished["finished_at"]


def test_the_same_pending_work_is_not_queued_twice(deployment):
    first = _enqueue(input_fingerprint=fingerprint("assessment", {"period": "2026-Q1"}, "x"))
    again = _enqueue(input_fingerprint=fingerprint("assessment", {"period": "2026-Q1"}, "x"))
    assert again["job_id"] == first["job_id"] and again["deduplicated"]
    store = SQLiteStore("data/satsa.db")
    try:
        JobQueue(store).cancel(first["job_id"])
    finally:
        store.close()
    later = _enqueue(input_fingerprint=fingerprint("assessment", {"period": "2026-Q1"}, "x"))
    assert later["job_id"] != first["job_id"], "a finished job does not block new work"


def test_an_expired_lease_is_requeued_and_the_retry_does_not_duplicate_the_run(deployment):
    job = _enqueue()
    dead = Worker(worker_id="dead-worker")
    try:
        claimed = dead.queue.claim("dead-worker", lease_seconds=60)
        assert claimed is not None and claimed["job_id"] == job["job_id"]
        # The dead worker had published the run, then died before recording success.
        ctx = JobContext(dead, claimed, dead.store)
        first = handlers.assessment(ctx)
    finally:
        dead.store.close()
    runs_before = _count("SELECT count(*) FROM runs")
    findings_before = _count("SELECT count(*) FROM findings WHERE run_id = ?", first["run_id"])
    _expire_lease(job["job_id"])

    (done,) = run_jobs(job["job_id"])
    assert done["state"] == "succeeded" and done["attempts"] == 2
    assert done["result"]["run_id"] == first["run_id"]
    assert _count("SELECT count(*) FROM runs") == runs_before, "the retry published a second run"
    assert _count("SELECT count(*) FROM findings WHERE run_id = ?", first["run_id"]) == findings_before


def test_a_job_that_is_unsafe_to_retry_fails_with_a_structured_error(deployment):
    demo = _enqueue("demo_seed", {}, max_attempts=1)
    spent = _enqueue(params={"period": "2026-Q2"}, max_attempts=1)
    store = SQLiteStore("data/satsa.db")
    try:
        queue = JobQueue(store)
        for jid in (demo["job_id"], spent["job_id"]):
            assert queue.claim("gone", job_id=jid) is not None
            _expire_lease(jid)
        assert set(queue.recover_expired(handlers.RETRY_SAFE)) == {demo["job_id"], spent["job_id"]}
        for jid in (demo["job_id"], spent["job_id"]):
            failed = queue.get(jid)
            assert failed is not None and failed["state"] == "failed"
            assert failed["error"]["type"] == "WorkerLost" and "gone" in failed["error"]["message"]
    finally:
        store.close()


def test_cancelling_a_queued_job_means_it_never_runs(deployment):
    job = _enqueue()
    store = SQLiteStore("data/satsa.db")
    try:
        assert JobQueue(store).cancel(job["job_id"])["state"] == "cancelled"
    finally:
        store.close()
    assert run_jobs(job["job_id"]) == []
    assert _count("SELECT count(*) FROM runs WHERE run_id = ?", f"RUN-{job['job_id']}") == 0


def test_a_running_job_stops_at_its_next_stage_when_cancelled(deployment, monkeypatch):
    job = _enqueue("test_kind", {})
    reached: list[str] = []

    def handler(ctx: JobContext) -> dict:
        ctx.stage("first stage")
        reached.append("first")
        JobQueue(ctx.store).cancel(ctx.job["job_id"])  # an analyst presses Cancel meanwhile
        ctx.stage("second stage")
        reached.append("second")
        return {}

    monkeypatch.setitem(handlers.HANDLERS, "test_kind", handler)
    monkeypatch.setattr("satsa.jobs.worker.HANDLERS", handlers.HANDLERS)
    (done,) = run_jobs(job["job_id"])
    assert reached == ["first"]
    assert done["state"] == "cancelled" and "second stage" in done["error"]["message"]


def test_a_failure_records_its_type_message_and_stage(deployment, monkeypatch):
    job = _enqueue("test_kind", {})

    def handler(ctx: JobContext) -> dict:
        ctx.stage("validating")
        raise ValueError("column created_at is not a timestamp")

    monkeypatch.setitem(handlers.HANDLERS, "test_kind", handler)
    (done,) = run_jobs(job["job_id"])
    assert done["state"] == "failed"
    assert done["error"]["type"] == "ValueError"
    assert done["error"]["message"] == "column created_at is not a timestamp"
    assert done["error"]["stage"] == "validating"


def test_cancellation_check_raises_between_stages(deployment):
    job = _enqueue()
    worker = Worker()
    try:
        claimed = worker.queue.claim(worker.worker_id, job_id=job["job_id"])
        assert claimed is not None
        ctx = JobContext(worker, claimed, worker.store)
        ctx.stage("one")
        worker.queue.cancel(job["job_id"])
        with pytest.raises(JobCancelled):
            ctx.stage("two")
    finally:
        worker.close()


def test_a_killed_worker_process_loses_no_job_and_duplicates_nothing(deployment):
    job = _enqueue()
    proc = subprocess.Popen([sys.executable, "-m", "satsa.cli", "worker", "--lease-seconds", "3"],
                            cwd=deployment, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 120
        while _job(job["job_id"])["state"] == "queued":
            assert time.monotonic() < deadline, "the worker never claimed the job"
            time.sleep(0.05)
    finally:
        proc.kill()  # no clean shutdown: like a crash or an OOM kill
        proc.wait()
    # Killed within ~50 ms of claiming an assessment that takes seconds: the job is mid-run.
    assert _job(job["job_id"])["state"] == "running"
    time.sleep(3.5)  # let the 3-second lease expire
    (done,) = run_jobs(job["job_id"])
    assert done["state"] == "succeeded" and done["attempts"] == 2, done
    assert _count("SELECT count(*) FROM runs WHERE run_id = ?", f"RUN-{job['job_id']}") == 1


def _analyst() -> TestClient:
    from satsa.api.routes import app

    client = TestClient(app)
    r = client.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                    follow_redirects=False)
    assert r.status_code == 303
    return client


CLEAN = "entity_id,alert_id,created_at,severity_final\nCSE-01,JOBS-CLEAN-1,2026-05-03T10:00:00Z,high\n"


def test_an_upload_becomes_an_import_job_with_a_visible_outcome(deployment):
    client = _analyst()
    r = client.post("/upload", data={"target_entity": "CSE-01", "period": "2026-05"},
                    files={"files": ("alerts.csv", CLEAN, "text/csv")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/jobs/JOB-")
    job_id = r.headers["location"].rsplit("/", 1)[1]
    page = client.get(f"/jobs/{job_id}")
    assert "queued" in page.text and "No worker has reported" in page.text
    assert 'http-equiv="refresh"' in page.text
    assert (Path("data/jobs") / job_id / "input" / "alerts.csv").exists()

    (done,) = run_jobs(job_id)
    assert done["state"] == "succeeded", done
    page = client.get(f"/jobs/{job_id}")
    assert "Batch ingested successfully" in page.text and f"RUN-{job_id}" in page.text
    assert 'http-equiv="refresh"' not in page.text
    api = client.get(f"/api/v1/jobs/{job_id}").json()
    assert api["state"] == "succeeded" and api["result"]["batch_id"] == f"BATCH-{job_id}-a1"
    assert "role" not in api["params"] and "lease_owner" not in api
    assert not (Path("data/jobs") / job_id / "input").exists(), "the input is removed once imported"


def test_an_import_retry_continues_from_the_batch_an_earlier_attempt_published(deployment, monkeypatch):
    client = _analyst()
    r = client.post("/upload", data={"target_entity": "CSE-01", "period": "2026-06"},
                    files={"files": ("alerts.csv", CLEAN.replace("JOBS-CLEAN", "JOBS-RETRY"), "text/csv")},
                    follow_redirects=False)
    job_id = r.headers["location"].rsplit("/", 1)[1]

    dead = Worker(worker_id="dead-worker")
    try:
        claimed = dead.queue.claim("dead-worker", job_id=job_id)
        assert claimed is not None

        def power_cut(*_a, **_k):
            raise RuntimeError("power cut after publication")

        with monkeypatch.context() as patched, pytest.raises(RuntimeError, match="power cut"):
            patched.setattr(handlers, "_assess", power_cut)
            handlers.import_files(JobContext(dead, claimed, dead.store))
    finally:
        dead.store.close()
    _expire_lease(job_id)

    (done,) = run_jobs(job_id)
    assert done["state"] == "succeeded" and done["attempts"] == 2, done
    assert done["result"]["batch_id"] == f"BATCH-{job_id}-a1"
    catalog = Catalog("data")
    try:
        mine = [b for b in catalog.batches(limit=1000) if b["batch_id"].startswith(f"BATCH-{job_id}")]
    finally:
        catalog.close()
    assert [b["state"] for b in mine] == ["published"], "the retry must not ingest the files again"


def test_the_jobs_page_says_when_a_worker_is_alive(deployment):
    client = _analyst()
    assert "No worker has reported" in client.get("/jobs").text
    worker = Worker()
    try:
        worker.run_once()  # nothing queued; it still reports in
        assert "Worker running" in client.get("/jobs").text
    finally:
        worker.close()
    assert "No worker has reported" in client.get("/jobs").text, "a stopped worker is not shown as alive"


def test_tuning_and_entity_changes_queue_assessments_instead_of_running_in_the_request(deployment):
    client = _analyst()
    runs_before = _count("SELECT count(*) FROM runs")
    r = client.post("/tuning/save", data={"period": "2026-Q1"}, follow_redirects=False)
    assert r.status_code == 303 and "queued as job JOB-" in unquote_plus(r.headers["location"])
    assert _count("SELECT count(*) FROM runs") == runs_before, "nothing ran inside the request"
    assert _count("SELECT count(*) FROM jobs WHERE kind = 'assessment' AND state = 'queued'") == 1
