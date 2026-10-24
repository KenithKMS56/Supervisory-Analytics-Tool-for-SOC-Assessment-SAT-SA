"""Resource preflight of jobs (docs/product_brief.md section 9: "disk/memory preflight checks").

A job the host cannot hold is refused before it starts, with the figures in its error, rather
than failing part-way or pushing the portals into swapping. On a private copy of the deployment.
"""

from __future__ import annotations

from collections import namedtuple

import pytest
from deploy_utils import copy_deployment

from satsa.jobs import handlers, worker
from satsa.jobs.queue import JobQueue
from satsa.jobs.worker import (
    ASSESS_BYTES_PER_ROW,
    MEMORY_BASE_BYTES,
    available_memory_bytes,
    run_jobs,
)
from satsa.store.catalog import Catalog, published_rows
from satsa.store.sqlite import SQLiteStore

MiB = 1024 * 1024


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    monkeypatch.delenv("SATSA_MEMORY_PREFLIGHT", raising=False)
    return root


def _enqueue(kind: str, params: dict) -> dict:
    store = SQLiteStore("data/satsa.db")
    try:
        return JobQueue(store).enqueue(kind, params, "analyst")
    finally:
        store.close()


def _runs() -> int:
    store = SQLiteStore("data/satsa.db")
    try:
        return store.conn.execute("SELECT count(*) FROM runs").fetchone()[0]
    finally:
        store.close()


def test_this_host_reports_its_free_memory():
    free = available_memory_bytes()
    assert free is not None and free > 64 * MiB


def test_published_rows_is_the_catalogs_count(deployment):
    rows = published_rows("data")
    catalog = Catalog("data")
    try:
        expected = catalog.conn.execute(
            "SELECT sum(bt.rows) FROM batch_tables bt JOIN batches b USING (batch_id) WHERE b.state = 'published'"
        ).fetchone()[0]
    finally:
        catalog.close()
    assert rows == expected and rows > 0
    assert published_rows(deployment / "no-such-dir") == 0


def test_an_assessment_the_host_cannot_hold_is_refused_before_it_starts(deployment, monkeypatch):
    needed = MEMORY_BASE_BYTES + ASSESS_BYTES_PER_ROW * published_rows("data")
    monkeypatch.setattr(worker, "available_memory_bytes", lambda: needed - MiB)
    before = _runs()
    job = _enqueue("assessment", {"period": "2026-Q1"})
    (done,) = run_jobs(job["job_id"])
    assert done["state"] == "failed"
    assert done["error"]["type"] == "InsufficientMemory"
    assert "MiB of memory is free" in done["error"]["message"] and "not started" in done["error"]["message"]
    assert _runs() == before, "nothing was assessed"


def test_the_same_assessment_runs_when_the_memory_is_there(deployment, monkeypatch):
    needed = MEMORY_BASE_BYTES + ASSESS_BYTES_PER_ROW * published_rows("data")
    monkeypatch.setattr(worker, "available_memory_bytes", lambda: needed + MiB)
    (done,) = run_jobs(_enqueue("assessment", {"period": "2026-Q1"})["job_id"])
    assert done["state"] == "succeeded", done


def test_the_memory_check_can_be_turned_off_for_a_misleading_host(deployment, monkeypatch):
    monkeypatch.setattr(worker, "available_memory_bytes", lambda: MiB)
    monkeypatch.setenv("SATSA_MEMORY_PREFLIGHT", "off")
    (done,) = run_jobs(_enqueue("assessment", {"period": "2026-Q1"})["job_id"])
    assert done["state"] == "succeeded", done


def _queue_import(name: str = "alerts.csv") -> dict:
    job = _enqueue("import", {"target_entity": "CSE-01", "period": "2026-05", "files": [name]})
    inbox = handlers.job_dir("data", job["job_id"]) / handlers.IMPORT_INPUT
    inbox.mkdir(parents=True)
    (inbox / name).write_text("alert_id,created_at,severity_final\nPF-1,2026-05-02T10:00:00Z,high\n", encoding="utf-8")
    return job


def _batches() -> int:
    catalog = Catalog("data")
    try:
        return catalog.conn.execute("SELECT count(*) FROM batches").fetchone()[0]
    finally:
        catalog.close()


def test_an_import_is_refused_when_the_data_volume_could_fill_up(deployment, monkeypatch):
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(worker.shutil, "disk_usage", lambda _p: usage(10 * MiB, 10 * MiB, MiB))
    before = _batches()
    (done,) = run_jobs(_queue_import()["job_id"])
    assert done["state"] == "failed" and done["error"]["type"] == "InsufficientDisk"
    assert "free on the data volume" in done["error"]["message"]
    assert _batches() == before, "nothing was staged or published"


def test_an_import_is_refused_when_memory_is_short(deployment, monkeypatch):
    monkeypatch.setattr(worker, "available_memory_bytes", lambda: MiB)
    before = _batches()
    (done,) = run_jobs(_queue_import()["job_id"])
    assert done["state"] == "failed" and done["error"]["type"] == "InsufficientMemory"
    assert _batches() == before
    # The upload is kept, so the import can be retried once memory is free.
    assert (handlers.job_dir("data", done["job_id"]) / handlers.IMPORT_INPUT / "alerts.csv").exists()
