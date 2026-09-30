"""The web app keeps the analytics tables loaded between requests (AnalyticsCache).

Before, every request built a new DuckDB store and re-read every Parquet file, including
the many requests that only needed SQLite. The cache is rebuilt when a new assessment run
completes or the stored data changes, and never otherwise.
"""

import shutil
import threading
from datetime import datetime
from pathlib import Path

import polars as pl
import pytest
from fastapi.testclient import TestClient

from satsa.api import routes
from satsa.ingest.pipeline import IngestionPipeline
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import (
    AnalyticsCache,
    DuckDBStore,
    ReadOnlyStoreError,
    analytics_cache,
    parquet_fingerprint,
)
from satsa.store.sqlite import SQLiteStore
from satsa.synth.generator import SyntheticDataGenerator

REPO = Path(__file__).resolve().parent.parent


def _seed_alerts(data_dir: Path, entity: str, n: int) -> None:
    store = DuckDBStore(data_dir)
    store.write_partitioned_parquet(
        "alert",
        pl.DataFrame(
            [{"entity_id": entity, "alert_id": f"{entity}-{i}", "created_at": datetime(2026, 1, 1, 9, i % 60)} for i in range(n)]
        ),
    )
    store.close()


def _count(view) -> int:
    return view.query("SELECT count(*) FROM alert").row(0)[0]


# ------------------------------------------------------------------ the cache itself


def test_tables_are_loaded_once_and_reused(tmp_path):
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    for _ in range(10):
        view = cache.view(tmp_path, "RUN-1")
        assert _count(view) == 5
        view.close()  # closes this request's cursor only
    assert cache.loads == 1


def test_a_new_run_retires_the_cache(tmp_path):
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    cache.view(tmp_path, "RUN-1").close()
    cache.view(tmp_path, "RUN-1").close()
    assert cache.loads == 1
    cache.view(tmp_path, "RUN-2").close()
    assert cache.loads == 2
    cache.view(tmp_path, "RUN-2").close()
    assert cache.loads == 2


def test_changed_data_retires_the_cache_even_without_a_run(tmp_path):
    """An ingest by another process (CLI, Admin Portal) must not leave the web app on old data."""
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    assert _count(cache.view(tmp_path, None)) == 5
    before = parquet_fingerprint(tmp_path / "parquet")

    _seed_alerts(tmp_path, "E2", 3)  # a second entity's file appears
    assert parquet_fingerprint(tmp_path / "parquet") != before
    assert _count(cache.view(tmp_path, None)) == 8
    assert cache.loads == 2

    (tmp_path / "parquet" / "alert" / "entity_id=E2" / "data.parquet").unlink()  # and is deleted again
    assert _count(cache.view(tmp_path, None)) == 5
    assert cache.loads == 3


def test_each_data_directory_has_its_own_cache(tmp_path):
    _seed_alerts(tmp_path / "a", "E1", 2)
    _seed_alerts(tmp_path / "b", "E1", 7)
    cache = AnalyticsCache()
    assert (_count(cache.view(tmp_path / "a", None)), _count(cache.view(tmp_path / "b", None))) == (2, 7)
    assert _count(cache.view(tmp_path / "a", None)) == 2
    assert cache.loads == 2
    cache.clear()
    cache.view(tmp_path / "a", None)
    assert cache.loads == 3


def test_fingerprint_of_an_empty_or_missing_store(tmp_path):
    assert parquet_fingerprint(tmp_path / "nothing-here") == (0, 0, 0)
    (tmp_path / "parquet").mkdir()
    (tmp_path / "parquet" / "notes.txt").write_text("not data")
    assert parquet_fingerprint(tmp_path / "parquet") == (0, 0, 0)


def test_shared_view_is_read_only(tmp_path):
    _seed_alerts(tmp_path, "E1", 5)
    view = AnalyticsCache().view(tmp_path, None)
    with pytest.raises(ReadOnlyStoreError):
        view.write_partitioned_parquet("alert", pl.DataFrame([{"entity_id": "E9", "alert_id": "X"}]))
    with pytest.raises(ReadOnlyStoreError):
        view.load_all_tables()
    assert _count(view) == 5


def test_views_can_be_used_from_many_threads_at_once(tmp_path):
    _seed_alerts(tmp_path, "E1", 400)
    cache = AnalyticsCache()
    results, errors = [], []

    def worker() -> None:
        try:
            for _ in range(25):
                view = cache.view(tmp_path, "RUN-1")
                results.append(view.query("SELECT count(*), min(alert_id) FROM alert WHERE entity_id = ?", ["E1"]).row(0))
                view.close()
        except Exception as exc:  # noqa: BLE001 - collected and asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert set(results) == {(400, "E1-0")} and len(results) == 200
    assert cache.loads == 1


# ------------------------------------------------------------------ through the web app


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A small, real SAT-SA data directory; the app is pointed at it by working directory."""
    shutil.copytree(REPO / "config", tmp_path / "config")
    monkeypatch.chdir(tmp_path)
    csv_dir, _ = SyntheticDataGenerator(seed=11, base_alerts_per_entity=60).save_dataset(tmp_path / "gen")
    (tmp_path / "data").mkdir()
    duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    IngestionPipeline(duck, sql).ingest_directory(csv_dir)

    def run() -> str:
        return AssessmentRunner(duck, sql).run_assessment(period="2026-Q1", actor="test")["run_id"]

    run()
    analytics_cache.clear()
    loads_before = analytics_cache.loads
    client = TestClient(routes.app)
    login = client.post(
        "/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"}, follow_redirects=False
    )
    assert login.status_code == 303 and "error" not in login.headers["location"]
    yield client, run, lambda: analytics_cache.loads - loads_before
    duck.close()
    sql.close()
    analytics_cache.clear()


def test_requests_reuse_the_loaded_tables_until_a_run_completes(workspace):
    client, run, loads = workspace
    assert loads() == 0  # logging in needs SQLite only

    pages = ("/portfolio", "/alerts", "/entity/CSE-02", "/api/v1/entities", "/upload", "/blind-review")
    for _ in range(3):
        for page in pages:
            assert client.get(page).status_code == 200, page
    assert loads() == 1  # 18 analytics requests, one load

    run()  # a new assessment run completes
    assert client.get("/portfolio").status_code == 200
    assert loads() == 2
    assert client.get("/api/v1/entities").status_code == 200
    assert loads() == 2


def test_state_only_requests_do_not_load_the_analytics_tables(workspace):
    client, _, loads = workspace
    for page in ("/queue", "/dq", "/runs", "/tuning", "/api/v1/runs", "/api/v1/findings", "/api/v1/queue",
                 "/api/session/status", "/api/v1/audit/verify"):  # fmt: skip
        assert client.get(page).status_code == 200, page
    assert loads() == 0


def test_mutating_request_is_seen_by_the_next_read(workspace):
    client, _, loads = workspace
    before = {e["entity_id"] for e in client.get("/api/v1/entities").json()}
    assert loads() == 1 and "CSE-NEW" not in before
    added = client.post(
        "/upload/add-entity",
        data={"entity_id": "CSE-NEW", "name": "New Entity", "sector": "power", "size_band": "Medium"},
        follow_redirects=False,
    )
    assert added.status_code == 303, added.text[:300]
    after = {e["entity_id"] for e in client.get("/api/v1/entities").json()}
    assert "CSE-NEW" in after and loads() >= 2
