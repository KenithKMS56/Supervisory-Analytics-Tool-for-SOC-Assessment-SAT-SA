"""The web app keeps the analytics tables loaded between requests (AnalyticsCache).

Before, every request built a new DuckDB store and re-read every Parquet file, including
the many requests that only needed SQLite. The cache is rebuilt when the stored data changes,
and never otherwise: an assessment run publishes no data, so a completed run does not rebuild
it. A refresher thread rebuilds it after a publication before any request asks, and a request
never reads tables older than the data.
"""

import shutil
import threading
import time
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
        view = cache.view(tmp_path)
        assert _count(view) == 5
        view.close()  # closes this request's cursor only
    assert cache.loads == 1


def test_a_request_waits_for_the_load_in_progress_instead_of_loading_again(tmp_path, monkeypatch):
    """Two requests after a publication: the second waits for the first one's load and reads its
    tables (current data, loaded once), never the previous tables."""
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    assert _count(cache.view(tmp_path)) == 5
    _seed_alerts(tmp_path, "E2", 3)

    started, release = threading.Event(), threading.Event()
    load = DuckDBStore.load_all_tables

    def slow_load(self, max_pub_seq=None):
        started.set()
        assert release.wait(10)
        load(self, max_pub_seq)

    monkeypatch.setattr(DuckDBStore, "load_all_tables", slow_load)
    counts: list[int] = []
    first = threading.Thread(target=lambda: counts.append(_count(cache.view(tmp_path))))
    first.start()
    assert started.wait(10)  # the first request is loading
    second = threading.Thread(target=lambda: counts.append(_count(cache.view(tmp_path))))
    second.start()
    second.join(0.3)
    assert second.is_alive()  # waiting for the load, not served the previous tables
    release.set()
    first.join(10)
    second.join(10)
    assert counts == [8, 8]
    assert cache.loads == 2  # the initial load and one after the publication


def test_changed_data_retires_the_cache_even_without_a_run(tmp_path):
    """An ingest by another process (CLI, Admin Portal) must not leave the web app on old data."""
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    cache.FINGERPRINT_SECONDS = 0  # look at the files on every request (the throttle: next test)
    assert _count(cache.view(tmp_path)) == 5
    before = parquet_fingerprint(tmp_path / "parquet")

    _seed_alerts(tmp_path, "E2", 3)  # a second entity's file appears
    assert parquet_fingerprint(tmp_path / "parquet") != before
    assert _count(cache.view(tmp_path)) == 8
    assert cache.loads == 2

    for f in (tmp_path / "parquet" / "alert" / "entity_id=E2").glob("*.parquet"):
        f.unlink()  # and is deleted again (the loader skips the missing published file, with a warning)
    assert _count(cache.view(tmp_path)) == 5
    assert cache.loads == 3


def test_a_publication_is_seen_at_once_and_a_file_removed_outside_the_catalog_soon_after(tmp_path, monkeypatch):
    """Every ingest path publishes through the catalog, whose sequence is read on every request,
    so new data is seen at once. The Parquet walk, which catches a file changed outside the
    catalog, is taken at most every FINGERPRINT_SECONDS: such a change is seen on the first
    request after that, never left in place indefinitely."""
    clock = [1000.0]
    monkeypatch.setattr("satsa.store.duckdb.time.monotonic", lambda: clock[0])
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    assert _count(cache.view(tmp_path)) == 5
    _seed_alerts(tmp_path, "E2", 3)  # published through the catalog (a direct batch)
    assert _count(cache.view(tmp_path)) == 8 and cache.loads == 2  # no time has passed

    for f in (tmp_path / "parquet" / "alert" / "entity_id=E2").glob("*.parquet"):
        f.unlink()  # removed behind the catalog's back
    clock[0] += cache.FINGERPRINT_SECONDS / 2
    assert _count(cache.view(tmp_path)) == 8 and cache.loads == 2  # within the interval
    clock[0] += cache.FINGERPRINT_SECONDS
    assert _count(cache.view(tmp_path)) == 5 and cache.loads == 3


def test_each_data_directory_has_its_own_cache(tmp_path):
    _seed_alerts(tmp_path / "a", "E1", 2)
    _seed_alerts(tmp_path / "b", "E1", 7)
    cache = AnalyticsCache()
    assert (_count(cache.view(tmp_path / "a")), _count(cache.view(tmp_path / "b"))) == (2, 7)
    assert _count(cache.view(tmp_path / "a")) == 2
    assert cache.loads == 2
    cache.clear()
    cache.view(tmp_path / "a")
    assert cache.loads == 3


def test_fingerprint_of_an_empty_or_missing_store(tmp_path):
    assert parquet_fingerprint(tmp_path / "nothing-here") == (0, 0, 0)
    (tmp_path / "parquet").mkdir()
    (tmp_path / "parquet" / "notes.txt").write_text("not data")
    assert parquet_fingerprint(tmp_path / "parquet") == (0, 0, 0)


def test_shared_view_is_read_only(tmp_path):
    _seed_alerts(tmp_path, "E1", 5)
    view = AnalyticsCache().view(tmp_path)
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
                view = cache.view(tmp_path)
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


def test_refresh_reloads_changed_data_before_any_request(tmp_path):
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    assert _count(cache.view(tmp_path)) == 5 and cache.loads == 1
    cache.refresh()
    assert cache.loads == 1  # nothing changed: nothing reloaded
    _seed_alerts(tmp_path, "E2", 3)
    cache.refresh()
    assert cache.loads == 2
    assert _count(cache.view(tmp_path)) == 8 and cache.loads == 2  # the request found it loaded


def test_refresh_leaves_a_data_directory_no_request_used(tmp_path):
    _seed_alerts(tmp_path / "a", "E1", 2)
    _seed_alerts(tmp_path / "b", "E1", 7)
    cache = AnalyticsCache()
    cache.view(tmp_path / "a").close()
    _seed_alerts(tmp_path / "a", "E2", 1)
    cache.refresh()
    assert cache.loads == 2  # "a" reloaded, "b" never loaded
    assert _count(cache.view(tmp_path / "b")) == 7 and cache.loads == 3


def _wait_for_loads(cache: AnalyticsCache, n: int) -> None:
    deadline = time.monotonic() + 30
    while cache.loads < n and time.monotonic() < deadline:
        time.sleep(0.05)


def test_the_refresher_thread_picks_up_a_publication(tmp_path, monkeypatch):
    monkeypatch.delenv("SATSA_ANALYTICS_REFRESH", raising=False)
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    cache.REFRESH_SECONDS = 0.05
    cache.view(tmp_path).close()
    assert cache.start_refresher()
    try:
        assert cache.start_refresher()  # once per process: a second call starts nothing new
        _seed_alerts(tmp_path, "E2", 3)
        _wait_for_loads(cache, 2)
        assert cache.loads == 2
        assert _count(cache.view(tmp_path)) == 8 and cache.loads == 2
    finally:
        cache.stop_refresher()
    assert cache._refresher is None


def test_the_refresher_keeps_running_after_a_failed_load(tmp_path, monkeypatch):
    monkeypatch.delenv("SATSA_ANALYTICS_REFRESH", raising=False)
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    cache.REFRESH_SECONDS = 0.05
    cache.view(tmp_path).close()
    load = DuckDBStore.load_all_tables
    failures: list[int] = []

    def failing_once(self, max_pub_seq=None):
        if not failures:
            failures.append(1)
            raise OSError("disk unavailable")
        load(self, max_pub_seq)

    monkeypatch.setattr(DuckDBStore, "load_all_tables", failing_once)
    assert cache.start_refresher()
    try:
        _seed_alerts(tmp_path, "E2", 3)
        _wait_for_loads(cache, 2)
        assert failures == [1] and cache.loads == 2
        assert _count(cache.view(tmp_path)) == 8
    finally:
        cache.stop_refresher()


def test_a_refresher_stopped_during_a_reload_ends_after_it_even_if_another_starts(tmp_path, monkeypatch):
    """Stopping does not wait out a long reload; a refresher started meanwhile must not revive
    the stopped one (two threads would then watch, and reload, side by side)."""
    monkeypatch.delenv("SATSA_ANALYTICS_REFRESH", raising=False)
    _seed_alerts(tmp_path, "E1", 5)
    cache = AnalyticsCache()
    cache.REFRESH_SECONDS = 0.05
    cache.view(tmp_path).close()
    _seed_alerts(tmp_path, "E2", 3)
    started, release = threading.Event(), threading.Event()
    load = DuckDBStore.load_all_tables

    def slow_load(self, max_pub_seq=None):
        started.set()
        assert release.wait(10)
        load(self, max_pub_seq)

    monkeypatch.setattr(DuckDBStore, "load_all_tables", slow_load)
    assert cache.start_refresher()
    first = cache._refresher
    assert started.wait(10)  # the first refresher is reloading
    cache.stop_refresher(wait_seconds=0)
    assert cache.start_refresher()
    second = cache._refresher
    try:
        release.set()
        first.join(10)
        assert not first.is_alive() and second.is_alive()
        assert _count(cache.view(tmp_path)) == 8 and cache.loads == 2
    finally:
        cache.stop_refresher()


def test_the_refresher_can_be_turned_off(tmp_path, monkeypatch):
    monkeypatch.setenv("SATSA_ANALYTICS_REFRESH", "off")
    cache = AnalyticsCache()
    assert cache.start_refresher() is False
    assert cache._refresher is None


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


def test_requests_reuse_the_loaded_tables_until_data_is_published(workspace):
    client, run, loads = workspace
    assert loads() == 0  # logging in needs SQLite only

    pages = ("/portfolio", "/alerts", "/entity/CSE-02", "/api/v1/entities", "/upload", "/blind-review")
    for _ in range(3):
        for page in pages:
            assert client.get(page).status_code == 200, page
    assert loads() == 1  # 18 analytics requests, one load

    run_id = run()  # a new assessment run completes; it publishes no data
    page = client.get("/portfolio")
    assert page.status_code == 200 and run_id in page.text  # the page shows the new run
    assert loads() == 1  # with the tables already loaded: the run did not change them

    _seed_alerts(Path("data"), "CSE-02", 3)  # data is published
    assert client.get("/portfolio").status_code == 200
    assert loads() == 2
    assert client.get("/api/v1/entities").status_code == 200
    assert loads() == 2


def test_the_served_app_runs_the_refresher(workspace, monkeypatch):
    monkeypatch.delenv("SATSA_ANALYTICS_REFRESH", raising=False)
    with TestClient(routes.app):  # runs start-up and shut-down, as a served instance does
        assert analytics_cache._refresher is not None and analytics_cache._refresher.is_alive()
    assert analytics_cache._refresher is None


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
    # The assessment that includes the new entity is a queued job (docs/product_brief.md section 9).
    from satsa.jobs.worker import run_pending_jobs

    assert [j["state"] for j in run_pending_jobs()] == ["succeeded"]
    after = {e["entity_id"] for e in client.get("/api/v1/entities").json()}
    assert "CSE-NEW" in after and loads() >= 2
