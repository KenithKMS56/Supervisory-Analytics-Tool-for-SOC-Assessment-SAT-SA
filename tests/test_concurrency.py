"""Concurrency: simultaneous audit writes must not fork the chain; runs are additive.

The web app opens a new SQLiteStore (its own connection) per request and runs
sync handlers in a thread pool, so two requests can append audit entries at the
same moment. Without serialization both read the same previous hash and insert
two rows with the same prev_hash -- a fork that later fails verification even
though nothing was tampered with.
"""

import threading

from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

THREADS = 8
APPENDS_PER_THREAD = 25


def _hammer(db_path, target, errors):
    barrier = threading.Barrier(THREADS)

    def worker(n: int) -> None:
        store = SQLiteStore(db_path)  # separate connection per thread, as per request
        try:
            barrier.wait()
            for i in range(APPENDS_PER_THREAD):
                target(store, n, i)
        except Exception as e:  # noqa: BLE001 - surfaced via `errors`
            errors.append(e)
        finally:
            store.close()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def test_concurrent_audit_appends_keep_chain_valid(tmp_path):
    db = tmp_path / "concurrent.db"
    SQLiteStore(db).close()  # create schema up front
    errors: list[Exception] = []
    _hammer(db, lambda s, n, i: s.append_audit("concurrent", f"worker{n}", {"i": i}), errors)
    assert errors == []

    store = SQLiteStore(db)
    result = store.verify_audit_chain_detailed()
    count = store.conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    prevs = store.conn.execute("SELECT count(DISTINCT prev_hash) FROM audit_log").fetchone()[0]
    store.close()
    assert count == THREADS * APPENDS_PER_THREAD
    assert prevs == count, "two entries share a prev_hash: the chain forked"
    assert result.ok, result.message


def test_concurrent_admin_audit_appends_keep_chain_valid(tmp_path):
    db = tmp_path / "concurrent_admin.db"
    SQLiteStore(db).close()
    errors: list[Exception] = []
    _hammer(
        db,
        lambda s, n, i: s.append_admin_audit("USER_UPDATED", f"admin{n}", target=f"u{i}"),
        errors,
    )
    assert errors == []
    store = SQLiteStore(db)
    ok, msg = store.verify_admin_audit_chain()
    count = store.conn.execute("SELECT count(*) FROM admin_audit_log").fetchone()[0]
    store.close()
    assert count == THREADS * APPENDS_PER_THREAD
    assert ok, msg


def test_shared_connection_appends_from_threads(tmp_path):
    """The admin app shares ONE store across requests; that must be safe too."""
    store = SQLiteStore(tmp_path / "shared.db")
    barrier = threading.Barrier(THREADS)
    errors: list[Exception] = []

    def worker(n: int) -> None:
        try:
            barrier.wait()
            for i in range(APPENDS_PER_THREAD):
                store.append_admin_audit("SHARED", f"w{n}", target=str(i))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    ok, msg = store.verify_admin_audit_chain()
    assert ok, msg
    store.close()


def test_runs_are_additive_not_destructive(tmp_path):
    """Two runs for the same period keep BOTH runs' findings (run_id is part of finding_id)."""
    from satsa.scoring.runner import AssessmentRunner

    duck = DuckDBStore("data")
    lite = SQLiteStore(tmp_path / "runs.db")
    runner = AssessmentRunner(duck, lite)
    first = runner.run_assessment(period="2026-Q1")
    second = runner.run_assessment(period="2026-Q1")
    assert first["run_id"] != second["run_id"]
    for res in (first, second):
        n = lite.conn.execute(
            "SELECT count(*) FROM findings WHERE run_id = ?", (res["run_id"],)
        ).fetchone()[0]
        assert n == res["findings_count"] > 0
    assert lite.verify_audit_chain_detailed().ok
    duck.close()
    lite.close()
