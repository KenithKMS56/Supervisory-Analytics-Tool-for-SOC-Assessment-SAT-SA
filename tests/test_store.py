"""Test storage layer: DuckDB and SQLite with hash chaining."""

import tempfile
from pathlib import Path

import polars as pl

from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def test_duckdb_store_initialization():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = DuckDBStore(tmpdir)
        df = pl.DataFrame(
            {
                "entity_id": ["CSE-01", "CSE-02"],
                "name": ["Entity One", "Entity Two"],
                "sector": ["power", "banking"],
                "size_band": ["large", "medium"],
                "soc_model": ["inhouse", "hybrid"],
                "timezone": ["UTC", "UTC"],
                "declared_shift_hours": ["09:00-18:00", "09:00-18:00"],
            }
        )
        store.write_partitioned_parquet("entity", df)
        res = store.query("SELECT count(*) as cnt FROM entity")
        assert res["cnt"][0] == 2
        store.close()


def test_sqlite_audit_hashchain():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        store = SQLiteStore(db_path)

        # Add 3 audit entries
        store.append_audit("ingest", "system", {"files": 3})
        store.append_audit("run", "supervisor", {"run_id": "run-101"})
        store.append_audit("feedback", "examiner", {"queue_id": "q-1", "status": "confirmed"})

        ok, msg = store.verify_audit_chain()
        assert ok is True
        assert "verified successfully" in msg

        # Test tamper detection
        cursor = store.conn.cursor()
        cursor.execute("UPDATE audit_log SET details_json = '{\"tampered\": true}' WHERE rowid = 2")
        store.conn.commit()

        ok, msg = store.verify_audit_chain()
        assert ok is False
        assert "Tampered record" in msg
        store.close()
