"""Container entrypoint for SAT-SA + NCIIPC Administration Platform.

Coordinates concurrent startup of:
- NCIIPC Administration Portal (http://0.0.0.0:8000)
- SAT-SA Supervisory Tool (http://0.0.0.0:8001)

Both portals share the exact same underlying SQLite database (in WAL mode),
DuckDB Parquet storage, and the admin activity feed.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def main() -> None:
    print("============================================================")
    print("      SAT-SA SUPERVISORY & NCIIPC ADMINISTRATION PLATFORM   ")
    print("============================================================")

    data_dir = Path("data")
    reports_dir = Path("reports")
    data_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 1. Initialize SQLite store and seed default administrative credentials
    try:
        from satsa.store.sqlite import SQLiteStore

        store = SQLiteStore("data/satsa.db")
        store.seed_default_organisations_and_cses()
        store.seed_default_admin()

        # Check if database has baseline assessment runs; if completely empty, run baseline seed
        cur = store.conn.cursor()
        cur.execute("SELECT count(*) FROM findings")
        findings_count = cur.fetchone()[0]

        if findings_count == 0:
            print("[+] Fresh volume detected. Seeding baseline supervisory demonstration dataset...")
            try:
                import tempfile
                from satsa.ingest.pipeline import IngestionPipeline
                from satsa.scoring.history import seed_historical_periods
                from satsa.scoring.runner import AssessmentRunner
                from satsa.store.duckdb import DuckDBStore
                from satsa.synth.generator import SyntheticDataGenerator

                duckdb_store = DuckDBStore("data")
                gen = SyntheticDataGenerator(seed=42, base_alerts_per_entity=1500)
                with tempfile.TemporaryDirectory() as tmpdir:
                    csv_dir, _ = gen.save_dataset(Path(tmpdir))
                    pipeline = IngestionPipeline(duckdb_store, store)
                    _ = pipeline.ingest_directory(csv_dir)
                    runner = AssessmentRunner(duckdb_store, store)
                    _ = runner.run_assessment(period="2026-Q1", actor="system")
                duckdb_store.close()
                seed_historical_periods("data", store, n_periods=3, actor="system")
                print("[+] Baseline assessment dataset seeded successfully.")
            except Exception as seed_err:
                print(f"[!] Notice: Baseline seed deferred: {seed_err}")

        store.close()
        print("[+] Shared identity and assessment database verified: data/satsa.db")
    except Exception as exc:
        print(f"[!] Storage initialization warning: {exc}")

    # 2. Launch NCIIPC Administration Portal on 0.0.0.0:8000
    print("[+] Launching NCIIPC Admin Portal on http://0.0.0.0:8000...")
    admin_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "satsa.admin.app:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--log-level",
            "info",
        ]
    )

    # 3. Launch SAT-SA Supervisory Tool on 0.0.0.0:8001
    print("[+] Launching SAT-SA Supervisory Tool on http://0.0.0.0:8001...")
    satsa_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "satsa.api:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8001",
            "--log-level",
            "info",
        ]
    )

    def handle_shutdown(signum, frame):
        print("\n[!] Received shutdown signal. Stopping platform services...")
        admin_proc.terminate()
        satsa_proc.terminate()
        try:
            admin_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            admin_proc.kill()
        try:
            satsa_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            satsa_proc.kill()
        print("[+] Platform services stopped cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    # 4. Monitor health of child processes
    while True:
        if admin_proc.poll() is not None:
            print("[!] NCIIPC Admin Portal terminated unexpectedly.")
            handle_shutdown(None, None)
        if satsa_proc.poll() is not None:
            print("[!] SAT-SA Portal terminated unexpectedly.")
            handle_shutdown(None, None)
        time.sleep(1)


if __name__ == "__main__":
    main()
