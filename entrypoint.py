"""Container entrypoint for SAT-SA + NCIIPC Administration Platform.

Coordinates concurrent startup of:
- NCIIPC Administration Portal (port 8000)
- SAT-SA Supervisory Tool (port 8001)

Both portals share the exact same underlying SQLite database (in WAL mode),
DuckDB Parquet storage, and the admin activity feed.

Bind address and TLS come from the environment (see satsa.serving): SATSA_HOST
(default 127.0.0.1) and SATSA_TLS_CERT + SATSA_TLS_KEY (default: plain HTTP).
`python entrypoint.py --healthcheck` probes both portals with the same settings.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ADMIN_PORT = 8000
SATSA_PORT = 8001


def healthcheck() -> int:
    """Exit status 0 when both portals answer /splash, over whichever scheme is configured."""
    import ssl
    import urllib.request

    from satsa.serving import serving_config

    config = serving_config()
    # The probe runs inside the container against its own loopback; the self-signed
    # certificate is not what is being checked here, only that the portal answers.
    context = ssl._create_unverified_context() if config.tls else None
    try:
        for port in (ADMIN_PORT, SATSA_PORT):
            url = f"{config.scheme}://127.0.0.1:{port}/splash"
            with urllib.request.urlopen(url, timeout=3, context=context) as resp:
                if resp.status != 200:
                    return 1
    except OSError as exc:
        print(f"[!] Healthcheck failed: {exc}")
        return 1
    return 0


def main() -> None:
    from satsa.serving import ServingConfigError, exposure_warning, serving_config

    if "--healthcheck" in sys.argv[1:]:
        sys.exit(healthcheck())

    try:
        config = serving_config()
    except ServingConfigError as exc:
        print(f"[!] Refusing to start: {exc}")
        sys.exit(2)

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
        for username in store.flag_unrotated_default_accounts():
            print(f"[!] Account '{username}' still uses its published default passphrase: "
                  "a new one must be set at first login.")

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
            except Exception as seed_err:  # noqa: BLE001 - the portals must start even if the demo seed fails
                print(f"[!] Notice: Baseline seed deferred: {seed_err}")

        store.close()
        print("[+] Shared identity and assessment database verified: data/satsa.db")
    except Exception as exc:  # noqa: BLE001 - reported; the portals report their own storage errors
        print(f"[!] Storage initialization warning: {exc}")

    warning = exposure_warning(config)
    if warning:
        print(f"[!] {warning}")
    child_env = config.child_env(os.environ)

    # 2. Launch NCIIPC Administration Portal
    print(f"[+] Launching NCIIPC Admin Portal on {config.scheme}://{config.host}:{ADMIN_PORT}...")
    admin_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", *config.uvicorn_args("satsa.admin.app:app", ADMIN_PORT)],
        env=child_env,
    )

    # 3. Launch SAT-SA Supervisory Tool
    print(f"[+] Launching SAT-SA Supervisory Tool on {config.scheme}://{config.host}:{SATSA_PORT}...")
    satsa_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", *config.uvicorn_args("satsa.api:app", SATSA_PORT)],
        env=child_env,
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
    # Best-effort, loopback-only egress guard for this launcher process (its only connections
    # are the loopback healthcheck); each portal process installs its own through its FastAPI
    # lifespan. See satsa.netguard.
    from satsa.netguard import install_egress_guard

    install_egress_guard()
    main()
