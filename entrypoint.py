"""Container entrypoint for SAT-SA + NCIIPC Administration Platform.

Coordinates concurrent startup of:
- NCIIPC Administration Portal (port 8000)
- SAT-SA Supervisory Tool (port 8001)
- the job worker (`satsa worker`), which runs imports and assessments

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

    # 1. Open (and migrate) the shared database, then prepare the deployment for its mode
    #    (satsa.deployment): production starts empty and is set up with a one-time token; demo
    #    seeds published accounts and loads synthetic data through a job.
    try:
        from satsa.deployment import DemoIsolationError, prepare_deployment

        for line in prepare_deployment("data"):
            print(line)
    except DemoIsolationError as exc:
        print(f"[!] Refusing to start: {exc}")
        sys.exit(2)
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

    # 4. Launch the job worker: imports and assessments run here, not in web requests (satsa.jobs).
    # Exactly one: it is the deployment's single analytical writer.
    print("[+] Launching the job worker...")
    worker_proc = subprocess.Popen([sys.executable, "-m", "satsa.cli", "worker"], env=child_env)
    processes = {"NCIIPC Admin Portal": admin_proc, "SAT-SA Portal": satsa_proc, "Job worker": worker_proc}

    def handle_shutdown(signum, frame):
        print("\n[!] Received shutdown signal. Stopping platform services...")
        for proc in processes.values():
            proc.terminate()
        for proc in processes.values():
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        print("[+] Platform services stopped cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    # 5. Monitor health of child processes. A job the worker was running when it died is
    # requeued (or failed) from its expired lease by the next worker, so nothing is lost.
    while True:
        for name, proc in processes.items():
            if proc.poll() is not None:
                print(f"[!] {name} terminated unexpectedly.")
                handle_shutdown(None, None)
        time.sleep(1)


if __name__ == "__main__":
    # Best-effort, loopback-only egress guard for this launcher process (its only connections
    # are the loopback healthcheck); each portal process installs its own through its FastAPI
    # lifespan. See satsa.netguard.
    from satsa.netguard import install_egress_guard

    install_egress_guard()
    main()
