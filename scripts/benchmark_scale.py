"""Scale benchmark: generate N entities x M alerts, then time ingest, assessment and page loads.

    python scripts/benchmark_scale.py --configs 10x50000,25x100000,50x100000 --out docs/benchmarks.md
    python scripts/benchmark_scale.py --configs 10x10000,10x10000:skewed,10x10000:freetext --readers

For each configuration a canonical CSV submission is generated (the same 14 tables and roughly
the same row ratios as `satsa generate-data`), then three stages run, each in its own process
so that its peak memory is its own:

  ingest   satsa's IngestionPipeline over the CSV directory
  assess   AssessmentRunner.run_assessment over the stored data
  pages    the web app (in-process test client): first page after start, then repeat loads

A configuration `ENTITIESxALERTS[:profile]` picks the shape of the data (docs/product_brief.md
section 13):

  uniform    every entity has the same number of alerts, spread evenly over the half-year
  skewed     the same total, split across entities by a Zipf law (the first holds the most)
  freetext   closure comments are submitted as free text of about 1 KiB with e-mail addresses
             and IP addresses in it, so redaction, hashing and shingling are part of ingest
  uneven     alerts crowd into the start of the half-year (density falls with time), so the
             months and quarters of the period hold very different volumes

With --readers, two more steps run after `pages`:

  readers  a real server (uvicorn) with ten signed-in reader sessions requesting pages in a
           loop: first with nothing else running, then while a second submission (two more
           entities of the same size) is ingested in another process; latency percentiles
           and errors are reported for both
  repeat   the first submission is ingested again unchanged: its time, and whether the stored
           alert count stays the same (a repeated submission must not double the data)

Every figure written to the report is measured on the machine the script runs on; a stage that
fails or exceeds --stage-timeout is reported as such, never estimated. Nothing here touches
the repository's own data/ directory: each configuration gets a scratch workspace.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

DAYS = 181  # 2026-01-01 .. 2026-06-30
ASSETS_PER_ENTITY = 40
RULES_PER_ENTITY = 30
PAGES = ("/portfolio", "/alerts", "/entity/{entity}", "/queue", "/api/v1/entities")
NEW_PASSPHRASE = "Benchmark-Passphrase#2026"


# ------------------------------------------------------------------ measurement helpers


def peak_memory_mb() -> float:
    """Peak resident memory of this process so far, in MiB."""
    if os.name == "nt":
        class Counters(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong)] + [
                (name, ctypes.c_size_t)
                for name in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                             "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                             "PagefileUsage", "PeakPagefileUsage")
            ]  # fmt: skip

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
        if not psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            return 0.0
        return counters.PeakWorkingSetSize / (1024 * 1024)
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


def total_ram_gb() -> float:
    if os.name == "nt":
        class Status(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong)
                for name in ("ullTotalPhys", "ullAvailPhys", "ullTotalPageFile", "ullAvailPageFile",
                             "ullTotalVirtual", "ullAvailVirtual", "ullAvailExtendedVirtual")
            ]  # fmt: skip

        status = Status()
        status.dwLength = ctypes.sizeof(Status)
        ctypes.WinDLL("kernel32").GlobalMemoryStatusEx(ctypes.byref(status))
        return status.ullTotalPhys / 1024**3
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1024**3


def cpu_name() -> str:
    if os.name == "nt":
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def machine_specs() -> dict[str, str]:
    import duckdb
    import polars

    return {
        "CPU": cpu_name(),
        "Logical CPUs": str(os.cpu_count()),
        "RAM": f"{total_ram_gb():.1f} GB",
        "OS": f"{platform.system()} {platform.release()} ({platform.version()})",
        "Python": platform.python_version(),
        "DuckDB": duckdb.__version__,
        "Polars": polars.__version__,
    }


# ------------------------------------------------------------------ data generation

# Closure comments as the synthetic generator submits them (already hashed), or as free text of
# about 1 KiB carrying personal data the ingest must redact before it hashes.
PRE_HASHED_COMMENT = """substr(md5(((h >> 5) % 5000)::varchar || alert_id), 1, 16) AS comment_norm_hash,
                   40 + CAST((h >> 9) % 160 AS INTEGER) AS comment_len, NULL AS comment_shingles"""
FREE_TEXT_COMMENT = """'Closed after review of ' || alert_id || ' by analyst' || ((h >> 20) % 12) || '@soc' || ((h >> 3) % 7)
                       || '.example.org from 10.' || ((h >> 4) % 250) || '.' || ((h >> 6) % 250) || '.' || ((h >> 8) % 250)
                       || '. ' || repeat('Checked the host timeline, the EDR process tree and the proxy logs; '
                       || 'no further activity was seen and the user confirmed the action. ', 1 + CAST((h >> 9) % 7 AS INTEGER))
                       AS comment"""


PROFILES = ("uniform", "skewed", "freetext", "uneven")


def alerts_by_entity(entities: int, alerts_per_entity: int, profile: str) -> list[int]:
    """Alerts of each entity: equal, or (skewed) the same total split by a Zipf law."""
    total = entities * alerts_per_entity
    if profile != "skewed":
        return [alerts_per_entity] * entities
    weights = [1 / (e + 1) for e in range(entities)]
    counts = [max(1, int(total * w / sum(weights))) for w in weights]
    counts[0] += total - sum(counts)
    return counts


def generate(csv_dir: Path, entities: int, alerts_per_entity: int, profile: str = "uniform",
             entity_offset: int = 0) -> dict[str, int]:
    """Write a canonical CSV submission with DuckDB (fast, deterministic: no random state).
    Entities are numbered from `entity_offset + 1`, so a second submission can add new ones."""
    import duckdb

    csv_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(":memory:")
    n = entities
    num = f"(e + 1 + {entity_offset})"
    ent = f"'CSE-' || lpad({num}::varchar, 3, '0')"
    span = DAYS * 86400
    counts_by_entity = alerts_by_entity(entities, alerts_per_entity, profile)
    con.execute("CREATE TABLE cnt (e BIGINT, m BIGINT)")
    con.executemany("INSERT INTO cnt VALUES (?, ?)", list(enumerate(counts_by_entity)))
    # Where in the half-year an alert falls, as a fraction: even, or crowded towards the start.
    position = "power(s / cnt.m, 2.5)" if profile == "uneven" else "(s / cnt.m)"
    # One row per alert: e = entity index, s = sequence within the entity, h = a stable hash.
    con.execute(f"""
        CREATE TABLE a AS
        SELECT cnt.e AS e, s, CAST(hash(({num.replace('e +', 'cnt.e +')}) * 1000003 + s) >> 1 AS BIGINT) AS h,
               {ent.replace('(e +', '(cnt.e +')} AS entity_id,
               'A' || lpad({num.replace('e +', 'cnt.e +')}::varchar, 3, '0') || '-' || lpad((s + 1)::varchar, 7, '0') AS alert_id,
               TIMESTAMP '2026-01-01 00:00:00'
                   + to_seconds(CAST(floor({position} * ({span} - 86400.0)) AS BIGINT) + CAST(hash(s, cnt.e) % 3600 AS BIGINT)) AS created_at
        FROM cnt, range({max(counts_by_entity)}) ts(s)
        WHERE s < cnt.m
    """)
    sev = "CASE WHEN h % 100 < 55 THEN 'low' WHEN h % 100 < 85 THEN 'medium' WHEN h % 100 < 97 THEN 'high' ELSE 'critical' END"
    disp = "CASE WHEN (h >> 8) % 100 < 8 THEN 'true_positive' WHEN (h >> 8) % 100 < 68 THEN 'false_positive' ELSE 'benign' END"
    human = "((h >> 16) % 10) <> 0"
    analyst = f"'ANALYST_' || lpad({num}::varchar, 3, '0') || '_' || lpad(((h >> 20) % 12)::varchar, 2, '0')"
    close_s = "1800 + CAST((h >> 24) % 12600 AS BIGINT)"  # 30 min .. 4 h
    tables: dict[str, str] = {
        "entity": f"""
            SELECT {ent} AS entity_id, 'Benchmark Entity ' || {num} AS name,
                   (['power', 'banking', 'telecom', 'transport', 'oil_and_gas'])[1 + e % 5] AS sector,
                   (['small', 'medium', 'large'])[1 + e % 3] AS size_band, 'inhouse' AS soc_model,
                   'internal' AS soc_provider, 'UTC' AS timezone, '09:00-18:00' AS declared_shift_hours
            FROM range({n}) te(e)""",
        "alert": f"""
            SELECT entity_id, alert_id,
                   'RULE-' || lpad((h % {RULES_PER_ENTITY})::varchar, 3, '0') AS rule_id,
                   (['Malware', 'Phishing', 'Unauthorized Access', 'Lateral Movement', 'Policy Violation',
                     'Credential Access', 'Suspicious Activity', 'Data Exfiltration'])[1 + (h >> 4) % 8] AS category,
                   {sev} AS severity_orig, {sev} AS severity_final,
                   'AST-' || lpad({num}::varchar, 3, '0') || '-' || lpad(((h >> 12) % {ASSETS_PER_ENTITY})::varchar, 3, '0') AS asset_id,
                   created_at, created_at + INTERVAL 7 MINUTE AS acknowledged_at,
                   created_at + INTERVAL 9 MINUTE AS first_touch_at,
                   created_at + to_seconds({close_s}) AS closed_at,
                   CASE WHEN {human} THEN {analyst} ELSE 'soar-engine' END AS closed_by,
                   CASE WHEN {human} THEN 'human' ELSE 'automation' END AS closed_by_type,
                   CASE WHEN {human} THEN NULL ELSE 'PB-' || (h % 9) END AS playbook_id,
                   {disp} AS disposition, 'closed' AS status
            FROM a""",
        "closure": f"""
            SELECT entity_id, alert_id AS ref_id, 'RC_VERIFIED' AS reason_code, {disp} AS disposition,
                   {FREE_TEXT_COMMENT if profile == "freetext" else PRE_HASHED_COMMENT}
            FROM a""",
        "workflow_event": f"""
            SELECT entity_id, 'alert' AS ref_type, alert_id AS ref_id,
                   created_at + to_seconds(CASE WHEN k = 0 THEN 60 ELSE 540 END) AS ts,
                   {analyst} AS actor, CASE WHEN k = 0 THEN 'triage' ELSE 'investigate' END AS action,
                   CASE WHEN k = 0 THEN 'open' ELSE 'investigating' END AS from_status, 'investigating' AS to_status,
                   20 + CAST((h >> 3) % 120 AS INTEGER) AS note_len
            FROM a, range(2) tk(k)""",
        "escalation": """
            SELECT entity_id, 'ESC-' || alert_id AS esc_id, alert_id AS ref_id,
                   created_at + INTERVAL 15 MINUTE AS escalated_at, 'tier1' AS from_role, 'tier2' AS to_role,
                   created_at + INTERVAL 25 MINUTE AS acknowledged_at, 'handled' AS outcome
            FROM a WHERE h % 20 = 0""",
        "case": f"""
            SELECT entity_id, 'CASE-' || alert_id AS case_id, {sev} AS severity, 'closed' AS status,
                   {analyst} AS owner, created_at + INTERVAL 20 MINUTE AS opened_at,
                   created_at + INTERVAL 2 DAY AS closed_at
            FROM a WHERE h % 20 = 1""",
        "case_alert_link": """
            SELECT entity_id, 'CASE-' || alert_id AS case_id, alert_id FROM a WHERE h % 20 = 1""",
        "asset": f"""
            SELECT {ent} AS entity_id,
                   'AST-' || lpad({num}::varchar, 3, '0') || '-' || lpad(x::varchar, 3, '0') AS asset_id,
                   (['server', 'workstation', 'plc', 'firewall'])[1 + x % 4] AS asset_type,
                   1 + x % 4 AS criticality, true AS monitored_flag, 'OPS' AS owner_unit
            FROM range({n}) te(e), range({ASSETS_PER_ENTITY}) tx(x)""",
        "log_source_daily": f"""
            SELECT {ent} AS entity_id,
                   'AST-' || lpad({num}::varchar, 3, '0') || '-' || lpad(x::varchar, 3, '0') AS asset_id,
                   'syslog_edr' AS source_type, DATE '2026-01-01' + CAST(d AS INTEGER) AS date,
                   800 + CAST(hash(e, x, d) % 900 AS INTEGER) AS event_count
            FROM range({n}) te(e), range({ASSETS_PER_ENTITY}) tx(x), range({DAYS}) td(d)""",
        "detection_rule": f"""
            SELECT {ent} AS entity_id, 'RULE-' || lpad(r::varchar, 3, '0') AS rule_id, 'Malware' AS category,
                   'TA0002' AS mitre_tactic, 'T1059' AS mitre_technique, true AS enabled,
                   TIMESTAMP '2026-06-20 00:00:00' AS last_fired
            FROM range({n}) te(e), range({RULES_PER_ENTITY}) tr(r)""",
        "sla_policy": f"""
            SELECT {ent} AS entity_id, sev AS severity, ack AS ack_minutes, res AS resolve_minutes
            FROM range({n}) te(e),
                 (VALUES ('critical', 15, 240), ('high', 30, 480), ('medium', 60, 1440), ('low', 120, 2880)) p(sev, ack, res)""",
        "declared_kpi": f"""
            SELECT {ent} AS entity_id, '2026-H1' AS period, metric, sev AS severity, val AS value
            FROM range({n}) te(e),
                 (VALUES ('MTTR', 'high', 150.0), ('MTTR', 'critical', 150.0), ('MTTA', 'high', 8.0), ('MTTA', 'critical', 8.0)) k(metric, sev, val)""",
        "external_report": """
            SELECT entity_id, 'CASE-' || alert_id AS incident_id, 'CERT-In' AS reported_to,
                   created_at + INTERVAL 3 HOUR AS reported_at
            FROM a WHERE h % 20 = 1""",
        "remediation": f"""
            SELECT {ent} AS entity_id, 'REM-' || {num} || '-' || x AS ticket_id,
                   'AST-' || lpad({num}::varchar, 3, '0') || '-' || lpad(x::varchar, 3, '0') AS linked_asset_id,
                   'RULE-' || lpad(x::varchar, 3, '0') AS linked_rule_id, 'tuning' AS type,
                   TIMESTAMP '2026-02-01 00:00:00' AS created_at, TIMESTAMP '2026-02-10 00:00:00' AS closed_at
            FROM range({n}) te(e), range(4) tx(x)""",
    }
    counts = {}
    for name, sql in tables.items():
        target = (csv_dir / f"{name}.csv").as_posix()
        con.execute(f"COPY ({sql}) TO '{target}' (HEADER, DELIMITER ',', TIMESTAMPFORMAT '%Y-%m-%dT%H:%M:%S')")
        counts[name] = con.execute(f"SELECT count(*) FROM ({sql})").fetchone()[0]
    con.close()
    return counts


# ------------------------------------------------------------------ stages (each in its own process)


def _ingest(workspace: Path, folder: str) -> dict:
    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    started = time.perf_counter()
    result = IngestionPipeline(duck, sql).ingest_directory(workspace / folder)
    seconds = time.perf_counter() - started
    duck.close()
    sql.close()
    if result.get("status") != "success":
        raise RuntimeError(f"ingest status {result.get('status')}: {result.get('message')}")
    return {"seconds": seconds, "rows": sum(result["row_counts"].values()), "dq_issues": result["dq_issues"],
            "batch_id": result.get("batch_id")}


def stage_ingest(workspace: Path) -> dict:
    return _ingest(workspace, "csv")


def stage_ingest_more(workspace: Path) -> dict:
    """A second submission (new entities), ingested while the readers run."""
    return _ingest(workspace, "csv_more")


def _stored_alerts() -> int:
    from satsa.store.duckdb import DuckDBStore

    duck = DuckDBStore("data")
    try:
        duck.load_all_tables()
        return int(duck.query("SELECT count(*) FROM alert").row(0)[0])
    finally:
        duck.close()


def stage_repeat(workspace: Path) -> dict:
    """The first submission again, unchanged: how long it takes, and whether the data doubles."""
    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    before = _stored_alerts()
    duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    started = time.perf_counter()
    result = IngestionPipeline(duck, sql).ingest_directory(workspace / "csv")
    seconds = time.perf_counter() - started
    duck.close()
    sql.close()
    after = _stored_alerts()
    return {"seconds": seconds, "status": result.get("status"), "message": str(result.get("message", ""))[:200],
            "alerts_before": before, "alerts_after": after}


def stage_assess(workspace: Path) -> dict:
    from satsa.scoring.runner import AssessmentRunner
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    started = time.perf_counter()
    result = AssessmentRunner(duck, sql).run_assessment(period="2026-H1", actor="benchmark")
    seconds = time.perf_counter() - started
    duck.close()
    sql.close()
    return {"seconds": seconds, "findings": result.get("findings_count", 0), "queue": result.get("queue_count", 0)}


def ensure_analyst() -> None:
    """A production start creates no accounts (an administrator issues them), so the benchmark
    issues its own analyst account in its scratch database."""
    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore("data/satsa.db")
    try:
        if not store.conn.execute("SELECT 1 FROM identities WHERE username = 'analyst'").fetchone():
            store.create_user("analyst", "analyst", NEW_PASSPHRASE)
    finally:
        store.close()


def stage_pages(workspace: Path) -> dict:
    from fastapi.testclient import TestClient

    from satsa.api.routes import app
    from satsa.store.duckdb import DuckDBStore, analytics_cache

    # What every request used to pay: a new store and a full reload of every Parquet table.
    started = time.perf_counter()
    store = DuckDBStore("data")
    store.load_all_tables()
    reload_seconds = time.perf_counter() - started
    entity = store.query("SELECT min(entity_id) FROM entity").row(0)[0]
    store.close()

    ensure_analyst()
    with TestClient(app) as client:  # runs start-up, as a served instance would
        login = client.post("/login", data={"username": "analyst", "password": NEW_PASSPHRASE},
                            follow_redirects=False)  # fmt: skip
        assert login.status_code == 303 and "/login" not in login.headers.get("location", ""), login.headers
        analytics_cache.clear()
        loads_before = analytics_cache.loads
        timings: dict[str, dict[str, float]] = {}
        for page in PAGES:
            url = page.format(entity=entity)
            samples = []
            for _ in range(6):
                started = time.perf_counter()
                response = client.get(url, follow_redirects=False)  # a redirect to /login is not a page load
                samples.append(time.perf_counter() - started)
                assert response.status_code == 200, (url, response.status_code, response.text[:300])
            timings[page] = {"first": samples[0], "repeat_median": statistics.median(samples[1:])}
        loads = analytics_cache.loads - loads_before
    return {"reload_seconds": reload_seconds, "pages": timings, "table_loads": loads, "requests": 6 * len(PAGES)}


STAGES = {"ingest": stage_ingest, "assess": stage_assess, "pages": stage_pages,
          "ingest_more": stage_ingest_more, "repeat": stage_repeat}


def run_stage_in_process(stage: str, workspace: Path) -> None:
    os.chdir(workspace)
    try:
        payload = STAGES[stage](workspace)
        payload["ok"] = True
    except BaseException as exc:  # noqa: BLE001 - the parent reports the failure verbatim
        payload = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
    payload["peak_mb"] = peak_memory_mb()
    print("BENCH_RESULT " + json.dumps(payload))


def run_stage(stage: str, workspace: Path, timeout: int) -> dict:
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "PYTHONIOENCODING": "utf-8"}
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--stage", stage, "--workspace", str(workspace)],
            capture_output=True, text=True, timeout=timeout, env=env, check=False,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"exceeded the {timeout}s stage timeout", "wall_seconds": timeout}
    wall = time.perf_counter() - started
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith("BENCH_RESULT "):
            return {**json.loads(line[len("BENCH_RESULT "):]), "wall_seconds": wall}
    tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
    return {"ok": False, "error": f"process exited {proc.returncode}: {tail[0][:300]}", "wall_seconds": wall}


# ------------------------------------------------------------------ concurrent readers

READERS = 10
READER_PAGES = ("/portfolio", "/entity/{entity}", "/queue", "/api/v1/entities", "/alerts")


def _percentile(samples: list[float], q: float) -> float:
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))]


def _summary(samples: list[float], errors: list[str], seconds: float) -> dict:
    if not samples:
        return {"requests": 0, "errors": len(errors), "error_examples": errors[:3]}
    return {"requests": len(samples), "errors": len(errors), "error_examples": errors[:3],
            "p50_ms": _percentile(samples, 0.50) * 1000, "p95_ms": _percentile(samples, 0.95) * 1000,
            "max_ms": max(samples) * 1000, "seconds": seconds, "per_second": len(samples) / seconds}


def _sign_in(base: str):  # type: ignore[no-untyped-def]
    import httpx

    client = httpx.Client(base_url=base, timeout=120, trust_env=False, follow_redirects=False)
    r = client.post("/login", data={"username": "analyst", "password": NEW_PASSPHRASE})
    if r.status_code != 303 or "/login" in r.headers.get("location", ""):
        raise RuntimeError(f"the reader could not sign in: {r.status_code} {r.headers.get('location')}")
    return client


def _read_loop(base: str, entity: str, stop, samples: list[float], errors: list[str], min_requests: int) -> None:  # type: ignore[no-untyped-def]
    client = _sign_in(base)
    try:
        i = 0
        while not stop.is_set() or i < min_requests:
            url = READER_PAGES[i % len(READER_PAGES)].format(entity=entity)
            started = time.perf_counter()
            try:
                r = client.get(url)
                elapsed = time.perf_counter() - started
                if r.status_code != 200:
                    errors.append(f"{url}: HTTP {r.status_code}")
                else:
                    samples.append(elapsed)
            except Exception as exc:  # noqa: BLE001 - every failure is reported
                errors.append(f"{url}: {type(exc).__name__}: {str(exc)[:120]}")
            i += 1
    finally:
        client.close()


def readers(workspace: Path, timeout: int, entities: int, alerts_per_entity: int, profile: str) -> dict:
    """Ten reader sessions against a served instance: idle, then while a second submission is
    ingested by another process. Pages are warmed first (the first-request cost is in `pages`)."""
    import socket
    import threading

    import httpx

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "PYTHONIOENCODING": "utf-8", "NO_PROXY": "*"}
    log = open(workspace / "server.log", "wb")  # noqa: SIM115 - closed below
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "satsa.api:app", "--host", "127.0.0.1", "--port", str(port)],
                              cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 120
        while True:
            try:
                if httpx.get(f"{base}/splash", timeout=2, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if server.poll() is not None or time.monotonic() > deadline:
                return {"ok": False, "error": "the server did not start"}
            time.sleep(0.3)
        entity = "CSE-001"
        warm = _sign_in(base)
        for page in READER_PAGES:
            warm.get(page.format(entity=entity))
        warm.close()

        def phase(concurrent=None) -> dict:  # type: ignore[no-untyped-def]
            stop = threading.Event()
            samples: list[float] = []
            errors: list[str] = []
            threads = [threading.Thread(target=_read_loop, args=(base, entity, stop, samples, errors, 20))
                       for _ in range(READERS)]
            started = time.perf_counter()
            for t in threads:
                t.start()
            other = None
            if concurrent is None:
                time.sleep(0.5)
            else:
                other = concurrent()
            stop.set()
            for t in threads:
                t.join(timeout=timeout)
            result = _summary(samples, errors, time.perf_counter() - started)
            if other is not None:
                result["concurrent"] = other
            return result

        idle = phase()
        generate(workspace / "csv_more", 2, alerts_per_entity, profile, entity_offset=entities)
        busy = phase(lambda: run_stage("ingest_more", workspace, timeout))
        return {"ok": True, "readers": READERS, "idle": idle, "during_ingest": busy}
    finally:
        server.terminate()
        try:
            server.wait(timeout=20)
        except subprocess.TimeoutExpired:
            server.kill()
        log.close()


def _dir_mb(path: Path) -> float:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) / 1024**2 if path.exists() else 0.0


# ------------------------------------------------------------------ orchestration and report


def benchmark(entities: int, alerts_per_entity: int, workdir: Path, timeout: int, profile: str = "uniform",
              with_readers: bool = False) -> dict:
    workspace = workdir / f"bench_{entities}x{alerts_per_entity}_{profile}"
    shutil.rmtree(workspace, ignore_errors=True)
    (workspace / "data").mkdir(parents=True)
    shutil.copytree(REPO / "config", workspace / "config")
    started = time.perf_counter()
    counts = generate(workspace / "csv", entities, alerts_per_entity, profile)
    per_entity = alerts_by_entity(entities, alerts_per_entity, profile)
    result: dict = {
        "entities": entities,
        "alerts_per_entity": alerts_per_entity,
        "profile": profile,
        "largest_entity_alerts": max(per_entity),
        "smallest_entity_alerts": min(per_entity),
        "alerts": counts["alert"],
        "rows": sum(counts.values()),
        "csv_mb": sum(f.stat().st_size for f in (workspace / "csv").iterdir()) / 1024**2,
        "generate_seconds": time.perf_counter() - started,
    }
    for stage in ("ingest", "assess", "pages"):
        print(f"  [{entities}x{alerts_per_entity}] {stage} ...", flush=True)
        result[stage] = run_stage(stage, workspace, timeout)
        print(f"  [{entities}x{alerts_per_entity}] {stage}: {json.dumps(result[stage])[:400]}", flush=True)
        if not result[stage]["ok"]:
            break  # later stages need this one's output
    parquet = workspace / "data" / "parquet"
    result["parquet_mb"] = sum(f.stat().st_size for f in parquet.rglob("*.parquet")) / 1024**2 if parquet.exists() else 0.0
    result["data_dir_mb"] = _dir_mb(workspace / "data")
    if with_readers and result.get("pages", {}).get("ok"):
        print(f"  [{entities}x{alerts_per_entity} {profile}] readers ...", flush=True)
        result["readers"] = readers(workspace, timeout, entities, alerts_per_entity, profile)
        print(f"  [{entities}x{alerts_per_entity} {profile}] readers: {json.dumps(result['readers'])[:600]}", flush=True)
        print(f"  [{entities}x{alerts_per_entity} {profile}] repeat ...", flush=True)
        result["repeat"] = run_stage("repeat", workspace, timeout)
        print(f"  [{entities}x{alerts_per_entity} {profile}] repeat: {json.dumps(result['repeat'])[:400]}", flush=True)
        result["data_dir_mb_after"] = _dir_mb(workspace / "data")
    shutil.rmtree(workspace, ignore_errors=True)
    return result


def _cell(stage: dict | None, key: str, fmt: str) -> str:
    if stage is None:
        return "not run"
    if not stage.get("ok"):
        return "FAILED"
    return format(stage[key], fmt)


def render(results: list[dict], specs: dict[str, str], command: str) -> str:
    lines = [
        "# SAT-SA Scale Benchmarks",
        "",
        "> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*",
        "",
        f"Measured on {datetime.now(UTC).strftime('%Y-%m-%d')} with `scripts/benchmark_scale.py`. Every figure below is a",
        "measurement from that run on the machine described here; nothing is extrapolated. Timings on",
        "other hardware will differ.",
        "",
        "```",
        command,
        "```",
        "",
        "## Machine",
        "",
        "| | |",
        "|---|---|",
        *[f"| {k} | {v} |" for k, v in specs.items()],
        "",
        "## What is measured",
        "",
        "- **Data:** a generated canonical submission: the 14 tables of `satsa generate-data`, with",
        "  2 workflow events and 1 closure per alert, a case and an escalation for 5% of alerts, and",
        f"  {ASSETS_PER_ENTITY} assets per entity reporting daily log volumes for {DAYS} days. It is clean, uniform data built",
        "  for volume; it says nothing about detection quality. Closure comments are submitted",
        "  pre-hashed (as the generator does), so free-text redaction is not part of the ingest time.",
        "- **Ingest:** `IngestionPipeline.ingest_directory` on the CSV directory (read, normalise,",
        "  pseudonymise, data-quality checks, Parquet write, manifest, audit entry).",
        "- **Assess:** `AssessmentRunner.run_assessment` (all 20 rules for every entity, scoring, review",
        "  queue, persistence).",
        "- **Pages:** the SAT-SA web app through an in-process client, signed in as the analyst. Each",
        "  page is requested 6 times: the first request, and the median of the next 5.",
        "- **Peak memory:** the highest resident memory of the process that ran the stage (each stage",
        "  runs in its own process).",
        "",
        "- **Profiles:** `uniform` (equal entities, even in time), `skewed` (same total, Zipf split",
        "  across entities), `freetext` (closure comments as ~1 KiB free text with e-mail and IP",
        "  addresses, redacted at ingest), `uneven` (alerts crowd into the start of the half-year).",
        "- **Readers** (with `--readers`): a served instance (uvicorn, one process) and ten signed-in",
        f"  sessions requesting {', '.join(READER_PAGES)} in turn, after one warming request each:",
        "  first with nothing else running, then while another process ingests a second submission",
        "  (two more entities). Latency is per request, measured by the client.",
        "- **Repeat:** the first submission ingested again, unchanged.",
        "- **Disk:** everything under `data/` (Parquet, databases, manifests) after the stages.",
        "",
        "## Results",
        "",
        "| Entities x alerts each | Profile | Alerts (largest / smallest entity) | Rows (all tables) | CSV | Parquet | Data dir | Ingest | Ingest peak | Assess | Assess peak | Findings |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        ingest, assess = r.get("ingest"), r.get("assess")
        lines.append(
            f"| {r['entities']} x {r['alerts_per_entity']:,} | {r.get('profile', 'uniform')} | {r['alerts']:,} "
            f"({r.get('largest_entity_alerts', r['alerts_per_entity']):,} / {r.get('smallest_entity_alerts', r['alerts_per_entity']):,}) | "
            f"{r['rows']:,} | {r['csv_mb']:,.0f} MiB | "
            f"{r['parquet_mb']:,.0f} MiB | {r.get('data_dir_mb', 0):,.0f} MiB | {_cell(ingest, 'seconds', ',.1f')} s | {_cell(ingest, 'peak_mb', ',.0f')} MiB | "
            f"{_cell(assess, 'seconds', ',.1f')} s | {_cell(assess, 'peak_mb', ',.0f')} MiB | {_cell(assess, 'findings', ',d')} |"
        )
    lines += [
        "",
        "### Page loads",
        "",
        "\"Reload\" is what every request paid before the analytics cache: building a store and",
        "re-reading every Parquet table. It is measured directly here (`DuckDBStore.load_all_tables`)",
        "and is now paid once, on the first analytics request after a run completes or the data changes.",
        "",
        "| Entities x alerts each | Reload (old per-request cost) | Page | First request | Repeat (median of 5) | Pages peak |",
        "|---|---:|---|---:|---:|---:|",
    ]
    for r in results:
        pages = r.get("pages")
        label = f"{r['entities']} x {r['alerts_per_entity']:,}"
        if pages is None or not pages.get("ok"):
            lines.append(f"| {label} | {'not run' if pages is None else 'FAILED'} | | | | |")
            continue
        for i, (page, t) in enumerate(pages["pages"].items()):
            lines.append(
                f"| {label if i == 0 else ''} | {format(pages['reload_seconds'], ',.2f') + ' s' if i == 0 else ''} | `{page}` | "
                f"{t['first'] * 1000:,.0f} ms | {t['repeat_median'] * 1000:,.0f} ms | "
                f"{format(pages['peak_mb'], ',.0f') + ' MiB' if i == 0 else ''} |"
            )
        lines.append(
            f"| | | *{pages['requests']} requests caused {pages['table_loads']} table load(s)* | | | |"
        )
    with_readers = [r for r in results if r.get("readers")]
    if with_readers:
        lines += ["", "### Ten concurrent readers", "",
                  "| Entities x alerts each | Profile | Phase | Requests | Errors | p50 | p95 | Max | Requests/s | Concurrent ingest |",
                  "|---|---|---|---:|---:|---:|---:|---:|---:|---|"]
        for r in with_readers:
            rd = r["readers"]
            label = f"{r['entities']} x {r['alerts_per_entity']:,}"
            if not rd.get("ok"):
                lines.append(f"| {label} | {r['profile']} | FAILED: {rd.get('error')} | | | | | | | |")
                continue
            for name, ph in (("idle", rd["idle"]), ("during ingest", rd["during_ingest"])):
                other = ph.get("concurrent")
                other_text = "" if other is None else (
                    f"{other['rows']:,} rows in {other['seconds']:,.1f} s, peak {other['peak_mb']:,.0f} MiB" if other.get("ok")
                    else f"FAILED: {other.get('error')}")
                if not ph.get("requests"):
                    lines.append(f"| {label} | {r['profile']} | {name} | 0 | {ph['errors']} | | | | | {other_text} |")
                    continue
                lines.append(
                    f"| {label} | {r['profile']} | {name} | {ph['requests']:,} | {ph['errors']} | {ph['p50_ms']:,.0f} ms | "
                    f"{ph['p95_ms']:,.0f} ms | {ph['max_ms']:,.0f} ms | {ph['per_second']:,.1f} | {other_text} |")
        lines += ["", "### Repeated submission", "",
                  "| Entities x alerts each | Profile | Repeat ingest | Status | Stored alerts before | after |",
                  "|---|---|---:|---|---:|---:|"]
        for r in with_readers:
            rp = r.get("repeat") or {}
            label = f"{r['entities']} x {r['alerts_per_entity']:,}"
            if not rp.get("ok"):
                lines.append(f"| {label} | {r['profile']} | FAILED: {rp.get('error')} | | | |")
                continue
            lines.append(f"| {label} | {r['profile']} | {rp['seconds']:,.1f} s | {rp['status']} | "
                         f"{rp['alerts_before']:,} | {rp['alerts_after']:,} |")
    failures = [
        f"- **{r['entities']} x {r['alerts_per_entity']:,}, {stage}:** {r[stage]['error']} "
        f"(after {r[stage].get('wall_seconds', 0):,.0f} s, peak {r[stage].get('peak_mb', 0):,.0f} MiB)"
        for r in results
        for stage in ("ingest", "assess", "pages", "repeat")
        if stage in r and not r[stage].get("ok")
    ]
    if failures:
        lines += ["", "### Stages that did not complete", "", *failures]
    lines += ["", "## Raw results", "", "```json", json.dumps(results, indent=1), "```", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="SAT-SA scale benchmark")
    parser.add_argument("--configs", default="10x50000,25x100000,50x100000",
                        help="comma-separated ENTITIESxALERTS[:profile], profile one of " + ", ".join(PROFILES))
    parser.add_argument("--readers", action="store_true", help="also measure ten concurrent readers and a repeat")
    parser.add_argument("--out", default="docs/benchmarks.md", help="Markdown report to write")
    parser.add_argument("--json", default=None, help="also write the raw results as JSON")
    parser.add_argument("--workdir", default=None, help="scratch directory (default: the system temp directory)")
    parser.add_argument("--stage-timeout", type=int, default=3600, help="seconds allowed per stage")
    parser.add_argument("--stage", choices=sorted(STAGES), help=argparse.SUPPRESS)
    parser.add_argument("--workspace", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.stage:
        run_stage_in_process(args.stage, Path(args.workspace))
        return 0

    configs = []
    for item in args.configs.split(","):
        size, _, profile = item.strip().lower().partition(":")
        if (profile or "uniform") not in PROFILES:
            parser.error(f"unknown profile {profile!r}")
        entities, alerts = (int(x) for x in size.split("x"))
        configs.append((entities, alerts, profile or "uniform"))
    # Absolute: each stage process changes into its workspace before using the path.
    workdir = (Path(args.workdir) if args.workdir else Path(tempfile.gettempdir()) / "satsa_bench").resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    results = []
    for entities, alerts_per_entity, profile in configs:
        print(f"== {entities} entities x {alerts_per_entity:,} alerts ({profile})", flush=True)
        results.append(benchmark(entities, alerts_per_entity, workdir, args.stage_timeout, profile, args.readers))
    command = "python scripts/benchmark_scale.py " + " ".join(sys.argv[1:])
    report = render(results, machine_specs(), command.strip())
    Path(args.out).write_text(report, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
