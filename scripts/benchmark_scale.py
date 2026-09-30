"""Scale benchmark: generate N entities x M alerts, then time ingest, assessment and page loads.

    python scripts/benchmark_scale.py --configs 10x50000,25x100000,50x100000 --out docs/benchmarks.md

For each configuration a canonical CSV submission is generated (the same 14 tables and roughly
the same row ratios as `satsa generate-data`), then three stages run, each in its own process
so that its peak memory is its own:

  ingest   satsa's IngestionPipeline over the CSV directory
  assess   AssessmentRunner.run_assessment over the stored data
  pages    the web app (in-process test client): first page after start, then repeat loads

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


def generate(csv_dir: Path, entities: int, alerts_per_entity: int) -> dict[str, int]:
    """Write a canonical CSV submission with DuckDB (fast, deterministic: no random state)."""
    import duckdb

    csv_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(":memory:")
    n, m = entities, alerts_per_entity
    ent = "'CSE-' || lpad((e + 1)::varchar, 3, '0')"
    span = DAYS * 86400
    # One row per alert: e = entity index, s = sequence within the entity, h = a stable hash.
    con.execute(f"""
        CREATE TABLE a AS
        SELECT e, s, CAST(hash(e * 1000003 + s) >> 1 AS BIGINT) AS h,
               {ent} AS entity_id,
               'A' || lpad((e + 1)::varchar, 3, '0') || '-' || lpad((s + 1)::varchar, 7, '0') AS alert_id,
               TIMESTAMP '2026-01-01 00:00:00'
                   + to_seconds(CAST(floor(s * ({span} - 86400.0) / {m}) AS BIGINT) + CAST(hash(s, e) % 3600 AS BIGINT)) AS created_at
        FROM range({n}) te(e), range({m}) ts(s)
    """)
    sev = "CASE WHEN h % 100 < 55 THEN 'low' WHEN h % 100 < 85 THEN 'medium' WHEN h % 100 < 97 THEN 'high' ELSE 'critical' END"
    disp = "CASE WHEN (h >> 8) % 100 < 8 THEN 'true_positive' WHEN (h >> 8) % 100 < 68 THEN 'false_positive' ELSE 'benign' END"
    human = "((h >> 16) % 10) <> 0"
    analyst = "'ANALYST_' || lpad((e + 1)::varchar, 3, '0') || '_' || lpad(((h >> 20) % 12)::varchar, 2, '0')"
    close_s = "1800 + CAST((h >> 24) % 12600 AS BIGINT)"  # 30 min .. 4 h
    tables: dict[str, str] = {
        "entity": f"""
            SELECT {ent} AS entity_id, 'Benchmark Entity ' || (e + 1) AS name,
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
                   'AST-' || lpad((e + 1)::varchar, 3, '0') || '-' || lpad(((h >> 12) % {ASSETS_PER_ENTITY})::varchar, 3, '0') AS asset_id,
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
                   substr(md5(((h >> 5) % 5000)::varchar || alert_id), 1, 16) AS comment_norm_hash,
                   40 + CAST((h >> 9) % 160 AS INTEGER) AS comment_len, NULL AS comment_shingles
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
                   'AST-' || lpad((e + 1)::varchar, 3, '0') || '-' || lpad(x::varchar, 3, '0') AS asset_id,
                   (['server', 'workstation', 'plc', 'firewall'])[1 + x % 4] AS asset_type,
                   1 + x % 4 AS criticality, true AS monitored_flag, 'OPS' AS owner_unit
            FROM range({n}) te(e), range({ASSETS_PER_ENTITY}) tx(x)""",
        "log_source_daily": f"""
            SELECT {ent} AS entity_id,
                   'AST-' || lpad((e + 1)::varchar, 3, '0') || '-' || lpad(x::varchar, 3, '0') AS asset_id,
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
            SELECT {ent} AS entity_id, 'REM-' || (e + 1) || '-' || x AS ticket_id,
                   'AST-' || lpad((e + 1)::varchar, 3, '0') || '-' || lpad(x::varchar, 3, '0') AS linked_asset_id,
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


def stage_ingest(workspace: Path) -> dict:
    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    started = time.perf_counter()
    result = IngestionPipeline(duck, sql).ingest_directory(workspace / "csv")
    seconds = time.perf_counter() - started
    duck.close()
    sql.close()
    if result.get("status") != "success":
        raise RuntimeError(f"ingest status {result.get('status')}: {result.get('message')}")
    return {"seconds": seconds, "rows": sum(result["row_counts"].values()), "dq_issues": result["dq_issues"]}


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

    with TestClient(app) as client:  # runs start-up, as a served instance would
        login = client.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                            follow_redirects=False)  # fmt: skip
        if login.headers.get("location") == "/change-password":  # a fresh database: first login
            changed = client.post(
                "/change-password",
                data={"current_password": "ChangeMe-Analyst#2026", "new_password": NEW_PASSPHRASE,
                      "confirm_password": NEW_PASSPHRASE},
                follow_redirects=False,
            )  # fmt: skip
            assert changed.status_code == 303, changed.text[:300]
        analytics_cache.clear()
        loads_before = analytics_cache.loads
        timings: dict[str, dict[str, float]] = {}
        for page in PAGES:
            url = page.format(entity=entity)
            samples = []
            for _ in range(6):
                started = time.perf_counter()
                response = client.get(url)
                samples.append(time.perf_counter() - started)
                assert response.status_code == 200, (url, response.status_code, response.text[:300])
            timings[page] = {"first": samples[0], "repeat_median": statistics.median(samples[1:])}
        loads = analytics_cache.loads - loads_before
    return {"reload_seconds": reload_seconds, "pages": timings, "table_loads": loads, "requests": 6 * len(PAGES)}


STAGES = {"ingest": stage_ingest, "assess": stage_assess, "pages": stage_pages}


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


# ------------------------------------------------------------------ orchestration and report


def benchmark(entities: int, alerts_per_entity: int, workdir: Path, timeout: int) -> dict:
    workspace = workdir / f"bench_{entities}x{alerts_per_entity}"
    shutil.rmtree(workspace, ignore_errors=True)
    (workspace / "data").mkdir(parents=True)
    shutil.copytree(REPO / "config", workspace / "config")
    started = time.perf_counter()
    counts = generate(workspace / "csv", entities, alerts_per_entity)
    result: dict = {
        "entities": entities,
        "alerts_per_entity": alerts_per_entity,
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
        "## Results",
        "",
        "| Entities x alerts each | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak | Findings |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        ingest, assess = r.get("ingest"), r.get("assess")
        lines.append(
            f"| {r['entities']} x {r['alerts_per_entity']:,} | {r['alerts']:,} | {r['rows']:,} | {r['csv_mb']:,.0f} MB | "
            f"{r['parquet_mb']:,.0f} MB | {_cell(ingest, 'seconds', ',.1f')} s | {_cell(ingest, 'peak_mb', ',.0f')} MB | "
            f"{_cell(assess, 'seconds', ',.1f')} s | {_cell(assess, 'peak_mb', ',.0f')} MB | {_cell(assess, 'findings', ',d')} |"
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
                f"{format(pages['peak_mb'], ',.0f') + ' MB' if i == 0 else ''} |"
            )
        lines.append(
            f"| | | *{pages['requests']} requests caused {pages['table_loads']} table load(s)* | | | |"
        )
    failures = [
        f"- **{r['entities']} x {r['alerts_per_entity']:,}, {stage}:** {r[stage]['error']} "
        f"(after {r[stage].get('wall_seconds', 0):,.0f} s, peak {r[stage].get('peak_mb', 0):,.0f} MB)"
        for r in results
        for stage in ("ingest", "assess", "pages")
        if stage in r and not r[stage].get("ok")
    ]
    if failures:
        lines += ["", "### Stages that did not complete", "", *failures]
    lines += ["", "## Raw results", "", "```json", json.dumps(results, indent=1), "```", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="SAT-SA scale benchmark")
    parser.add_argument("--configs", default="10x50000,25x100000,50x100000", help="comma-separated ENTITIESxALERTS")
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

    configs = [tuple(int(x) for x in item.lower().split("x")) for item in args.configs.split(",")]
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.gettempdir()) / "satsa_bench"
    workdir.mkdir(parents=True, exist_ok=True)
    results = []
    for entities, alerts_per_entity in configs:
        print(f"== {entities} entities x {alerts_per_entity:,} alerts", flush=True)
        results.append(benchmark(entities, alerts_per_entity, workdir, args.stage_timeout))
    command = "python scripts/benchmark_scale.py " + " ".join(sys.argv[1:])
    report = render(results, machine_specs(), command.strip())
    Path(args.out).write_text(report, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
