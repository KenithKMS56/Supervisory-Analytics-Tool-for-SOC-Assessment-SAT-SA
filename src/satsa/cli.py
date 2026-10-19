"""CLI for SAT-SA."""

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from satsa.serving import ServingConfig

app = typer.Typer(
    name="satsa",
    help="Supervisory Analytics Tool for SOC Assessment (NCIIPC)",
    add_completion=False,
)
console = Console()


@app.command("version")
def version_cmd() -> None:
    """Show SAT-SA version."""
    from satsa import __version__

    console.print(f"[bold green]SAT-SA[/bold green] version {__version__} (Air-gapped, No AI/ML)")


@app.command("generate-data")
def generate_data_cmd(
    output_dir: str = typer.Option("data/generated", "--output-dir", "-o", help="Output directory"),
    seed: int = typer.Option(42, "--seed", "-s", help="Random seed for deterministic generation"),
    alerts_per_entity: int = typer.Option(1500, "--alerts", "-n", help="Base alerts per entity"),
) -> None:
    """Generate realistic synthetic SOC data for 10 CSEs with ground truth defects."""
    from pathlib import Path

    from satsa.synth.generator import SyntheticDataGenerator

    console.print(
        f"[bold blue]Generating synthetic SOC dataset...[/bold blue] (seed={seed}, base_alerts={alerts_per_entity})"
    )
    gen = SyntheticDataGenerator(seed=seed, base_alerts_per_entity=alerts_per_entity)
    csv_dir, gt_path = gen.save_dataset(Path(output_dir))
    console.print("[bold green][+] Dataset successfully generated:[/bold green]")
    console.print(f"  * Tables (CSV): [cyan]{csv_dir}[/cyan]")
    console.print(f"  * Ground Truth: [cyan]{gt_path}[/cyan]")


SOURCE_MAPPINGS = {
    "splunk": "config/mappings/cse_splunk.yaml",
    "servicenow": "config/mappings/cse_servicenow.yaml",
    "thehive": "config/mappings/cse_thehive.yaml",
    "xsiam": "config/mappings/cse_cortex_xsiam.yaml",
}
# Mappings whose `headers:` let an export be recognised by its columns (detect_source_mapping).
MAPPINGS_DIR = "config/mappings"


def _print_ingest_coverage(result: dict[str, Any]) -> None:
    """Say plainly what the submission does not contain and which rules that costs."""
    for report in result.get("file_sanitising", []):
        colour = "yellow" if report.get("long_rows_truncated") or report.get("records_skipped") else "cyan"
        console.print(f"  * Read [{colour}]{report['file']}[/{colour}]: {'; '.join(report['notes'])}")
    files = result.get("file_coverage", [])
    if files:
        stored = sum(sum(f["stored"].values()) for f in files)
        clean = [f for f in files if f["status"] == "ingested" and not f["filtered"]]
        console.print(
            f"  * Files: {len(files)} submitted, {stored} rows stored"
            + ("; every row of every file stored" if len(clean) == len(files) else "")
        )
        for f in files:
            if f in clean:
                continue
            colour = {"unreadable": "red", "nothing stored": "red", "empty": "cyan", "ingested": "cyan"}.get(
                f["status"], "yellow"
            )
            console.print(f"    - [{colour}]{f['summary']}[/{colour}]")
    if result.get("source"):
        console.print(f"  * Source mapping: [cyan]{result['source']}[/cyan]")
        for table, info in sorted(result.get("field_coverage", {}).items()):
            empty = [c for c, n in info["filled"].items() if n == 0]
            console.print(
                f"    - {table}: {info['rows']} rows; "
                + (f"no value for: [yellow]{', '.join(empty)}[/yellow]" if empty else "every column filled")
            )
        for name in result.get("unmapped_files", []):
            console.print(f"    - [yellow]not described by the mapping, not ingested:[/yellow] {name}")
        for name, columns in sorted(result.get("unused_source_columns", {}).items()):
            console.print(f"    - {name}: source columns not used: {', '.join(columns)}")

    # Group entities with the same gaps so ten identical CSEs print once.
    grouped: dict[tuple[str, str], list[str]] = {}
    for entity_id, cov in sorted(result.get("rule_coverage", {}).items()):
        skipped = "; ".join(f"{r} (no {', '.join(t)})" for r, t in sorted(cov["not_assessed"].items()))
        degraded = "; ".join(f"{r} (alert.{', alert.'.join(c)} empty)" for r, c in sorted(cov["degraded"].items()))
        if skipped or degraded:
            grouped.setdefault((skipped, degraded), []).append(entity_id)
    for (skipped, degraded), entity_ids in grouped.items():
        console.print(f"  * Rule coverage for [cyan]{', '.join(entity_ids)}[/cyan]:")
        if skipped:
            console.print(f"    - [yellow]Not assessed[/yellow] (table never submitted): {skipped}")
        if degraded:
            console.print(f"    - [yellow]Cannot fire[/yellow] (input column empty): {degraded}")
    if result.get("rule_coverage") and not grouped:
        console.print("  * Rule coverage: all 20 rules can be assessed for every entity in this submission.")


@app.command("ingest")
def ingest_cmd(
    data_dir: str = typer.Option(
        "data/generated/csv", "--data-dir", "-d", help="Directory containing CSV tables to ingest"
    ),
    db_path: str = typer.Option(
        "data/satsa.db", "--db-path", help="Path to SQLite metadata database"
    ),
    parquet_dir: str = typer.Option(
        "data", "--parquet-dir", help="Root directory for Parquet storage"
    ),
    source: str = typer.Option(
        None, "--source", help=f"Product export to translate: {', '.join(sorted(SOURCE_MAPPINGS))}"
    ),
    mapping_path: str = typer.Option(
        None, "--mapping", help="Source mapping YAML (instead of --source), see config/mappings/"
    ),
    entity: str = typer.Option(
        None, "--entity", "-e", help="Entity the files belong to (required with --source / --mapping)"
    ),
    api_config: str = typer.Option(
        None,
        "--api-config",
        help="YAML of local REST endpoints to fetch the submission from (instead of --data-dir)",
    ),
    period: str = typer.Option(
        None,
        "--period",
        "-p",
        help="Review period the submission covers (2026-Q1, 2026-H1, 2026-03); recorded on the batch",
    ),
) -> None:
    """Ingest datasets, execute DQ checks, pseudonymise actors, redact PII, and store partitioned Parquet.

    --data-dir reads CSV, JSON/NDJSON and SQLite database exports (.db/.sqlite/.sqlite3, one
    table per canonical table). --api-config fetches the tables from local REST endpoints first.
    """
    import tempfile
    from pathlib import Path

    from satsa.ingest.mapper import MappingError, SourceMapping
    from satsa.ingest.pipeline import IngestionPipeline, detect_source_mapping
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    mapping = None
    if source and mapping_path:
        console.print("[bold red][!] Give either --source or --mapping, not both.[/bold red]")
        raise typer.Exit(code=2)
    if source or mapping_path:
        if source and source not in SOURCE_MAPPINGS:
            console.print(
                f"[bold red][!] Unknown source '{source}'. Known: {', '.join(sorted(SOURCE_MAPPINGS))}.[/bold red]"
            )
            raise typer.Exit(code=2)
        if not entity:
            console.print("[bold red][!] --entity is required with --source / --mapping.[/bold red]")
            raise typer.Exit(code=2)
        try:
            mapping = SourceMapping(SOURCE_MAPPINGS[source] if source else mapping_path)
        except MappingError as exc:
            console.print(f"[bold red][!] {exc}[/bold red]")
            raise typer.Exit(code=2) from None

    staging = None
    if api_config:
        from satsa.ingest.adapters import stage_api_submission

        staging = tempfile.TemporaryDirectory(prefix="satsa-api-")
        try:
            counts = stage_api_submission(api_config, staging.name)
        except (OSError, ValueError, TypeError) as exc:
            staging.cleanup()
            console.print(f"[bold red][!] API submission could not be fetched: {exc}[/bold red]")
            raise typer.Exit(code=2) from None
        console.print(
            "[bold blue]Fetched from local API:[/bold blue] "
            + ", ".join(f"{t} ({n})" for t, n in sorted(counts.items()))
        )
        data_dir = staging.name

    if mapping is None and not api_config:
        mapping = detect_source_mapping(data_dir, MAPPINGS_DIR)
        if mapping is not None:
            console.print(
                f"[bold blue]Recognised a {mapping.source} export by its columns:[/bold blue] "
                f"translating it with [cyan]{mapping.path.name}[/cyan]"
            )
            if not entity and not mapping.entity_id:
                console.print("[bold red][!] Give --entity: the export does not say which CSE it belongs to.[/bold red]")
                raise typer.Exit(code=2)

    console.print(f"[bold blue]Starting ingestion from:[/bold blue] [cyan]{api_config or data_dir}[/cyan]")
    duckdb_store = DuckDBStore(parquet_dir)
    sqlite_store = SQLiteStore(db_path)
    pipeline = IngestionPipeline(duckdb_store, sqlite_store)

    try:
        result = pipeline.ingest_directory(
            Path(data_dir), default_entity_id=entity, mapping=mapping, period=period, transport="cli"
        )
    finally:
        duckdb_store.close()
        sqlite_store.close()
        if staging is not None:
            staging.cleanup()

    if result.get("status") == "partial":
        console.print(
            "[bold red][!] Ingestion incomplete:[/bold red] these tables could not be stored: "
            f"{', '.join(result.get('failed_tables', []))}. Findings that depend on them are unreliable; "
            "fix the data and re-ingest before running an assessment."
        )
        raise typer.Exit(code=1)
    if result.get("status") == "success":
        console.print("[bold green][+] Ingestion completed successfully:[/bold green]")
        console.print(f"  * Batch ID: [cyan]{result.get('batch_id')}[/cyan]")
        console.print(
            f"  * Entities ({len(result.get('entities', []))}): [cyan]{', '.join(result.get('entities', []))}[/cyan]"
        )
        console.print(
            f"  * Data Quality Issues Detected: [yellow]{result.get('dq_issues')}[/yellow]"
        )
        _print_ingest_coverage(result)
    else:
        console.print(f"[bold red][!] Ingestion failed/empty:[/bold red] {result.get('message')}")
        if result.get("status") == "rejected":
            raise typer.Exit(code=1)


@app.command("replay")
def replay_cmd(
    run_id: str = typer.Argument(..., help="Run to replay (see the Runs page)"),
    data_dir: str = typer.Option("data", "--data-dir", help="Data directory (Parquet tree and catalog.db)"),
    db_path: str = typer.Option("data/satsa.db", "--db-path", help="Path to the operational SQLite database"),
) -> None:
    """Re-run a recorded assessment with its own configuration, selection and source snapshot, and compare."""
    import json as _json

    from satsa.scoring.replay import ReplayError, replay_run
    from satsa.store.sqlite import SQLiteStore

    sqlite_store = SQLiteStore(db_path)
    try:
        report = replay_run(run_id, data_dir, sqlite_store)
    except ReplayError as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=2) from None
    finally:
        sqlite_store.close()
    verdict = "[bold green]reproduced[/bold green]" if report["results_match"] else "[bold red]NOT reproduced[/bold red]"
    console.print(f"Run {run_id}: results {verdict}; fingerprint "
                  f"{'matches' if report['fingerprint_match'] else 'differs'}")
    if report["differences"]:
        console.print("Differences in the inputs:")
        console.print(_json.dumps(report["differences"], indent=2, default=str))
    if not report["results_match"]:
        console.print(_json.dumps({k: report[k] for k in ("score_differences", "findings_only_recorded",
                                                          "findings_only_replay")}, indent=2, default=str))
        raise typer.Exit(code=1)


@app.command("migrate")
def migrate_cmd(
    data_dir: str = typer.Option("data", "--data-dir", help="Data directory (Parquet tree and catalog.db)"),
    db_path: str = typer.Option("data/satsa.db", "--db-path", help="Path to the operational SQLite database"),
) -> None:
    """Apply pending schema migrations, adopt pre-catalog Parquet files, recover and verify (docs/migrations.md).

    Takes a backup of each database before migrating it. Safe to run more than once.
    """
    from satsa.store.catalog import Catalog
    from satsa.store.migrations import applied_versions
    from satsa.store.sqlite import SQLiteStore

    sqlite_store = SQLiteStore(db_path)
    applied = sqlite_store.schema_versions_applied
    versions = applied_versions(sqlite_store.conn)
    backups = [
        r["backup_path"]
        for r in sqlite_store.conn.execute("SELECT DISTINCT backup_path FROM schema_migrations WHERE backup_path IS NOT NULL")
    ]
    sqlite_store.close()
    catalog = Catalog(data_dir)
    try:
        legacy = catalog.adopt_legacy_files()
        recovered = catalog.recover()
        problems = catalog.verify()
        catalog_versions = applied_versions(catalog.conn)
    finally:
        catalog.close()
    console.print("[bold blue]Operational store[/bold blue] " + db_path)
    console.print(f"  * migrations applied now: {applied or 'none (up to date)'}; schema versions: {versions}")
    for b in backups:
        console.print(f"  * pre-migration backup: {b}")
    console.print("[bold blue]Publication catalog[/bold blue] " + str(Path(data_dir) / "catalog.db"))
    console.print(f"  * schema versions: {catalog_versions}")
    console.print(f"  * legacy Parquet adopted as batch: {legacy or 'none'}")
    console.print(
        f"  * recovery: {recovered['staging_discarded']} staging dir(s) discarded, "
        f"{recovered['orphans_quarantined']} orphan file(s) quarantined"
    )
    if problems:
        console.print(f"[bold red][!] {len(problems)} published file(s) failed verification:[/bold red]")
        for problem in problems[:50]:
            console.print(f"    {problem}")
        raise typer.Exit(code=1)
    console.print("[bold green][+] Every published file is present and matches its recorded hash.[/bold green]")
    _report_pseudonym_key(data_dir)


def _report_pseudonym_key(data_dir: str) -> None:
    """Move a legacy .satsa_salt into the keyring (satsa.keys), or say why it cannot."""
    from satsa.keys import PseudonymKeyMissing, current_key, status

    try:
        key = current_key(data_dir)
    except PseudonymKeyMissing as exc:
        console.print(f"[bold red][!] Pseudonymisation key: {exc}[/bold red]")
        raise typer.Exit(code=1) from exc
    origin = status(data_dir)["versions"][-1]["origin"]
    console.print(f"[bold blue]Pseudonymisation key[/bold blue] {key.key_id} ({origin})")


@app.command("verify-data")
def verify_data_cmd(
    data_dir: str = typer.Option("data", "--data-dir", help="Data directory (Parquet tree and catalog.db)"),
) -> None:
    """Check that every published Parquet file exists and matches the SHA-256 recorded at publication."""
    from satsa.store.catalog import Catalog

    catalog = Catalog(data_dir)
    try:
        problems = catalog.verify()
        files = sum(1 for e in catalog.published_manifest() if e["rel_path"])
        seq = catalog.max_pub_seq()
    finally:
        catalog.close()
    if problems:
        console.print(f"[bold red][!] {len(problems)} of {files} published file(s) failed:[/bold red]")
        for problem in problems[:100]:
            console.print(f"    {problem}")
        raise typer.Exit(code=1)
    console.print(f"[bold green][+] {files} published file(s) verified (publication sequence {seq}).[/bold green]")


@app.command("recover")
def recover_cmd(
    data_dir: str = typer.Option("data", "--data-dir", help="Data directory (Parquet tree and catalog.db)"),
) -> None:
    """Quarantine what an interrupted writer left behind (staging files, unlisted batch files)."""
    from satsa.store.catalog import Catalog

    catalog = Catalog(data_dir)
    try:
        report = catalog.recover()
    finally:
        catalog.close()
    console.print(
        f"[bold green][+] Recovery done:[/bold green] {report['staging_discarded']} staging dir(s) discarded, "
        f"{report['orphans_quarantined']} orphan file(s) moved to {Path(data_dir) / 'quarantine'}"
    )


@app.command("run")
def run_cmd(
    period: str = typer.Option(
        "",
        "--period",
        "-p",
        help="Review period to assess (2026, 2026-Q1, 2026-H1 or 2026-03): only records of that period "
        "are read. Default: every submitted record, with no period filter (the run says so).",
    ),
    db_path: str = typer.Option(
        "data/satsa.db", "--db-path", help="Path to SQLite metadata database"
    ),
    parquet_dir: str = typer.Option(
        "data", "--parquet-dir", help="Root directory for Parquet storage"
    ),
    reference_date: str = typer.Option(
        "",
        "--reference-date",
        help="Date the assessment is 'as of' (YYYY-MM-DD) for time-dependent rules such as stale "
        "cases. Default: the latest timestamp in the submitted data. Never the current date.",
    ),
) -> None:
    """Execute supervisory assessment across all entities: evaluate rules, compute risk index, rank review queue."""
    from datetime import datetime

    as_of = None
    if reference_date:
        try:
            as_of = datetime.strptime(reference_date, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red][!] --reference-date must be YYYY-MM-DD[/bold red]")
            raise typer.Exit(code=2) from None
    from satsa.scoring.runner import AssessmentRunner
    from satsa.scoring.selection import window_for_period
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    console.print(
        "[bold blue]Executing supervisory assessment for:[/bold blue] "
        f"[cyan]{window_for_period(period or None).describe()}[/cyan]"
    )
    duckdb_store = DuckDBStore(parquet_dir)
    sqlite_store = SQLiteStore(db_path)
    runner = AssessmentRunner(duckdb_store, sqlite_store)

    res = runner.run_assessment(period=period or None, reference_date=as_of)
    if res.get("fingerprint"):
        console.print(f"  * Analytical fingerprint: [cyan]{res['fingerprint'][:16]}[/cyan]")
    if res.get("reference_date"):
        console.print(f"  * Reference date (as of): [cyan]{res['reference_date']}[/cyan]")
    duckdb_store.close()
    sqlite_store.close()

    if res.get("status") == "success":
        console.print("[bold green][+] Assessment executed successfully:[/bold green]")
        console.print(f"  * Run ID: [cyan]{res.get('run_id')}[/cyan]")
        console.print(f"  * Config Hash: [cyan]{res.get('config_hash')}[/cyan]")
        console.print(f"  * Total Findings Flagged: [yellow]{res.get('findings_count')}[/yellow]")
        console.print(f"  * Review Queue Items Generated: [cyan]{res.get('queue_count')}[/cyan]")
        console.print(
            f"  * Exploratory Leads (not scored): [cyan]{res.get('anomaly_signals_count', 0)}[/cyan]"
        )
        console.print("\n[bold]Entity Supervisory Risk Summary:[/bold]")
        for ent, data in res.get("entity_scores", {}).items():
            color = (
                "red"
                if data["risk_index"] > 50
                else ("yellow" if data["risk_index"] > 25 else "green")
            )
            coverage = data.get("coverage")
            evidence = (
                f" -- {data['classification_status'].replace('_', ' ')}, {coverage:.0%} of rules assessed"
                if data.get("classification_status") and coverage is not None
                else ""
            )
            console.print(
                f"  * {ent}: [{color}]Risk Index = {data['risk_index']:.1f} ({data['risk_band']})[/{color}]{evidence}"
            )
    else:
        console.print(f"[bold red][!] Run failed:[/bold red] {res.get('message')}")


@app.command("seed-history")
def seed_history_cmd(
    periods: int = typer.Option(
        3, "--periods", "-n", help="Number of chronological historical periods to compute"
    ),
    db_path: str = typer.Option(
        "data/satsa.db", "--db-path", help="Path to SQLite metadata database"
    ),
    parquet_dir: str = typer.Option(
        "data", "--parquet-dir", help="Root directory for Parquet storage"
    ),
) -> None:
    """Seed genuine multi-period historical assessment runs for the portfolio trend chart.

    Splits the already-ingested alert/case timeline into N chronological windows and
    re-runs the real deterministic rule engine against each window's actual data
    subset, persisting a real EntityScore per period. This does NOT fabricate any
    numbers -- entities whose defects only appear later in the timeline will
    genuinely show a rising risk index across periods; entities with stable behavior
    will genuinely show a flat one.
    """
    from satsa.scoring.history import seed_historical_periods
    from satsa.store.sqlite import SQLiteStore

    console.print(
        f"[bold blue]Seeding {periods} genuine historical assessment periods...[/bold blue]"
    )
    sqlite_store = SQLiteStore(db_path)
    results = seed_historical_periods(
        parquet_dir, sqlite_store, n_periods=periods, actor="cli:seed-history"
    )
    sqlite_store.close()

    if not results:
        console.print(
            "[bold yellow][!] No alert data found to window -- ingest data first.[/bold yellow]"
        )
        raise typer.Exit(code=1)

    console.print("[bold green][+] Historical periods computed:[/bold green]")
    for r in results:
        console.print(
            f"  * {r['period']}: Run ID [cyan]{r['run_id']}[/cyan] | "
            f"Findings: [yellow]{r['findings_count']}[/yellow]"
        )


def _serving_config_or_exit(
    host: str | None, certfile: str | None, keyfile: str | None
) -> ServingConfig:
    """Bind address and TLS for `serve` / `admin`; over TLS the session cookies become Secure."""
    import os

    from satsa.serving import (
        ENV_COOKIE_SECURE,
        ServingConfigError,
        exposure_warning,
        serving_config,
    )

    try:
        config = serving_config(host=host, certfile=certfile, keyfile=keyfile)
    except ServingConfigError as exc:
        console.print(f"[bold red][!] Refusing to start: {exc}[/bold red]")
        raise typer.Exit(code=2) from None
    warning = exposure_warning(config)
    if warning:
        console.print(f"[bold yellow][!] {warning}[/bold yellow]")
    if config.tls:
        os.environ.setdefault(ENV_COOKIE_SECURE, "1")
    return config


def _run_uvicorn_guarded(app_path: str, config, port: int) -> None:
    """Run uvicorn with the best-effort, loopback-only egress guard installed for the whole
    process lifetime (the app's lifespan also installs it; installs are reference-counted)."""
    import uvicorn

    from satsa.netguard import install_egress_guard, uninstall_egress_guard

    guarded = install_egress_guard()
    try:
        uvicorn.run(
            app_path,
            host=config.host,
            port=port,
            log_level="info",
            ssl_certfile=config.certfile,
            ssl_keyfile=config.keyfile,
        )
    finally:
        if guarded:
            uninstall_egress_guard()


@app.command("serve")
def serve_cmd(
    host: str = typer.Option(
        None, "--host", "-h", help="Bind address (default: SATSA_HOST, else loopback 127.0.0.1)"
    ),
    port: int = typer.Option(8001, "--port", "-p", help="Server port (default 8001)"),
    ssl_certfile: str = typer.Option(None, "--ssl-certfile", help="TLS certificate (default: SATSA_TLS_CERT)"),
    ssl_keyfile: str = typer.Option(None, "--ssl-keyfile", help="TLS private key (default: SATSA_TLS_KEY)"),
) -> None:
    """Launch local offline server-rendered UI and REST API."""
    config = _serving_config_or_exit(host, ssl_certfile, ssl_keyfile)
    console.print(
        f"[bold green][+] Launching SAT-SA offline dashboard at:[/bold green] [cyan]{config.scheme}://{config.host}:{port}[/cyan]"
    )
    console.print("[dim]Fully offline, air-gapped server. Press Ctrl+C to exit.[/dim]")
    _run_uvicorn_guarded("satsa.api:app", config, port)


@app.command("admin")
def admin_cmd(
    host: str = typer.Option(
        None, "--host", "-h", help="Bind address (default: SATSA_HOST, else loopback 127.0.0.1)"
    ),
    port: int = typer.Option(8000, "--port", "-p", help="NCIIPC Administration Portal port (default 8000)"),
    ssl_certfile: str = typer.Option(None, "--ssl-certfile", help="TLS certificate (default: SATSA_TLS_CERT)"),
    ssl_keyfile: str = typer.Option(None, "--ssl-keyfile", help="TLS private key (default: SATSA_TLS_KEY)"),
) -> None:
    """Launch NCIIPC Administration Portal control plane."""
    config = _serving_config_or_exit(host, ssl_certfile, ssl_keyfile)
    console.print(
        f"[bold green][+] Launching NCIIPC Administration Portal at:[/bold green] [cyan]{config.scheme}://{config.host}:{port}[/cyan]"
    )
    console.print("[dim]Administrative identity and control console. Press Ctrl+C to exit.[/dim]")
    _run_uvicorn_guarded("satsa.admin.app:app", config, port)


@app.command("tls-cert")
def tls_cert_cmd(
    out_dir: str = typer.Option("certs", "--out", "-o", help="Directory for the certificate and key"),
    hostname: list[str] = typer.Option(["localhost"], "--hostname", help="DNS name(s) the portals are reached by"),
    ip: list[str] = typer.Option(["127.0.0.1"], "--ip", help="IP address(es) the portals are reached by"),
    days: int = typer.Option(365, "--days", help="Validity in days (1-825)"),
    force: bool = typer.Option(False, "--force", help="Replace an existing certificate and key"),
) -> None:
    """Create a self-signed TLS certificate offline (needs the local `openssl` command)."""
    from satsa.serving import (
        ENV_TLS_CERT,
        ENV_TLS_KEY,
        ServingConfigError,
        generate_self_signed_cert,
    )

    try:
        cert, key = generate_self_signed_cert(out_dir, list(hostname), list(ip), days=days, force=force)
    except ServingConfigError as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=1) from None
    console.print(f"[bold green][+] Certificate:[/bold green] {cert}")
    console.print(f"[bold green][+] Private key:[/bold green] {key}")
    console.print(f"[dim]Serve with TLS: set {ENV_TLS_CERT}={cert} and {ENV_TLS_KEY}={key}[/dim]")


@app.command("report")
def report_cmd(
    entity: str = typer.Option("all", "--entity", "-e", help="Entity ID (or 'all'/'portfolio')"),
    fmt: str = typer.Option("all", "--format", "-f", help="Format: html, pdf, csv, all"),
    output_dir: str = typer.Option("reports", "--output-dir", "-o", help="Output directory"),
    db_path: str = typer.Option(
        "data/satsa.db", "--db-path", help="Path to SQLite metadata database"
    ),
    parquet_dir: str = typer.Option(
        "data", "--parquet-dir", help="Root directory for Parquet storage"
    ),
) -> None:
    """Generate self-contained HTML, PDF, and CSV supervisory assessment reports."""
    from pathlib import Path

    from satsa.report.generator import ReportGenerator, ReportNotFoundError
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    console.print(
        f"[bold blue]Generating supervisory reports...[/bold blue] (format={fmt}, entity={entity})"
    )
    duckdb_store = DuckDBStore(parquet_dir)
    duckdb_store.load_all_tables()
    sqlite_store = SQLiteStore(db_path)
    rep_gen = ReportGenerator(duckdb_store, sqlite_store)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    # Every report and export is of one run: the latest, as the UI shows by default.
    try:
        latest_run = rep_gen.resolve_run().run_id
    except ReportNotFoundError:
        duckdb_store.close()
        sqlite_store.close()
        console.print("[red]No assessment run yet: run `satsa run` first.[/red]")
        raise typer.Exit(code=1) from None

    generated = []

    # CSV Exports
    if fmt in ("csv", "all"):
        f_csv = rep_gen.export_findings_csv(out_path / "findings_export.csv")
        q_csv = rep_gen.export_queue_csv(out_path / "review_queue_export.csv")
        m_csv = rep_gen.export_metrics_csv(out_path / "metrics_export.csv")
        generated.extend([f_csv, q_csv, m_csv])

    # Portfolio HTML
    if (entity == "all" or entity.lower() == "portfolio") and fmt in ("html", "all"):
        p_html = rep_gen.generate_portfolio_html(out_path / "portfolio_summary_report.html")
        generated.append(p_html)

    # Portfolio PDF
    if (entity == "all" or entity.lower() == "portfolio") and fmt in ("pdf", "all"):
        from satsa.report.naming import portfolio_pdf_name

        run_id = rep_gen.resolve_run().run_id
        generated.append(
            rep_gen.generate_portfolio_pdf(out_path / portfolio_pdf_name(run_id))
        )

    # Entity-specific or all entities HTML & PDF
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT DISTINCT entity_id FROM entity_scores WHERE run_id = ? ORDER BY entity_id", (latest_run,))
    available_entities = [r["entity_id"] for r in cur.fetchall()]

    if entity == "all":
        target_entities = available_entities
    elif entity.lower() == "portfolio":
        target_entities = []
    else:
        target_entities = [entity]

    for ent in target_entities:
        if fmt in ("html", "all"):
            h = rep_gen.generate_entity_html(ent, out_path / f"{ent}_supervisory_report.html")
            generated.append(h)
        if fmt in ("pdf", "all"):
            try:
                p = rep_gen.generate_entity_pdf(ent, out_path / f"{ent}_supervisory_report.pdf")
            except ReportNotFoundError:
                console.print(f"[yellow]  * Skipped PDF for {ent}: not scored in the latest run[/yellow]")
                continue
            generated.append(p)

    duckdb_store.close()
    sqlite_store.close()

    console.print(
        f"[bold green][+] Successfully generated {len(generated)} report artifacts in:[/bold green] [cyan]{out_path}[/cyan]"
    )
    for g in generated[:8]:
        console.print(f"  * [dim]{g.name}[/dim]")
    if len(generated) > 8:
        console.print(f"  * ... and {len(generated) - 8} more files.")


@app.command("validate")
def validate_cmd(
    ground_truth: str = typer.Option(
        "data/generated/ground_truth.json", "--ground-truth", "-g", help="Ground truth JSON path"
    ),
    shadow_csv: str = typer.Option(
        "", "--shadow-csv", help="Optional path to historical manual review CSV for shadow pilot"
    ),
    adjudication_csv: str = typer.Option(
        "",
        "--adjudication-csv",
        help="With --shadow-csv: write the findings the workpaper does not adjudicate to this CSV "
        "for blind examiner labelling (no scores or severities)",
    ),
    output_md: str = typer.Option(
        "docs/validation_report.md", "--output-md", help="Output markdown report path"
    ),
    output_html: str = typer.Option(
        "docs/validation_report.html", "--output-html", help="Output HTML report path"
    ),
    db_path: str = typer.Option(
        "data/satsa.db", "--db-path", help="Path to SQLite metadata database"
    ),
    parquet_dir: str = typer.Option(
        "data", "--parquet-dir", help="Root directory for Parquet storage"
    ),
) -> None:
    """Execute validation harness against ground truth: precision, recall, lift, stability, and audit verification."""
    from pathlib import Path

    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore
    from satsa.validate.harness import (
        ADJUDICATION_COLUMNS,
        ShadowPilotAdapter,
        ValidationHarness,
        adjudication_sheet,
    )

    console.print(
        f"[bold blue]Running validation harness against:[/bold blue] [cyan]{ground_truth}[/cyan]"
    )
    duckdb_store = DuckDBStore(parquet_dir)
    duckdb_store.load_all_tables()
    sqlite_store = SQLiteStore(db_path)
    harness = ValidationHarness(duckdb_store, sqlite_store, ground_truth)

    results = harness.run_full_validation()

    # Shadow pilot check if provided. The evaluation is stored, so the report
    # below (and the /shadow-pilot page) can show it; without --shadow-csv the
    # report shows the latest evaluation already stored for this run, if any.
    shadow_res = None
    if shadow_csv:
        adapter = ShadowPilotAdapter(sqlite_store)
        reviews = adapter.load_manual_reviews(shadow_csv)
        shadow_res = adapter.evaluate_shadow_pilot(reviews, results["run_id"])
        if shadow_res.get("status") == "success":
            sqlite_store.save_shadow_result(results["run_id"], "cli", Path(shadow_csv).name, shadow_res)
            if adjudication_csv:
                from satsa.csv_safe import SafeDictWriter

                sheet = adjudication_sheet(sqlite_store, shadow_res)
                with open(adjudication_csv, "w", encoding="utf-8", newline="") as f:
                    writer = SafeDictWriter(f, fieldnames=ADJUDICATION_COLUMNS)
                    writer.writeheader()
                    writer.writerows(sheet)
                console.print(
                    f"[bold green][+] Adjudication sheet:[/bold green] {len(sheet)} unadjudicated findings "
                    f"written to [cyan]{adjudication_csv}[/cyan]"
                )
    stored = sqlite_store.list_shadow_results(results["run_id"], limit=1)
    md_file, html_file = harness.generate_report(
        output_md, output_html, run_id=results["run_id"], shadow_result=stored[0] if stored else None
    )

    duckdb_store.close()
    sqlite_store.close()

    ranking = results["entity_ranking"]
    rules = results["rule_detection"]
    lift = results["review_effort_lift"]
    stab = results["stability"]
    audit = results["audit"]

    console.print("\n[bold green][+] Validation Benchmark Results:[/bold green]")
    console.print(
        f"  * Entity Rank Precision@k: [bold cyan]{ranking.get('precision_at_k', 0) * 100:.1f}%[/bold cyan]"
    )
    console.print(
        f"  * Injected Defect Recall:  [bold cyan]{rules.get('overall_recall', 0) * 100:.1f}%[/bold cyan] ({rules.get('true_positives')}/{rules.get('total_injected_defects')})"
    )
    console.print(
        f"  * Overall Defect Precision:[bold cyan]{rules.get('overall_precision', 0) * 100:.1f}%[/bold cyan] "
        f"({rules.get('true_positives')} of {rules.get('total_findings')} findings)"
    )
    _print_false_positives(rules)
    _print_sensitivity(results.get("threshold_sensitivity", {}))
    console.print(
        f"  * Ranking Stability (+/-20%):[bold cyan]Spearman rho = {stab.get('spearman_rho_plus_20'):.4f}[/bold cyan]"
    )
    console.print(
        f"  * Cryptographic Audit:     [bold green]{audit.get('audit_message')}[/bold green]"
    )

    console.print("\n[bold]Review-Effort Lift Table (vs Random Sampling):[/bold]")
    for b_k, b_v in lift.get("budgets", {}).items():
        console.print(
            f"  * Budget {b_k}: [yellow]{b_v['defects_found']}/{b_v['records_examined']} queue alerts affected"
            f"{' (queue exhausted)' if b_v['queue_exhausted'] else ''}[/yellow] | Hit Rate = {b_v['hit_rate_top_k'] * 100:.1f}% vs {b_v['random_baseline_hit_rate'] * 100:.2f}% random | [bold green]Lift = {b_v['lift_factor']:.2f}x[/bold green]"
        )

    if shadow_res and shadow_res.get("status") == "success":
        n = shadow_res["total_confirmed_issues"]
        precision = shadow_res["workpaper_precision"]
        precision_text = "n/a" if precision is None else f"{precision * 100:.1f}%"
        console.print(
            "\n[bold]Shadow Pilot Evaluation:[/bold] "
            f"{shadow_res['total_manual_reviews']} workpaper rows ({n} confirmed) | "
            f"finding recall {shadow_res['rule_finding_recall'] * 100:.1f}% ({shadow_res['matched_findings']}/{n}) | "
            f"queue record recall {shadow_res['queue_record_recall'] * 100:.1f}% ({shadow_res['matched_queue']}/{n}) | "
            f"precision {precision_text} | "
            f"{len(shadow_res['findings_unadjudicated'])} findings not adjudicated | "
            f"rule config hash {shadow_res['config_hash']}"
        )
        def ci(interval: list[float] | None) -> str:
            return f" (95% CI {interval[0] * 100:.0f}-{interval[1] * 100:.0f}%)" if interval else ""

        for r in shadow_res["per_rule"]:
            adjudicated = r["findings_confirmed"] + r["findings_rejected"]
            console.print(
                f"      {r['rule_id']}: recall {r['reproduced']}/{r['confirmed']}{ci(r['recall_ci'])} | "
                f"precision {r['findings_confirmed']}/{adjudicated}{ci(r['precision_ci'])} | "
                f"{r['findings_unadjudicated']} not adjudicated | fires on "
                f"{(r['firing_rate'] or 0) * 100:.0f}% of entities"
            )
    elif shadow_res:
        console.print(f"\n[bold]Shadow Pilot Evaluation:[/bold] {shadow_res}")

    console.print("\n[bold green][+] Validation reports generated:[/bold green]")
    console.print(f"  * Markdown: [cyan]{md_file}[/cyan]")
    console.print(f"  * HTML:     [cyan]{html_file}[/cyan]")


def _print_false_positives(rules: dict) -> None:
    """Print which (entity, rule) findings counted as false positives."""
    for label, key in (
        ("clean entities", "false_positives_on_clean_entities"),
        ("defect entities (rule not injected)", "false_positives_on_defect_entities"),
    ):
        pairs = rules.get(key, [])
        console.print(f"  * False positives on {label}: [yellow]{len(pairs)}[/yellow] {' '.join(pairs)}")


def _print_sensitivity(sens: dict) -> None:
    """Print which single-threshold perturbations changed a rule's outcome."""
    if not sens:
        return
    console.print(
        f"  * Threshold sensitivity (+/-{sens['perturbation_percent']}%): [yellow]{sens['changed']} of "
        f"{sens['perturbations']}[/yellow] perturbations changed an outcome; not covered (no tunable threshold): "
        f"{' '.join(sens['rules_not_covered'])}"
    )
    for r in sens["rows"]:
        if r["changed"]:
            out = r["outcome"]
            console.print(
                f"      {r['rule_id']} {r['param']} {r['baseline']} -> {r['tested']}: "
                f"missed {out['fn'] or '-'}, false alarm {out['fp'] or '-'}"
            )


@app.command("validate-stress")
def validate_stress_cmd(
    seed: int = typer.Option(9901, "--seed", "-s", help="Stress dataset random seed"),
    output_md: str = typer.Option(
        "docs/validation_stress_report.md", "--output-md", help="Output markdown report path"
    ),
) -> None:
    """Run the harder 'stress scenario' validation (borderline threshold, ambiguous dual-rule,
    and noisy-clean cases) in a fully isolated temp store -- never touches data/satsa.db or
    data/parquet. Reports real, likely-imperfect precision/recall, clearly labeled as such.

    See src/satsa/synth/stress.py and docs/validation.md Section 2A for the methodology.
    """
    import tempfile
    from pathlib import Path

    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.scoring.runner import AssessmentRunner
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore
    from satsa.synth.stress import save_stress_dataset
    from satsa.validate.harness import ValidationHarness, sensitivity_markdown

    console.print("[bold blue]Generating and evaluating the stress scenario dataset...[/bold blue]")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        csv_dir, gt_path = save_stress_dataset(tmp_path / "generated", seed=seed)

        duckdb_store = DuckDBStore(tmp_path / "store")
        sqlite_store = SQLiteStore(tmp_path / "store" / "stress.db")
        pipeline = IngestionPipeline(duckdb_store, sqlite_store)
        pipeline.ingest_directory(csv_dir)

        runner = AssessmentRunner(duckdb_store, sqlite_store)
        res = runner.run_assessment(period="STRESS", actor="cli:validate-stress")

        harness = ValidationHarness(duckdb_store, sqlite_store, gt_path)
        results = harness.run_full_validation(res["run_id"])

        duckdb_store.close()
        sqlite_store.close()

    ranking = results["entity_ranking"]
    rules = results["rule_detection"]

    console.print("\n[bold yellow][!] Stress Scenario Results (harder than the primary correctness check):[/bold yellow]")
    console.print(
        f"  * Entity Rank Precision@k: [bold cyan]{ranking.get('precision_at_k', 0) * 100:.1f}%[/bold cyan]"
    )
    console.print(
        f"  * Injected Defect Recall:  [bold cyan]{rules.get('overall_recall', 0) * 100:.1f}%[/bold cyan] "
        f"({rules.get('true_positives')}/{rules.get('total_injected_defects')})"
    )
    console.print(
        f"  * Overall Defect Precision:[bold cyan]{rules.get('overall_precision', 0) * 100:.1f}%[/bold cyan] "
        f"({rules.get('true_positives')} of {rules.get('total_findings')} findings)"
    )
    _print_false_positives(rules)
    _print_sensitivity(results.get("threshold_sensitivity", {}))
    fp_clean = rules.get("false_positives_on_clean_entities", [])
    fp_defect = rules.get("false_positives_on_defect_entities", [])

    md_path = Path(output_md)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_lines = [
        "# SAT-SA Stress Scenario Validation Report",
        "",
        "> Companion to docs/validation.md. Unlike the primary synthetic dataset (whose injected",
        "> defects clearly exceed each rule's threshold by design), this scenario injects a",
        "> borderline-threshold case, an ambiguous dual-rule case, and a noisy true-negative case.",
        "> It is still synthetic and built against the rules' own thresholds, so a perfect score",
        "> shows the rules behave as specified near those thresholds, not real-world accuracy.",
        "",
        f"**Run ID:** `{res['run_id']}` | **Seed:** `{seed}`",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Entity Rank Precision@k | {ranking.get('precision_at_k', 0) * 100:.1f}% |",
        f"| Entity Rank Recall@k | {ranking.get('recall_at_k', 0) * 100:.1f}% |",
        f"| Injected Defect Recall | {rules.get('overall_recall', 0) * 100:.1f}% ({rules.get('true_positives')}/{rules.get('total_injected_defects')}) |",
        f"| Overall Defect Precision | {rules.get('overall_precision', 0) * 100:.1f}% ({rules.get('true_positives')} of {rules.get('total_findings')} findings) |",
        f"| False Positives | {rules.get('false_positives')} |",
        "",
        "Every finding whose (entity, rule) pair is not an injected defect counts as a false positive, on any",
        "entity and for any rule.",
        "",
        f"- False positives on the clean entity: {', '.join(fp_clean) or 'none'}",
        f"- False positives on defect entities (rule not injected there): {', '.join(fp_defect) or 'none'}",
        f"- Missed defects: {', '.join(rules.get('missed_defects', [])) or 'none'}",
        "",
        "## Per-rule breakdown",
        "| Rule ID | TP | FN | FP |",
        "|---|---|---|---|",
    ]
    for r_code, counts in rules.get("rule_breakdown", {}).items():
        md_lines.append(f"| `{r_code}` | {counts.get('tp', 0)} | {counts.get('fn', 0)} | {counts.get('fp', 0)} |")
    md_lines += ["", "## Threshold sensitivity", "", *sensitivity_markdown(results.get("threshold_sensitivity", {}))]
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    console.print(f"\n[bold green][+] Stress report written to:[/bold green] [cyan]{md_path}[/cyan]")


@app.command("validate-independent")
def validate_independent_cmd(
    seeds: int = typer.Option(20, "--seeds", "-n", help="Number of seeds to run"),
    start_seed: int = typer.Option(1, "--start-seed", help="First seed"),
    output_md: str = typer.Option(
        "docs/validation_independent_report.md", "--output-md", help="Markdown report path"
    ),
    output_json: str = typer.Option("", "--output-json", help="Also write the raw per-seed results as JSON"),
    rules_config: str = typer.Option("config/rules.yaml", "--rules-config", help="Rule configuration to evaluate"),
    sweep: bool = typer.Option(True, "--sweep/--no-sweep", help="Run the +/-20% threshold sweep per seed"),
) -> None:
    """Validate on the INDEPENDENT generator (written from the documented rule catalogue):
    engine vs three naive baselines, family ablation, +/-20% sweep, Wilson intervals.

    Each seed runs in its own temporary store; data/ is never touched. Synthetic data only.
    """
    import json
    from pathlib import Path

    from satsa.validate.independent import aggregate, render_markdown, run_seed

    results = []
    for seed in range(start_seed, start_seed + seeds):
        r = run_seed(seed, rules_config=rules_config, sweep=sweep)
        e = r["engine"]
        console.print(
            f"  * seed {seed}: {e['tp']}/{e['tp'] + e['fn']} defects detected, {e['fp']} false positives "
            f"({e['fp_on_decoys']} on decoys), {r['seconds']} s"
        )
        results.append(r)
    agg = aggregate(results)
    t = agg["totals"]
    command = (
        f"satsa validate-independent --seeds {seeds} --start-seed {start_seed}"
        + ("" if sweep else " --no-sweep")
        + (f" --rules-config {rules_config}" if rules_config != "config/rules.yaml" else "")
    )
    md = Path(output_md)
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text(render_markdown(results, agg, command), encoding="utf-8")
    if output_json:
        Path(output_json).write_text(json.dumps({"results": results}, indent=1, default=str), encoding="utf-8")
    recall = t["tp"] / max(t["tp"] + t["fn"], 1)
    precision = t["tp"] / max(t["tp"] + t["fp"], 1)
    console.print(
        f"[bold green][+] Independent set:[/bold green] recall {recall * 100:.1f}% ({t['tp']:g}/{t['tp'] + t['fn']:g}), "
        f"precision {precision * 100:.1f}% ({t['tp']:g}/{t['tp'] + t['fp']:g}), decoys flagged "
        f"{t['decoys_flagged']:g}/{t['decoys']:g}. Report: [cyan]{md}[/cyan]"
    )


@app.command("offline-bundle")
def offline_bundle_cmd(
    output_dir: str = typer.Option("dist", "--output-dir", "-o", help="Output directory"),
    wheelhouse: str | None = typer.Option(
        None,
        "--wheelhouse",
        help="Wheelhouse from scripts/build_wheelhouse.sh to include (default: ./wheelhouse if present)",
    ),
    signing_key: str | None = typer.Option(
        None, "--signing-key", help="Ed25519 release key (satsa release keygen) to sign SHA256SUMS"
    ),
) -> None:
    """Package SAT-SA for air-gapped installation: sources, configs, wheelhouse, containerfiles, and scripts."""
    from satsa.bundle.packager import BundlePathTooLongError, OfflinePackager, WheelhouseError

    console.print("[bold blue]Building SAT-SA offline deployment bundle...[/bold blue]")
    packager = OfflinePackager(dist_dir=output_dir, wheelhouse=wheelhouse)
    try:
        archive = packager.create_bundle(output_tar=True, signing_key=signing_key)
    except (WheelhouseError, BundlePathTooLongError, TypeError, ValueError) as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=1) from None
    console.print(
        f"[bold green][+] Offline bundle successfully packaged:[/bold green] [cyan]{archive}[/cyan]"
    )
    console.print(f"  * Bundle directory: [dim]{packager.bundle_dir}[/dim]")
    if packager.wheelhouse is None:
        console.print(
            "[bold yellow][!] No wheelhouse included: install_offline will refuse to run until the bundle "
            "is rebuilt with one (scripts/build_wheelhouse.sh, docs/offline_install.md).[/bold yellow]"
        )
    console.print("  * Deployment instructions: [dim]README_OFFLINE.md inside bundle[/dim]")
    if signing_key is None:
        console.print("[yellow]  * SHA256SUMS is not signed (pass --signing-key to sign it)[/yellow]")
    else:
        console.print("  * SHA256SUMS signed; verify with: satsa release verify <bundle dir> --public-key <key>")


@app.command("benchmark")
def benchmark_cmd(
    data_dir: str = typer.Option("data", "--data-dir", help="Data directory"),
) -> None:
    """Benchmark columnar Parquet scan throughput and assessment execution runtime."""
    from satsa.bench.benchmark import BenchmarkRunner

    console.print("[bold blue]Executing SAT-SA performance benchmark...[/bold blue]")
    bench = BenchmarkRunner(data_dir)

    console.print("\n[bold]1. One in-memory DuckDB aggregation query (one thread, generated table):[/bold]")
    col_results = bench.run_columnar_scan_benchmark([50_000, 200_000, 1_000_000])
    for r in col_results:
        console.print(
            f"  * {r['alert_count']:,} alerts: query time = [cyan]{r['query_time_sec']}s[/cyan] | "
            f"Throughput = [bold green]{r['throughput_rows_per_sec']:,.0f} rows/s[/bold green]"
        )

    console.print("\n[bold]2. End-to-End Supervisory Assessment Runtime:[/bold]")
    e2e = bench.run_end_to_end_assessment_benchmark()
    console.print(f"  * Dataset alert count:   [cyan]{e2e['dataset_alerts']:,}[/cyan]")
    console.print(f"  * Execution time:        [cyan]{e2e['total_elapsed_sec']}s[/cyan]")
    console.print(
        f"  * Assessment throughput: [bold green]{e2e['throughput_alerts_per_sec']:,.1f} alerts/s[/bold green]"
    )
    console.print(
        "[dim]Scan figures time one in-memory query (DuckDB pinned to one thread); they are not "
        "assessment times. Scale is measured, not extrapolated, by scripts/benchmark_scale.py "
        "(docs/benchmarks.md).[/dim]"
    )


rules_app = typer.Typer(help="Manage signed supervisory rule packs")
app.add_typer(rules_app, name="rules")


SECRET_HELP = (
    "HMAC signing secret (>= 32 chars). Defaults to the SATSA_RULEPACK_SECRET environment "
    "variable; there is NO built-in key and the command refuses to run without one."
)


def _make_signer(secret: str | None):
    from satsa.bundle.rules_signer import RulePackKeyError, RulePackSigner

    try:
        return RulePackSigner(secret=secret)
    except RulePackKeyError as e:
        console.print(f"[bold red][!] {e}[/bold red]")
        raise typer.Exit(code=1) from None


@rules_app.command("export")
def rules_export_cmd(
    config_dir: str = typer.Option("config", "--config-dir", "-c", help="Source config directory"),
    output_path: str = typer.Option(
        "dist/rule_pack_v1.tar.gz", "--output", "-o", help="Output archive path"
    ),
    version: str = typer.Option("1.0.0", "--version", "-v", help="Rule pack version"),
    secret: str | None = typer.Option(
        None, "--secret", envvar="SATSA_RULEPACK_SECRET", show_envvar=True, help=SECRET_HELP
    ),
) -> None:
    """Export and sign supervisory rules and configuration."""
    signer = _make_signer(secret)
    out = signer.export_rule_pack(config_dir=config_dir, output_path=output_path, version=version)
    console.print(
        f"[bold green][+] Rule pack signed and exported:[/bold green] [cyan]{out}[/cyan] (version {version})"
    )


@rules_app.command("import")
def rules_import_cmd(
    archive_path: str = typer.Argument(..., help="Path to signed rule pack tar.gz"),
    target_dir: str = typer.Option("config", "--target-dir", "-t", help="Target config directory"),
    db_path: str = typer.Option(
        "data/satsa.db", "--db-path", help="Path to SQLite metadata database"
    ),
    secret: str | None = typer.Option(
        None, "--secret", envvar="SATSA_RULEPACK_SECRET", show_envvar=True, help=SECRET_HELP
    ),
) -> None:
    """Verify cryptographic signature and checksums before importing rule pack."""
    from satsa.store.sqlite import SQLiteStore

    signer = _make_signer(secret)
    sqlite_store = SQLiteStore(db_path)
    try:
        res = signer.import_rule_pack(
            archive_path, target_config_dir=target_dir, sqlite_store=sqlite_store, actor="cli:rules"
        )
        console.print(
            f"[bold green][+] Rule pack verified and imported successfully:[/bold green] {res}"
        )
    except (ValueError, PermissionError, FileNotFoundError, OSError) as e:
        console.print(f"[bold red][!] Rule pack import failed:[/bold red] {e}")
        raise typer.Exit(code=1) from None
    finally:
        sqlite_store.close()


users_app = typer.Typer(help="Manage local RBAC identities (admin for the :8000 portal; analyst, examiner for SAT-SA)")
app.add_typer(users_app, name="users")


@users_app.command("list")
def users_list_cmd(
    db_path: str = typer.Option("data/satsa.db", "--db-path", help="Path to SQLite database"),
) -> None:
    """List local identities and their roles (never prints passphrases or hashes)."""
    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(db_path)
    for row in store.list_identities():
        console.print(f"  * [cyan]{row['username']}[/cyan] -- role: [yellow]{row['role']}[/yellow]")
    store.close()


@users_app.command("set-password")
def users_set_password_cmd(
    username: str = typer.Argument(..., help="Username to create or update"),
    role: str = typer.Option(
        "examiner", "--role", "-r", help="Role: admin (Admin Portal only), analyst, or examiner"
    ),
    password: str = typer.Option(
        ..., "--password", "-p", prompt=True, hide_input=True, help="New passphrase"
    ),
    db_path: str = typer.Option("data/satsa.db", "--db-path", help="Path to SQLite database"),
) -> None:
    """Create or rotate the passphrase for a local identity. Use this to replace demo credentials."""
    from satsa.auth.identities import ROLES
    from satsa.store.sqlite import SQLiteStore

    if role not in ROLES:
        console.print(f"[bold red][!] Invalid role '{role}'. Must be one of: {ROLES}[/bold red]")
        raise typer.Exit(code=1)

    store = SQLiteStore(db_path)
    store.upsert_identity(username, role, password)
    store.append_audit(
        action="identity_set_password", actor="cli:users", details={"username": username, "role": role}
    )
    store.close()
    console.print(f"[bold green][+] Identity '{username}' (role={role}) saved.[/bold green]")


audit_app = typer.Typer(help="Manage and verify cryptographic audit log chain")
app.add_typer(audit_app, name="audit")


CHAIN_TABLES = {"audit": "audit_log", "admin": "admin_audit_log"}


def _chain_table(chain: str) -> str:
    if chain not in CHAIN_TABLES:
        console.print(f"[bold red][!] --chain must be one of {sorted(CHAIN_TABLES)}[/bold red]")
        raise typer.Exit(code=2)
    return CHAIN_TABLES[chain]


@audit_app.command("verify")
def audit_verify_cmd(
    db_path: str = typer.Option("data/satsa.db", "--db-path", help="Path to SQLite database"),
    chain: str = typer.Option("audit", "--chain", help="Which chain: 'audit' (SAT-SA) or 'admin'"),
    checkpoint_count: int | None = typer.Option(
        None, "--checkpoint-count", help="Entry count recorded earlier by `satsa audit head`"
    ),
    checkpoint_head: str | None = typer.Option(
        None, "--checkpoint-head", help="Head hash recorded earlier by `satsa audit head`"
    ),
    checkpoint_file: str | None = typer.Option(
        None, "--checkpoint", help="Signed checkpoint file from `satsa audit checkpoint --sign`"
    ),
    pubkey: str | None = typer.Option(
        None, "--pubkey", help="Public key that signed the checkpoint (from `satsa audit keygen`)"
    ),
) -> None:
    """Verify the audit hash chain (each row checked with its own recorded algorithm).

    The chain alone cannot detect deletion of its newest rows or a full recomputation of the
    chain. A signed checkpoint (--checkpoint FILE --pubkey KEY) or a recorded head
    (--checkpoint-count N --checkpoint-head H) detects both: the live chain must match or
    extend the recorded head. Tamper-evident, not tamper-proof (DECISIONS.md ADR-005, ADR-008).
    """
    from satsa.store.sqlite import SQLiteStore

    table = _chain_table(chain)
    if (checkpoint_count is None) != (checkpoint_head is None):
        console.print("[bold red][!] --checkpoint-count and --checkpoint-head go together.[/bold red]")
        raise typer.Exit(code=2)
    if checkpoint_file and checkpoint_count is not None:
        console.print("[bold red][!] Use either --checkpoint FILE or --checkpoint-count/--checkpoint-head.[/bold red]")
        raise typer.Exit(code=2)
    if checkpoint_file and not pubkey:
        console.print("[bold red][!] --checkpoint needs --pubkey: the signature is always checked.[/bold red]")
        raise typer.Exit(code=2)
    if checkpoint_file:
        _verify_signed_checkpoint(db_path, checkpoint_file, str(pubkey))
        return
    store = SQLiteStore(db_path)
    try:
        if checkpoint_count is not None and checkpoint_head is not None:
            ok, msg = store.verify_checkpoint(checkpoint_count, checkpoint_head, table=table)
        else:
            result = store.verify_chain(table)
            ok, msg = result.ok, result.message
    finally:
        store.close()
    if ok:
        console.print(f"[bold green][+] Audit integrity verified:[/bold green] {msg}")
        if checkpoint_count is None:
            console.print(
                "[dim]Note: without a checkpoint this cannot detect removal of the newest entries; "
                "see `satsa audit head`.[/dim]"
            )
    else:
        console.print(f"[bold red][!] Audit chain broken/tampered:[/bold red] {msg}")
        raise typer.Exit(code=1)


@audit_app.command("head")
def audit_head_cmd(
    db_path: str = typer.Option("data/satsa.db", "--db-path", help="Path to SQLite database"),
    chain: str = typer.Option("audit", "--chain", help="Which chain: 'audit' (SAT-SA) or 'admin'"),
) -> None:
    """Print the chain's entry count and head hash for an examiner to record OFF-BOX.

    A hash chain cannot, by itself, detect truncation of its newest entries: the
    shortened chain is still internally consistent. Recording this checkpoint
    somewhere the database's operators cannot edit (paper, a separate system)
    and later running `satsa audit verify --checkpoint-count N --checkpoint-head H`
    detects such truncation or a rewrite of history up to that point.
    """
    from satsa.store.sqlite import SQLiteStore, utc_now_iso

    store = SQLiteStore(db_path)
    try:
        head = store.audit_head(table=_chain_table(chain))
    finally:
        store.close()
    console.print(f"chain:      {chain}")
    console.print(f"entries:    {head.count}")
    console.print(f"head_hash:  {head.head_hash}")
    console.print(f"hash_alg:   {head.hash_alg or '-'}")
    console.print(f"recorded:   {utc_now_iso()}")
    console.print(
        f"[dim]Verify later with: satsa audit verify --chain {chain} "
        f"--checkpoint-count {head.count} --checkpoint-head {head.head_hash}[/dim]"
    )


def _verify_signed_checkpoint(db_path: str, checkpoint_file: str, pubkey: str) -> None:
    from satsa.audit import checkpoint as cp
    from satsa.audit.keys import load_verifier
    from satsa.audit.signing import AlgorithmUnavailableError, KeyFormatError, UnknownAlgorithmError
    from satsa.store.sqlite import SQLiteStore

    try:
        payload = cp.load(checkpoint_file)
        sig = payload.get("signature")
        algorithm = sig.get("alg") if isinstance(sig, dict) else None
        if not algorithm:
            raise cp.CheckpointError("checkpoint is not signed")
        verifier = load_verifier(pubkey, algorithm=str(algorithm))
    except (cp.CheckpointError, KeyFormatError, UnknownAlgorithmError, AlgorithmUnavailableError, OSError) as exc:
        console.print(f"[bold red][!] Checkpoint not verified:[/bold red] {exc}")
        raise typer.Exit(code=1) from None
    store = SQLiteStore(db_path)
    try:
        result = cp.verify_checkpoint_file(store, checkpoint_file, verifier)
    finally:
        store.close()
    if result.ok:
        console.print(f"[bold green][+] Signed checkpoint verified:[/bold green] {result.message}")
    else:
        console.print(f"[bold red][!] Checkpoint not verified:[/bold red] {result.message}")
        raise typer.Exit(code=1)


@audit_app.command("keygen")
def audit_keygen_cmd(
    out_dir: str = typer.Option("audit-keys", "--out-dir", "-o", help="Directory for the key pair"),
    algorithm: str = typer.Option("ed25519", "--alg", help="Signature algorithm (only ed25519 is implemented)"),
    force: bool = typer.Option(False, "--force", help="Replace an existing key pair"),
) -> None:
    """Create a signing key pair for audit checkpoints, readable by its owner only.

    Keep the private key OFF the supervisory host (removable media held by the examiner) and
    give the public key to whoever verifies checkpoints. See DECISIONS.md ADR-008.
    """
    from satsa.audit.keys import KeyPermissionError, generate_keypair
    from satsa.audit.signing import AlgorithmUnavailableError, UnknownAlgorithmError

    try:
        private_path, public_path = generate_keypair(out_dir, algorithm=algorithm, force=force)
    except (UnknownAlgorithmError, AlgorithmUnavailableError, FileExistsError, KeyPermissionError) as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=1) from None
    console.print(f"[bold green][+] Private key:[/bold green] {private_path} (owner-only; keep it off-box)")
    console.print(f"[bold green][+] Public key:[/bold green]  {public_path}")


@audit_app.command("checkpoint")
def audit_checkpoint_cmd(
    db_path: str = typer.Option("data/satsa.db", "--db-path", help="Path to SQLite database"),
    chain: str = typer.Option("audit", "--chain", help="Which chain: 'audit' (SAT-SA) or 'admin'"),
    sign: bool = typer.Option(False, "--sign", help="Sign the checkpoint (needs --key)"),
    key: str | None = typer.Option(None, "--key", help="Private key from `satsa audit keygen`"),
    algorithm: str = typer.Option("ed25519", "--alg", help="Signature algorithm (only ed25519 is implemented)"),
    out: str | None = typer.Option(None, "--out", "-o", help="Write the checkpoint here (default: print it)"),
) -> None:
    """Emit a JSON checkpoint of the chain head (entry count, head hash, time, tool version).

    Store it OFF-BOX. With --sign --key it is signed, and `satsa audit verify --checkpoint FILE
    --pubkey KEY` later checks the signature and that the live chain matches or extends it.
    """
    from pathlib import Path

    from satsa.audit import checkpoint as cp
    from satsa.audit.keys import KeyPermissionError, load_signer
    from satsa.audit.signing import AlgorithmUnavailableError, KeyFormatError, UnknownAlgorithmError
    from satsa.store.sqlite import SQLiteStore

    if sign != bool(key):
        console.print("[bold red][!] --sign and --key go together.[/bold red]")
        raise typer.Exit(code=2)
    _chain_table(chain)
    signer = None
    if sign:
        try:
            signer = load_signer(str(key), algorithm=algorithm)
        except (KeyPermissionError, KeyFormatError, UnknownAlgorithmError, AlgorithmUnavailableError, OSError) as exc:
            console.print(f"[bold red][!] {exc}[/bold red]")
            raise typer.Exit(code=1) from None
    store = SQLiteStore(db_path)
    try:
        payload = cp.build_checkpoint(store, chain=chain)
    except cp.CheckpointError as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=1) from None
    finally:
        store.close()
    if signer is not None:
        payload = cp.sign_checkpoint(payload, signer)
    text = cp.dumps(payload)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text, encoding="utf-8")
        console.print(
            f"[bold green][+] Checkpoint written:[/bold green] {out} ({payload['entries']} entries, "
            f"{'signed' if signer else 'UNSIGNED'}). Copy it off-box."
        )
    else:
        typer.echo(text, nl=False)



def _audit_key_change(data_dir: str, action: str, key_id: str) -> None:
    import getpass

    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(Path(data_dir) / "satsa.db")
    try:
        store.append_audit(action=action, actor=f"cli:{getpass.getuser()}", details={"key_id": key_id})
    finally:
        store.close()


keys_app = typer.Typer(help="Pseudonymisation keys kept in data/secrets/ (docs/key_management.md)")
app.add_typer(keys_app, name="keys")


@keys_app.command("status")
def keys_status(data_dir: str = typer.Option("data", "--data-dir")) -> None:
    """Show the key versions (ids and dates only, never key material)."""
    from satsa.keys import status

    console.print_json(data=status(data_dir))


@keys_app.command("init")
def keys_init(
    data_dir: str = typer.Option("data", "--data-dir"),
    new_key_breaks_linkage: bool = typer.Option(
        False, "--new-key-breaks-linkage",
        help="Create a new key although existing data used a key that is lost. Pseudonyms will not link.",
    ),
) -> None:
    """Create the keyring (importing a legacy .satsa_salt if present)."""
    from satsa.keys import PseudonymKeyMissing, current_key, init_new_key_breaking_linkage

    try:
        key = current_key(data_dir)
    except PseudonymKeyMissing as exc:
        if not new_key_breaks_linkage:
            console.print(f"[bold red][!] {exc}[/bold red]")
            raise typer.Exit(code=1) from exc
        key = init_new_key_breaking_linkage(data_dir)
        _audit_key_change(data_dir, "pseudonym_key_created_breaking_linkage", key.key_id)
        console.print("[bold yellow][!] New key created: pseudonyms from now on do not match earlier ones.[/bold yellow]")
    console.print(f"Current key: {key.key_id}")


@keys_app.command("rotate")
def keys_rotate(
    data_dir: str = typer.Option("data", "--data-dir"),
    confirm: bool = typer.Option(False, "--i-understand-pseudonyms-will-not-link",
                                 help="Required: pseudonyms made after rotation differ from earlier ones."),
) -> None:
    """Add a new key version for new submissions; earlier versions are kept."""
    from satsa.keys import rotate

    if not confirm:
        console.print("[bold red]Refusing: pass --i-understand-pseudonyms-will-not-link.[/bold red]")
        raise typer.Exit(code=2)
    key = rotate(data_dir)
    _audit_key_change(data_dir, "pseudonym_key_rotated", key.key_id)
    console.print(f"Current key is now {key.key_id}. Batches record the key they used.")



@app.command("worker")
def worker_cmd(
    db_path: str = typer.Option("data/satsa.db", "--db-path"),
    data_dir: str = typer.Option("data", "--data-dir"),
    once: bool = typer.Option(False, "--once", help="Run the queued jobs, then exit"),
    lease_seconds: int = typer.Option(120, "--lease-seconds", help="How long a job stays leased without a heartbeat"),
    poll_seconds: float = typer.Option(2.0, "--poll-seconds"),
) -> None:
    """Run the local job worker: imports, assessments and demo seeding (docs/deployment_ops.md)."""
    import signal
    import threading

    from satsa.jobs.worker import Worker
    from satsa.netguard import install_egress_guard

    # Same best-effort, loopback-only egress guard as the portals (satsa.netguard).
    install_egress_guard()
    worker = Worker(db_path, data_dir, lease_seconds=lease_seconds)
    try:
        if once:
            done = worker.run_until_idle()
            for job in done:
                console.print(f"{job['job_id']} {job['kind']}: {job['state']}")
            return
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        console.print(f"[bold blue]Worker {worker.worker_id}[/bold blue] waiting for jobs (Ctrl+C stops it)")
        worker.run_forever(stop, poll_seconds)
    finally:
        worker.close()


jobs_app = typer.Typer(help="Inspect and cancel durable jobs")
app.add_typer(jobs_app, name="jobs")


@jobs_app.command("list")
def jobs_list(db_path: str = typer.Option("data/satsa.db", "--db-path"), limit: int = 20) -> None:
    """Recent jobs, newest first."""
    from satsa.jobs.queue import JobQueue
    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(db_path)
    try:
        queue = JobQueue(store)
        for job in queue.recent(limit):
            console.print(f"{job['job_id']}  {job['kind']:<10} {job['state']:<9} {job['stage'] or ''}")
        workers = queue.live_workers()
        console.print(f"Live workers: {', '.join(w['worker_id'] for w in workers) or 'none'}")
    finally:
        store.close()


@jobs_app.command("cancel")
def jobs_cancel(job_id: str, db_path: str = typer.Option("data/satsa.db", "--db-path")) -> None:
    """Cancel a queued job, or ask a running one to stop at its next stage."""
    from satsa.jobs.queue import JobQueue
    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(db_path)
    try:
        job = JobQueue(store).cancel(job_id)
    finally:
        store.close()
    if job is None:
        console.print(f"[bold red]No job {job_id}[/bold red]")
        raise typer.Exit(code=1)
    console.print(f"{job_id}: {job['state']}{' (cancel requested)' if job['cancel_requested'] else ''}")



@app.command("setup")
def setup_cmd(
    admin_username: str = typer.Option(..., "--admin-username", help="First administrator of the Admin Portal"),
    deployment_name: str = typer.Option(..., "--deployment-name"),
    timezone: str = typer.Option("Asia/Kolkata", "--timezone", help="IANA time zone name"),
    job_inputs_days: int = typer.Option(30, "--keep-job-inputs-days"),
    backups_keep: int = typer.Option(7, "--keep-backups"),
    data_dir: str = typer.Option("data", "--data-dir"),
) -> None:
    """First-run setup from the shell, instead of the Admin Portal's /setup page.

    The passphrase is read from the SATSA_SETUP_PASSPHRASE environment variable or prompted for
    (never a command-line argument, which would land in shell history). Shell access to the data
    directory stands in for the one-time token."""
    import os

    from satsa.deployment import SetupError, complete_setup
    from satsa.store.sqlite import SQLiteStore

    passphrase = os.environ.get("SATSA_SETUP_PASSPHRASE") or typer.prompt(
        "Administrator passphrase", hide_input=True, confirmation_prompt=True
    )
    store = SQLiteStore(Path(data_dir) / "satsa.db")
    try:
        complete_setup(store, data_dir, token=None, admin_username=admin_username, passphrase=passphrase,
                       confirm=passphrase, deployment_name=deployment_name, timezone=timezone,
                       job_inputs_days=job_inputs_days, backups_keep=backups_keep,
                       actor=f"cli:{admin_username}", require_token=False)
    except SetupError as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=1) from exc
    finally:
        store.close()
    console.print(f"[bold green][+] Set up. Sign in to the Admin Portal (:8000) as {admin_username}.[/bold green]")


deployment_app = typer.Typer(help="Deployment mode and settings (docs/first_run_setup.md)")
app.add_typer(deployment_app, name="deployment")


@deployment_app.command("show")
def deployment_show(data_dir: str = typer.Option("data", "--data-dir")) -> None:
    """Mode, name, time zone, retention and setup state (no secrets)."""
    from satsa.deployment import settings, setup_pending
    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(Path(data_dir) / "satsa.db")
    try:
        shown = {k: v for k, v in settings(store).items() if k != "setup_token_sha256"}
        shown["setup_pending"] = str(setup_pending(store))
    finally:
        store.close()
    console.print_json(data=shown)



credentials_app = typer.Typer(help="Service credentials for the submission API (docs/api_credentials.md)")
app.add_typer(credentials_app, name="service-credential")


@credentials_app.command("create")
def credential_create(
    name: str = typer.Option(..., "--name", help="Who or what uses it, e.g. 'CSE-01 Splunk connector'"),
    entity: list[str] = typer.Option(..., "--entity", help="An entity it may submit for (repeatable)"),
    expires_days: int = typer.Option(90, "--expires-days", help="Lifetime, 1-365 days"),
    db_path: str = typer.Option("data/satsa.db", "--db-path"),
) -> None:
    """Issue a credential. The token is printed once and cannot be shown again."""
    import getpass

    from satsa.auth.service_credentials import CredentialError, issue
    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(db_path)
    try:
        token, record = issue(store, name=name, entities=entity, expires_days=expires_days,
                              created_by=f"cli:{getpass.getuser()}")
    except CredentialError as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=1) from exc
    finally:
        store.close()
    console.print(f"Credential {record['credential_id']} ({record['name']}) for {', '.join(record['entities'])}, "
                  f"expires {record['expires_at']}.")
    console.print("Token (shown once; store it in the client's secret store):")
    print(token)


@credentials_app.command("list")
def credential_list(db_path: str = typer.Option("data/satsa.db", "--db-path")) -> None:
    """Every credential with its scope, expiry, revocation and last use (never the secret)."""
    from satsa.auth.service_credentials import listing
    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(db_path)
    try:
        console.print_json(data=listing(store))
    finally:
        store.close()


@credentials_app.command("revoke")
def credential_revoke(credential_id: str, db_path: str = typer.Option("data/satsa.db", "--db-path")) -> None:
    """Revoke a credential; it stops working on its next request."""
    import getpass

    from satsa.auth.service_credentials import revoke
    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(db_path)
    try:
        done = revoke(store, credential_id, f"cli:{getpass.getuser()}")
    finally:
        store.close()
    if not done:
        console.print(f"[bold red]No active credential {credential_id}[/bold red]")
        raise typer.Exit(code=1)
    console.print(f"Revoked {credential_id}.")



entity_app = typer.Typer(help="Retire or reinstate entities (nothing is ever erased)")
app.add_typer(entity_app, name="entity")


@entity_app.command("retire")
def entity_retire(entity_id: str, reason: str = typer.Option(..., "--reason"),
                  db_path: str = typer.Option("data/satsa.db", "--db-path")) -> None:
    """Leave an entity out of future assessments; its submissions and history are kept."""
    import getpass

    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(db_path)
    try:
        done = store.retire_entity(entity_id.strip().upper(), f"cli:{getpass.getuser()}", reason)
    finally:
        store.close()
    console.print(f"{entity_id}: {'retired' if done else 'already retired'}. The next assessment leaves it out.")


@entity_app.command("reinstate")
def entity_reinstate(entity_id: str, db_path: str = typer.Option("data/satsa.db", "--db-path")) -> None:
    """Undo a retirement: the entity is assessed again from the next run."""
    import getpass

    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(db_path)
    try:
        done = store.reinstate_entity(entity_id.strip().upper(), f"cli:{getpass.getuser()}")
    finally:
        store.close()
    if not done:
        console.print(f"[bold red]{entity_id} is not retired[/bold red]")
        raise typer.Exit(code=1)
    console.print(f"{entity_id} reinstated.")



def _backup_passphrase(encrypt: bool, confirm: bool) -> str | None:
    import os

    if not encrypt:
        return None
    return os.environ.get("SATSA_BACKUP_PASSPHRASE") or typer.prompt(
        "Backup passphrase", hide_input=True, confirmation_prompt=confirm
    )


@app.command("backup")
def backup_cmd(
    dest: str = typer.Option(..., "--dest", help="Directory to write the backup into (ideally another disk)"),
    data_dir: str = typer.Option("data", "--data-dir"),
    config_dir: str = typer.Option("config", "--config-dir"),
    encrypt: bool = typer.Option(False, "--encrypt", help="One AES-256-GCM file; passphrase from SATSA_BACKUP_PASSPHRASE or a prompt"),
    keep: int = typer.Option(0, "--keep", help="Afterwards keep only the newest N backups in --dest (0: keep all)"),
) -> None:
    """Consistent backup of databases, published data, held batches, keys and configuration (docs/backup_restore.md)."""
    from satsa.backup import BackupError, create_backup, prune_backups

    try:
        out = create_backup(data_dir, dest, config_dir=config_dir, passphrase=_backup_passphrase(encrypt, True))
    except BackupError as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[bold green][+] Backup written:[/bold green] {out}")
    if keep:
        for removed in prune_backups(dest, keep):
            console.print(f"    removed old backup {removed.name}")


@app.command("restore")
def restore_cmd(
    source: str = typer.Argument(..., help="A backup directory or .satsa-backup file"),
    target: str = typer.Option(..., "--target", help="A new, empty directory (the restored deployment root)"),
    replay: str = typer.Option("", "--replay", help="Also replay this run in the restored instance"),
) -> None:
    """Verify a backup, restore it into an empty directory, and optionally prove a run reproduces."""
    from satsa.backup import BackupError, restore_backup

    passphrase = _backup_passphrase(Path(source).is_file(), False)
    try:
        report = restore_backup(source, target, passphrase=passphrase)
    except BackupError as exc:
        console.print(f"[bold red][!] Restore refused: {exc}[/bold red]")
        raise typer.Exit(code=1) from exc
    console.print_json(data=report)
    if replay:
        from satsa.scoring.replay import replay_run
        from satsa.store.sqlite import SQLiteStore

        store = SQLiteStore(Path(target) / "data" / "satsa.db")
        try:
            result = replay_run(replay, Path(target) / "data", store)
        finally:
            store.close()
        ok = result["results_match"] and result["fingerprint_match"]
        console.print(f"Replay of {replay}: {'reproduced' if ok else 'DIFFERS'} {result['differences'] or ''}")
        if not ok:
            raise typer.Exit(code=1)


ops_app = typer.Typer(help="Readiness, retention and diagnostics (docs/deployment_ops.md)")
app.add_typer(ops_app, name="ops")


@ops_app.command("ready")
def ops_ready(data_dir: str = typer.Option("data", "--data-dir")) -> None:
    """Readiness checks; exit status 1 when not ready."""
    from satsa.ops import readiness

    report = readiness(data_dir)
    console.print_json(data=report)
    if not report["ready"]:
        raise typer.Exit(code=1)


@ops_app.command("retention")
def ops_retention(
    data_dir: str = typer.Option("data", "--data-dir"),
    backups_dir: str = typer.Option("", "--backups-dir", help="Also prune backups here to the configured number"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Apply the retention settings: old job inputs and surplus backups. Never assessment evidence."""
    import getpass

    from satsa.ops import apply_retention

    console.print_json(data=apply_retention(data_dir, backups_dir=backups_dir or None,
                                            actor=f"cli:{getpass.getuser()}", dry_run=dry_run))


@ops_app.command("diagnostics")
def ops_diagnostics(
    out: str = typer.Option(..., "--out", help="Zip file to write"),
    data_dir: str = typer.Option("data", "--data-dir"),
) -> None:
    """Write a redacted support package (no data, secrets or usernames) for review before sharing."""
    from satsa.ops import diagnostics_bundle

    console.print(f"Diagnostics package: {diagnostics_bundle(out, data_dir)} (review it before sharing)")


release_app = typer.Typer(help="Release signing and verification of offline bundles (docs/offline_install.md)")
app.add_typer(release_app, name="release")


@release_app.command("keygen")
def release_keygen(out: str = typer.Option(..., "--out", help="Directory for the key pair")) -> None:
    """Create an Ed25519 release key pair. Keep the private key offline; publish the public key."""
    from satsa.bundle.release import generate_keypair, public_key_fingerprint

    Path(out).mkdir(parents=True, exist_ok=True)
    try:
        private, public = generate_keypair(out)
    except FileExistsError as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=1) from None
    console.print(f"Private key: {private} (keep offline)")
    console.print(f"Public key: {public}")
    console.print(f"Fingerprint: {public_key_fingerprint(public.read_bytes())} (publish it out of band)")


@release_app.command("verify")
def release_verify(
    bundle: str = typer.Argument(..., help="Extracted bundle directory"),
    public_key: str | None = typer.Option(
        None, "--public-key", help="Release public key obtained separately (never the one inside the bundle)"
    ),
) -> None:
    """Check the signature, every file hash, and that no file was added or removed."""
    from satsa.bundle.release import ReleaseVerificationError, public_key_fingerprint, verify

    try:
        result = verify(bundle, public_key)
    except ReleaseVerificationError as exc:
        console.print(f"[bold red][!] Verification failed: {exc}[/bold red]")
        raise typer.Exit(code=1) from None
    console.print(f"[green]{result['files']} files match SHA256SUMS[/green]")
    if result["signature_verified"] and public_key is not None:
        console.print(f"[green]Signature valid for key {public_key_fingerprint(Path(public_key).read_bytes())}[/green]")
    else:
        console.print("[yellow]Signature not checked: pass --public-key[/yellow]")


pilot_app = typer.Typer(help="Independent pilot evaluation from blinded reviews (docs/shadow_pilot_runbook.md, Part B)")
app.add_typer(pilot_app, name="pilot")


def _pilot_account(store: Any, username: str) -> str:
    """The role of an active SAT-SA account: pilot actions are made in a named person's name."""
    row = store.conn.execute("SELECT role, status FROM identities WHERE username = ?", (username,)).fetchone()
    if row is None or (row["status"] or "ACTIVE").upper() != "ACTIVE":
        console.print(f"[bold red][!] {username!r} is not an active account[/bold red]")
        raise typer.Exit(code=1)
    return str(row["role"])


def _pilot_call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    from satsa.cases.workflow import CaseError

    try:
        return fn(*args, **kwargs)
    except CaseError as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        raise typer.Exit(code=1) from None


@pilot_app.command("freeze")
def pilot_freeze(
    name: str = typer.Option(..., "--name", help="A name for the protocol (never reused)"),
    run_id: str = typer.Option(..., "--run", help="Completed run whose configuration is frozen"),
    actor: str = typer.Option(..., "--actor", help="The analyst freezing it"),
    seed: int | None = typer.Option(None, "--seed", help="Seed of the calibration / held-out split (random if omitted)"),
    calibration: float = typer.Option(0.3, "--calibration", help="Share of entities kept for calibration"),
    budget: int = typer.Option(10, "--budget", help="Entities per arm an examiner can review (fixed budget)"),
    notes: str = typer.Option("", "--notes"),
) -> None:
    """Freeze thresholds and the entity split before any judgement is looked at."""
    from satsa.store.sqlite import SQLiteStore
    from satsa.validate import pilot

    store = SQLiteStore("data/satsa.db")
    try:
        res = _pilot_call(pilot.freeze_protocol, store, name, run_id, actor, _pilot_account(store, actor), seed=seed,
                          calibration_fraction=calibration, budget=budget, notes=notes)
    finally:
        store.close()
    console.print(f"[green]Protocol {res['protocol_id']} frozen at configuration {res['config_hash']} (seed {res['seed']})[/green]")
    console.print(f"  calibration: {', '.join(res['calibration']) or 'none'}")
    console.print(f"  held out:    {', '.join(res['held_out'])}")


@pilot_app.command("replicate")
def pilot_replicate(
    sample_id: str = typer.Option(..., "--sample", help="Blind sample to repeat"),
    assignee: str = typer.Option(..., "--assignee", help="The second, independent examiner"),
    actor: str = typer.Option(..., "--actor", help="The analyst assigning it"),
) -> None:
    """Assign a blind sample's entities to a second examiner, in a new order."""
    from satsa.store.sqlite import SQLiteStore
    from satsa.validate import pilot

    store = SQLiteStore("data/satsa.db")
    try:
        res = _pilot_call(pilot.replicate_sample, store, sample_id, assignee, actor, _pilot_account(store, actor))
    finally:
        store.close()
    console.print(f"[green]Sample {res['sample_id']} ({res['tasks']} tasks) assigned to {assignee}[/green]")


@pilot_app.command("adjudicate")
def pilot_adjudicate(
    protocol_id: str = typer.Option(..., "--protocol"),
    run_id: str = typer.Option(..., "--run"),
    entity_id: str = typer.Option(..., "--entity"),
    label: str = typer.Option(..., "--label", help="Low, Moderate, Elevated or Critical"),
    rationale: str = typer.Option(..., "--rationale"),
    actor: str = typer.Option(..., "--actor", help="An examiner who reviewed neither side"),
) -> None:
    """Settle a disagreement between the two reviewers of an entity."""
    from satsa.store.sqlite import SQLiteStore
    from satsa.validate import pilot

    store = SQLiteStore("data/satsa.db")
    try:
        res = _pilot_call(pilot.adjudicate, store, protocol_id, run_id, entity_id, label, actor,
                          _pilot_account(store, actor), rationale)
    finally:
        store.close()
    console.print(f"[green]Recorded {res['adjudication_id']}[/green]")


@pilot_app.command("evaluate")
def pilot_evaluate(
    protocol_id: str = typer.Option(..., "--protocol"),
    out: str | None = typer.Option(None, "--out", help="Write the Markdown report here"),
    json_out: str | None = typer.Option(None, "--json", help="Write the raw figures here"),
) -> None:
    """The pilot's figures under a frozen protocol; nothing unanswered is counted as negative."""
    import json as _json

    from satsa.store.sqlite import SQLiteStore
    from satsa.validate import pilot

    store = SQLiteStore("data/satsa.db")
    try:
        res = _pilot_call(pilot.evaluate, store, protocol_id)
    finally:
        store.close()
    report = pilot.evaluation_markdown(res)
    if out:
        Path(out).write_text(report, encoding="utf-8")
        console.print(f"[green]Wrote {out}[/green]")
    else:
        console.print(report)
    if json_out:
        Path(json_out).write_text(_json.dumps(res, indent=1), encoding="utf-8")


if __name__ == "__main__":
    app()
