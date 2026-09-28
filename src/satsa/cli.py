"""CLI for SAT-SA."""

import typer
from rich.console import Console

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
) -> None:
    """Ingest datasets, execute DQ checks, pseudonymise actors, redact PII, and store partitioned Parquet."""
    from pathlib import Path

    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    console.print(f"[bold blue]Starting ingestion from:[/bold blue] [cyan]{data_dir}[/cyan]")
    duckdb_store = DuckDBStore(parquet_dir)
    sqlite_store = SQLiteStore(db_path)
    pipeline = IngestionPipeline(duckdb_store, sqlite_store)

    result = pipeline.ingest_directory(Path(data_dir))
    duckdb_store.close()
    sqlite_store.close()

    if result.get("status") == "success":
        console.print("[bold green][+] Ingestion completed successfully:[/bold green]")
        console.print(f"  * Batch ID: [cyan]{result.get('batch_id')}[/cyan]")
        console.print(
            f"  * Entities ({len(result.get('entities', []))}): [cyan]{', '.join(result.get('entities', []))}[/cyan]"
        )
        console.print(
            f"  * Data Quality Issues Detected: [yellow]{result.get('dq_issues')}[/yellow]"
        )
    else:
        console.print(f"[bold red][!] Ingestion failed/empty:[/bold red] {result.get('message')}")


@app.command("run")
def run_cmd(
    period: str = typer.Option("2026-Q1", "--period", "-p", help="Supervisory review period"),
    db_path: str = typer.Option(
        "data/satsa.db", "--db-path", help="Path to SQLite metadata database"
    ),
    parquet_dir: str = typer.Option(
        "data", "--parquet-dir", help="Root directory for Parquet storage"
    ),
) -> None:
    """Execute supervisory assessment across all entities: evaluate rules, compute risk index, rank review queue."""
    from satsa.scoring.runner import AssessmentRunner
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    console.print(
        f"[bold blue]Executing supervisory assessment for period:[/bold blue] [cyan]{period}[/cyan]"
    )
    duckdb_store = DuckDBStore(parquet_dir)
    sqlite_store = SQLiteStore(db_path)
    runner = AssessmentRunner(duckdb_store, sqlite_store)

    res = runner.run_assessment(period=period)
    duckdb_store.close()
    sqlite_store.close()

    if res.get("status") == "success":
        console.print("[bold green][+] Assessment executed successfully:[/bold green]")
        console.print(f"  * Run ID: [cyan]{res.get('run_id')}[/cyan]")
        console.print(f"  * Config Hash: [cyan]{res.get('config_hash')}[/cyan]")
        console.print(f"  * Total Findings Flagged: [yellow]{res.get('findings_count')}[/yellow]")
        console.print(f"  * Review Queue Items Generated: [cyan]{res.get('queue_count')}[/cyan]")
        console.print("\n[bold]Entity Supervisory Risk Summary:[/bold]")
        for ent, data in res.get("entity_scores", {}).items():
            color = (
                "red"
                if data["risk_index"] > 50
                else ("yellow" if data["risk_index"] > 25 else "green")
            )
            console.print(
                f"  * {ent}: [{color}]Risk Index = {data['risk_index']:.1f} ({data['risk_band']})[/{color}]"
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


@app.command("serve")
def serve_cmd(
    host: str = typer.Option(
        "127.0.0.1", "--host", "-h", help="Bind address (default local air-gapped 127.0.0.1)"
    ),
    port: int = typer.Option(8001, "--port", "-p", help="Server port (default 8001)"),
) -> None:
    """Launch local offline server-rendered UI and REST API."""
    import uvicorn

    console.print(
        f"[bold green][+] Launching SAT-SA offline dashboard at:[/bold green] [cyan]http://{host}:{port}[/cyan]"
    )
    console.print("[dim]Fully offline, air-gapped server. Press Ctrl+C to exit.[/dim]")
    uvicorn.run("satsa.api:app", host=host, port=port, log_level="info")


@app.command("admin")
def admin_cmd(
    host: str = typer.Option(
        "127.0.0.1", "--host", "-h", help="Bind address (default local air-gapped 127.0.0.1)"
    ),
    port: int = typer.Option(8000, "--port", "-p", help="NCIIPC Administration Portal port (default 8000)"),
) -> None:
    """Launch NCIIPC Administration Portal control plane."""
    import uvicorn

    console.print(
        f"[bold green][+] Launching NCIIPC Administration Portal at:[/bold green] [cyan]http://{host}:{port}[/cyan]"
    )
    console.print("[dim]Administrative identity and control console. Press Ctrl+C to exit.[/dim]")
    uvicorn.run("satsa.admin.app:app", host=host, port=port, log_level="info")


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

    from satsa.report.generator import ReportGenerator
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

    # Entity-specific or all entities HTML & PDF
    cur = sqlite_store.conn.cursor()
    cur.execute("SELECT DISTINCT entity_id FROM entity_scores")
    available_entities = [r["entity_id"] for r in cur.fetchall()]

    target_entities = available_entities if entity == "all" else [entity]

    for ent in target_entities:
        if fmt in ("html", "all"):
            h = rep_gen.generate_entity_html(ent, out_path / f"{ent}_supervisory_report.html")
            generated.append(h)
        if fmt in ("pdf", "all"):
            p = rep_gen.generate_entity_pdf(ent, out_path / f"{ent}_supervisory_report.pdf")
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
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore
    from satsa.validate.harness import ShadowPilotAdapter, ValidationHarness

    console.print(
        f"[bold blue]Running validation harness against:[/bold blue] [cyan]{ground_truth}[/cyan]"
    )
    duckdb_store = DuckDBStore(parquet_dir)
    duckdb_store.load_all_tables()
    sqlite_store = SQLiteStore(db_path)
    harness = ValidationHarness(duckdb_store, sqlite_store, ground_truth)

    results = harness.run_full_validation()
    md_file, html_file = harness.generate_report(output_md, output_html)

    # Shadow pilot check if provided
    shadow_res = None
    if shadow_csv:
        adapter = ShadowPilotAdapter(sqlite_store)
        reviews = adapter.load_manual_reviews(shadow_csv)
        shadow_res = adapter.evaluate_shadow_pilot(reviews, results["run_id"])

    duckdb_store.close()
    sqlite_store.close()

    ranking = results["entity_ranking"]
    rules = results["rule_detection"]
    lift = results["review_effort_lift"]
    stab = results["stability"]
    audit = results["audit"]

    console.print("\n[bold green][+] Validation Benchmark Results:[/bold green]")
    console.print(
        f"  * Entity Rank Precision@7: [bold cyan]{ranking.get('precision_at_k', 0) * 100:.1f}%[/bold cyan]"
    )
    console.print(
        f"  * Injected Defect Recall:  [bold cyan]{rules.get('overall_recall', 0) * 100:.1f}%[/bold cyan] ({rules.get('true_positives')}/{rules.get('total_injected_defects')})"
    )
    console.print(
        f"  * Overall Defect Precision:[bold cyan]{rules.get('overall_precision', 0) * 100:.1f}%[/bold cyan]"
    )
    console.print(
        f"  * Ranking Stability (+/-20%):[bold cyan]Spearman rho = {stab.get('spearman_rho_plus_20'):.4f}[/bold cyan]"
    )
    console.print(
        f"  * Cryptographic Audit:     [bold green]{audit.get('audit_message')}[/bold green]"
    )

    console.print("\n[bold]Review-Effort Lift Table (vs Random Sampling):[/bold]")
    for b_k, b_v in lift.get("budgets", {}).items():
        console.print(
            f"  * Budget {b_k}: [yellow]{b_v['defects_found']} defects found[/yellow] | Hit Rate = {b_v['hit_rate_top_k'] * 100:.1f}% vs {b_v['random_baseline_hit_rate'] * 100:.2f}% random | [bold green]Lift = {b_v['lift_factor']:.2f}x[/bold green]"
        )

    if shadow_res:
        console.print(f"\n[bold]Shadow Pilot Evaluation:[/bold] {shadow_res}")

    console.print("\n[bold green][+] Validation reports generated:[/bold green]")
    console.print(f"  * Markdown: [cyan]{md_file}[/cyan]")
    console.print(f"  * HTML:     [cyan]{html_file}[/cyan]")


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
    import shutil
    import tempfile
    from pathlib import Path

    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.scoring.runner import AssessmentRunner
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore
    from satsa.synth.stress import save_stress_dataset
    from satsa.validate.harness import ValidationHarness

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
        f"  * Overall Defect Precision:[bold cyan]{rules.get('overall_precision', 0) * 100:.1f}%[/bold cyan]"
    )
    console.print(f"  * False Positives: [yellow]{rules.get('false_positives')}[/yellow]")

    md_path = Path(output_md)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_lines = [
        "# SAT-SA Stress Scenario Validation Report",
        "",
        "> This is the HARDER, more realistic companion to docs/validation.md. Unlike the primary",
        "> synthetic dataset (whose injected defects clearly exceed each rule's threshold by design),",
        "> this scenario injects a borderline-threshold case, an ambiguous dual-rule case, and a",
        "> noisy true-negative case. These numbers are NOT expected to be 100%.",
        "",
        f"**Run ID:** `{res['run_id']}` | **Seed:** `{seed}`",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Entity Rank Precision@k | {ranking.get('precision_at_k', 0) * 100:.1f}% |",
        f"| Entity Rank Recall@k | {ranking.get('recall_at_k', 0) * 100:.1f}% |",
        f"| Injected Defect Recall | {rules.get('overall_recall', 0) * 100:.1f}% ({rules.get('true_positives')}/{rules.get('total_injected_defects')}) |",
        f"| Overall Defect Precision | {rules.get('overall_precision', 0) * 100:.1f}% |",
        f"| False Positives | {rules.get('false_positives')} |",
        "",
        "## Per-rule breakdown",
        "| Rule ID | TP | FN | FP |",
        "|---|---|---|---|",
    ]
    for r_code, counts in rules.get("rule_breakdown", {}).items():
        md_lines.append(f"| `{r_code}` | {counts.get('tp', 0)} | {counts.get('fn', 0)} | {counts.get('fp', 0)} |")
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    console.print(f"\n[bold green][+] Stress report written to:[/bold green] [cyan]{md_path}[/cyan]")


@app.command("offline-bundle")
def offline_bundle_cmd(
    output_dir: str = typer.Option("dist", "--output-dir", "-o", help="Output directory"),
) -> None:
    """Package SAT-SA for air-gapped installation: sources, configs, containerfiles, and scripts."""
    from satsa.bundle.packager import OfflinePackager

    console.print("[bold blue]Building SAT-SA offline deployment bundle...[/bold blue]")
    packager = OfflinePackager()
    archive = packager.create_bundle(output_tar=True)
    console.print(
        f"[bold green][+] Offline bundle successfully packaged:[/bold green] [cyan]{archive}[/cyan]"
    )
    console.print(f"  * Bundle directory: [dim]{packager.bundle_dir}[/dim]")
    console.print("  * Deployment instructions: [dim]README_OFFLINE.md inside bundle[/dim]")


@app.command("benchmark")
def benchmark_cmd(
    data_dir: str = typer.Option("data", "--data-dir", help="Data directory"),
) -> None:
    """Benchmark columnar Parquet scan throughput and assessment execution runtime."""
    from satsa.bench.benchmark import BenchmarkRunner

    console.print("[bold blue]Executing SAT-SA performance benchmark...[/bold blue]")
    bench = BenchmarkRunner(data_dir)

    console.print("\n[bold]1. Columnar Parquet Scan & Aggregation Benchmark:[/bold]")
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
        f"  * Extrapolated 5M time:  [bold yellow]{e2e['extrapolated_5m_runtime_minutes']:.1f} minutes[/bold yellow]"
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


users_app = typer.Typer(help="Manage local RBAC identities (admin, supervisor, examiner)")
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
        "examiner", "--role", "-r", help="Role: admin, supervisor, or examiner"
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
) -> None:
    """Verify the audit hash chain (each row checked with its own recorded algorithm).

    The chain alone cannot detect deletion of its newest rows; pass a checkpoint
    recorded off-box with `satsa audit head` to detect that too.
    """
    from satsa.store.sqlite import SQLiteStore

    table = _chain_table(chain)
    if (checkpoint_count is None) != (checkpoint_head is None):
        console.print("[bold red][!] --checkpoint-count and --checkpoint-head go together.[/bold red]")
        raise typer.Exit(code=2)
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


if __name__ == "__main__":
    app()
