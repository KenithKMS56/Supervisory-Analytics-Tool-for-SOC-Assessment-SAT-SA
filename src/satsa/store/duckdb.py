"""DuckDB columnar storage interface for SAT-SA."""

from pathlib import Path
from typing import Any

import duckdb
import polars as pl


class DuckDBStore:
    """Manages DuckDB queries and partitioned Parquet files for analytics."""

    def __init__(self, data_dir: Path | str = "data"):
        self.data_dir = Path(data_dir)
        self.parquet_dir = self.data_dir / "parquet"
        self.parquet_dir.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(":memory:")
        # Force single-threaded execution. DuckDB's default multi-threaded
        # vectorized execution combines parallel partial aggregates (SUM/AVG
        # over floating-point columns) in a run-dependent order, which is not
        # associative in floating-point arithmetic and can flip a rule's
        # threshold comparison (e.g. share > 0.25) by a few ULPs between two
        # runs on IDENTICAL input data. That silently contradicts the
        # byte-identical reproducibility guarantee in DECISIONS.md ADR-002/
        # ADR-003, so determinism is pinned explicitly rather than left to
        # incidental single-threaded scheduling.
        self.conn.execute("PRAGMA threads=1")
        self._init_schemas()

    def _init_schemas(self) -> None:
        """Initialize empty tables and views in DuckDB."""
        # Initialize DuckDB tables for all canonical datasets
        ddl_statements = [
            """
            CREATE TABLE IF NOT EXISTS entity (
                entity_id VARCHAR PRIMARY KEY,
                name VARCHAR,
                sector VARCHAR,
                size_band VARCHAR,
                soc_model VARCHAR,
                soc_provider VARCHAR,
                timezone VARCHAR,
                declared_shift_hours VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS asset (
                entity_id VARCHAR,
                asset_id VARCHAR,
                asset_type VARCHAR,
                criticality INTEGER,
                monitored_flag BOOLEAN,
                owner_unit VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS log_source_daily (
                entity_id VARCHAR,
                asset_id VARCHAR,
                source_type VARCHAR,
                date DATE,
                event_count INTEGER
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS detection_rule (
                entity_id VARCHAR,
                rule_id VARCHAR,
                category VARCHAR,
                mitre_tactic VARCHAR,
                mitre_technique VARCHAR,
                enabled BOOLEAN,
                last_fired TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS alert (
                entity_id VARCHAR,
                alert_id VARCHAR,
                rule_id VARCHAR,
                category VARCHAR,
                severity_orig VARCHAR,
                severity_final VARCHAR,
                asset_id VARCHAR,
                created_at TIMESTAMP,
                acknowledged_at TIMESTAMP,
                first_touch_at TIMESTAMP,
                closed_at TIMESTAMP,
                closed_by VARCHAR,
                closed_by_type VARCHAR,
                playbook_id VARCHAR,
                disposition VARCHAR,
                status VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS "case" (
                entity_id VARCHAR,
                case_id VARCHAR,
                severity VARCHAR,
                status VARCHAR,
                owner VARCHAR,
                opened_at TIMESTAMP,
                closed_at TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS case_alert_link (
                entity_id VARCHAR,
                case_id VARCHAR,
                alert_id VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS workflow_event (
                entity_id VARCHAR,
                ref_type VARCHAR,
                ref_id VARCHAR,
                ts TIMESTAMP,
                actor VARCHAR,
                action VARCHAR,
                from_status VARCHAR,
                to_status VARCHAR,
                note_len INTEGER
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS escalation (
                entity_id VARCHAR,
                esc_id VARCHAR,
                ref_id VARCHAR,
                escalated_at TIMESTAMP,
                from_role VARCHAR,
                to_role VARCHAR,
                acknowledged_at TIMESTAMP,
                outcome VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS closure (
                entity_id VARCHAR,
                ref_id VARCHAR,
                reason_code VARCHAR,
                disposition VARCHAR,
                comment_norm_hash VARCHAR,
                comment_len INTEGER,
                comment_shingles VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS remediation (
                entity_id VARCHAR,
                ticket_id VARCHAR,
                linked_asset_id VARCHAR,
                linked_rule_id VARCHAR,
                type VARCHAR,
                created_at TIMESTAMP,
                closed_at TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS external_report (
                entity_id VARCHAR,
                incident_id VARCHAR,
                reported_to VARCHAR,
                reported_at TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS declared_kpi (
                entity_id VARCHAR,
                period VARCHAR,
                metric VARCHAR,
                severity VARCHAR,
                value DOUBLE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sla_policy (
                entity_id VARCHAR,
                severity VARCHAR,
                ack_minutes INTEGER,
                resolve_minutes INTEGER
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS submission_batch (
                batch_id VARCHAR PRIMARY KEY,
                entity_id VARCHAR,
                period_start TIMESTAMP,
                period_end TIMESTAMP,
                file_name VARCHAR,
                sha256 VARCHAR,
                row_counts VARCHAR
            )
            """,
        ]
        for stmt in ddl_statements:
            self.conn.execute(stmt)

    def write_partitioned_parquet(self, table_name: str, df: pl.DataFrame) -> None:
        """Write DataFrame to Parquet partitioned by entity_id where applicable."""
        if df.is_empty():
            return

        target_dir = self.parquet_dir / table_name
        target_dir.mkdir(parents=True, exist_ok=True)

        # Check if entity_id is present
        if "entity_id" in df.columns:
            entities = df["entity_id"].unique().to_list()
            for entity in entities:
                ent_df = df.filter(pl.col("entity_id") == entity)
                ent_dir = target_dir / f"entity_id={entity}"
                ent_dir.mkdir(parents=True, exist_ok=True)
                file_path = ent_dir / "data.parquet"

                # If file exists, append/combine
                if file_path.exists():
                    try:
                        existing = pl.read_parquet(file_path)
                        combined = pl.concat([existing, ent_df], how="diagonal_relaxed").unique()
                        combined.write_parquet(file_path)
                    except Exception:  # noqa: BLE001
                        ent_df.write_parquet(file_path)
                else:
                    ent_df.write_parquet(file_path)
        else:
            file_path = target_dir / "data.parquet"
            if file_path.exists():
                try:
                    existing = pl.read_parquet(file_path)
                    combined = pl.concat([existing, df], how="diagonal_relaxed").unique()
                    combined.write_parquet(file_path)
                except Exception:  # noqa: BLE001
                    df.write_parquet(file_path)
            else:
                df.write_parquet(file_path)

        # Refresh DuckDB in-memory table/view
        self.load_table_from_parquet(table_name)

    def load_table_from_parquet(self, table_name: str) -> None:
        """Load or replace in-memory DuckDB table from partitioned Parquet files."""
        target_dir = self.parquet_dir / table_name
        if not target_dir.exists():
            return

        parquet_glob = str(target_dir / "**" / "*.parquet")
        files = list(target_dir.glob("**/*.parquet"))
        if not files:
            return

        escaped_glob = parquet_glob.replace("\\", "/")
        escaped_table_name = f'"{table_name}"' if table_name == "case" else table_name
        try:
            self.conn.execute(f"DELETE FROM {escaped_table_name}")
            if table_name == "entity":
                self.conn.execute(
                    f"INSERT OR REPLACE INTO {escaped_table_name} BY NAME SELECT * FROM read_parquet('{escaped_glob}', hive_partitioning=true, union_by_name=true)"
                )
            else:
                self.conn.execute(
                    f"INSERT INTO {escaped_table_name} BY NAME SELECT * FROM read_parquet('{escaped_glob}', hive_partitioning=true, union_by_name=true)"
                )
        except duckdb.Error:
            try:
                self.conn.execute(
                    f"INSERT INTO {escaped_table_name} SELECT * FROM read_parquet('{escaped_glob}', hive_partitioning=true)"
                )
            except duckdb.Error:
                pass

    def load_all_tables(self) -> None:
        """Reload all canonical tables from disk."""
        tables = [
            "entity",
            "asset",
            "log_source_daily",
            "detection_rule",
            "alert",
            "case",
            "case_alert_link",
            "workflow_event",
            "escalation",
            "closure",
            "remediation",
            "external_report",
            "declared_kpi",
            "sla_policy",
            "submission_batch",
        ]
        for t in tables:
            self.load_table_from_parquet(t)

    def query(self, sql: str, params: list[Any] | None = None) -> pl.DataFrame:
        """Execute query and return Polars DataFrame."""
        if params:
            return self.conn.execute(sql, params).pl()
        return self.conn.execute(sql).pl()

    def execute(self, sql: str, params: list[Any] | None = None) -> None:
        """Execute raw DDL or modification statement."""
        if params:
            self.conn.execute(sql, params)
        else:
            self.conn.execute(sql)

    def close(self) -> None:
        """Close DuckDB connection."""
        self.conn.close()
