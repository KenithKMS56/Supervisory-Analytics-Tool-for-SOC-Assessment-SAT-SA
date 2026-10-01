"""Performance benchmarking suite for SAT-SA: evaluates columnar scan and rule scaling."""

import os
import time
from typing import Any

import duckdb

from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def get_process_memory_mb() -> float:
    """Estimate current process RSS memory in MB."""
    try:
        import psutil

        process = psutil.Process(os.getpid())
        return process.memory_info().rss / (1024 * 1024)
    except ImportError:
        # Fallback if psutil not present
        return 0.0


class BenchmarkRunner:
    """Executes throughput, query latency, and memory scaling benchmarks."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir

    def run_columnar_scan_benchmark(
        self, scale_sizes: list[int] | None = None
    ) -> list[dict[str, Any]]:
        """Time ONE in-memory DuckDB aggregation query over a generated alert table.

        This is a scan figure, not an assessment time: it excludes reading Parquet, the 20 rules,
        scoring and persistence (measured end to end by scripts/benchmark_scale.py, reported in
        docs/benchmarks.md). The connection is pinned to one thread, as DuckDBStore is, so the
        figure reflects how SAT-SA actually runs DuckDB.
        """
        scale_sizes = scale_sizes or [50_000, 200_000, 500_000, 1_000_000]
        results = []

        con = duckdb.connect(":memory:")
        con.execute("PRAGMA threads=1")  # same as DuckDBStore (reproducible aggregation)
        for n in scale_sizes:
            # Generate simulated alert batch in memory
            t0 = time.perf_counter()
            con.execute(f"""
                CREATE OR REPLACE TABLE bench_alerts AS
                SELECT
                    'CSE-' || lpad(((i % 10) + 1)::varchar, 2, '0') as entity_id,
                    'ALT-' || i::varchar as alert_id,
                    'RULE-' || (i % 25)::varchar as rule_id,
                    CASE (i % 4)
                        WHEN 0 THEN 'low'
                        WHEN 1 THEN 'medium'
                        WHEN 2 THEN 'high'
                        ELSE 'critical'
                    END as severity_final,
                    TIMESTAMP '2026-01-01 00:00:00' + INTERVAL (i * 30) SECOND as created_at,
                    TIMESTAMP '2026-01-01 00:05:00' + INTERVAL (i * 30) SECOND as acknowledged_at,
                    TIMESTAMP '2026-01-01 00:25:00' + INTERVAL (i * 30) SECOND as closed_at,
                    'analyst_' || (i % 15)::varchar as closed_by,
                    CASE WHEN i % 5 = 0 THEN 'soar' ELSE 'human' END as closed_by_type,
                    CASE WHEN i % 10 = 0 THEN 'true_positive' ELSE 'false_positive' END as disposition
                FROM range({n}) t(i);
            """)
            gen_time = time.perf_counter() - t0

            # Execute typical supervisory analytical query (MTTA, MTTR, FP%, SOAR share per entity & severity)
            t_query_0 = time.perf_counter()
            _ = con.execute("""
                SELECT
                    entity_id,
                    severity_final,
                    count(*) as total_alerts,
                    quantile_cont(epoch(closed_at - created_at) / 60.0, 0.5) as median_mttr_min,
                    quantile_cont(epoch(acknowledged_at - created_at) / 60.0, 0.5) as median_mtta_min,
                    count(CASE WHEN disposition = 'false_positive' THEN 1 END) * 100.0 / count(*) as fp_rate,
                    count(CASE WHEN closed_by_type = 'soar' THEN 1 END) * 100.0 / count(*) as soar_share
                FROM bench_alerts
                GROUP BY entity_id, severity_final
                ORDER BY entity_id, severity_final;
            """).pl()
            query_time = time.perf_counter() - t_query_0
            throughput = n / max(query_time, 0.0001)

            mem_mb = get_process_memory_mb()

            results.append(
                {
                    "alert_count": n,
                    "gen_time_sec": round(gen_time, 3),
                    "query_time_sec": round(query_time, 4),
                    "throughput_rows_per_sec": round(throughput, 1),
                    "memory_rss_mb": round(mem_mb, 1),
                }
            )

        con.close()
        return results

    def run_end_to_end_assessment_benchmark(self) -> dict[str, Any]:
        """Benchmark full end-to-end supervisory assessment on existing repository data."""
        duckdb_store = DuckDBStore(self.data_dir)
        duckdb_store.load_all_tables()
        sqlite_store = SQLiteStore(f"{self.data_dir}/satsa.db")

        df_alerts = duckdb_store.query("SELECT count(*) as total FROM alert")
        alert_count = df_alerts.to_dicts()[0]["total"] if not df_alerts.is_empty() else 0

        runner = AssessmentRunner(duckdb_store, sqlite_store)
        t0 = time.perf_counter()
        res = runner.run_assessment(period="2026-Q1")
        elapsed = time.perf_counter() - t0

        mem_mb = get_process_memory_mb()
        duckdb_store.close()
        sqlite_store.close()

        throughput = alert_count / max(elapsed, 0.001)

        return {
            "dataset_alerts": alert_count,
            "total_elapsed_sec": round(elapsed, 3),
            "findings_count": res.get("findings_count", 0),
            "queue_count": res.get("queue_count", 0),
            "throughput_alerts_per_sec": round(throughput, 1),
            "memory_rss_mb": round(mem_mb, 1),
        }
