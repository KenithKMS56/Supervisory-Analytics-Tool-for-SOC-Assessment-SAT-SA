"""SQL metrics engine running vectorized DuckDB analytics queries."""

import polars as pl

from satsa.store.duckdb import DuckDBStore


class MetricsEngine:
    """Computes operational, timing, workflow, and coverage metrics in SQL."""

    def __init__(self, duckdb_store: DuckDBStore):
        self.store = duckdb_store

    def compute_timing_metrics(self) -> pl.DataFrame:
        """Calculate p5, p50, p95 for TT-Ack, TT-First-Touch, and TT-Close by severity."""
        sql = """
        SELECT
            entity_id,
            severity_final as severity,
            closed_by_type,
            count(*) as n_alerts,
            quantile_cont(epoch(acknowledged_at) - epoch(created_at), 0.50) as mtta_p50_secs,
            quantile_cont(epoch(first_touch_at) - epoch(created_at), 0.50) as touch_p50_secs,
            quantile_cont(epoch(closed_at) - epoch(created_at), 0.05) as mttr_p5_secs,
            quantile_cont(epoch(closed_at) - epoch(created_at), 0.50) as mttr_p50_secs,
            quantile_cont(epoch(closed_at) - epoch(created_at), 0.95) as mttr_p95_secs
        FROM alert
        WHERE closed_at >= created_at
        GROUP BY entity_id, severity_final, closed_by_type
        """
        return self.store.query(sql)

    def compute_workflow_metrics(self) -> pl.DataFrame:
        """Calculate workflow events per alert and zero-event closure share."""
        sql = """
        WITH alert_events AS (
            SELECT
                a.entity_id,
                a.alert_id,
                a.severity_final,
                a.closed_by_type,
                count(w.ref_id) as event_count,
                count(CASE WHEN w.action = 'investigate' THEN 1 END) as investigate_count
            FROM alert a
            LEFT JOIN workflow_event w ON a.entity_id = w.entity_id AND w.ref_type = 'alert' AND a.alert_id = w.ref_id
            GROUP BY a.entity_id, a.alert_id, a.severity_final, a.closed_by_type
        )
        SELECT
            entity_id,
            closed_by_type,
            count(*) as total_alerts,
            avg(event_count) as avg_events_per_alert,
            count(CASE WHEN event_count <= 1 THEN 1 END) * 1.0 / count(*) as share_low_events,
            count(CASE WHEN investigate_count = 0 THEN 1 END) * 1.0 / count(*) as share_zero_investigate
        FROM alert_events
        GROUP BY entity_id, closed_by_type
        """
        return self.store.query(sql)

    def compute_metric_sweep(self) -> dict[str, dict[str, float]]:
        """
        Automated metric sweep computing ~100 distinct numeric metrics per entity.
        Returns {entity_id: {metric_name: value}}.
        """
        entity_metrics: dict[str, dict[str, float]] = {}

        # 1. Severities x dispositions x closed_by_type counts and ratios
        sql = """
        SELECT
            entity_id,
            severity_final,
            disposition,
            closed_by_type,
            count(*) as cnt,
            avg(epoch(closed_at) - epoch(created_at)) as avg_dur
        FROM alert
        GROUP BY entity_id, severity_final, disposition, closed_by_type
        """
        df = self.store.query(sql)
        for row in df.iter_rows(named=True):
            ent = row["entity_id"]
            if ent not in entity_metrics:
                entity_metrics[ent] = {}
            prefix = f"{row['severity_final']}_{row['disposition']}_{row['closed_by_type']}"
            entity_metrics[ent][f"{prefix}_count"] = float(row["cnt"])
            entity_metrics[ent][f"{prefix}_avg_dur_sec"] = float(row["avg_dur"] or 0.0)

        # 2. Hourly volume profile (24 metrics)
        sql_hours = """
        SELECT
            entity_id,
            extract(hour from created_at) as hr,
            count(*) as hr_cnt
        FROM alert
        GROUP BY entity_id, hr
        """
        df_hr = self.store.query(sql_hours)
        for row in df_hr.iter_rows(named=True):
            ent = row["entity_id"]
            hr = int(row["hr"])
            if ent not in entity_metrics:
                entity_metrics[ent] = {}
            entity_metrics[ent][f"hour_{hr:02d}_volume"] = float(row["hr_cnt"])

        # 3. Category distribution (12 categories)
        sql_cat = """
        SELECT
            entity_id,
            category,
            count(*) as cat_cnt
        FROM alert
        GROUP BY entity_id, category
        """
        df_cat = self.store.query(sql_cat)
        for row in df_cat.iter_rows(named=True):
            ent = row["entity_id"]
            cat = str(row["category"]).lower().replace(" ", "_")
            if ent not in entity_metrics:
                entity_metrics[ent] = {}
            entity_metrics[ent][f"cat_{cat}_count"] = float(row["cat_cnt"])

        return entity_metrics
