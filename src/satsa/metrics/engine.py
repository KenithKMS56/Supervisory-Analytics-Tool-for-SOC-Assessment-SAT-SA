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
        WHERE closed_at IS NOT NULL AND created_at IS NOT NULL
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

    def compute_escalation_metrics(self) -> pl.DataFrame:
        """Calculate escalation rates and unescalated Critical TP counts."""
        sql = """
        WITH alert_esc AS (
            SELECT
                a.entity_id,
                a.alert_id,
                a.severity_final,
                a.disposition,
                count(e.esc_id) as esc_count
            FROM alert a
            LEFT JOIN escalation e ON a.entity_id = e.entity_id AND a.alert_id = e.ref_id
            GROUP BY a.entity_id, a.alert_id, a.severity_final, a.disposition
        )
        SELECT
            entity_id,
            count(*) as total_alerts,
            count(CASE WHEN severity_final IN ('high', 'critical') THEN 1 END) as high_crit_count,
            count(CASE WHEN severity_final IN ('high', 'critical') AND esc_count > 0 THEN 1 END) as high_crit_escalated,
            count(CASE WHEN severity_final = 'critical' AND disposition = 'true_positive' AND esc_count = 0 THEN 1 END) as unescalated_critical_tp
        FROM alert_esc
        GROUP BY entity_id
        """
        return self.store.query(sql)

    def compute_text_hygiene_metrics(self) -> pl.DataFrame:
        """Calculate repeated comment hash share and unique comment ratio."""
        sql = """
        WITH alert_comments AS (
            SELECT
                a.entity_id,
                a.alert_id,
                a.closed_by_type,
                c.comment_norm_hash,
                c.comment_len
            FROM alert a
            JOIN closure c ON a.entity_id = c.entity_id AND a.alert_id = c.ref_id
            WHERE a.closed_by_type = 'human'
        ),
        hash_counts AS (
            SELECT
                entity_id,
                comment_norm_hash,
                count(*) as repeats
            FROM alert_comments
            GROUP BY entity_id, comment_norm_hash
        )
        SELECT
            a.entity_id,
            count(a.alert_id) as total_human_closures,
            count(DISTINCT a.comment_norm_hash) as distinct_hashes,
            count(DISTINCT a.comment_norm_hash) * 1.0 / max(count(a.alert_id), 1) as unique_hash_ratio,
            coalesce(max(h.repeats), 0) as max_hash_repeats,
            sum(CASE WHEN h.repeats >= 5 THEN 1 ELSE 0 END) * 1.0 / max(count(a.alert_id), 1) as template_reuse_share
        FROM alert_comments a
        JOIN hash_counts h ON a.entity_id = h.entity_id AND a.comment_norm_hash = h.comment_norm_hash
        GROUP BY a.entity_id
        """
        return self.store.query(sql)

    def compute_recurrence_metrics(self) -> pl.DataFrame:
        """Find repeat alerts on same (asset, rule) within 30 days without remediation."""
        sql = """
        WITH alert_pairs AS (
            SELECT
                entity_id,
                asset_id,
                rule_id,
                count(*) as pair_count,
                count(CASE WHEN disposition IN ('false_positive', 'benign') THEN 1 END) as benign_count
            FROM alert
            GROUP BY entity_id, asset_id, rule_id
        ),
        active_remediations AS (
            SELECT DISTINCT entity_id, linked_asset_id, linked_rule_id
            FROM remediation
        )
        SELECT
            p.entity_id,
            count(CASE WHEN p.pair_count >= 5 AND p.benign_count = p.pair_count AND r.linked_asset_id IS NULL THEN 1 END) as repeat_pairs_unresolved,
            sum(CASE WHEN p.pair_count >= 5 AND p.benign_count = p.pair_count AND r.linked_asset_id IS NULL THEN p.pair_count ELSE 0 END) as repeat_alert_volume
        FROM alert_pairs p
        LEFT JOIN active_remediations r ON p.entity_id = r.entity_id AND p.asset_id = r.linked_asset_id AND p.rule_id = r.linked_rule_id
        GROUP BY p.entity_id
        """
        return self.store.query(sql)

    def compute_activity_and_volume_metrics(self) -> pl.DataFrame:
        """Calculate alerts per asset per day, night-time share, and CUSUM volume signals."""
        sql = """
        SELECT
            entity_id,
            count(*) as total_alerts,
            count(DISTINCT asset_id) as active_assets,
            count(CASE WHEN extract(hour from created_at) < 8 OR extract(hour from created_at) >= 20 THEN 1 END) * 1.0 / count(*) as night_share,
            count(CASE WHEN extract(dow from created_at) IN (0, 6) THEN 1 END) * 1.0 / count(*) as weekend_share
        FROM alert
        GROUP BY entity_id
        """
        return self.store.query(sql)

    def compute_kpi_reconciliation(self) -> pl.DataFrame:
        """Compare empirical MTTA/MTTR with declared KPIs."""
        sql = """
        WITH empirical AS (
            SELECT
                entity_id,
                avg(epoch(acknowledged_at) - epoch(created_at)) / 60.0 as empirical_mtta_mins,
                avg(epoch(closed_at) - epoch(created_at)) / 60.0 as empirical_mttr_mins
            FROM alert
            WHERE severity_final = 'critical' AND closed_at IS NOT NULL
            GROUP BY entity_id
        ),
        declared AS (
            SELECT
                entity_id,
                max(CASE WHEN metric = 'MTTA' THEN value END) as declared_mtta,
                max(CASE WHEN metric = 'MTTR' THEN value END) as declared_mttr
            FROM declared_kpi
            WHERE severity = 'critical'
            GROUP BY entity_id
        )
        SELECT
            e.entity_id,
            e.empirical_mtta_mins,
            d.declared_mtta,
            e.empirical_mttr_mins,
            d.declared_mttr,
            abs(e.empirical_mttr_mins - coalesce(d.declared_mttr, e.empirical_mttr_mins)) / max(e.empirical_mttr_mins, 1.0) as mttr_gap_ratio
        FROM empirical e
        LEFT JOIN declared d ON e.entity_id = d.entity_id
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
