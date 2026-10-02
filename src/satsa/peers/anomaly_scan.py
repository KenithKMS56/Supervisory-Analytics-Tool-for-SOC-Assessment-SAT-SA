"""Exploratory anomaly scan: indicators no rule was written for.

The 20 rules test conditions someone anticipated. The problem statement also asks for
"previously unknown indicators", so this scan computes a fixed catalogue of operational rates
for every entity (`METRICS` below) and flags two kinds of signal:

* **peer outlier**: a rate at least `z_threshold` robust standard deviations from the entity's
  peer cohort (the cohort the rules use, the entity itself excluded). The robust z is
  (value - peer median) / max(1.4826 * peer MAD, the metric's spread floor), the same estimator
  as `Rule.robust_z`. Durations and per-unit counts are compared on a log10 scale.
* **time shift**: a sustained change inside the entity's own submission. The first
  `reference_months` months set the entity's own baseline (median and spread) and a two-sided
  CUSUM (`SPCDetector.cusum`) tests every later month against it. No peer is involved. A
  change that starts inside the reference months is not seen by this test (the peer scan
  still compares the period as a whole).

Signals are leads, not findings. Unlike the rules they were not built against a known defect,
so they carry no severity, do not enter the risk index and do not reach the review queue. Each
says which rule, if any, already tests something close (`related_rule`). Every value the scan
computed is returned (`metric_values`) so a signal can be re-derived from stored numbers.

Everything is deterministic: fixed SQL, classical statistics, sorted output.
"""

from __future__ import annotations

import hashlib
import math
from calendar import monthrange
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from satsa.models.canonical import Entity
from satsa.peers.grouping import PeerResolver
from satsa.peers.robust_stats import RobustStats
from satsa.peers.spc import SPCDetector
from satsa.store.duckdb import DuckDBStore

# Scales a metric is compared on. "share" is a 0-1 proportion; "duration" is seconds and
# "per_unit" a non-negative rate, both compared as log10(value + 1).
SHARE, DURATION, PER_UNIT = "share", "duration", "per_unit"


@dataclass(frozen=True)
class Metric:
    key: str
    label: str
    domain: str
    scale: str
    # Smallest spread the robust z divides by, on the comparison scale: 0.05 is five
    # percentage points for a share; 0.15 on log10 is about a 1.4x ratio.
    min_spread: float
    # Canonical tables the metric reads (an entity that never submitted one is not compared).
    tables: tuple[str, ...] = ("alert",)
    related_rule: str | None = None


METRICS: dict[str, Metric] = {
    m.key: m
    for m in [
        # Disposition and severity mix
        Metric("tp_share", "Share of alerts closed as true positive", "Threat Detection", SHARE, 0.03, related_rule="EG11"),
        Metric("unknown_disposition_share", "Share of alerts with no recorded disposition", "Governance and Oversight", SHARE, 0.05),
        Metric("critical_high_share", "Share of alerts rated high or critical", "Threat Detection", SHARE, 0.05),
        Metric("downgrade_share", "Share of alerts whose severity was lowered during triage", "Investigation", SHARE, 0.03),
        Metric("automation_share", "Share of alerts closed by automation", "Security Operations", SHARE, 0.05),
        Metric("unacknowledged_closed_share", "Share of closed alerts never acknowledged", "Investigation", SHARE, 0.03),
        Metric("open_share", "Share of alerts still open at the end of the period", "Incident Response", SHARE, 0.03, related_rule="EG09"),
        # When work happens
        Metric("night_share", "Share of alerts raised at night (20:00-08:00)", "Security Operations", SHARE, 0.05, related_rule="NS03"),
        Metric("weekend_share", "Share of alerts raised at weekends", "Security Operations", SHARE, 0.04),
        # Speed
        Metric("ack_median_hc", "Median time to acknowledge high/critical alerts", "Investigation", DURATION, 0.15),
        Metric("close_median_hc", "Median time to close high/critical alerts (human)", "Investigation", DURATION, 0.15, related_rule="EG01"),
        Metric("close_median_lm", "Median time to close low/medium alerts (human)", "Investigation", DURATION, 0.15),
        Metric("sla_breach_share_hc", "Share of high/critical alerts closed after the SLA resolve time", "Incident Response", SHARE, 0.05, ("alert", "sla_policy"), "EG06"),
        # Depth of investigation
        Metric("events_per_alert", "Workflow events recorded per alert", "Investigation", PER_UNIT, 0.1, ("alert", "workflow_event")),
        Metric("no_investigate_share_human", "Share of human-closed alerts with no investigate step", "Investigation", SHARE, 0.05, ("alert", "workflow_event"), "EG02"),
        Metric("comment_distinct_ratio", "Distinct closure comments per closure", "Operational Discipline", SHARE, 0.05, ("closure",), "EG04"),
        Metric("comment_len_median", "Median closure comment length (characters)", "Investigation", PER_UNIT, 0.1, ("closure",)),
        # Escalation and incident handling
        Metric("escalation_per_tp", "Escalated alerts per true-positive alert", "Escalation", PER_UNIT, 0.05, ("alert", "escalation"), "EG03"),
        Metric("esc_ack_median", "Median time for Tier-2 to acknowledge an escalation", "Escalation", DURATION, 0.15, ("escalation",), "EG08"),
        Metric("tp_case_link_share", "Share of true-positive alerts linked to a case", "Incident Response", SHARE, 0.05, ("alert", "case_alert_link"), "NS04"),
        Metric("case_close_median_crit", "Median time to close a critical case", "Incident Response", DURATION, 0.15, ("case",)),
        # People
        Metric("top_analyst_share", "Share of human closures made by the busiest analyst", "Operational Discipline", SHARE, 0.05, related_rule="EG07"),
        Metric("analysts_per_1k", "Distinct closing analysts per 1,000 human closures", "Operational Discipline", PER_UNIT, 0.1),
        # Coverage and resilience
        Metric("alerts_per_monitored_asset", "Alerts per monitored asset", "Threat Detection", PER_UNIT, 0.15, ("alert", "asset")),
        Metric("monitored_asset_alert_share", "Share of monitored assets with at least one alert", "Cyber Resilience", SHARE, 0.05, ("alert", "asset"), "NS06"),
        Metric("critical_unmonitored_share", "Share of critical assets (criticality 3-4) not monitored", "Cyber Resilience", SHARE, 0.05, ("asset",)),
        Metric("log_day_coverage", "Share of monitored asset-days with log events", "Cyber Resilience", SHARE, 0.03, ("asset", "log_source_daily"), "NS01"),
        Metric("remediation_per_1k", "Remediation tickets per 1,000 alerts", "Cyber Resilience", PER_UNIT, 0.15, ("alert", "remediation"), "EG05"),
        # Detection content
        Metric("rule_mitre_mapped_share", "Share of enabled detection rules mapped to a MITRE technique", "Threat Detection", SHARE, 0.05, ("detection_rule",)),
        Metric("rule_disabled_share", "Share of detection rules disabled", "Threat Detection", SHARE, 0.05, ("detection_rule",)),
        Metric("playbook_share", "Share of alerts handled with a playbook", "Security Operations", SHARE, 0.05),
    ]
}
# Category mix is added per category present in the portfolio: "category_share:<name>".
CATEGORY_PREFIX = "category_share:"

# Monthly series tested for time shifts: metric -> (label, scale, minimum spread).
MONTHLY: dict[str, tuple[str, str, float]] = {
    "alerts_per_day": ("Alerts per day", PER_UNIT, 0.1),
    "tp_share": ("Share of alerts closed as true positive", SHARE, 0.03),
    "automation_share": ("Share of alerts closed by automation", SHARE, 0.05),
    "night_share": ("Share of alerts raised at night (20:00-08:00)", SHARE, 0.05),
    "close_median_hc": ("Median time to close high/critical alerts (human)", DURATION, 0.15),
}
MONTHLY_DOMAIN = {
    "alerts_per_day": "Threat Detection",
    "tp_share": "Threat Detection",
    "automation_share": "Security Operations",
    "night_share": "Security Operations",
    "close_median_hc": "Investigation",
}

_SEV_RANK = (
    "CASE lower({col}) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
    "WHEN 'low' THEN 1 ELSE 0 END"
)
_HC = "lower(a.severity_final) IN ('high', 'critical')"
_SECS = "epoch(a.closed_at) - epoch(a.created_at)"

# One query per source; each returns entity_id plus metric columns and their populations
# (column "<metric>" and "<metric>__n").
_QUERIES: list[str] = [
    f"""
    SELECT a.entity_id,
        avg(CASE WHEN a.disposition = 'true_positive' THEN 1.0 ELSE 0.0 END) AS tp_share,
        count(*) AS tp_share__n,
        avg(CASE WHEN a.disposition IS NULL OR a.disposition = 'unknown' THEN 1.0 ELSE 0.0 END) AS unknown_disposition_share,
        count(*) AS unknown_disposition_share__n,
        avg(CASE WHEN {_HC} THEN 1.0 ELSE 0.0 END) AS critical_high_share,
        count(*) AS critical_high_share__n,
        avg(CASE WHEN {_SEV_RANK.format(col="a.severity_final")} < {_SEV_RANK.format(col="a.severity_orig")}
                 THEN 1.0 ELSE 0.0 END) AS downgrade_share,
        count(*) AS downgrade_share__n,
        avg(CASE WHEN a.closed_by_type = 'automation' THEN 1.0 ELSE 0.0 END) AS automation_share,
        count(*) AS automation_share__n,
        avg(CASE WHEN a.acknowledged_at IS NULL THEN 1.0 ELSE 0.0 END) FILTER (WHERE a.closed_at IS NOT NULL)
            AS unacknowledged_closed_share,
        count(*) FILTER (WHERE a.closed_at IS NOT NULL) AS unacknowledged_closed_share__n,
        avg(CASE WHEN a.closed_at IS NULL OR a.status = 'open' THEN 1.0 ELSE 0.0 END) AS open_share,
        count(*) AS open_share__n,
        avg(CASE WHEN extract(hour FROM a.created_at) >= 20 OR extract(hour FROM a.created_at) < 8
                 THEN 1.0 ELSE 0.0 END) AS night_share,
        count(*) AS night_share__n,
        avg(CASE WHEN dayofweek(a.created_at) IN (0, 6) THEN 1.0 ELSE 0.0 END) AS weekend_share,
        count(*) AS weekend_share__n,
        avg(CASE WHEN a.playbook_id IS NOT NULL AND a.playbook_id <> '' THEN 1.0 ELSE 0.0 END) AS playbook_share,
        count(*) AS playbook_share__n,
        quantile_cont(epoch(a.acknowledged_at) - epoch(a.created_at), 0.5)
            FILTER (WHERE {_HC} AND a.acknowledged_at >= a.created_at) AS ack_median_hc,
        count(*) FILTER (WHERE {_HC} AND a.acknowledged_at >= a.created_at) AS ack_median_hc__n,
        quantile_cont({_SECS}, 0.5)
            FILTER (WHERE {_HC} AND a.closed_by_type = 'human' AND a.closed_at >= a.created_at) AS close_median_hc,
        count(*) FILTER (WHERE {_HC} AND a.closed_by_type = 'human' AND a.closed_at >= a.created_at) AS close_median_hc__n,
        quantile_cont({_SECS}, 0.5)
            FILTER (WHERE NOT {_HC} AND a.closed_by_type = 'human' AND a.closed_at >= a.created_at) AS close_median_lm,
        count(*) FILTER (WHERE NOT {_HC} AND a.closed_by_type = 'human' AND a.closed_at >= a.created_at)
            AS close_median_lm__n
    FROM alert a
    GROUP BY a.entity_id
    """,
    f"""
    SELECT a.entity_id,
        avg(CASE WHEN {_SECS} > s.resolve_minutes * 60 THEN 1.0 ELSE 0.0 END) AS sla_breach_share_hc,
        count(*) AS sla_breach_share_hc__n
    FROM alert a
    JOIN sla_policy s ON s.entity_id = a.entity_id AND lower(s.severity) = lower(a.severity_final)
    WHERE {_HC} AND a.closed_at >= a.created_at
    GROUP BY a.entity_id
    """,
    """
    WITH ev AS (
        SELECT entity_id, ref_id,
            count(*) AS n_events,
            count(*) FILTER (WHERE action = 'investigate') AS n_investigate
        FROM workflow_event WHERE ref_type = 'alert'
        GROUP BY entity_id, ref_id
    )
    SELECT a.entity_id,
        avg(coalesce(ev.n_events, 0)) AS events_per_alert,
        count(*) AS events_per_alert__n,
        avg(CASE WHEN coalesce(ev.n_investigate, 0) = 0 THEN 1.0 ELSE 0.0 END)
            FILTER (WHERE a.closed_by_type = 'human' AND a.closed_at IS NOT NULL) AS no_investigate_share_human,
        count(*) FILTER (WHERE a.closed_by_type = 'human' AND a.closed_at IS NOT NULL) AS no_investigate_share_human__n
    FROM alert a
    LEFT JOIN ev ON ev.entity_id = a.entity_id AND ev.ref_id = a.alert_id
    GROUP BY a.entity_id
    """,
    """
    SELECT entity_id,
        count(DISTINCT comment_norm_hash) * 1.0 / count(*) AS comment_distinct_ratio,
        count(*) AS comment_distinct_ratio__n,
        quantile_cont(comment_len, 0.5) AS comment_len_median,
        count(*) AS comment_len_median__n
    FROM closure
    GROUP BY entity_id
    """,
    """
    WITH tp AS (
        SELECT entity_id, alert_id FROM alert WHERE disposition = 'true_positive'
    ), esc AS (
        SELECT DISTINCT entity_id, ref_id FROM escalation
    ), lnk AS (
        SELECT DISTINCT entity_id, alert_id FROM case_alert_link
    )
    SELECT tp.entity_id,
        count(esc.ref_id) * 1.0 / count(*) AS escalation_per_tp,
        count(*) AS escalation_per_tp__n,
        avg(CASE WHEN lnk.alert_id IS NOT NULL THEN 1.0 ELSE 0.0 END) AS tp_case_link_share,
        count(*) AS tp_case_link_share__n
    FROM tp
    LEFT JOIN esc ON esc.entity_id = tp.entity_id AND esc.ref_id = tp.alert_id
    LEFT JOIN lnk ON lnk.entity_id = tp.entity_id AND lnk.alert_id = tp.alert_id
    GROUP BY tp.entity_id
    """,
    """
    SELECT entity_id,
        quantile_cont(epoch(acknowledged_at) - epoch(escalated_at), 0.5) AS esc_ack_median,
        count(*) AS esc_ack_median__n
    FROM escalation
    WHERE acknowledged_at >= escalated_at
    GROUP BY entity_id
    """,
    """
    SELECT entity_id,
        quantile_cont(epoch(closed_at) - epoch(opened_at), 0.5) AS case_close_median_crit,
        count(*) AS case_close_median_crit__n
    FROM "case"
    WHERE lower(severity) = 'critical' AND closed_at >= opened_at
    GROUP BY entity_id
    """,
    """
    WITH per AS (
        SELECT entity_id, closed_by, count(*) AS n
        FROM alert
        WHERE closed_by_type = 'human' AND closed_at IS NOT NULL AND closed_by IS NOT NULL
        GROUP BY entity_id, closed_by
    )
    SELECT entity_id,
        max(n) * 1.0 / sum(n) AS top_analyst_share,
        sum(n) AS top_analyst_share__n,
        count(*) * 1000.0 / sum(n) AS analysts_per_1k,
        sum(n) AS analysts_per_1k__n
    FROM per
    GROUP BY entity_id
    """,
    """
    WITH mon AS (
        SELECT entity_id, asset_id FROM asset WHERE monitored_flag
    ), hit AS (
        SELECT DISTINCT entity_id, asset_id FROM alert
    ), vol AS (
        SELECT entity_id, count(*) AS n_alerts FROM alert GROUP BY entity_id
    )
    SELECT mon.entity_id,
        max(coalesce(vol.n_alerts, 0)) * 1.0 / count(*) AS alerts_per_monitored_asset,
        count(*) AS alerts_per_monitored_asset__n,
        avg(CASE WHEN hit.asset_id IS NOT NULL THEN 1.0 ELSE 0.0 END) AS monitored_asset_alert_share,
        count(*) AS monitored_asset_alert_share__n
    FROM mon
    LEFT JOIN hit ON hit.entity_id = mon.entity_id AND hit.asset_id = mon.asset_id
    LEFT JOIN vol ON vol.entity_id = mon.entity_id
    GROUP BY mon.entity_id
    """,
    """
    SELECT entity_id,
        avg(CASE WHEN NOT monitored_flag THEN 1.0 ELSE 0.0 END) AS critical_unmonitored_share,
        count(*) AS critical_unmonitored_share__n
    FROM asset
    WHERE criticality >= 3
    GROUP BY entity_id
    """,
    """
    WITH days AS (
        SELECT entity_id, count(DISTINCT date) AS n_days FROM log_source_daily GROUP BY entity_id
    ), active AS (
        SELECT l.entity_id, count(DISTINCT (l.asset_id, l.date)) AS n_active
        FROM log_source_daily l
        JOIN asset s ON s.entity_id = l.entity_id AND s.asset_id = l.asset_id AND s.monitored_flag
        WHERE l.event_count > 0
        GROUP BY l.entity_id
    ), mon AS (
        SELECT entity_id, count(*) AS n_assets FROM asset WHERE monitored_flag GROUP BY entity_id
    )
    SELECT mon.entity_id,
        least(1.0, coalesce(active.n_active, 0) * 1.0 / (mon.n_assets * days.n_days)) AS log_day_coverage,
        mon.n_assets * days.n_days AS log_day_coverage__n
    FROM mon
    JOIN days ON days.entity_id = mon.entity_id
    LEFT JOIN active ON active.entity_id = mon.entity_id
    """,
    """
    WITH rem AS (SELECT entity_id, count(*) AS n FROM remediation GROUP BY entity_id)
    SELECT a.entity_id,
        max(coalesce(rem.n, 0)) * 1000.0 / count(*) AS remediation_per_1k,
        count(*) AS remediation_per_1k__n
    FROM alert a
    LEFT JOIN rem ON rem.entity_id = a.entity_id
    GROUP BY a.entity_id
    """,
    """
    SELECT entity_id,
        avg(CASE WHEN mitre_technique IS NOT NULL AND mitre_technique <> '' THEN 1.0 ELSE 0.0 END)
            FILTER (WHERE enabled) AS rule_mitre_mapped_share,
        count(*) FILTER (WHERE enabled) AS rule_mitre_mapped_share__n,
        avg(CASE WHEN NOT enabled THEN 1.0 ELSE 0.0 END) AS rule_disabled_share,
        count(*) AS rule_disabled_share__n
    FROM detection_rule
    GROUP BY entity_id
    """,
]

_CATEGORY_SQL = """
SELECT entity_id, category, count(*) AS n FROM alert WHERE category IS NOT NULL GROUP BY entity_id, category
"""

_MONTHLY_SQL = f"""
SELECT a.entity_id,
    strftime(a.created_at, '%Y-%m') AS month,
    count(*) AS n,
    avg(CASE WHEN a.disposition = 'true_positive' THEN 1.0 ELSE 0.0 END) AS tp_share,
    avg(CASE WHEN a.closed_by_type = 'automation' THEN 1.0 ELSE 0.0 END) AS automation_share,
    avg(CASE WHEN extract(hour FROM a.created_at) >= 20 OR extract(hour FROM a.created_at) < 8
             THEN 1.0 ELSE 0.0 END) AS night_share,
    quantile_cont({_SECS}, 0.5)
        FILTER (WHERE {_HC} AND a.closed_by_type = 'human' AND a.closed_at >= a.created_at) AS close_median_hc,
    count(*) FILTER (WHERE {_HC} AND a.closed_by_type = 'human' AND a.closed_at >= a.created_at)
        AS close_median_hc__n
FROM alert a
WHERE a.created_at IS NOT NULL
GROUP BY a.entity_id, month
"""

_SPAN_SQL = """
SELECT entity_id, min(created_at) AS first_at, max(created_at) AS last_at
FROM alert WHERE created_at IS NOT NULL GROUP BY entity_id
"""


@dataclass
class AnomalySignal:
    signal_id: str
    run_id: str
    entity_id: str
    kind: str  # peer_outlier | time_shift
    metric: str
    label: str
    domain: str
    value: float
    baseline: float
    z: float
    direction: str  # above | below
    n: int
    rationale: str
    related_rule: str | None = None
    cohort: str | None = None
    n_peers: int = 0
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "run_id": self.run_id,
            "entity_id": self.entity_id,
            "kind": self.kind,
            "metric": self.metric,
            "label": self.label,
            "domain": self.domain,
            "value": self.value,
            "baseline": self.baseline,
            "z": self.z,
            "direction": self.direction,
            "n": self.n,
            "rationale": self.rationale,
            "related_rule": self.related_rule,
            "cohort": self.cohort,
            "n_peers": self.n_peers,
            "detail": self.detail,
        }


def _on_scale(value: float, scale: str) -> float:
    return value if scale == SHARE else math.log10(max(value, 0.0) + 1.0)


def format_value(value: float, scale: str) -> str:
    """Human-readable value for rationale text and the UI."""
    if scale == SHARE:
        return f"{value * 100:.1f}%"
    if scale == DURATION:
        secs = max(value, 0.0)
        if secs < 120:
            return f"{secs:.0f} s"
        if secs < 7200:
            return f"{secs / 60:.0f} min"
        if secs < 172800:
            return f"{secs / 3600:.1f} h"
        return f"{secs / 86400:.1f} days"
    return f"{value:.2f}" if value < 100 else f"{value:.0f}"


def _metric_for(key: str) -> Metric:
    if key.startswith(CATEGORY_PREFIX):
        cat = key[len(CATEGORY_PREFIX):]
        return Metric(key, f"Share of alerts in category '{cat}'", "Threat Detection", SHARE, 0.05, related_rule="NS02")
    return METRICS[key]


def _signal_id(run_id: str, entity_id: str, kind: str, metric: str) -> str:
    digest = hashlib.sha256(f"{run_id}|{entity_id}|{kind}|{metric}".encode()).hexdigest()[:12]
    return f"ANOM-{entity_id}-{digest}"


class AnomalyScanner:
    """Computes the metric catalogue and flags peer outliers and time shifts."""

    def __init__(self, config_path: Path | str = "config/anomaly.yaml"):
        self.config_path = Path(config_path)
        cfg: dict[str, Any] = {}
        if self.config_path.exists():
            with open(self.config_path, encoding="utf-8") as f:
                cfg = (yaml.safe_load(f) or {}).get("anomaly_scan", {}) or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.z_threshold = float(cfg.get("z_threshold", 3.5))
        self.min_peers = int(cfg.get("min_peers", 3))
        self.min_population = int(cfg.get("min_population", 30))
        self.max_signals = int(cfg.get("max_signals_per_entity", 10))
        ts = cfg.get("time_shift", {}) or {}
        self.time_shift_enabled = bool(ts.get("enabled", True))
        self.reference_months = max(2, int(ts.get("reference_months", 3)))
        self.min_months = max(self.reference_months + 2, int(ts.get("min_months", 5)))
        self.min_month_population = int(ts.get("min_month_population", 20))
        self.cusum_k = float(ts.get("cusum_k", 0.5))
        self.cusum_h = float(ts.get("cusum_h", 4.0))

    @property
    def config_hash(self) -> str:
        if not self.config_path.exists():
            return "default"
        return hashlib.sha256(self.config_path.read_bytes()).hexdigest()[:16]

    # --- metric computation -------------------------------------------------------------

    def compute_metrics(
        self, store: DuckDBStore, submitted: dict[str, set[str]] | None = None
    ) -> dict[str, dict[str, tuple[float, int]]]:
        """entity_id -> metric -> (value, population). Metrics reading a table the entity
        never submitted (per its submission manifest) are left out, as the rules do."""
        values: dict[str, dict[str, tuple[float, int]]] = {}
        for sql in _QUERIES:
            df = store.query(sql)
            for row in df.iter_rows(named=True):
                ent = row["entity_id"]
                for col, val in row.items():
                    if col == "entity_id" or col.endswith("__n") or val is None:
                        continue
                    n = int(row.get(f"{col}__n") or 0)
                    if isinstance(val, float) and not math.isfinite(val):
                        continue
                    values.setdefault(ent, {})[col] = (float(val), n)

        # Category mix: a category any entity reports is a share (possibly 0) for every entity.
        cat_df = store.query(_CATEGORY_SQL)
        totals: dict[str, int] = {}
        counts: dict[tuple[str, str], int] = {}
        for row in cat_df.iter_rows(named=True):
            totals[row["entity_id"]] = totals.get(row["entity_id"], 0) + int(row["n"])
            counts[(row["entity_id"], str(row["category"]))] = int(row["n"])
        categories = sorted({cat for _, cat in counts})
        for ent, total in totals.items():
            for cat in categories:
                values.setdefault(ent, {})[f"{CATEGORY_PREFIX}{cat}"] = (counts.get((ent, cat), 0) / total, total)

        if submitted:
            for ent, metrics in values.items():
                manifest = submitted.get(ent)
                if manifest is None:
                    continue
                for key in list(metrics):
                    if any(t not in manifest for t in _metric_for(key).tables):
                        del metrics[key]
        return values

    def compute_monthly(self, store: DuckDBStore) -> dict[str, dict[str, list[tuple[str, float, int]]]]:
        """entity_id -> metric -> [(month, value, population)] in month order.

        Alerts per day divides by the days of the month the entity's submission covers, so a
        part month at either end of the period is not read as a drop in volume.
        """
        spans: dict[str, tuple[date, date]] = {}
        for row in store.query(_SPAN_SQL).iter_rows(named=True):
            first, last = row["first_at"], row["last_at"]
            if isinstance(first, datetime) and isinstance(last, datetime):
                spans[row["entity_id"]] = (first.date(), last.date())

        series: dict[str, dict[str, list[tuple[str, float, int]]]] = {}
        df = store.query(_MONTHLY_SQL)
        for row in sorted(df.iter_rows(named=True), key=lambda r: (r["entity_id"], r["month"])):
            ent, month, n = row["entity_id"], row["month"], int(row["n"])
            out = series.setdefault(ent, {})
            span = spans.get(ent)
            if span:
                year, mon = (int(p) for p in month.split("-"))
                start = max(date(year, mon, 1), span[0])
                end = min(date(year, mon, monthrange(year, mon)[1]), span[1])
                days = (end - start).days + 1
                if days > 0:
                    out.setdefault("alerts_per_day", []).append((month, n / days, n))
            if n >= self.min_month_population:
                for key in ("tp_share", "automation_share", "night_share"):
                    if row[key] is not None:
                        out.setdefault(key, []).append((month, float(row[key]), n))
            n_close = int(row.get("close_median_hc__n") or 0)
            if row["close_median_hc"] is not None and n_close >= self.min_month_population:
                out.setdefault("close_median_hc", []).append((month, float(row["close_median_hc"]), n_close))
        return series

    # --- detection ----------------------------------------------------------------------

    def scan(
        self,
        run_id: str,
        entities: list[Entity],
        store: DuckDBStore,
        peer_resolver: PeerResolver,
        submitted: dict[str, set[str]] | None = None,
    ) -> dict[str, Any]:
        """Run both scans. Returns {"signals": [...], "metric_values": [...], "suppressed": {...}}."""
        if not self.enabled:
            return {"signals": [], "metric_values": [], "suppressed": {}}

        values = self.compute_metrics(store, submitted)
        monthly = self.compute_monthly(store) if self.time_shift_enabled else {}

        metric_rows: list[dict[str, Any]] = []
        for ent in sorted(values):
            for key in sorted(values[ent]):
                val, n = values[ent][key]
                metric_rows.append({"entity_id": ent, "period": "run", "metric": key, "value": val, "n": n})
        for ent in sorted(monthly):
            for key in sorted(monthly[ent]):
                for month, val, n in monthly[ent][key]:
                    metric_rows.append({"entity_id": ent, "period": month, "metric": f"monthly:{key}", "value": val, "n": n})

        by_entity: dict[str, list[AnomalySignal]] = {}
        for entity in sorted(entities, key=lambda e: e.entity_id):
            ent_id = entity.entity_id
            peers, cohort, _weak = peer_resolver.resolve_peers(entity, entities)
            found = self._peer_outliers(run_id, ent_id, peers, cohort, values)
            found += self._time_shifts(run_id, ent_id, monthly.get(ent_id, {}))
            by_entity[ent_id] = found

        signals: list[AnomalySignal] = []
        suppressed: dict[str, int] = {}
        for ent_id, found in by_entity.items():
            found.sort(key=lambda s: (-abs(s.z), s.kind, s.metric))
            signals.extend(found[: self.max_signals])
            if len(found) > self.max_signals:
                suppressed[ent_id] = len(found) - self.max_signals
        return {
            "signals": [s.as_dict() for s in signals],
            "metric_values": metric_rows,
            "suppressed": suppressed,
        }

    def _peer_outliers(
        self,
        run_id: str,
        ent_id: str,
        peers: list[str],
        cohort: str,
        values: dict[str, dict[str, tuple[float, int]]],
    ) -> list[AnomalySignal]:
        out: list[AnomalySignal] = []
        own = values.get(ent_id, {})
        for key in sorted(own):
            val, n = own[key]
            if n < self.min_population:
                continue
            metric = _metric_for(key)
            peer_vals = [
                values[p][key][0]
                for p in peers
                if key in values.get(p, {}) and values[p][key][1] >= self.min_population
            ]
            if len(peer_vals) < self.min_peers:
                continue
            scaled_peers = [_on_scale(v, metric.scale) for v in peer_vals]
            median = RobustStats.median(scaled_peers)
            spread = max(1.4826 * RobustStats.mad(scaled_peers), metric.min_spread)
            z = (_on_scale(val, metric.scale) - median) / spread
            if abs(z) < self.z_threshold:
                continue
            baseline = RobustStats.median(peer_vals)
            direction = "above" if z > 0 else "below"
            related = (
                f" {metric.related_rule} tests a related condition; check whether it fired."
                if metric.related_rule
                else " No rule tests this directly."
            )
            rationale = (
                f"{metric.label} is {format_value(val, metric.scale)} at {ent_id} against a peer median of "
                f"{format_value(baseline, metric.scale)} across {len(peer_vals)} peers ({cohort}): "
                f"{abs(z):.1f} robust standard deviations {direction} the cohort, on {n} records."
                f"{related} This is a lead, not a finding: ask the entity what explains the difference."
            )
            out.append(
                AnomalySignal(
                    signal_id=_signal_id(run_id, ent_id, "peer_outlier", key),
                    run_id=run_id,
                    entity_id=ent_id,
                    kind="peer_outlier",
                    metric=key,
                    label=metric.label,
                    domain=metric.domain,
                    value=val,
                    baseline=baseline,
                    z=round(z, 3),
                    direction=direction,
                    n=n,
                    rationale=rationale,
                    related_rule=metric.related_rule,
                    cohort=cohort,
                    n_peers=len(peer_vals),
                    detail={
                        "scale": metric.scale,
                        "peer_values": {p: values[p][key][0] for p in sorted(peers) if key in values.get(p, {})},
                        "spread_floor": metric.min_spread,
                        "z_threshold": self.z_threshold,
                    },
                )
            )
        return out

    def _time_shifts(
        self, run_id: str, ent_id: str, series: dict[str, list[tuple[str, float, int]]]
    ) -> list[AnomalySignal]:
        out: list[AnomalySignal] = []
        for key in sorted(series):
            points = series[key]
            if len(points) < self.min_months:
                continue
            label, scale, floor = MONTHLY[key]
            ref = self.reference_months
            scaled = [_on_scale(v, scale) for _, v, _ in points]
            s_high, s_low, alarms = SPCDetector.cusum(
                scaled[ref:],
                slack_k=self.cusum_k,
                threshold_h=self.cusum_h,
                min_scale=floor,
                reference=scaled[:ref],
            )
            if not alarms:
                continue
            first = alarms[0]
            upward = s_high[first] > self.cusum_h
            chart = s_high if upward else s_low
            # The shift starts after the chart last stood at zero before the alarm.
            start = first
            while start > 0 and chart[start - 1] > 0:
                start -= 1
            stat = chart[first]
            first, start = first + ref, start + ref  # positions in the full series
            before = [v for _, v, _ in points[:ref]]
            after = [v for _, v, _ in points[start:]]
            baseline = RobustStats.median(before)
            value = RobustStats.median(after)
            months = [m for m, _, _ in points]
            direction = "above" if upward else "below"
            rationale = (
                f"{label} at {ent_id} shifted {'up' if upward else 'down'} from {months[start]}: median "
                f"{format_value(value, scale)} from then on against {format_value(baseline, scale)} in "
                f"{months[0]} to {months[ref - 1]} (CUSUM {stat:.1f} crossed the decision interval "
                f"{self.cusum_h:g} in {months[first]}). "
                "A change inside the period can mean a control, a tool or a team changed; ask the entity what "
                "happened in that month. This is a lead, not a finding."
            )
            out.append(
                AnomalySignal(
                    signal_id=_signal_id(run_id, ent_id, "time_shift", key),
                    run_id=run_id,
                    entity_id=ent_id,
                    kind="time_shift",
                    metric=f"monthly:{key}",
                    label=label,
                    domain=MONTHLY_DOMAIN[key],
                    value=value,
                    baseline=baseline,
                    z=round(stat if upward else -stat, 3),
                    direction=direction,
                    n=sum(n for _, _, n in points),
                    rationale=rationale,
                    detail={
                        "scale": scale,
                        "months": months,
                        "values": [v for _, v, _ in points],
                        "reference_months": months[:ref],
                        "shift_from": months[start],
                        "alarm_month": months[first],
                        "cusum_k": self.cusum_k,
                        "cusum_h": self.cusum_h,
                        "spread_floor": floor,
                    },
                )
            )
        return out
