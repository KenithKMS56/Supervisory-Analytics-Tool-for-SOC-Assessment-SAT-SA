"""Base class and interface for deterministic detection rules."""

from abc import ABC, abstractmethod
from typing import Any

from satsa.models.outputs import Finding, FindingEvidence
from satsa.peers.robust_stats import RobustStats
from satsa.store.duckdb import DuckDBStore

# Minimum peers with enough data before a rule compares against them with a robust z-score.
MIN_PEERS_FOR_Z = 3


class BaseRule(ABC):
    """Abstract base class for all supervisory assessment rules."""

    id: str
    name: str
    version: str = "1.0.0"
    domain: str
    level: str = "entity"  # entity, alert, case, asset
    min_sample: int = 10
    severity_weight: float = 80.0
    params: dict[str, Any] = {}
    benign_explanations: list[str] = []
    examiner_check: str = ""

    def __init__(self, config_override: dict[str, Any] | None = None):
        if config_override:
            self.params = {**self.params, **config_override.get("params", {})}
            self.min_sample = config_override.get("min_sample", self.min_sample)
            self.severity_weight = float(
                config_override.get("severity_weight", self.severity_weight)
            )

    @staticmethod
    def peer_filter(entity_id: str, peer_ids: list[str]) -> tuple[str, list[Any]]:
        """SQL condition (on `entity_id`) and params selecting the comparison cohort.

        The resolved peer cohort when one is given; otherwise every other entity. The
        target entity is never part of its own baseline.
        """
        if peer_ids:
            return f"entity_id IN ({', '.join('?' for _ in peer_ids)})", list(peer_ids)
        return "entity_id != ?", [entity_id]

    @staticmethod
    def robust_z(value: float, peer_values: list[float], min_spread: float) -> tuple[float, float] | None:
        """Robust z-score of `value` against peer values, and the peer median.

        z = (value - median) / max(1.4826 * MAD, min_spread). 1.4826 * MAD estimates the
        standard deviation for normal data; `min_spread` stops near-identical peers from making
        a trivial difference look extreme while still letting a genuine outlier among identical
        peers register. Returns None with fewer than MIN_PEERS_FOR_Z peers: too few to estimate
        a spread, so the caller falls back to its absolute threshold.
        """
        if len(peer_values) < MIN_PEERS_FOR_Z:
            return None
        median = RobustStats.median(peer_values)
        scale = max(1.4826 * RobustStats.mad(peer_values), min_spread)
        return (value - median) / scale, median

    @staticmethod
    def population(store: DuckDBStore, sql: str, params: list[Any]) -> int:
        """Size of the population a rule examined (a `SELECT count(*) ...` query).

        This, not the number of offending records, is the sample size for confidence:
        how many offenders there are already drives the score through its distance term.
        """
        df = store.query(sql, params)
        return int(df.row(0)[0]) if not df.is_empty() else 0

    def compute_rule_score(self, distance: float, n_sample: int) -> tuple[float, float]:
        """
        Calculate rule score (0..100) and confidence (0..1).
        score = min(100, max(0, distance * severity_weight * confidence))
        """
        confidence = min(1.0, float(n_sample) / max(1.0, float(self.min_sample)))
        norm_dist = min(2.0, max(0.0, distance))  # Cap normalized distance at 2x
        raw_score = (norm_dist / 2.0) * (self.severity_weight) * confidence
        final_score = min(100.0, max(0.0, raw_score))
        return round(final_score, 1), round(confidence, 2)

    @abstractmethod
    def evaluate(
        self, entity_id: str, store: DuckDBStore, peer_ids: list[str], run_id: str
    ) -> tuple[list[Finding], list[FindingEvidence]]:
        """Evaluate rule logic on entity data vs peers and return findings and evidences."""
