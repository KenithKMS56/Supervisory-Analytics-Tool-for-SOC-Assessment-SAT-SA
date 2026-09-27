"""Base class and interface for deterministic detection rules."""

from abc import ABC, abstractmethod
from typing import Any

from satsa.models.outputs import Finding, FindingEvidence
from satsa.store.duckdb import DuckDBStore


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
