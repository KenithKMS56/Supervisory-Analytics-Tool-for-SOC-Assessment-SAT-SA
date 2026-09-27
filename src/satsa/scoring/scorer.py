"""Probabilistic scoring engine using Noisy-OR domain aggregation and Entity Risk Index calculation."""

from pathlib import Path
from typing import Any

import yaml

from satsa.models.outputs import DomainScore, EntityScore, Finding


class ScoringEngine:
    """Computes rule scores, domain scores via Noisy-OR, and composite Entity Risk Index."""

    def __init__(self, config_path: Path | str = "config/scoring.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.domain_weights: dict[str, float] = {
            d: info.get("weight", 0.125) for d, info in self.config.get("domains", {}).items()
        }
        self.breadth_weight: float = float(
            self.config.get("scoring", {}).get("breadth_weight", 0.10)
        )
        self.risk_bands: dict[str, dict[str, Any]] = self.config.get("risk_bands", {})

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def compute_domain_scores(
        self, entity_id: str, run_id: str, findings: list[Finding]
    ) -> list[DomainScore]:
        """
        Aggregate rule scores within each domain using probabilistic Noisy-OR:
        domain_score = 100 * (1 - prod(1 - (s_i / 100)))
        """
        domain_findings: dict[str, list[float]] = {d: [] for d in self.domain_weights}

        for f in findings:
            if f.entity_id == entity_id and f.domain in domain_findings:
                domain_findings[f.domain].append(f.score)

        scores: list[DomainScore] = []
        for domain, rule_scores in domain_findings.items():
            if not rule_scores:
                scores.append(
                    DomainScore(run_id=run_id, entity_id=entity_id, domain=domain, score=0.0)
                )
                continue

            # Noisy-OR combination: 1 - prod(1 - p_i)
            prod_complement = 1.0
            for s in rule_scores:
                p_i = min(1.0, max(0.0, s / 100.0))
                prod_complement *= 1.0 - p_i

            d_score = round(100.0 * (1.0 - prod_complement), 1)
            scores.append(
                DomainScore(run_id=run_id, entity_id=entity_id, domain=domain, score=d_score)
            )

        return scores

    def compute_entity_score(
        self, entity_id: str, run_id: str, domain_scores: list[DomainScore], findings: list[Finding]
    ) -> EntityScore:
        """
        Calculate composite Entity Risk Index:
        Weighted mean of 8 domains + breadth factor based on distinct rules triggered.
        """
        dom_map = {ds.domain: ds.score for ds in domain_scores if ds.entity_id == entity_id}

        # Weighted mean
        weighted_sum = 0.0
        total_weight = 0.0
        for domain, weight in self.domain_weights.items():
            score = dom_map.get(domain, 0.0)
            weighted_sum += score * weight
            total_weight += weight

        base_score = weighted_sum / max(total_weight, 0.001)

        # Breadth factor: distinct rules triggered
        distinct_rules = len({f.rule_id for f in findings if f.entity_id == entity_id})
        # 10 rules triggered = 100% breadth penalty
        breadth_score = min(100.0, distinct_rules * 10.0)

        # Composite index
        risk_index = round(
            (1.0 - self.breadth_weight) * base_score + self.breadth_weight * breadth_score, 1
        )
        risk_band = self.classify_risk_band(risk_index)

        return EntityScore(
            run_id=run_id,
            entity_id=entity_id,
            risk_index=risk_index,
            risk_band=risk_band,
            distinct_rules_triggered=distinct_rules,
            domain_scores=dom_map,
        )

    def classify_risk_band(self, score: float) -> str:
        """Assign risk band based on explicit cutoffs in config."""
        for band_name, band_info in self.risk_bands.items():
            min_val = float(band_info.get("min", 0.0))
            max_val = float(band_info.get("max", 100.0))
            if min_val <= score <= max_val:
                return str(band_info.get("label", band_name.title()))
        if score > 75.0:
            return "Critical Supervisory Concern"
        return "Low Supervisory Concern"
