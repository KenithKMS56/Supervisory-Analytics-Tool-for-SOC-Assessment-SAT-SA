"""Probabilistic scoring engine using Noisy-OR domain aggregation and Entity Risk Index calculation."""

from pathlib import Path
from typing import Any

import yaml

from satsa.models.outputs import DomainScore, EntityScore, Finding


def band_tier(risk_band: str) -> str:
    """Display tier for a stored risk-band label: 'critical', 'moderate' or 'low'.

    The single place that maps an entity's classification to a colour and to "requires
    action" (anything above low), so the dashboard, HTML reports and PDFs agree with the
    stored band rather than each re-deriving one from the risk index.
    """
    label = risk_band.strip().lower()
    if label.startswith(("critical", "high")):
        return "critical"
    if label.startswith("moderate"):
        return "moderate"
    return "low"


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
        entity_findings = [f for f in findings if f.entity_id == entity_id]
        risk_band = self.apply_band_floor(self.classify_risk_band(risk_index), entity_findings)

        return EntityScore(
            run_id=run_id,
            entity_id=entity_id,
            risk_index=risk_index,
            risk_band=risk_band,
            distinct_rules_triggered=distinct_rules,
            domain_scores=dom_map,
        )

    def band_floor(self, findings: list[Finding]) -> str | None:
        """Lowest band label the entity's findings allow, or None when no floor applies.

        The risk index averages over 8 domains, so one maximum-severity finding in one
        domain cannot lift it past ~14/100: on the index alone, an entity with an
        unreported critical incident is "Low Supervisory Concern". `band_floors` in the
        config maps a finding severity to the minimum band key for an entity that has
        such a finding with at least `min_confidence`.
        """
        floors = self.config.get("band_floors", {})
        min_conf = float(floors.get("min_confidence", 0.5))
        order = list(self.risk_bands)
        best = -1
        for f in findings:
            key = floors.get(f.severity)
            if key in self.risk_bands and f.confidence >= min_conf:
                best = max(best, order.index(key))
        if best < 0:
            return None
        band = self.risk_bands[order[best]]
        return str(band.get("label", order[best].title()))

    def apply_band_floor(self, index_band: str, findings: list[Finding]) -> str:
        """The higher of the index-derived band and the findings' band floor."""
        floor = self.band_floor(findings)
        if floor is None:
            return index_band
        labels = [str(info.get("label", name.title())) for name, info in self.risk_bands.items()]
        if index_band in labels and labels.index(floor) <= labels.index(index_band):
            return index_band
        return floor

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
