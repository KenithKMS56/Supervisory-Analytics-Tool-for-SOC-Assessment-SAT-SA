"""Probabilistic scoring engine using Noisy-OR domain aggregation and Entity Risk Index calculation."""

from pathlib import Path
from typing import Any

import yaml

from satsa.models.outputs import DomainScore, EntityScore, Finding

# Band of an entity whose submission supports too few rules to classify it (and that has no
# finding severe enough to set a band floor). Never shown as low concern.
INSUFFICIENT_EVIDENCE_BAND = "Insufficient Evidence"

# Result states that count as an assessment of the control (rules.contracts).
_ASSESSED = frozenset({"finding", "assessed_clear"})


def band_tier(risk_band: str) -> str:
    """Display tier for a stored risk-band label: 'critical', 'moderate', 'low' or 'insufficient'.

    The single place that maps an entity's classification to a colour and to "requires
    action" (anything but low), so the dashboard, HTML reports and PDFs agree with the
    stored band rather than each re-deriving one from the risk index. 'insufficient' (no
    classification for want of evidence) requires action too: a data request.
    """
    label = risk_band.strip().lower()
    if label.startswith("insufficient"):
        return "insufficient"
    if label.startswith(("critical", "high")):
        return "critical"
    if label.startswith("moderate"):
        return "moderate"
    return "low"


# Blinded review: the examiner's concern level and the system band on one 1-4 scale.
# The review form says "Elevated" where the system band says "High".
_EXAMINER_CONCERN_LEVELS = {"low": 1, "moderate": 2, "elevated": 3, "high": 3, "critical": 4}
_BAND_LEVELS = {"low": 1, "moderate": 2, "high": 3, "critical": 4}


def blind_review_concordance(examiner_concern: str, system_risk_band: str) -> float:
    """Agreement (0-100) between an examiner's blind concern level and the system's band.

    100 when they match, minus 25 per band of difference. Raises ValueError for a value it
    cannot place on the scale: guessing a level would silently misstate agreement, which is
    how every High and Critical entity once came to be scored as if the system said Low.
    """
    examiner = _EXAMINER_CONCERN_LEVELS.get(examiner_concern.strip().lower())
    if examiner is None:
        raise ValueError(f"Unknown examiner concern level: {examiner_concern!r}")
    band_word = (system_risk_band.split() or [""])[0].lower()
    if band_word == "insufficient":
        raise ValueError(
            "The system did not classify this entity (insufficient evidence), so there is no system "
            "band to compare a blind review with."
        )
    system = _BAND_LEVELS.get(band_word)
    if system is None:
        raise ValueError(f"Unknown system risk band: {system_risk_band!r}")
    return max(0.0, 100.0 - abs(examiner - system) * 25.0)


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
        coverage_cfg = self.config.get("evidence_coverage", {})
        # Share of applicable rules that must be assessed to classify the entity fully, and below
        # which it is not classified at all (docs/analytics_methodology.md, "Evidence coverage").
        self.assessable_min = float(coverage_cfg.get("assessable_min", 0.9))
        self.insufficient_below = float(coverage_cfg.get("insufficient_below", 0.25))

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def compute_domain_scores(
        self,
        entity_id: str,
        run_id: str,
        findings: list[Finding],
        rule_states: dict[str, tuple[str, str]] | None = None,
    ) -> list[DomainScore]:
        """
        Aggregate rule scores within each domain using probabilistic Noisy-OR:
        domain_score = 100 * (1 - prod(1 - (s_i / 100)))

        `rule_states` (rule_id -> (domain, result state)) makes the score evidence-aware: a
        domain none of whose applicable rules could be assessed, and with no finding, is
        unknown (score None), never 0. Without it every domain is treated as assessed.
        """
        domain_findings: dict[str, list[float]] = {d: [] for d in self.domain_weights}

        for f in findings:
            if f.entity_id == entity_id and f.domain in domain_findings:
                domain_findings[f.domain].append(f.score)

        applicable: dict[str, int] = {}
        assessed: dict[str, int] = {}
        for domain, state in (rule_states or {}).values():
            if state != "not_applicable":
                applicable[domain] = applicable.get(domain, 0) + 1
            if state in _ASSESSED:
                assessed[domain] = assessed.get(domain, 0) + 1

        scores: list[DomainScore] = []
        for domain, rule_scores in domain_findings.items():
            counts: dict[str, Any] = {}
            if rule_states is not None:
                n_app, n_ass = applicable.get(domain, 0), assessed.get(domain, 0)
                status = "unknown" if n_ass == 0 else ("assessed" if n_ass == n_app else "partial")
                counts = {"rules_applicable": n_app, "rules_assessed": n_ass, "coverage_status": status}
            if not rule_scores:
                unknown = rule_states is not None and counts["rules_assessed"] == 0
                scores.append(
                    DomainScore(
                        run_id=run_id, entity_id=entity_id, domain=domain, score=None if unknown else 0.0, **counts
                    )
                )
                continue

            # Noisy-OR combination: 1 - prod(1 - p_i)
            prod_complement = 1.0
            for s in rule_scores:
                p_i = min(1.0, max(0.0, s / 100.0))
                prod_complement *= 1.0 - p_i

            d_score = round(100.0 * (1.0 - prod_complement), 1)
            scores.append(
                DomainScore(run_id=run_id, entity_id=entity_id, domain=domain, score=d_score, **counts)
            )

        return scores

    def compute_entity_score(
        self,
        entity_id: str,
        run_id: str,
        domain_scores: list[DomainScore],
        findings: list[Finding],
        coverage: dict[str, Any] | None = None,
    ) -> EntityScore:
        """
        Calculate composite Entity Risk Index:
        Weighted mean of the domains with a known score + breadth factor based on distinct
        rules triggered. An unknown domain (score None) is left out of the mean, with the
        weights of the known domains renormalised, instead of counting as 0.

        `coverage` (from `classify_coverage`) is recorded on the score; an entity classified
        `insufficient_evidence` gets the band "Insufficient Evidence" unless a finding sets a
        band floor (a serious finding is reported whatever else is missing).
        """
        dom_map = {ds.domain: ds.score for ds in domain_scores if ds.entity_id == entity_id}

        # Weighted mean over known domains
        weighted_sum = 0.0
        total_weight = 0.0
        for domain, weight in self.domain_weights.items():
            score = dom_map.get(domain, 0.0)
            if score is None:
                continue
            weighted_sum += score * weight
            total_weight += weight

        base_score = weighted_sum / total_weight if total_weight > 0 else 0.0

        # Breadth factor: distinct rules triggered
        distinct_rules = len({f.rule_id for f in findings if f.entity_id == entity_id})
        # 10 rules triggered = 100% breadth penalty
        breadth_score = min(100.0, distinct_rules * 10.0)

        # Composite index
        risk_index = round(
            (1.0 - self.breadth_weight) * base_score + self.breadth_weight * breadth_score, 1
        )
        entity_findings = [f for f in findings if f.entity_id == entity_id]
        cov = coverage or {}
        if cov.get("classification_status") == "insufficient_evidence":
            risk_band = self.band_floor(entity_findings) or INSUFFICIENT_EVIDENCE_BAND
        else:
            risk_band = self.apply_band_floor(self.classify_risk_band(risk_index), entity_findings)

        return EntityScore(
            run_id=run_id,
            entity_id=entity_id,
            risk_index=risk_index,
            risk_band=risk_band,
            distinct_rules_triggered=distinct_rules,
            domain_scores=dom_map,
            **cov,
        )

    def classify_coverage(self, states: dict[str, str], missing_by_rule: dict[str, list[str]]) -> dict[str, Any]:
        """Evidence coverage of one entity from its rules' result states (rule_id -> state).

        `coverage` is assessed / applicable, where applicable excludes rules ruled not
        applicable by an audited decision. `data_request_priority` ranks the missing inputs by
        how many rules each would let the next assessment evaluate.
        """
        counts = {s: 0 for s in ("finding", "assessed_clear", "degraded", "insufficient_evidence", "not_applicable")}
        for state in states.values():
            counts[state] = counts.get(state, 0) + 1
        applicable = len(states) - counts["not_applicable"]
        assessed = counts["finding"] + counts["assessed_clear"]
        coverage = round(assessed / applicable, 4) if applicable else 0.0
        if applicable == 0 or coverage < self.insufficient_below:
            status = "insufficient_evidence"
        elif coverage >= self.assessable_min:
            status = "assessable"
        else:
            status = "partially_assessable"
        unlocks: dict[str, list[str]] = {}
        for rule_id, missing in missing_by_rule.items():
            for item in missing:
                unlocks.setdefault(item, []).append(rule_id)
        priority = [
            {"input": item, "rules": sorted(rules)}
            for item, rules in sorted(unlocks.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        ]
        return {
            "classification_status": status,
            "rules_applicable": applicable,
            "rules_assessed": assessed,
            "rules_degraded": counts["degraded"],
            "rules_insufficient": counts["insufficient_evidence"],
            "rules_not_applicable": counts["not_applicable"],
            "coverage": coverage,
            "data_request_priority": priority,
            "missing_inputs": sorted(unlocks),
        }

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
