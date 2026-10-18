"""Cross-entity ("systemic") correlation detector: possible shared-provider patterns.

Every rule in satsa.rules.execution_gaps and satsa.rules.negative_space evaluates ONE entity in
isolation. This module looks ACROSS entities: when several entities that share the same
third-party SOC provider all trigger the same rule in the same run, the pattern is surfaced as
its own lead, separate from the per-entity findings.

Co-occurrence is a hypothesis, not proof of shared-vendor causation (brief §7). Each lead says:

- **affected / assessable / group size**: how many of the provider's clients triggered the rule,
  how many could be assessed for it (a client whose data could not support the rule is neither
  affected nor clear), and how many clients the provider has in the run;
- **comparison rate**: the same rate among assessable entities with other providers;
- **p-value and q-value**: a one-sided hypergeometric (Fisher exact) test of the provider's
  count against the portfolio rate, and the Benjamini-Hochberg q-value across every
  provider-and-rule pair tested in the run. Leads are ranked by it. With few entities these
  bounds are wide; a lead with q above `max_q` is still listed but marked as weak.

Leads never enter a score or the review queue. How often they are false discoveries can only be
measured on held-out, independently labelled data (docs/analytics_context.md).
"""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from satsa.models.canonical import Entity
from satsa.models.outputs import Finding

_ASSESSED = ("finding", "assessed_clear")


def hypergeom_upper_tail(k: int, n: int, successes: int, population: int) -> float:
    """P(X >= k) for X ~ Hypergeometric(population, successes, draws n)."""
    if population <= 0 or n <= 0:
        return 1.0
    lo, hi = max(k, 0, n - (population - successes)), min(n, successes)
    if lo > hi:
        return 0.0 if k > hi else 1.0
    denom = math.comb(population, n)
    return min(1.0, sum(math.comb(successes, i) * math.comb(population - successes, n - i) for i in range(lo, hi + 1)) / denom)


def benjamini_hochberg(p_values: list[float]) -> list[float]:
    """BH q-values, in the order given."""
    m = len(p_values)
    order = sorted(range(m), key=lambda i: p_values[i])
    q = [1.0] * m
    running = 1.0
    for rank in range(m, 0, -1):
        i = order[rank - 1]
        running = min(running, p_values[i] * m / rank)
        q[i] = min(1.0, running)
    return q


class SystemicCorrelationDetector:
    """Detects rules that fire across multiple entities sharing an SOC provider."""

    def __init__(self, config_path: Path | str = "config/systemic.yaml"):
        self.config_path = Path(config_path)
        cfg = self._load_config()
        self.min_entity_count: int = int(cfg.get("min_entity_count", 3))
        self.shared_attribute: str = cfg.get("shared_attribute", "soc_provider")
        self.excluded_attribute_values: set[str] = set(cfg.get("excluded_attribute_values", []))
        self.excluded_rule_ids: set[str] = set(cfg.get("excluded_rule_ids", []))
        self.max_q: float = float(cfg.get("max_q", 0.2))

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return raw.get("systemic", {})

    def evaluate(
        self,
        entities: list[Entity],
        findings: list[Finding],
        run_id: str,
        results: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Correlate findings across entities that share an SOC provider.

        `results` are the run's per-rule results (satsa.rules.contracts states). Without them
        every entity counts as assessable for every rule.
        """
        attr_by_entity: dict[str, str] = {}
        for e in entities:
            value = getattr(e, self.shared_attribute, None) or "internal"
            attr_by_entity[e.entity_id] = str(value)

        affected: dict[str, set[str]] = {}  # rule -> entities with a finding
        for f in findings:
            if f.rule_id not in self.excluded_rule_ids and f.entity_id in attr_by_entity:
                affected.setdefault(f.rule_id, set()).add(f.entity_id)
        assessable: dict[str, set[str]] | None = None
        if results is not None:
            assessable = {}
            for r in results:
                if r["state"] in _ASSESSED and r["entity_id"] in attr_by_entity:
                    assessable.setdefault(r["rule_id"], set()).add(r["entity_id"])

        clients: dict[str, set[str]] = {}
        for ent, value in attr_by_entity.items():
            clients.setdefault(value, set()).add(ent)

        tested: list[dict[str, Any]] = []
        for rule_id, hit in sorted(affected.items()):
            pool = (assessable or {}).get(rule_id, set()) | hit if assessable is not None else set(attr_by_entity)
            hit_total = len(hit)
            for value, members in sorted(clients.items()):
                if value in self.excluded_attribute_values:
                    continue
                hit_here = hit & members
                if len(hit_here) < self.min_entity_count:
                    continue
                assessable_here = pool & members
                others = pool - members
                other_hit = hit & others
                p = hypergeom_upper_tail(len(hit_here), len(assessable_here), hit_total, len(pool))
                tested.append({
                    "rule_id": rule_id, "value": value, "entity_ids": sorted(hit_here),
                    "group_size": len(members), "assessable": len(assessable_here),
                    "comparison_affected": len(other_hit), "comparison_assessable": len(others),
                    "p_value": p,
                })
        for item, q in zip(tested, benjamini_hochberg([t["p_value"] for t in tested]), strict=True):
            item["q_value"] = q

        now = datetime.now(UTC).isoformat()
        out: list[dict[str, Any]] = []
        for t in sorted(tested, key=lambda x: (x["q_value"], x["p_value"], x["value"], x["rule_id"])):
            n_hit, n_ass = len(t["entity_ids"]), t["assessable"]
            rate = n_hit / n_ass if n_ass else 0.0
            cmp_rate = t["comparison_affected"] / t["comparison_assessable"] if t["comparison_assessable"] else None
            comparison = (
                f"against {t['comparison_affected']} of {t['comparison_assessable']} assessable entities with "
                f"other providers ({cmp_rate:.0%})" if cmp_rate is not None
                else "with no assessable entity under another provider to compare with"
            )
            strength = "weak" if t["q_value"] > self.max_q else "notable"
            rationale = (
                f"{n_hit} of {n_ass} assessable clients of {self.shared_attribute}='{t['value']}' "
                f"(provider group of {t['group_size']}: {', '.join(t['entity_ids'])} affected) triggered rule "
                f"{t['rule_id']} in this run ({rate:.0%}), {comparison}. One-sided Fisher exact p = "
                f"{t['p_value']:.3g}, Benjamini-Hochberg q = {t['q_value']:.3g} across {len(tested)} "
                f"provider-and-rule pairs tested ({strength} lead). Co-occurrence is a hypothesis to examine "
                "with the provider across its client roster, not evidence that the provider caused it."
            )
            out.append({
                "systemic_id": hashlib.sha256(
                    f"{run_id}:{self.shared_attribute}:{t['value']}:{t['rule_id']}".encode()
                ).hexdigest()[:16],
                "run_id": run_id,
                "rule_id": t["rule_id"],
                "shared_attribute": self.shared_attribute,
                "shared_value": t["value"],
                "entity_count": n_hit,
                "entity_ids": t["entity_ids"],
                "assessable_count": n_ass,
                "group_size": t["group_size"],
                "comparison_affected": t["comparison_affected"],
                "comparison_assessable": t["comparison_assessable"],
                "p_value": t["p_value"],
                "q_value": t["q_value"],
                "title": f"Possible shared-provider pattern: {t['rule_id']} at {n_hit} of {n_ass} assessable "
                         f"clients of {t['value']}",
                "rationale": rationale,
                "severity": self._severity_for(t["rule_id"], findings),
                "created_at": now,
            })
        return out

    @staticmethod
    def _severity_for(rule_id: str, findings: list[Finding]) -> str:
        """Use the highest individual severity observed for this rule_id as the systemic severity."""
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        candidates = [f.severity for f in findings if f.rule_id == rule_id]
        if not candidates:
            return "medium"
        return max(candidates, key=lambda s: order.get(s, 0))
