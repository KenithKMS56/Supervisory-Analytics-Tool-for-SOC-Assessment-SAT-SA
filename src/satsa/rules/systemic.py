"""Cross-entity ("systemic") correlation detector.

Every rule in satsa.rules.execution_gaps and satsa.rules.negative_space
evaluates ONE entity in isolation. This module looks ACROSS entities: if
several entities that share the same third-party SOC provider all trigger
the identical rule in the same assessment run, that pattern is surfaced as
its own "systemic gap, possible shared-vendor issue" finding, separate from
the individual per-entity finding cards -- because the likely root cause is
the shared vendor's process or detection engineering, not any one entity's
own negligence.

This is the tool's answer to the problem statement's invitation to surface
"additional supervisory signals beyond the illustrative examples": a
correlation ACROSS the portfolio that no single-entity rule could see.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from satsa.models.canonical import Entity
from satsa.models.outputs import Finding


class SystemicCorrelationDetector:
    """Detects rules that fire identically across multiple entities sharing an SOC provider."""

    def __init__(self, config_path: Path | str = "config/systemic.yaml"):
        self.config_path = Path(config_path)
        cfg = self._load_config()
        self.min_entity_count: int = int(cfg.get("min_entity_count", 3))
        self.shared_attribute: str = cfg.get("shared_attribute", "soc_provider")
        self.excluded_attribute_values: set[str] = set(cfg.get("excluded_attribute_values", []))
        self.excluded_rule_ids: set[str] = set(cfg.get("excluded_rule_ids", []))

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return raw.get("systemic", {})

    def evaluate(
        self, entities: list[Entity], findings: list[Finding], run_id: str
    ) -> list[dict[str, Any]]:
        """Correlate findings across entities that share an SOC provider.

        Args:
            entities: all entities evaluated in this run (must expose the
                configured `shared_attribute`, e.g. `soc_provider`).
            findings: all per-entity findings produced by the normal rule
                evaluation loop for this run.
            run_id: the current assessment run id.

        Returns:
            A list of systemic finding dicts ready for
            SQLiteStore.save_systemic_findings, one per (shared_value,
            rule_id) pair that met `min_entity_count`.
        """
        attr_by_entity: dict[str, str] = {}
        for e in entities:
            value = getattr(e, self.shared_attribute, None) or "internal"
            attr_by_entity[e.entity_id] = str(value)

        # (shared_value, rule_id) -> set of entity_ids that triggered it
        groups: dict[tuple[str, str], set[str]] = {}
        for f in findings:
            if f.rule_id in self.excluded_rule_ids:
                continue
            shared_value = attr_by_entity.get(f.entity_id)
            if not shared_value or shared_value in self.excluded_attribute_values:
                continue
            key = (shared_value, f.rule_id)
            groups.setdefault(key, set()).add(f.entity_id)

        now = datetime.now(UTC).isoformat()
        systemic_findings: list[dict[str, Any]] = []
        for (shared_value, rule_id), entity_ids in groups.items():
            if len(entity_ids) < self.min_entity_count:
                continue

            sorted_ids = sorted(entity_ids)
            systemic_id = hashlib.sha256(
                f"{run_id}:{self.shared_attribute}:{shared_value}:{rule_id}".encode()
            ).hexdigest()[:16]

            severity = self._severity_for(rule_id, findings)
            rationale = (
                f"{len(sorted_ids)} entities sharing {self.shared_attribute}='{shared_value}' "
                f"({', '.join(sorted_ids)}) all triggered rule {rule_id} in the same assessment "
                "run. This many entities under one shared provider showing the identical gap "
                "suggests a shared-vendor process or detection-engineering failure rather than "
                "independent entity-level negligence -- examine the provider's practices across "
                "its full client roster, not just these entities individually."
            )
            systemic_findings.append(
                {
                    "systemic_id": systemic_id,
                    "run_id": run_id,
                    "rule_id": rule_id,
                    "shared_attribute": self.shared_attribute,
                    "shared_value": shared_value,
                    "entity_count": len(sorted_ids),
                    "entity_ids": sorted_ids,
                    "title": f"Systemic gap: {rule_id} across {len(sorted_ids)} entities under {shared_value}",
                    "rationale": rationale,
                    "severity": severity,
                    "created_at": now,
                }
            )

        return systemic_findings

    @staticmethod
    def _severity_for(rule_id: str, findings: list[Finding]) -> str:
        """Use the highest individual severity observed for this rule_id as the systemic severity."""
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        candidates = [f.severity for f in findings if f.rule_id == rule_id]
        if not candidates:
            return "medium"
        return max(candidates, key=lambda s: order.get(s, 0))
