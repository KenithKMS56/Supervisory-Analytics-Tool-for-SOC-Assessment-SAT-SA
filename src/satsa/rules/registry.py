"""Rule registry for instantiating and configuring all detection rules."""

from pathlib import Path
from typing import Any

import yaml

from satsa.rules.base import BaseRule
from satsa.rules.execution_gaps import (
    EG01FastClosure,
    EG02AckWithoutInvestigation,
    EG03CriticalWithoutEscalation,
    EG04TemplateDrivenInvestigations,
    EG05RepeatAlertsNoRootCause,
    EG06MetricGaming,
    EG07AnalystImplausibility,
    EG08EscalationWithoutFollowThrough,
    EG09BacklogAndAging,
    EG10KPIRadicalGap,
    EG11DispositionExtremes,
    EG12WorkflowNonConformance,
)
from satsa.rules.negative_space import (
    NS01SilentCriticalAssets,
    NS02MissingAlertCategories,
    NS03UnexpectedlyLowOrFlatActivity,
    NS04MissingRecords,
    NS05RuleCoverageGaps,
    NS06InventoryVsTelemetry,
    NS07AbsentExternalReporting,
    NS08SubmissionCompleteness,
)

# Tables (beyond `alert`) each rule's conclusion rests on. When an entity has no rows at all
# in one of them, the rule cannot tell "the SOC did not do this" from "this table was not
# submitted": EG03 reads a missing escalation table as "no critical alert was ever escalated".
# The assessment runner reports these cases on the DQ view; it does not skip the rules.
RULE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "EG01": ("workflow_event",),
    "EG02": ("workflow_event", "closure"),
    "EG03": ("escalation",),
    "EG04": ("closure",),
    "EG05": ("remediation",),
    "EG06": ("sla_policy",),
    "EG08": ("escalation",),
    "EG09": ("case",),
    "EG10": ("declared_kpi",),
    "EG12": ("case", "workflow_event"),
    "NS01": ("asset", "log_source_daily"),
    "NS04": ("case_alert_link",),
    "NS05": ("detection_rule",),
    "NS06": ("asset", "log_source_daily"),
    "NS07": ("case", "external_report"),
}


# Rules that never read the alert table. Every other rule is built on it.
ALERT_FREE_RULES = frozenset({"EG08", "EG09", "EG12", "NS01", "NS07"})

# Alert columns a rule's conclusion rests on. When a source cannot supply one (every value
# empty, or every disposition unknown), the rule still runs but can never fire: a clean result
# from it says nothing about the control. Ingestion reports these as `rule_input_missing`.
RULE_ALERT_FIELDS: dict[str, tuple[str, ...]] = {
    "EG01": ("severity_final", "closed_at"),
    "EG02": ("closed_at",),
    "EG03": ("severity_final", "disposition"),
    "EG04": ("closed_at",),
    "EG05": ("rule_id", "asset_id", "disposition"),
    "EG06": ("severity_final", "closed_at", "closed_by"),
    "EG07": ("closed_at", "closed_by"),
    "EG10": ("severity_final", "closed_at"),
    "EG11": ("disposition",),
    "NS02": ("category",),
    "NS04": ("severity_final", "disposition"),
    "NS05": ("rule_id",),
    "NS06": ("asset_id",),
}


def rule_tables(rule_id: str) -> tuple[str, ...]:
    """Every table a rule reads, `alert` included."""
    base = () if rule_id in ALERT_FREE_RULES else ("alert",)
    return base + RULE_DEPENDENCIES.get(rule_id, ())


def rule_coverage(
    submitted_tables: set[str], empty_alert_fields: set[str] | None = None
) -> dict[str, dict[str, list[str]]]:
    """What an entity's submission lets each rule do.

    `not_assessed`: rule -> tables it needs that the entity never submitted (the rule is
    skipped). `degraded`: rule -> alert columns it needs that hold no usable value (the rule
    runs but cannot fire). `empty_alert_fields=None` means the alert columns were not examined.
    """
    not_assessed: dict[str, list[str]] = {}
    degraded: dict[str, list[str]] = {}
    for cls in RuleRegistry.RULE_CLASSES:
        missing = [t for t in rule_tables(cls.id) if t not in submitted_tables]
        if missing:
            not_assessed[cls.id] = missing
            continue
        unusable = [c for c in RULE_ALERT_FIELDS.get(cls.id, ()) if c in (empty_alert_fields or set())]
        if unusable:
            degraded[cls.id] = unusable
    assessed = [
        cls.id for cls in RuleRegistry.RULE_CLASSES if cls.id not in not_assessed and cls.id not in degraded
    ]
    return {"assessed": {r: [] for r in assessed}, "not_assessed": not_assessed, "degraded": degraded}


class RuleRegistry:
    """Registry maintaining active rule classes and config overrides."""

    RULE_CLASSES: list[type[BaseRule]] = [
        EG01FastClosure,
        EG02AckWithoutInvestigation,
        EG03CriticalWithoutEscalation,
        EG04TemplateDrivenInvestigations,
        EG05RepeatAlertsNoRootCause,
        EG06MetricGaming,
        EG07AnalystImplausibility,
        EG08EscalationWithoutFollowThrough,
        EG09BacklogAndAging,
        EG10KPIRadicalGap,
        EG11DispositionExtremes,
        EG12WorkflowNonConformance,
        NS01SilentCriticalAssets,
        NS02MissingAlertCategories,
        NS03UnexpectedlyLowOrFlatActivity,
        NS04MissingRecords,
        NS05RuleCoverageGaps,
        NS06InventoryVsTelemetry,
        NS07AbsentExternalReporting,
        NS08SubmissionCompleteness,
    ]

    def __init__(self, config_path: Path | str = "config/rules.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.rules: dict[str, BaseRule] = {}
        self._instantiate_rules()

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _instantiate_rules(self) -> None:
        rule_configs = self.config.get("rules", {})
        for cls in self.RULE_CLASSES:
            override = rule_configs.get(cls.id)
            rule_instance = cls(config_override=override)
            self.rules[cls.id] = rule_instance

    def get_rule(self, rule_id: str) -> BaseRule | None:
        return self.rules.get(rule_id)

    def get_all_rules(self) -> list[BaseRule]:
        return list(self.rules.values())
