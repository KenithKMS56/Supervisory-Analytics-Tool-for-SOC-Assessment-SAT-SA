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
