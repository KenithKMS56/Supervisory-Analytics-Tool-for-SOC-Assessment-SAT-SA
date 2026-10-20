"""Rule contracts: what each rule needs before its silence means anything.

One registry, read by the assessment runner (per-rule result states), the ingestion preview
(likely rule eligibility), the API, the UI and the reports. It is derived from the dependency
tables in `satsa.rules.registry` so there is a single source of truth for what a rule reads.

Per rule:
- `required_tables`: tables the rule's conclusion rests on. One that was never submitted (or was
  rejected, or holds nothing for the assessed period) makes the result `insufficient_evidence`.
- `alert_fields`: alert columns it reads. When none of the entity's alerts carries a usable
  value, the rule runs but cannot fire: its result is `degraded`, never `assessed_clear`.
- `population_table`: whose rows (for the entity, in the selected window) are counted as the
  evaluated population; with fewer than the rule's `min_sample` rows and no finding, the result
  is `insufficient_evidence`. This is the rule's base population, which can be broader than the
  sub-population a rule finally examines (e.g. human-closed high-severity alerts); see
  docs/analytics_methodology.md, "Evidence coverage".
"""

from __future__ import annotations

from dataclasses import dataclass

from satsa.rules.base import BaseRule
from satsa.rules.registry import ALERT_FREE_RULES, RULE_ALERT_FIELDS, RuleRegistry, rule_tables
from satsa.store.duckdb import DuckDBStore

# Result states (persisted in rule_results.state).
FINDING = "finding"
ASSESSED_CLEAR = "assessed_clear"
INSUFFICIENT_EVIDENCE = "insufficient_evidence"
DEGRADED = "degraded"
NOT_APPLICABLE = "not_applicable"
RESULT_STATES = (FINDING, ASSESSED_CLEAR, INSUFFICIENT_EVIDENCE, DEGRADED, NOT_APPLICABLE)
ASSESSED_STATES = frozenset({FINDING, ASSESSED_CLEAR})

# Base population of rules that do not read alerts.
_POPULATION_TABLE = {"EG08": "escalation", "EG09": "case", "EG12": "case", "NS01": "asset", "NS07": "case"}


@dataclass(frozen=True)
class RuleContract:
    rule_id: str
    name: str
    domain: str
    required_tables: tuple[str, ...]
    alert_fields: tuple[str, ...]
    population_table: str
    min_sample: int

    def as_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "domain": self.domain,
            "required_tables": list(self.required_tables),
            "alert_fields": list(self.alert_fields),
            "population_table": self.population_table,
            "min_sample": self.min_sample,
        }


def contract_for(rule: BaseRule) -> RuleContract:
    return RuleContract(
        rule_id=rule.id,
        name=rule.name,
        domain=rule.domain,
        required_tables=rule_tables(rule.id),
        alert_fields=RULE_ALERT_FIELDS.get(rule.id, ()),
        population_table=_POPULATION_TABLE.get(rule.id, "alert" if rule.id not in ALERT_FREE_RULES else "case"),
        min_sample=int(rule.min_sample),
    )


def contracts(registry: RuleRegistry | None = None) -> list[RuleContract]:
    reg = registry or RuleRegistry()
    return [contract_for(rule) for rule in reg.get_all_rules()]


def evaluated_population(contract: RuleContract, store: DuckDBStore, entity_id: str) -> int:
    q = f'"{contract.population_table}"'
    df = store.query(f"SELECT count(*) FROM {q} WHERE entity_id = ?", [entity_id])
    return int(df.row(0)[0]) if not df.is_empty() else 0


def unusable_alert_fields(store: DuckDBStore, entity_id: str, fields: set[str]) -> set[str]:
    """Alert columns among `fields` with no usable value in any of the entity's selected alerts.

    'Usable' matches ingestion's rule_input_missing check: not null, and for disposition not
    `unknown`/`unmapped`.
    """
    if not fields:
        return set()
    total = store.query("SELECT count(*) FROM alert WHERE entity_id = ?", [entity_id]).row(0)[0]
    if not total:
        return set()
    columns = set(store.query("SELECT * FROM alert LIMIT 0").columns)
    unusable: set[str] = set()
    for f in sorted(fields):
        if f not in columns:
            unusable.add(f)
            continue
        cond = f'"{f}" IS NOT NULL'
        if f in ("disposition", "severity_final"):
            cond += f" AND lower(CAST(\"{f}\" AS VARCHAR)) NOT IN ('unknown', 'unmapped', '')"
        n = store.query(f"SELECT count(*) FROM alert WHERE entity_id = ? AND {cond}", [entity_id]).row(0)[0]
        if not n:
            unusable.add(f)
    return unusable
