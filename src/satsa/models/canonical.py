"""Canonical input data schemas for SAT-SA."""

from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Entity(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    name: str
    sector: str = "general"  # power, banking, telecom, oil_and_gas, transport
    size_band: str = "medium"  # small, medium, large
    soc_model: str = "inhouse"  # inhouse, mssp, hybrid
    # Identifies WHICH shared provider runs this entity's SOC (or "internal" for
    # in-house). Distinct from soc_model: two entities can both be soc_model=mssp
    # but use different vendors. Used by the systemic/cross-entity correlation
    # detector (satsa.rules.systemic) to find negative-space patterns clustered
    # around a single shared vendor rather than any one entity's own operations.
    soc_provider: str = "internal"
    timezone: str = "UTC"
    declared_shift_hours: str = "09:00-18:00"

    @field_validator(
        "soc_model",
        "soc_provider",
        "timezone",
        "declared_shift_hours",
        "sector",
        "size_band",
        mode="before",
    )
    @classmethod
    def default_if_none(cls, v: object, info: object) -> str:
        if v is None or not str(v).strip():
            field_name = getattr(info, "field_name", "")
            defaults: dict[str, str] = {
                "sector": "general",
                "size_band": "medium",
                "soc_model": "inhouse",
                "soc_provider": "internal",
                "timezone": "UTC",
                "declared_shift_hours": "09:00-18:00",
            }
            return defaults.get(field_name, "general")
        return str(v).strip()


class Asset(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    asset_id: str
    asset_type: str
    criticality: int = Field(ge=1, le=4)
    monitored_flag: bool = True
    owner_unit: str | None = None


class LogSourceDaily(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    asset_id: str
    source_type: str
    date: date
    event_count: int = Field(ge=0)


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    rule_id: str
    category: str
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    enabled: bool = True
    last_fired: datetime | None = None


class Alert(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    alert_id: str
    rule_id: str
    category: str
    severity_orig: str  # low, medium, high, critical
    severity_final: str  # low, medium, high, critical
    asset_id: str
    created_at: datetime
    acknowledged_at: datetime | None = None
    first_touch_at: datetime | None = None
    closed_at: datetime | None = None
    closed_by: str | None = None  # pseudonymised
    closed_by_type: str = "human"  # human, automation
    playbook_id: str | None = None
    disposition: str = "unknown"  # true_positive, false_positive, benign, unknown
    status: str = "closed"  # open, escalated, closed


class Case(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    case_id: str
    severity: str  # low, medium, high, critical
    status: str  # open, escalated, closed
    owner: str | None = None
    opened_at: datetime
    closed_at: datetime | None = None


class CaseAlertLink(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    case_id: str
    alert_id: str


class WorkflowEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    ref_type: str  # alert, case
    ref_id: str
    ts: datetime
    actor: str | None = None  # pseudonymised
    action: str  # triage, investigate, escalate, contain, comment, close
    from_status: str | None = None
    to_status: str | None = None
    note_len: int = 0


class Escalation(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    esc_id: str
    ref_id: str
    escalated_at: datetime
    from_role: str = "tier1"
    to_role: str = "tier2"
    acknowledged_at: datetime | None = None
    outcome: str | None = None


class Closure(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    ref_id: str
    reason_code: str
    disposition: str
    comment_norm_hash: str
    comment_len: int
    comment_shingles: str | None = None  # serialized comma-separated shingles or bloom filter


class Remediation(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    ticket_id: str
    linked_asset_id: str | None = None
    linked_rule_id: str | None = None
    type: str = "tuning"  # rca, tuning, patch, config
    created_at: datetime
    closed_at: datetime | None = None


class ExternalReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    incident_id: str
    reported_to: str = "NCIIPC"
    reported_at: datetime


class DeclaredKPI(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    period: str  # e.g., 2026-Q1 or 2026-01
    metric: str  # MTTA, MTTR, SLA_pct, backlog
    severity: str
    value: float


class SLAPolicy(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_id: str
    severity: str
    ack_minutes: int
    resolve_minutes: int


class SubmissionBatch(BaseModel):
    model_config = ConfigDict(extra="ignore")

    batch_id: str
    entity_id: str
    period_start: datetime
    period_end: datetime
    file_name: str
    sha256: str
    row_counts: dict[str, int]
