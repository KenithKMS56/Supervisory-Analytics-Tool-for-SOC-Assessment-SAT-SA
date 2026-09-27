"""Output schemas for SAT-SA."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Run(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    period: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    config_hash: str
    code_version: str
    status: str = "completed"
    manifest_json: str | None = None


class MetricValue(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    entity_id: str
    period: str
    metric: str
    value: float
    n: int


class FindingEvidence(BaseModel):
    model_config = ConfigDict(extra="ignore")

    finding_id: str
    record_type: str  # alert, case, asset, workflow
    record_id: str
    details: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    finding_id: str
    run_id: str
    entity_id: str
    rule_id: str
    rule_version: str
    domain: str
    level: str  # alert, case, asset, entity
    score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str  # low, medium, high, critical
    title: str
    rationale: str
    peer_comparison: dict[str, Any] = Field(default_factory=dict)
    limitations: str | None = None
    benign_explanations: list[str] = Field(default_factory=list)
    examiner_check: str
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DomainScore(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    entity_id: str
    domain: str
    score: float = Field(ge=0.0, le=100.0)


class EntityScore(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    entity_id: str
    risk_index: float = Field(ge=0.0, le=100.0)
    risk_band: str  # Low, Moderate, High, Critical
    distinct_rules_triggered: int = 0
    domain_scores: dict[str, float] = Field(default_factory=dict)


class ReviewQueueItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    queue_id: str
    run_id: str
    entity_id: str
    record_type: str  # alert, case
    record_id: str
    severity: str
    score: float
    selection_reason: str
    is_random: bool = False
    examiner_status: str = "pending"  # pending, confirmed, not_an_issue, needs_more_data
    examiner_note: str | None = None


class ExaminerFeedback(BaseModel):
    model_config = ConfigDict(extra="ignore")

    feedback_id: str
    queue_id: str
    finding_id: str | None = None
    examiner_id: str
    status: str  # confirmed, not_an_issue, needs_more_data
    notes: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuditLogEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    log_id: str
    ts: datetime = Field(default_factory=datetime.utcnow)
    action: str  # ingest, run, config_change, export, feedback, verify
    actor: str = "system"
    details_json: str
    prev_hash: str
    curr_hash: str


class DQIssue(BaseModel):
    model_config = ConfigDict(extra="ignore")

    issue_id: str
    batch_id: str | None = None
    entity_id: str
    check_name: str
    severity: str  # warning, error
    count: int
    sample_records: list[str] = Field(default_factory=list)
    details: str
