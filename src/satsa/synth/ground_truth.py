"""Ground truth schema and tracking for synthetic dataset."""

from typing import Any

from pydantic import BaseModel, Field


class InjectedDefect(BaseModel):
    entity_id: str
    rule_id: str
    defect_type: str
    affected_ids: list[str] = Field(default_factory=list)
    share: float = 0.0
    description: str


class GroundTruth(BaseModel):
    version: str = "1.0.0"
    seed: int
    created_at: str
    entities: dict[str, dict[str, Any]]
    defects: list[InjectedDefect]
    clean_entities: list[str]
    confounders: list[dict[str, Any]]
