"""Finding Card formatting and explainability model."""

from typing import Any

from pydantic import BaseModel, Field

from satsa.models.outputs import Finding, FindingEvidence


class FindingCard(BaseModel):
    """Rich explainability card for human examiners and supervisory reports."""

    finding_id: str
    run_id: str
    entity_id: str
    rule_id: str
    rule_version: str
    rule_name: str
    domain: str
    score: float
    confidence: float
    severity: str
    title: str
    rationale: str
    peer_comparison: dict[str, Any] = Field(default_factory=dict)
    peer_group: str = "cohort"
    peer_count: int = 0
    parameters_used: dict[str, Any] = Field(default_factory=dict)
    limitations: str = "Evaluated on ingested metadata; raw payload inspection not performed."
    benign_explanations: list[str] = Field(default_factory=list)
    examiner_check: str
    evidence_records: list[dict[str, Any]] = Field(default_factory=list)
    statutory_wording: str = (
        "Indicator requiring supervisory review; not a compliance determination."
    )

    @classmethod
    def from_finding_and_evidence(
        cls,
        finding: Finding,
        evidences: list[FindingEvidence],
        rule_name: str,
        params: dict[str, Any],
        peer_group: str,
        peer_count: int,
    ) -> "FindingCard":
        """Construct a complete explainable finding card."""
        relevant_ev = [
            {"record_type": ev.record_type, "record_id": ev.record_id, **ev.details}
            for ev in evidences
            if ev.finding_id == finding.finding_id
        ]
        return cls(
            finding_id=finding.finding_id,
            run_id=finding.run_id,
            entity_id=finding.entity_id,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            rule_name=rule_name,
            domain=finding.domain,
            score=finding.score,
            confidence=finding.confidence,
            severity=finding.severity,
            title=finding.title,
            rationale=finding.rationale,
            peer_comparison=finding.peer_comparison,
            peer_group=peer_group,
            peer_count=peer_count,
            parameters_used=params,
            limitations=finding.limitations
            or "Evaluated on ingested metadata; raw payload inspection not performed.",
            benign_explanations=finding.benign_explanations,
            examiner_check=finding.examiner_check,
            evidence_records=relevant_ev,
        )
