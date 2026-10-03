"""Finding Card formatting and explainability model."""

from typing import Any

from pydantic import BaseModel, Field

from satsa import FINDING_NOTICE
from satsa.models.outputs import Finding, FindingEvidence

# Why a supervisor would care, per rule: the "Why it matters" part of the finding page. Each
# follows the rule's Purpose in docs/analytics_methodology.md Section 3 and says what the pattern
# may mean, not that it does; tests/test_finding_page.py checks every registered rule has one.
WHY_IT_MATTERS: dict[str, str] = {
    "EG01": (
        "High and critical alerts closed much faster than peers usually take, with almost no recorded "
        "work, may have been dismissed without investigation. Real attacks among them would then go "
        "unhandled while the SOC's closure figures look good."
    ),
    "EG02": (
        "Alerts closed with no investigation step and a near-empty comment leave no record that anyone "
        "looked. From the records alone, a checked false positive cannot be told from an ignored alert."
    ),
    "EG03": (
        "A confirmed critical incident that never left the first tier was not seen by the people meant to "
        "judge its impact and direct the response; containment and reporting may have been decided without them."
    ),
    "EG04": (
        "Many closures sharing the same comment suggest copied closure notes. The record then does not show "
        "why each alert was judged harmless, so the closures cannot be reviewed."
    ),
    "EG05": (
        "The same detection firing on the same asset again and again, always closed as harmless and never "
        "tuned or remediated, uses analyst time and teaches analysts to dismiss it; real activity on that "
        "asset can then be missed."
    ),
    "EG06": (
        "Closure times bunched just inside the SLA limit, or one analyst closing many alerts within the same "
        "minute, suggest the metric is being managed rather than the alerts. Reported SLA performance may then "
        "overstate the service."
    ),
    "EG07": (
        "One analyst closing more alerts in an hour than a person can examine suggests scripted closure or a "
        "shared account. Either way those alerts were probably not reviewed, and the record may not show who "
        "did the work."
    ),
    "EG08": (
        "Escalations nobody acknowledged mean the senior tier may never have acted on incidents the first "
        "tier judged serious enough to pass up."
    ),
    "EG09": (
        "Cases left open for weeks show a backlog that is not being worked down; incidents in it may still "
        "be uncontained."
    ),
    "EG10": (
        "When the time to resolve recomputed from the SOC's own records is far longer than the figure it "
        "declared, the declared figure cannot be relied on, and its other declared figures deserve the same check."
    ),
    "EG11": (
        "No true positives over a whole period, or a false-positive rate far above peers', suggests badly "
        "tuned detections or alerts dismissed by habit. Either can hide real attacks."
    ),
    "EG12": (
        "Critical cases with no recorded containment step suggest the required response was skipped or not "
        "recorded; the records alone cannot tell which."
    ),
    "NS01": (
        "A critical asset that sends no events cannot raise an alert. An attack on it during the silent days "
        "would not have been seen."
    ),
    "NS02": (
        "When most peers detect a category of threat and this entity reports none, it may lack the detection "
        "or the log source rather than be free of that threat."
    ),
    "NS03": (
        "Far less night-time activity than peers suggests the SOC is not watching around the clock, or that "
        "logging falls away out of hours, when intrusions are less likely to be noticed."
    ),
    "NS04": (
        "Confirmed high or critical incidents with no case record leave no trace of how they were handled: "
        "records may be missing, or the incidents were never worked."
    ),
    "NS05": (
        "A large share of detection rules that never fire suggests a stale rule set, with rules for sources "
        "no longer collected or rules that are broken. Detection coverage on paper then exceeds coverage in practice."
    ),
    "NS06": (
        "Registered assets that send no telemetry at all are not monitored, whatever the asset inventory says."
    ),
    "NS07": (
        "A critical incident with no matching external report may not have reached the authorities it should "
        "have. Whether a report was due, and by when, has to be checked against the obligations that apply."
    ),
    "NS08": (
        "Months missing from the submission are periods the assessment cannot see; withheld or lost records "
        "can hide the very weaknesses this review looks for."
    ),
}


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
    why_it_matters: str = ""
    peer_comparison: dict[str, Any] = Field(default_factory=dict)
    peer_group: str = "cohort"
    peer_count: int = 0
    parameters_used: dict[str, Any] = Field(default_factory=dict)
    limitations: str = "Evaluated on ingested metadata; raw payload inspection not performed."
    benign_explanations: list[str] = Field(default_factory=list)
    examiner_check: str
    evidence_records: list[dict[str, Any]] = Field(default_factory=list)
    statutory_wording: str = FINDING_NOTICE

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
            why_it_matters=WHY_IT_MATTERS.get(finding.rule_id, ""),
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
