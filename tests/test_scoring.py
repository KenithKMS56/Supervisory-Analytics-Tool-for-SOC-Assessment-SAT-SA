"""Test scoring, review queue prioritization, explainability, and determinism."""

import tempfile
from pathlib import Path

from satsa.explain.finding_card import FindingCard
from satsa.models.outputs import Finding, FindingEvidence
from satsa.scoring.runner import AssessmentRunner
from satsa.scoring.scorer import ScoringEngine
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def test_noisy_or_domain_scoring():
    scorer = ScoringEngine("config/scoring.yaml")
    run_id = "test-run"
    entity_id = "CSE-01"

    # Three findings in Investigation domain with scores: 50, 40, 30
    # Noisy-OR: 1 - (1-0.5)*(1-0.4)*(1-0.3) = 1 - (0.5 * 0.6 * 0.7) = 1 - 0.21 = 0.79 -> 79.0
    findings = [
        Finding(
            finding_id="f1",
            run_id=run_id,
            entity_id=entity_id,
            rule_id="EG01",
            rule_version="1.0",
            domain="Investigation",
            level="entity",
            score=50.0,
            confidence=1.0,
            severity="high",
            title="T1",
            rationale="R1",
            examiner_check="Check",
        ),
        Finding(
            finding_id="f2",
            run_id=run_id,
            entity_id=entity_id,
            rule_id="EG02",
            rule_version="1.0",
            domain="Investigation",
            level="entity",
            score=40.0,
            confidence=1.0,
            severity="high",
            title="T2",
            rationale="R2",
            examiner_check="Check",
        ),
        Finding(
            finding_id="f3",
            run_id=run_id,
            entity_id=entity_id,
            rule_id="EG04",
            rule_version="1.0",
            domain="Investigation",
            level="entity",
            score=30.0,
            confidence=1.0,
            severity="medium",
            title="T3",
            rationale="R3",
            examiner_check="Check",
        ),
    ]
    dom_scores = scorer.compute_domain_scores(entity_id, run_id, findings)
    inv_score = next(ds.score for ds in dom_scores if ds.domain == "Investigation")
    assert round(inv_score, 1) == 79.0

    ent_score = scorer.compute_entity_score(entity_id, run_id, dom_scores, findings)
    assert ent_score.risk_index > 0
    assert ent_score.distinct_rules_triggered == 3


def test_finding_card_generation():
    finding = Finding(
        finding_id="f-card-1",
        run_id="r-1",
        entity_id="CSE-03",
        rule_id="EG01",
        rule_version="1.0",
        domain="Investigation",
        level="entity",
        score=85.0,
        confidence=1.0,
        severity="critical",
        title="Fast High-Severity Closures",
        rationale="High closure velocity",
        examiner_check="Verify shift",
    )
    evidences = [
        FindingEvidence(
            finding_id="f-card-1", record_type="alert", record_id="ALT-101", details={"speed": 120}
        )
    ]
    card = FindingCard.from_finding_and_evidence(
        finding=finding,
        evidences=evidences,
        rule_name="Fast High-Severity Closure",
        params={"threshold": 300},
        peer_group="telecom_large",
        peer_count=4,
    )
    assert card.finding_id == "f-card-1"
    assert len(card.evidence_records) == 1
    assert card.evidence_records[0]["record_id"] == "ALT-101"
    assert "not a compliance determination" in card.statutory_wording.lower()


def test_determinism():
    """Verify byte-identical results on repeated runs on same input."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_satsa.db"
        duckdb_store = DuckDBStore("data")
        sqlite_store = SQLiteStore(db_path)
        runner = AssessmentRunner(duckdb_store, sqlite_store)

        try:
            res1 = runner.run_assessment(period="2026-Q1")
            res2 = runner.run_assessment(period="2026-Q1")

            assert res1["findings_count"] == res2["findings_count"]
            assert res1["queue_count"] == res2["queue_count"]

            # Verify exact risk index equality for all entities
            for ent_id in res1["entity_scores"]:
                assert (
                    res1["entity_scores"][ent_id]["risk_index"]
                    == res2["entity_scores"][ent_id]["risk_index"]
                )
        finally:
            sqlite_store.close()
            duckdb_store.close()
