"""Tests for the cross-entity ('systemic') correlation detector."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.models.canonical import Entity
from satsa.models.outputs import Finding
from satsa.rules.systemic import SystemicCorrelationDetector
from satsa.store.sqlite import SQLiteStore

client = TestClient(app)
client.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"})


def _finding(entity_id: str, rule_id: str, severity: str = "high") -> Finding:
    return Finding(
        finding_id=f"FND-{rule_id}-{entity_id}",
        run_id="RUN-TEST",
        entity_id=entity_id,
        rule_id=rule_id,
        rule_version="1.0.0",
        domain="Threat Detection",
        level="entity",
        score=70.0,
        confidence=0.9,
        severity=severity,
        title="test finding",
        rationale="test",
        examiner_check="test",
        created_at=datetime.now(UTC),
    )


def _entities(providers: dict[str, str]) -> list[Entity]:
    return [
        Entity(entity_id=eid, name=eid, sector="banking", size_band="medium", soc_provider=prov)
        for eid, prov in providers.items()
    ]


def test_three_entities_same_provider_same_rule_triggers_systemic_finding():
    detector = SystemicCorrelationDetector()
    entities = _entities(
        {"A-01": "MSSP-X", "A-02": "MSSP-X", "A-03": "MSSP-X", "A-04": "internal"}
    )
    findings = [
        _finding("A-01", "NS01"),
        _finding("A-02", "NS01"),
        _finding("A-03", "NS01"),
        _finding("A-04", "NS01"),  # different provider, doesn't count toward the group
    ]
    results = detector.evaluate(entities, findings, run_id="RUN-TEST")
    assert len(results) == 1
    assert results[0]["shared_value"] == "MSSP-X"
    assert results[0]["rule_id"] == "NS01"
    assert results[0]["entity_count"] == 3
    assert sorted(results[0]["entity_ids"]) == ["A-01", "A-02", "A-03"]


def test_below_min_entity_count_does_not_trigger():
    detector = SystemicCorrelationDetector()
    entities = _entities({"A-01": "MSSP-X", "A-02": "MSSP-X"})
    findings = [_finding("A-01", "NS01"), _finding("A-02", "NS01")]
    results = detector.evaluate(entities, findings, run_id="RUN-TEST")
    assert results == []


def test_internal_soc_provider_is_excluded_even_with_enough_entities():
    """In-house SOCs sharing a rule is not evidence of a shared-vendor problem."""
    detector = SystemicCorrelationDetector()
    entities = _entities({"A-01": "internal", "A-02": "internal", "A-03": "internal"})
    findings = [_finding("A-01", "NS03"), _finding("A-02", "NS03"), _finding("A-03", "NS03")]
    results = detector.evaluate(entities, findings, run_id="RUN-TEST")
    assert results == []


def test_excluded_rule_ids_never_trigger_systemic_correlation():
    """NS05/EG12/EG10 are known-near-universal in the synthetic dataset and excluded
    from correlation so they don't produce a misleading portfolio-wide 'systemic' finding.
    """
    detector = SystemicCorrelationDetector()
    entities = _entities({"A-01": "MSSP-X", "A-02": "MSSP-X", "A-03": "MSSP-X"})
    findings = [_finding("A-01", "NS05"), _finding("A-02", "NS05"), _finding("A-03", "NS05")]
    results = detector.evaluate(entities, findings, run_id="RUN-TEST")
    assert results == []


def test_different_rules_do_not_get_grouped_together():
    detector = SystemicCorrelationDetector()
    entities = _entities({"A-01": "MSSP-X", "A-02": "MSSP-X", "A-03": "MSSP-X"})
    findings = [_finding("A-01", "NS01"), _finding("A-02", "NS03"), _finding("A-03", "EG05")]
    results = detector.evaluate(entities, findings, run_id="RUN-TEST")
    assert results == []


def test_demo_dataset_produces_a_real_systemic_finding():
    """End-to-end: the primary demo dataset's synthetic systemic scenario
    (3 entities under soc_provider='MSSP-Meridian', see synth/generator.py)
    must actually be detected by a real assessment run against fixture data.
    """
    store = SQLiteStore("data/satsa.db")
    cur = store.conn.cursor()
    cur.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1")
    run_id = cur.fetchone()["run_id"]
    findings = store.get_systemic_findings(run_id)
    store.close()

    assert findings, "expected at least one systemic finding from the fixture demo dataset"
    ns01_findings = [f for f in findings if f["rule_id"] == "NS01"]
    assert ns01_findings
    assert ns01_findings[0]["shared_value"] == "MSSP-Meridian"
    assert set(ns01_findings[0]["entity_ids"]) == {"CSE-02", "CSE-05", "CSE-09"}


def test_portfolio_view_renders_systemic_section():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Systemic / Cross-Entity Findings" in resp.text
    assert "MSSP-Meridian" in resp.text
