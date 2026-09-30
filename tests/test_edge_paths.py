"""Edge paths of the audit chain, scoring and rules that the data-driven tests never reach:
empty stores, unknown tables, missing configuration, checkpoints on a broken chain."""

from datetime import datetime

import pytest

from satsa.rules.registry import RuleRegistry
from satsa.scoring.runner import AssessmentRunner
from satsa.scoring.scorer import ScoringEngine
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

# ------------------------------------------------------------------ audit chain


@pytest.fixture
def audit(tmp_path):
    store = SQLiteStore(tmp_path / "audit.db")
    yield store
    store.close()


def test_empty_audit_chain_verifies_and_has_a_genesis_head(audit):
    audit.conn.execute("DELETE FROM audit_log")
    audit.conn.commit()
    result = audit.verify_chain("audit_log")
    assert result.ok and result.entries == 0 and "empty" in result.message
    head = audit.audit_head()
    assert (head.count, head.head_hash) == (0, SQLiteStore.GENESIS_HASH)
    assert audit.verify_checkpoint(0, SQLiteStore.GENESIS_HASH) == (True, "Checkpoint was an empty chain.")


def test_only_the_two_audit_tables_can_be_verified(audit):
    for call in (audit.verify_chain, audit.audit_head):
        with pytest.raises(ValueError, match="Unsupported audit table"):
            call("identities")
    with pytest.raises(ValueError, match="Unsupported audit table"):
        audit.count_recent_login_failures("x", 15, table="sessions")


def test_checkpoint_on_a_tampered_chain_reports_the_tampering(audit):
    for i in range(4):
        audit.append_audit(action="ingest", actor="pipeline", details={"n": i})
    head = audit.audit_head()
    ok, message = audit.verify_checkpoint(head.count, head.head_hash)
    assert ok and "0 entries appended since" in message

    audit.append_audit(action="run", actor="pipeline", details={})
    ok, message = audit.verify_checkpoint(head.count, head.head_hash)
    assert ok and "1 entries appended since" in message

    first = audit.conn.execute("SELECT log_id FROM audit_log ORDER BY rowid LIMIT 1").fetchone()[0]
    audit.conn.execute("UPDATE audit_log SET actor = 'someone-else' WHERE log_id = ?", (first,))
    audit.conn.commit()
    ok, message = audit.verify_checkpoint(head.count, head.head_hash)
    assert not ok and "Tampered record" in message
    assert audit.verify_audit_chain()[0] is False


def test_admin_audit_chain_covers_the_target_column(audit):
    audit.append_admin_audit("USER_CREATE", "nciipc_admin", target="alice", details={"role": "examiner"})
    audit.append_admin_audit("USER_BLOCK", "nciipc_admin", target="alice", details={})
    assert audit.verify_chain("admin_audit_log").ok
    audit.conn.execute("UPDATE admin_audit_log SET target = 'bob' WHERE action = 'USER_BLOCK'")
    audit.conn.commit()
    result = audit.verify_chain("admin_audit_log")
    assert not result.ok and "Tampered record" in result.message


# ------------------------------------------------------------------ scoring


def test_scoring_without_a_config_file_uses_the_built_in_cutoffs(tmp_path):
    engine = ScoringEngine(tmp_path / "missing.yaml")
    assert engine.config == {} and engine.risk_bands == {}
    assert engine.classify_risk_band(80.0) == "Critical Supervisory Concern"
    assert engine.classify_risk_band(75.0) == "Low Supervisory Concern"
    assert engine.classify_risk_band(0.0) == "Low Supervisory Concern"


def test_configured_bands_are_matched_by_their_cutoffs():
    engine = ScoringEngine("config/scoring.yaml")
    labels = [engine.classify_risk_band(score) for score in (0.0, 12.0, 30.0, 95.0)]
    assert labels[0].startswith("Low") and labels[-1] != labels[0]
    assert labels == sorted(labels, key=labels.index)  # each score lands in exactly one band


def test_assessment_needs_a_valid_entity(tmp_path):
    duck, sql = DuckDBStore(tmp_path / "pq"), SQLiteStore(tmp_path / "s.db")
    try:
        runner = AssessmentRunner(duck, sql)
        assert runner.run_assessment(period="2026-Q1", refresh_tables=False) == {
            "status": "error", "message": "No entities found in storage.",
        }  # fmt: skip
        duck.execute("INSERT INTO entity (entity_id, name) VALUES ('bad id; --', 'Broken')")
        result = runner.run_assessment(period="2026-Q1", refresh_tables=False)
        assert result == {"status": "error", "message": "No entities with valid IDs found in storage."}
        assert sql.conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 0
    finally:
        duck.close()
        sql.close()


# ------------------------------------------------------------------ rules with nothing to judge


def test_rules_return_nothing_for_an_entity_with_no_records(tmp_path):
    store = DuckDBStore(tmp_path / "pq")
    try:
        for rule in RuleRegistry().get_all_rules():
            assert rule.evaluate("NOBODY", store, [], "RUN") == ([], []), rule.id
    finally:
        store.close()


def test_case_rules_below_their_thresholds_stay_silent(tmp_path):
    """One stale case (EG09 needs 3) and one critical case without containment (EG12 needs 2)."""
    store = DuckDBStore(tmp_path / "pq")
    try:
        store.execute(
            'INSERT INTO "case" (entity_id, case_id, severity, status, opened_at) VALUES '
            "('E1', 'C1', 'critical', 'open', ?), ('E1', 'C2', 'high', 'closed', ?)",
            [datetime(2026, 1, 1), datetime(2026, 3, 1)],
        )
        registry = RuleRegistry()
        for rule_id in ("EG09", "EG12"):
            rule = registry.get_rule(rule_id)
            rule.reference_date = datetime(2026, 6, 1)
            try:
                assert rule.evaluate("E1", store, [], "RUN") == ([], []), rule_id
            finally:
                rule.reference_date = None
    finally:
        store.close()
