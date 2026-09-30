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


# ------------------------------------------------------------------ impossible timestamps


def test_alerts_closed_before_creation_do_not_move_the_kpi_reconciliation(tmp_path):
    """Two alerts stamped closed 60 days before they were raised must not decide EG10 either
    way: they are timestamp faults (DQ check close_before_create), not closure times."""
    store = DuckDBStore(tmp_path / "pq")
    try:
        store.execute(
            "INSERT INTO declared_kpi (entity_id, period, metric, severity, value) VALUES ('E1', '2026-Q1', 'MTTR', 'high', 100.0)"
        )
        rows = [("E1", f"A{i}", datetime(2026, 2, 1 + i % 20, 9), datetime(2026, 2, 1 + i % 20, 12)) for i in range(40)]
        rows += [("E1", f"BAD{i}", datetime(2026, 5, 1), datetime(2026, 3, 1)) for i in range(2)]
        for entity_id, alert_id, created, closed in rows:
            store.execute(
                "INSERT INTO alert (entity_id, alert_id, severity_final, created_at, closed_at, closed_by_type) "
                "VALUES (?, ?, 'high', ?, ?, 'human')",
                [entity_id, alert_id, created, closed],
            )
        findings, _ = RuleRegistry().get_rule("EG10").evaluate("E1", store, [], "RUN")
        # 40 alerts at 180 minutes against a declared 100: an 80% gap. Averaged with the two
        # inverted records the mean would be about -4,000 minutes and the gap would vanish.
        assert len(findings) == 1
        assert findings[0].peer_comparison["empirical_mttr_mins"] == pytest.approx(180.0)
    finally:
        store.close()


@pytest.mark.parametrize("seed,volume", [(42, 300), (808, 600), (808, 1500), (303, 300)])
def test_generated_defects_are_what_their_ground_truth_says(seed, volume):
    from satsa.synth.generator import SyntheticDataGenerator

    data, truth = SyntheticDataGenerator(seed=seed, base_alerts_per_entity=volume).generate()
    assert not [a.alert_id for a in data["alert"] if a.closed_at and a.closed_at < a.created_at]
    period_end = max(a.created_at for a in data["alert"])
    cases = {c.case_id: c for c in data["case"]}
    for defect in truth.defects:
        assert defect.affected_ids, f"{defect.entity_id}:{defect.rule_id} records a defect that touched nothing"
        if defect.rule_id == "EG09":
            stale = [cid for cid in defect.affected_ids if (period_end - cases[cid].opened_at).days > 14]
            assert len(stale) >= 3, "EG09's injected cases must actually be stale"
