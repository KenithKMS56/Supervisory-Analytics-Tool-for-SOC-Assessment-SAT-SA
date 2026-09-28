"""Tests for the Admin Portal's activity feed (operator session monitor of SAT-SA's own users)."""

import pytest

from satsa.store.sqlite import SQLiteStore


@pytest.fixture
def clean_test_stores(tmp_path):
    db_file = str(tmp_path / "activity_feed_test.db")
    store = SQLiteStore(db_file)
    store.seed_default_admin()
    yield store, db_file
    store.close()


def test_live_event_recording_and_retrieval(clean_test_stores):
    store, _ = clean_test_stores

    # Record diverse operational events
    e1 = store.record_live_event("USER_LOGIN", actor="operator_01", role="SOC Analyst", entity_id="CSE-01")
    e2 = store.record_live_event("ASSESSMENT_STARTED", actor="operator_01", role="SOC Analyst", entity_id="CSE-01")
    e3 = store.record_live_event("FINDING_VIEWED", actor="supervisor", role="NCIIPC Supervisor", entity_id="CSE-01", details={"rule_id": "EG03"})
    e4 = store.record_live_event("ACCOUNT_BLOCKED", actor="nciipc_admin", role="admin", entity_id="operator_01", is_admin=True)

    assert e1 > 0
    assert e2 > e1
    assert e3 > e2
    assert e4 > e3

    # Retrieve all events
    all_events = store.get_live_events(since_id=0, limit=10)
    assert len(all_events) == 4
    event_types = [e["event_type"] for e in all_events]
    assert event_types == ["USER_LOGIN", "ASSESSMENT_STARTED", "FINDING_VIEWED", "ACCOUNT_BLOCKED"]
    assert all_events[2]["details"]["rule_id"] == "EG03"

    # Incremental polling with since_id
    delta_events = store.get_live_events(since_id=e2, limit=10)
    assert len(delta_events) == 2
    assert [e["event_type"] for e in delta_events] == ["FINDING_VIEWED", "ACCOUNT_BLOCKED"]


def test_online_operators_tracking_and_blocking(clean_test_stores):
    store, _ = clean_test_stores

    # Create user and active session
    store.create_user("operator_alpha", "SOC Analyst", "SecurePass#2026", org_id="ORG-POWER", cse_id="CSE-01")
    token = store.create_session("operator_alpha", "SOC Analyst")

    online = store.get_online_operators()
    online_unames = [u["username"] for u in online]
    assert "operator_alpha" in online_unames

    # Block user
    store.set_user_status("operator_alpha", "BLOCKED")
    # Verify session was cleared upon blocking
    session = store.get_session(token)
    assert session is None

    # Online operator list should no longer include the blocked user
    online_after = store.get_online_operators()
    assert "operator_alpha" not in [u["username"] for u in online_after]
