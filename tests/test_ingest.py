"""Test ingestion pipeline, normalisation, redaction, and DQ checks."""

import json
from datetime import UTC, datetime

import pytest

from satsa.ingest.adapters import SourceAdapter
from satsa.ingest.dq_checks import DQValidator
from satsa.ingest.mapper import CSEMapper
from satsa.ingest.normaliser import TaxonomyNormaliser
from satsa.ingest.pseudonymise import Pseudonymiser
from satsa.ingest.redact import Redactor


def test_pseudonymiser_determinism(tmp_path):
    salt_file = tmp_path / ".test_salt"
    p1 = Pseudonymiser(salt_file)
    p2 = Pseudonymiser(salt_file)

    res1 = p1.pseudonymise("analyst_john_doe", prefix="USER")
    res2 = p2.pseudonymise("analyst_john_doe", prefix="USER")
    assert res1 == res2
    assert res1.startswith("USER_")
    assert p1.pseudonymise(None) is None


def test_redactor_and_shingles():
    text = "Host admin.corp.internal with ip 192.168.1.100 and contact sec@cse.org detected error 1234567890."
    redacted = Redactor.redact_text(text)
    assert "192.168.1.100" not in redacted
    assert "sec@cse.org" not in redacted
    assert "[REDACTED_IPV4]" in redacted
    assert "[REDACTED_EMAIL]" in redacted

    shingles = Redactor.generate_shingles(redacted, k=2)
    assert len(shingles) > 0
    jacc = Redactor.jaccard_similarity(shingles, shingles)
    assert jacc == 1.0


def test_taxonomy_normaliser():
    norm = TaxonomyNormaliser("config/taxonomy.yaml")
    assert norm.normalise_severity("sev0") == "critical"
    assert norm.normalise_severity("informational") == "low"
    assert norm.normalise_severity("nonexistent") == "unmapped"
    assert norm.normalise_disposition("True Positive") == "true_positive"
    assert norm.normalise_status("in_progress") == "open"


def test_dq_validator():
    # Test inverted timestamps
    records = [
        {
            "alert_id": "ALT-1",
            "created_at": datetime(2026, 1, 2, tzinfo=UTC),
            "closed_at": datetime(2026, 1, 1, tzinfo=UTC),
        },
        {
            "alert_id": "ALT-2",
            "created_at": datetime(2026, 1, 1, tzinfo=UTC),
            "closed_at": datetime(2026, 1, 2, tzinfo=UTC),
        },
    ]
    issues = DQValidator.check_timestamp_logic(records, "CSE-TEST")
    assert len(issues) == 1
    assert issues[0].check_name == "close_before_create"
    assert issues[0].sample_records == ["ALT-1"]

    # Test sequence gaps
    records_gap = [{"alert_id": f"ALT-{i:04d}"} for i in range(1, 25)]
    records_gap.append({"alert_id": "ALT-0500"})
    gap_issues = DQValidator.check_id_sequence_gaps(records_gap, "alert_id", "CSE-TEST")
    assert len(gap_issues) == 1
    assert gap_issues[0].check_name == "id_sequence_gap"


def test_example_mappings():
    # Verify 3 shipped mappings instantiate and map correctly
    splunk_mapper = CSEMapper("config/mappings/cse_splunk.yaml")
    splunk_record = {
        "notable_id": "SPL-101",
        "urgency": "critical",
        "dest_host": "srv-db-01",
        "time": "2026-03-01T12:00:00Z",
        "status_label": "True Positive",
        "status_code": "4",
    }
    mapped = splunk_mapper.map_record(splunk_record)
    assert mapped["entity_id"] == "CSE-01"
    assert mapped["alert_id"] == "SPL-101"
    assert mapped["severity"] == "critical"
    assert mapped["disposition"] == "true_positive"
    assert mapped["status"] == "closed"

    sn_mapper = CSEMapper("config/mappings/cse_servicenow.yaml")
    sn_record = {
        "number": "INC0099",
        "priority": "1 - Critical",
        "state": "Closed",
        "close_code": "Solved (Permanently)",
        "sys_created_on": "2026-03-01 10:00:00",
    }
    mapped_sn = sn_mapper.map_record(sn_record)
    assert mapped_sn["entity_id"] == "CSE-02"
    assert mapped_sn["severity"] == "critical"
    assert mapped_sn["status"] == "closed"

    hive_mapper = CSEMapper("config/mappings/cse_thehive.yaml")
    hive_record = {
        "_id": "HIVE-888",
        "severity": 4,
        "status": "Resolved",
        "resolutionStatus": "TruePositive",
        "createdAt": 1772452800000,
    }
    mapped_hive = hive_mapper.map_record(hive_record)
    assert mapped_hive["entity_id"] == "CSE-03"
    assert mapped_hive["severity"] == "critical"
    assert mapped_hive["disposition"] == "true_positive"


def test_read_api_from_local_fixture(tmp_path):
    """read_api() against a local fixture file (PS requirement #2: API sources) --
    zero network calls, exercises the same records_key extraction as a live call.
    """
    fixture = tmp_path / "api_ticketing_response.json"
    fixture.write_text(
        json.dumps(
            {
                "tickets": [
                    {"ticket_id": "TCK-001", "priority_level": "P1", "ticket_status": "resolved"},
                    {"ticket_id": "TCK-002", "priority_level": "P3", "ticket_status": "new"},
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = SourceAdapter.read_api({"fixture_path": str(fixture), "records_key": "tickets"})
    assert len(rows) == 2
    assert rows[0]["ticket_id"] == "TCK-001"


def test_read_api_refuses_non_loopback_host():
    """The air-gap guarantee: read_api() must refuse any non-loopback URL before
    ever opening a socket.
    """
    with pytest.raises(ValueError, match="non-loopback"):
        SourceAdapter.read_api({"url": "http://example.com/api/tickets"})

    with pytest.raises(ValueError, match="non-loopback"):
        SourceAdapter.read_api({"url": "https://8.8.8.8/tickets"})


def test_read_api_requires_exactly_one_source():
    with pytest.raises(ValueError):
        SourceAdapter.read_api({})
    with pytest.raises(ValueError):
        SourceAdapter.read_api({"fixture_path": "a.json", "url": "http://127.0.0.1/x"})


def test_read_api_against_live_loopback_server():
    """read_api() against a REAL local HTTP server bound to 127.0.0.1 -- this is
    loopback traffic, consistent with test_offline.py's air-gap guard, which
    explicitly permits 127.0.0.1/localhost and only blocks non-loopback hosts.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    response_body = json.dumps({"tickets": [{"ticket_id": "TCK-LIVE-001"}]}).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        rows = SourceAdapter.read_api(
            {"url": f"http://127.0.0.1:{port}/api/v2/tickets", "records_key": "tickets"}
        )
        assert rows == [{"ticket_id": "TCK-LIVE-001"}]
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_api_ticketing_mapping_config():
    mapper = CSEMapper("config/mappings/cse_api_ticketing.yaml")
    raw_ticket = {
        "ticket_id": "TCK-2026-0042",
        "priority_level": "P1",
        "ticket_status": "resolved",
        "resolution_code": "confirmed_incident",
        "created_timestamp": "2026-03-01T09:00:00Z",
    }
    mapped = mapper.map_record(raw_ticket, table_type="case_record")
    assert mapped["entity_id"] == "CSE-04"
    assert mapped["case_id"] == "TCK-2026-0042"
    assert mapped["severity"] == "critical"
    assert mapped["status"] == "closed"
    assert mapped["disposition"] == "true_positive"


def _write_csv(path, header, rows):
    path.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")


def test_orphaned_child_records_are_reported(tmp_path):
    """A closure or escalation pointing at an alert that is not in the submission makes rules read
    'no closure / no escalation' for the wrong reason; ingest must say so on the DQ view."""
    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    src = tmp_path / "in"
    src.mkdir()
    _write_csv(
        src / "alert.csv",
        "entity_id,alert_id,created_at,severity_final",
        ["DQ-ENT,A-1,2026-01-05T09:00:00,high", "DQ-ENT,A-2,2026-01-06T09:00:00,high"],
    )
    _write_csv(src / "closure.csv", "entity_id,ref_id,comment_len", ["DQ-ENT,A-1,40", "DQ-ENT,A-999,40"])
    _write_csv(
        src / "escalation.csv",
        "entity_id,esc_id,ref_id,escalated_at",
        ["DQ-ENT,E-1,A-2,2026-01-06T09:05:00", "DQ-ENT,E-2,A-777,2026-01-06T09:05:00"],
    )
    sqlite_store = SQLiteStore(tmp_path / "s.db")
    duck = DuckDBStore(tmp_path / "d")
    res = IngestionPipeline(duck, sqlite_store).ingest_directory(src)
    rows = sqlite_store.conn.execute(
        "SELECT issue_id, count FROM dq_issues WHERE check_name = 'orphan_foreign_keys' ORDER BY issue_id"
    ).fetchall()
    duck.close()
    sqlite_store.close()
    assert res["status"] == "success" and res["failed_tables"] == []
    assert [(r["issue_id"], r["count"]) for r in rows] == [
        ("DQ-ORPHAN-DQ-ENT-closure-alert", 1),
        ("DQ-ORPHAN-DQ-ENT-escalation-alert", 1),
    ]


def test_a_table_that_fails_to_store_is_reported_not_swallowed(tmp_path, monkeypatch):
    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    src = tmp_path / "in"
    src.mkdir()
    _write_csv(src / "alert.csv", "entity_id,alert_id,created_at,severity_final", ["DQ-ENT,A-1,2026-01-05T09:00:00,high"])
    _write_csv(src / "escalation.csv", "entity_id,esc_id,ref_id,escalated_at", ["DQ-ENT,E-1,A-1,2026-01-05T09:05:00"])
    sqlite_store = SQLiteStore(tmp_path / "s.db")
    duck = DuckDBStore(tmp_path / "d")
    real_write = duck.write_partitioned_parquet

    def flaky(table, df):
        if table == "escalation":
            raise OSError("disk full")
        return real_write(table, df)

    monkeypatch.setattr(duck, "write_partitioned_parquet", flaky)
    res = IngestionPipeline(duck, sqlite_store).ingest_directory(src)
    issue = sqlite_store.conn.execute(
        "SELECT severity, details FROM dq_issues WHERE check_name = 'table_write_failed'"
    ).fetchone()
    duck.close()
    sqlite_store.close()
    assert res["status"] == "partial" and res["failed_tables"] == ["escalation"]
    assert issue["severity"] == "error" and "escalation" in issue["details"]


def test_rule_dependencies_name_real_rules_and_tables(tmp_path):
    from satsa.rules.registry import RULE_DEPENDENCIES, RuleRegistry
    from satsa.store.duckdb import DuckDBStore

    rule_ids = {cls.id for cls in RuleRegistry.RULE_CLASSES}
    assert set(RULE_DEPENDENCIES) <= rule_ids
    store = DuckDBStore(tmp_path / "d")
    try:
        for table in {t for tables in RULE_DEPENDENCIES.values() for t in tables}:
            store.query(f'SELECT entity_id FROM "{table}" LIMIT 0')  # raises if the table is unknown
    finally:
        store.close()


def test_assessment_warns_when_a_rule_depends_on_a_table_with_no_rows(tmp_path):
    """An alerts-only submission has no escalation table, so EG03 would read every critical
    true positive as unescalated. The run must say so on the DQ view, and stop saying so once
    the table is supplied."""
    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.scoring.runner import AssessmentRunner
    from satsa.store.duckdb import DuckDBStore
    from satsa.store.sqlite import SQLiteStore

    src = tmp_path / "in"
    src.mkdir()
    _write_csv(
        src / "alert.csv",
        "entity_id,alert_id,created_at,severity_final,disposition",
        ["DEP-ENT,A-1,2026-01-05T09:00:00,critical,true_positive"],
    )
    sqlite_store = SQLiteStore(tmp_path / "s.db")
    duck = DuckDBStore(tmp_path / "d")
    pipeline = IngestionPipeline(duck, sqlite_store)
    pipeline.ingest_directory(src)
    runner = AssessmentRunner(duck, sqlite_store)
    runner.run_assessment(period="T", actor="test")

    def warned_tables():
        rows = sqlite_store.conn.execute(
            "SELECT issue_id, sample_records_json FROM dq_issues WHERE check_name = 'rule_dependency_empty'"
        ).fetchall()
        return {r["issue_id"].removeprefix("DQ-DEPENDENCY-DEP-ENT-"): r["sample_records_json"] for r in rows}

    first = warned_tables()
    assert "EG03" in first["escalation"] and "NS07" in first["external_report"]

    more = tmp_path / "more"
    more.mkdir()
    _write_csv(more / "escalation.csv", "entity_id,esc_id,ref_id,escalated_at", ["DEP-ENT,E-1,A-1,2026-01-05T09:05:00"])
    pipeline.ingest_directory(more)
    runner.run_assessment(period="T", actor="test")
    second = warned_tables()
    duck.close()
    sqlite_store.close()
    assert "escalation" not in second and "external_report" in second
