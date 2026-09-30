"""Product export connectors: Splunk ES, ServiceNow SIR and TheHive 5, end to end.

Each test ingests a sample export from tests/fixtures/connectors/ through its mapping in
config/mappings/, runs an assessment and checks the findings, what the ingest report says
the source could not supply, and that no personal identifier from the export is stored.
The samples are hand-built to the products' export field names (see build_fixtures.py);
they are not captures from live systems.
"""

import csv
import importlib.util
import json
from datetime import datetime
from pathlib import Path

import polars as pl
import pytest
from typer.testing import CliRunner

from satsa.ingest.mapper import MappingError, SourceMapping, parse_source_timestamp
from satsa.ingest.pipeline import IngestionPipeline
from satsa.rules.registry import RuleRegistry, rule_coverage, rule_tables
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "connectors"
MAPPINGS = Path("config/mappings")
ALL_RULES = {cls.id for cls in RuleRegistry.RULE_CLASSES}


class Workspace:
    def __init__(self, root: Path):
        self.root = root
        self.duck = DuckDBStore(root / "pq")
        self.sql = SQLiteStore(root / "satsa.db")
        self.pipeline = IngestionPipeline(self.duck, self.sql, salt_file=root / "salt")

    def ingest(self, source: str, entity_id: str, directory: Path | None = None) -> dict:
        mapping = SourceMapping(MAPPINGS / f"cse_{source}.yaml")
        return self.pipeline.ingest_directory(directory or FIXTURES / source, default_entity_id=entity_id, mapping=mapping)

    def assess(self) -> dict[str, dict]:
        AssessmentRunner(self.duck, self.sql).run_assessment(period="2026-H1", actor="test")
        return {
            row["rule_id"]: dict(row)
            for row in self.sql.conn.execute("SELECT rule_id, entity_id, title, rationale FROM findings")
        }

    def dq(self, check_name: str) -> list[dict]:
        rows = self.sql.conn.execute(
            "SELECT entity_id, details, sample_records_json FROM dq_issues WHERE check_name = ?", (check_name,)
        ).fetchall()
        return [dict(r) for r in rows]

    def stored_text(self) -> str:
        """Everything persisted, as one string: Parquet cells, findings, evidence and DQ notes."""
        parts = []
        for parquet in (self.root / "pq").rglob("*.parquet"):
            parts.append(json.dumps(pl.read_parquet(parquet).to_dicts(), default=str))
        for table in ("findings", "finding_evidences", "dq_issues", "review_queue", "audit_log"):
            parts.append(json.dumps([tuple(r) for r in self.sql.conn.execute(f"SELECT * FROM {table}")], default=str))
        return "\n".join(parts)

    def close(self) -> None:
        self.duck.close()
        self.sql.close()


@pytest.fixture
def ws(tmp_path):
    workspace = Workspace(tmp_path)
    yield workspace
    workspace.close()


def _empty_columns(result: dict, table: str) -> set[str]:
    return {c for c, n in result["field_coverage"][table]["filled"].items() if n == 0}


# ------------------------------------------------------------------ Splunk ES


def test_splunk_export_end_to_end(ws):
    result = ws.ingest("splunk", "CSE-SPL")
    assert result["status"] == "success" and result["source"] == "splunk_es"
    assert result["row_counts"] == {"alert": 209, "workflow_event": 314, "closure": 175, "entity": 1}
    assert result["submitted_tables"] == ["alert", "closure", "workflow_event"]

    # Fields the export maps cleanly, and the ones it cannot supply.
    assert _empty_columns(result, "alert") == {"acknowledged_at", "first_touch_at", "playbook_id"}
    assert result["field_coverage"]["alert"]["filled"]["closed_at"] == 175  # 34 notables still open
    assert _empty_columns(result, "workflow_event") == {"from_status"}
    assert _empty_columns(result, "closure") == set()

    coverage = result["rule_coverage"]["CSE-SPL"]
    assert set(coverage["assessed"]) == {"EG01", "EG02", "EG04", "EG07", "EG11", "NS02", "NS03", "NS08"}
    assert coverage["degraded"] == {}
    assert coverage["not_assessed"] == {
        "EG03": ["escalation"], "EG05": ["remediation"], "EG06": ["sla_policy"], "EG08": ["escalation"],
        "EG09": ["case"], "EG10": ["declared_kpi"], "EG12": ["case"], "NS01": ["asset", "log_source_daily"],
        "NS04": ["case_alert_link"], "NS05": ["detection_rule"], "NS06": ["asset", "log_source_daily"],
        "NS07": ["case", "external_report"],
    }  # fmt: skip

    findings = ws.assess()
    assert set(findings) == {"EG02", "EG07"}
    # The bulk closure: 36 notables closed by one analyst in one hour, uninvestigated.
    assert "36 of 164 alerts" in findings["EG02"]["rationale"]
    assert "36 closures per hour" in findings["EG07"]["rationale"]
    # The skipped rules are on the DQ view, one entry per rule, none of them as findings.
    assert len(ws.dq("rule_not_assessed")) == 12
    assert ws.dq("id_sequence_gap") == []  # GUID ids: the check is switched off by the mapping


def test_splunk_timestamps_and_value_maps(ws):
    ws.ingest("splunk", "CSE-SPL")
    first = ws.duck.query("SELECT * FROM alert ORDER BY created_at LIMIT 1").to_dicts()[0]
    # "2026-01-06T20:39:27.000+0530" in the export is 15:09:27 UTC.
    assert first["created_at"] == datetime(2026, 1, 6, 15, 9, 27)
    assert first["closed_at"] == datetime(2026, 1, 6, 22, 21, 27)  # review_time 1767738087 (epoch seconds)
    assert (first["severity_orig"], first["severity_final"], first["status"]) == ("low", "low", "closed")
    assert first["disposition"] == "true_positive" and first["category"] == "network"

    by_type = dict(ws.duck.query("SELECT closed_by_type, count(*) FROM alert GROUP BY 1").rows())
    assert set(by_type) == {"human", "automation"}  # soar_automation is a service account
    statuses = dict(ws.duck.query("SELECT status, count(*) FROM alert GROUP BY 1").rows())
    assert statuses == {"closed": 175, "open": 34}
    # An open notable has no closer and no closure time, whatever its owner column says.
    assert ws.duck.query("SELECT count(*) FROM alert WHERE status = 'open' AND closed_at IS NOT NULL").row(0)[0] == 0
    actions = dict(ws.duck.query("SELECT action, count(*) FROM workflow_event GROUP BY 1").rows())
    assert set(actions) == {"investigate", "close"}


# ------------------------------------------------------------------ ServiceNow SIR


def test_servicenow_export_end_to_end(ws):
    result = ws.ingest("servicenow", "CSE-SNW")
    assert result["status"] == "success" and result["source"] == "servicenow_sir"
    assert result["row_counts"] == {"case_record": 14, "workflow_event": 50, "entity": 1}
    assert result["submitted_tables"] == ["case", "workflow_event"]
    assert _empty_columns(result, "case") == set()
    assert result["field_coverage"]["case"]["filled"]["closed_at"] == 9  # five incidents still open
    assert _empty_columns(result, "workflow_event") == {"note_len"}

    coverage = result["rule_coverage"]["CSE-SNW"]
    assert set(coverage["assessed"]) == {"EG09", "EG12"}
    # A ticketing export has no alerts: every alert-based rule is skipped, not run on nothing.
    assert {r for r, tables in coverage["not_assessed"].items() if "alert" in tables} == {
        "EG01", "EG02", "EG03", "EG04", "EG05", "EG06", "EG07", "EG10", "EG11",
        "NS02", "NS03", "NS04", "NS05", "NS06", "NS08",
    }  # fmt: skip
    assert coverage["not_assessed"]["NS07"] == ["external_report"]
    assert set(coverage["not_assessed"]) | set(coverage["assessed"]) == ALL_RULES

    findings = ws.assess()
    assert set(findings) == {"EG09", "EG12"}
    assert "4 open cases aged beyond 14 days" in findings["EG09"]["rationale"]
    assert "as of 2026-06-24" in findings["EG09"]["rationale"]  # the export's last timestamp, not today
    assert "3 Critical incident cases" in findings["EG12"]["rationale"]
    evidence = {
        r[0] for r in ws.sql.conn.execute("SELECT record_id FROM finding_evidences WHERE finding_id LIKE 'FND-EG12-%'")
    }
    # Cited by incident number (translated from sys_audit's sys_id), not by sys_id.
    assert evidence == {"SIR0010003", "SIR0010005", "SIR0010007"}


def test_servicenow_local_times_become_utc_and_audit_rows_are_filtered(ws):
    ws.ingest("servicenow", "CSE-SNW")
    first = ws.duck.query('SELECT * FROM "case" ORDER BY opened_at LIMIT 1').to_dicts()[0]
    # "2026-01-12 09:30:00" at +05:30 is 04:00 UTC.
    assert (first["case_id"], first["opened_at"]) == ("SIR0010001", datetime(2026, 1, 12, 4, 0, 0))
    assert (first["severity"], first["status"]) == ("critical", "closed")
    events = ws.duck.query("SELECT DISTINCT ref_type, action FROM workflow_event").rows()
    assert {r[0] for r in events} == {"case"}
    # Only state changes on sn_si_incident: assignment changes and other tables are left out.
    assert {r[1] for r in events} == {"investigate", "contain", "eradicate", "recover", "review", "close"}
    assert ws.duck.query("SELECT count(*) FROM workflow_event WHERE ref_id NOT LIKE 'SIR%'").row(0)[0] == 0


# ------------------------------------------------------------------ TheHive 5


def test_thehive_export_end_to_end(ws):
    result = ws.ingest("thehive", "CSE-HIV")
    assert result["status"] == "success" and result["source"] == "thehive5"
    assert result["row_counts"] == {"alert": 94, "case_alert_link": 6, "case_record": 8, "entity": 1}
    assert result["submitted_tables"] == ["alert", "case", "case_alert_link"]
    # TheHive alerts carry no asset, no verdict and no playbook reference.
    assert _empty_columns(result, "alert") == {"asset_id", "disposition", "playbook_id"}
    assert _empty_columns(result, "case") == set()

    coverage = result["rule_coverage"]["CSE-HIV"]
    assert set(coverage["assessed"]) == {"EG07", "EG09", "NS02", "NS03", "NS08"}
    # These two run but cannot fire: every alert's disposition is unknown.
    assert coverage["degraded"] == {"EG11": ["disposition"], "NS04": ["disposition"]}
    assert set(coverage["not_assessed"]) == {
        "EG01", "EG02", "EG03", "EG04", "EG05", "EG06", "EG08", "EG10", "EG12", "NS01", "NS05", "NS06", "NS07",
    }  # fmt: skip

    findings = ws.assess()
    assert set(findings) == {"EG07", "EG09"}
    assert "34 closures per hour" in findings["EG07"]["rationale"]
    assert "4 open cases aged beyond 14 days" in findings["EG09"]["rationale"]

    flagged = ws.dq("rule_input_missing")
    assert len(flagged) == 1 and json.loads(flagged[0]["sample_records_json"]) == ["EG11", "NS04"]
    assert "alert.disposition holds no usable value" in flagged[0]["details"]
    assert "not evidence that the control works" in flagged[0]["details"]


# ------------------------------------------------------------------ combined, privacy, reporting


def test_siem_and_ticketing_exports_for_one_entity_widen_coverage(ws):
    splunk = ws.ingest("splunk", "CSE-MIX")
    combined = ws.ingest("servicenow", "CSE-MIX")
    before, after = splunk["rule_coverage"]["CSE-MIX"], combined["rule_coverage"]["CSE-MIX"]
    assert "EG09" in before["not_assessed"] and "EG12" in before["not_assessed"]
    # The manifest is cumulative: cases from the ticketing export make EG09 and EG12 assessable.
    assert {"EG09", "EG12"} <= set(after["assessed"]) and "EG07" in after["assessed"]
    assert set(ws.assess()) == {"EG02", "EG07", "EG09", "EG12"}


@pytest.mark.parametrize(
    ("source", "identifiers"),
    [
        ("splunk", ["asharma", "kpatel", "rverma", "10.20.", "jump server", "Closed - no action"]),
        ("servicenow", ["Priya", "Sharma", "Arjun", "Mehta", "Neha", "priya.sharma", "@cse-power.example", "RCA document"]),
        ("thehive", ["l.dsouza", "m.khan", "s.rao", "@cse-water.example", "wazuh-feeder"]),
    ],
)
def test_no_personal_identifier_from_an_export_is_stored(ws, source, identifiers):
    """Analyst names, e-mail addresses, IP addresses and free-text comments stay out of every store."""
    raw = "\n".join(p.read_text(encoding="utf-8") for p in (FIXTURES / source).iterdir())
    assert all(token in raw for token in identifiers), "the fixture must contain what the test looks for"
    ws.ingest(source, "CSE-PRIV")
    ws.assess()
    stored = ws.stored_text()
    for token in identifiers:
        assert token not in stored, f"{token!r} from the {source} export was stored"
    people = ws.duck.query(
        'SELECT closed_by AS p FROM alert WHERE closed_by_type = \'human\' AND closed_by IS NOT NULL '
        'UNION ALL SELECT actor FROM workflow_event WHERE actor IS NOT NULL '
        'UNION ALL SELECT owner FROM "case" WHERE owner IS NOT NULL'
    )["p"].to_list()
    assert people and all(p.startswith(("ANALYST_", "ACTOR_", "OWNER_")) for p in people)


def test_a_file_the_mapping_does_not_describe_is_reported_not_guessed(ws, tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    for name in ("notable_events.csv", "incident_review.csv"):
        (export / name).write_bytes((FIXTURES / "splunk" / name).read_bytes())
    (export / "asset_inventory.csv").write_text("host,priority\nPLC-GW-01,critical\n", encoding="utf-8")
    result = ws.ingest("splunk", "CSE-SPL", export)
    assert result["unmapped_files"] == ["asset_inventory.csv"]
    assert "asset" not in result["submitted_tables"]  # so NS01/NS06 stay "not assessed"
    assert "NS01" in result["rule_coverage"]["CSE-SPL"]["not_assessed"]
    issue = ws.dq("file_not_mapped")
    assert len(issue) == 1 and "asset_inventory.csv" in issue[0]["details"]
    assert result["unused_source_columns"]["notable_events.csv"] == [
        "comment", "disposition", "reviewer", "src", "status", "user",
    ]  # fmt: skip


def test_cli_ingest_with_source_reports_what_is_missing(tmp_path):
    from satsa.cli import app

    args = ["ingest", "--data-dir", str(FIXTURES / "thehive"), "--db-path", str(tmp_path / "s.db"),
            "--parquet-dir", str(tmp_path / "pq")]  # fmt: skip
    runner = CliRunner()
    refused = runner.invoke(app, [*args, "--source", "thehive"])
    assert refused.exit_code == 2 and "--entity is required" in refused.output
    assert runner.invoke(app, [*args, "--source", "qradar", "--entity", "CSE-HIV"]).exit_code == 2

    done = runner.invoke(app, [*args, "--source", "thehive", "--entity", "CSE-HIV"], env={"COLUMNS": "400"})
    assert done.exit_code == 0, done.output
    out = " ".join(done.output.split())
    assert "Source mapping: thehive5" in out
    assert "alert: 94 rows; no value for: asset_id, playbook_id, disposition" in out
    assert "Not assessed (table never submitted):" in out and "EG03 (no escalation)" in out
    assert "Cannot fire (input column empty): EG11 (alert.disposition empty); NS04 (alert.disposition empty)" in out


def test_canonical_submission_reports_full_rule_coverage(tmp_path):
    """The native CSV layout with every table: nothing skipped, nothing degraded."""
    from satsa.synth.generator import SyntheticDataGenerator

    csv_dir, _ = SyntheticDataGenerator(seed=7, base_alerts_per_entity=120).save_dataset(tmp_path / "gen")
    workspace = Workspace(tmp_path / "ws")
    try:
        result = workspace.pipeline.ingest_directory(csv_dir)
        assert result["source"] is None and result["unmapped_files"] == []
        for entity_id, coverage in result["rule_coverage"].items():
            assert coverage["degraded"] == {}, entity_id
            assert set(coverage["assessed"]) | set(coverage["not_assessed"]) == ALL_RULES
    finally:
        workspace.close()


# ------------------------------------------------------------------ mapping format


def test_fixtures_are_reproducible(tmp_path):
    spec = importlib.util.spec_from_file_location("build_fixtures", FIXTURES / "build_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.build_splunk(tmp_path / "splunk")
    module.build_servicenow(tmp_path / "servicenow")
    module.build_thehive(tmp_path / "thehive")
    for built in sorted(tmp_path.rglob("*.*")):
        committed = FIXTURES / built.relative_to(tmp_path)
        assert built.read_text(encoding="utf-8").splitlines() == committed.read_text(encoding="utf-8").splitlines()


def test_fixture_columns_are_the_native_export_columns():
    def header(path):
        with open(path, encoding="utf-8", newline="") as f:
            return next(csv.reader(f))

    assert header(FIXTURES / "splunk" / "notable_events.csv")[:6] == [
        "_time", "event_id", "rule_name", "security_domain", "severity", "urgency",
    ]  # fmt: skip
    assert header(FIXTURES / "splunk" / "incident_review.csv") == [
        "time", "rule_id", "rule_name", "status", "owner", "urgency", "comment", "user", "disposition",
    ]  # fmt: skip
    assert {"number", "sys_id", "priority", "state", "assigned_to", "opened_at", "closed_at"} <= set(
        header(FIXTURES / "servicenow" / "sn_si_incident.csv")
    )
    assert header(FIXTURES / "servicenow" / "sys_audit.csv")[:6] == [
        "documentkey", "tablename", "fieldname", "oldvalue", "newvalue", "sys_created_on",
    ]  # fmt: skip
    alert = json.loads((FIXTURES / "thehive" / "thehive_alerts.json").read_text(encoding="utf-8"))[0]
    assert {"_id", "_type", "type", "source", "sourceRef", "title", "severity", "date", "stage", "caseId"} <= set(alert)


def test_source_timestamp_parsing():
    from satsa.ingest.mapper import _parse_utc_offset

    ist = _parse_utc_offset("+05:30")
    assert parse_source_timestamp("2026-03-01 10:00:00", "%Y-%m-%d %H:%M:%S", ist) == datetime(2026, 3, 1, 4, 30)
    assert parse_source_timestamp("2026-03-01T10:00:00Z", "iso") == datetime(2026, 3, 1, 10, 0)
    assert parse_source_timestamp("2026-03-01T10:00:00+0530", "%Y-%m-%dT%H:%M:%S%z") == datetime(2026, 3, 1, 4, 30)
    assert parse_source_timestamp(1772452800000, "epoch_ms") == datetime(2026, 3, 2, 12, 0)
    assert parse_source_timestamp("1772452800.5", "epoch_s") == datetime(2026, 3, 2, 12, 0, 0, 500000)
    for bad in ("", None, "not a date", "31/02/2026"):
        assert parse_source_timestamp(bad, "%Y-%m-%d %H:%M:%S") is None
    assert parse_source_timestamp("abc", "epoch_ms") is None
    with pytest.raises(MappingError, match="utc_offset"):
        _parse_utc_offset("IST")


def _mapping(tmp_path, text: str) -> SourceMapping:
    path = tmp_path / "m.yaml"
    path.write_text(text, encoding="utf-8")
    return SourceMapping(path)


def test_mapping_rows_conditions_defaults_and_nested_fields(tmp_path):
    mapping = _mapping(tmp_path, """
source: demo
timestamp_format: iso
tables:
  - table: alert
    files: ["demo*"]
    required: [alert_id]
    where: {kind: [alert]}
    columns:
      alert_id: id
      asset_id: observable.host
      closed_at: {column: [resolved, ignored], when: {state: [done]}}
      closed_by_type: {column: closer, values: closer_type, default: human}
      status: state
      note_len: {column: note, transform: length}
      ref_type: {const: alert}
value_mappings:
  status: {done: closed}
  closer_type: {bot: automation}
""")
    spec = mapping.specs_for_file("DEMO_export")[0]
    assert mapping.specs_for_file("other") == []
    assert spec.source_columns() == {"kind", "id", "observable.host", "resolved", "ignored", "state", "closer", "note"}
    mapped = mapping.map_rows(
        [
            {"kind": "alert", "id": "A1", "observable": {"host": "H1"}, "resolved": None, "ignored": "2026-01-02T00:00:00Z",
             "state": "done", "closer": "bot", "note": "four"},
            {"kind": "alert", "id": "A2", "observable": {}, "resolved": "2026-01-03T00:00:00Z", "state": "working",
             "closer": "someone", "note": ""},
            {"kind": "alert", "id": "", "state": "done"},
            {"kind": "case", "id": "C1"},
        ],
        spec,
        "CSE-Z",
    )  # fmt: skip
    assert (mapped.source_rows, mapped.skipped_by_filter, mapped.dropped_missing_required) == (4, 1, 1)
    first, second = mapped.rows
    assert first == {
        "entity_id": "CSE-Z", "alert_id": "A1", "asset_id": "H1", "closed_at": datetime(2026, 1, 2),
        "closed_by_type": "automation", "status": "closed", "note_len": 4, "ref_type": "alert",
    }  # fmt: skip
    # Not "done": no closure time even though the export holds one. Unknown status goes to the taxonomy.
    assert (second["closed_at"], second["closed_by_type"], second["asset_id"], second["note_len"]) == (None, "human", None, 0)
    assert second["status"] == "unmapped"
    assert set(first) == set(second) and "kind" not in first  # only mapped fields: no raw column passes through
    assert mapped.filled["closed_at"] == 1 and mapped.filled["alert_id"] == 2


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("source: x\n", "no `tables:` section"),
        ("tables:\n  - table: alert\n    files: ['a*']\n", "needs `table`, `files` and `columns`"),
        ("tables:\n  - table: alert\n    files: ['a*']\n    columns:\n      alert_id: {when: {a: [b]}}\n", "needs a source `column` or a `const`"),
        ("tables:\n  - table: alert\n    files: ['a*']\n    columns:\n      status: {column: s, values: nope}\n", "value_mappings.nope is not defined"),
        ("timezone: Asia/Kolkata\ntables:\n  - table: alert\n    files: ['a*']\n    columns:\n      alert_id: id\n", "utc_offset"),
        ("tables:\n  - table: alert\n    files: ['a*']\n    columns:\n      ref_id: {column: k, lookup: {files: 'b*'}}\n", "lookup needs"),
    ],
)  # fmt: skip
def test_unusable_mapping_is_rejected_when_loaded(tmp_path, text, message):
    with pytest.raises(MappingError, match=message):
        _mapping(tmp_path, text)
    with pytest.raises(MappingError, match="not found"):
        SourceMapping(tmp_path / "missing.yaml")


def test_shipped_mappings_load_and_flat_mappings_are_refused_by_the_pipeline():
    for name, tables in (
        ("cse_splunk.yaml", ["alert", "workflow_event", "closure"]),
        ("cse_servicenow.yaml", ["case_record", "workflow_event"]),
        ("cse_thehive.yaml", ["alert", "case_alert_link", "case_record"]),
    ):
        assert [spec.table for spec in SourceMapping(MAPPINGS / name).tables] == tables
    # The REST ticketing mapping is a flat, single-record mapping (CSEMapper), not a pipeline mapping.
    with pytest.raises(MappingError, match="no `tables:` section"):
        SourceMapping(MAPPINGS / "cse_api_ticketing.yaml")


# ------------------------------------------------------------------ rule inputs


def test_rule_coverage_names_missing_tables_and_empty_columns():
    assert rule_tables("EG03") == ("alert", "escalation")
    assert rule_tables("EG09") == ("case",)  # never reads alerts
    assert rule_tables("NS08") == ("alert",)
    full = {"alert", "case", "escalation", "closure", "workflow_event", "asset", "log_source_daily", "declared_kpi",
            "detection_rule", "case_alert_link", "sla_policy", "external_report", "remediation"}  # fmt: skip
    assert set(rule_coverage(full)["assessed"]) == ALL_RULES
    nothing = rule_coverage(set())
    assert set(nothing["not_assessed"]) == ALL_RULES and nothing["assessed"] == {}
    degraded = rule_coverage(full, {"disposition", "asset_id"})["degraded"]
    assert degraded == {
        "EG03": ["disposition"], "EG05": ["asset_id", "disposition"], "EG11": ["disposition"],
        "NS04": ["disposition"], "NS06": ["asset_id"],
    }  # fmt: skip
