"""Connector conformance: every shipped file-export mapping meets one contract
(docs/connector_compatibility.md, "Conformance contract").

Each mapping's fixture goes through the ingestion service exactly as a CSE's export would. The
same six checks apply to all of them, so a new mapping is held to what the others already do:

1. it loads, and the pipeline accepts it;
2. its fixture ingests into one published batch for the named entity, with nothing stored under
   another entity;
3. every stored timestamp is UTC (naive datetimes, as the store holds them);
4. no personal identifier from the export is stored;
5. every source row is accounted for: stored, or reported as rejected;
6. the ingest report puts every rule in one state: assessed, not assessed (naming the tables it
   lacks) or degraded (naming the empty columns).

The fixtures are hand-built to the products' documented field names (docs/connectors.md); this
is fixture verification, not production verification.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import polars as pl
import pytest

from satsa.ingest.mapper import SourceMapping
from satsa.ingest.pipeline import IngestionPipeline
from satsa.rules.registry import RuleRegistry
from satsa.store.duckdb import CANONICAL_TABLES, DuckDBStore
from satsa.store.sqlite import SQLiteStore

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "connectors"
MAPPINGS = Path("config/mappings")
ENTITY = "CSE-CONF"
ALL_RULES = {cls.id for cls in RuleRegistry.RULE_CLASSES}


def _xsiam_export(directory: Path) -> Path:
    from test_xsiam_mapping import _submission

    return _submission(directory)


# mapping file, fixture directory (or a builder), identifiers the export holds that must not be stored
CONNECTORS = {
    "splunk": ("cse_splunk.yaml", FIXTURES / "splunk", ["asharma", "kpatel", "rverma"]),
    "servicenow": ("cse_servicenow.yaml", FIXTURES / "servicenow", ["priya.sharma", "@cse-power.example"]),
    "thehive": ("cse_thehive.yaml", FIXTURES / "thehive", ["l.dsouza", "@cse-water.example"]),
    "xsiam": ("cse_cortex_xsiam.yaml", _xsiam_export, ["jane analyst", "jane.analyst@example.org"]),
}


def test_every_shipped_file_mapping_is_under_this_contract():
    shipped = {p.name for p in MAPPINGS.glob("*.yaml")}
    covered = {mapping for mapping, _, _ in CONNECTORS.values()}
    # The REST ticketing mapping is an API source, tested in test_anomaly_scan.py.
    assert shipped - covered == {"cse_api_ticketing.yaml"}


@pytest.fixture(params=sorted(CONNECTORS))
def conformed(request, tmp_path):
    name = request.param
    mapping_file, source, identifiers = CONNECTORS[name]
    directory = source(tmp_path / "export") if callable(source) else source
    (tmp_path / "salt").write_bytes(b"conformance-test-salt-32-bytes!!")
    duck, sql = DuckDBStore(tmp_path / "pq"), SQLiteStore(tmp_path / "satsa.db")
    try:
        mapping = SourceMapping(MAPPINGS / mapping_file)
        result = IngestionPipeline(duck, sql, salt_file=tmp_path / "salt").ingest_directory(
            directory, default_entity_id=ENTITY, mapping=mapping)
        duck.load_all_tables()
        frames = {t: duck.query(f'SELECT * FROM "{t}"') for t in CANONICAL_TABLES
                  if duck.query(f"SELECT count(*) FROM information_schema.tables WHERE table_name = '{t}'").row(0)[0]}
        dq = [dict(r) for r in sql.conn.execute("SELECT check_name, details FROM dq_issues")]
    finally:
        duck.close()
        sql.close()
    catalog = sqlite3.connect(tmp_path / "pq" / "catalog.db")
    try:
        batches = catalog.execute("SELECT batch_id, state, entity_id FROM batches").fetchall()
    finally:
        catalog.close()
    stored_text = "\n".join(json.dumps(pl.read_parquet(p).to_dicts(), default=str)
                            for p in (tmp_path / "pq").rglob("*.parquet"))
    # The export as text, read both as UTF-8 and as Windows-1252 (XSIAM's encoding).
    raw = "\n".join(f.read_bytes().decode("utf-8", errors="replace") + f.read_bytes().decode("cp1252", errors="replace")
                    for f in directory.iterdir() if f.is_file())
    return {"name": name, "mapping": mapping, "raw": raw, "result": result, "frames": frames, "dq": dq, "batches": batches,
            "stored": stored_text, "identifiers": identifiers}


def test_1_the_mapping_loads_and_names_its_tables(conformed):
    assert conformed["mapping"].tables, f"{conformed['name']}: a mapping must describe at least one table"


def test_2_one_published_batch_for_the_named_entity_only(conformed):
    published = [b for b in conformed["batches"] if b[1] == "published"]
    assert len(published) == 1, conformed["batches"]
    for table, frame in conformed["frames"].items():
        if "entity_id" in frame.columns and frame.height:
            assert set(frame["entity_id"].to_list()) == {ENTITY}, table


def test_3_every_stored_timestamp_is_utc(conformed):
    seen = 0
    for table, frame in conformed["frames"].items():
        for column, dtype in frame.schema.items():
            if isinstance(dtype, pl.Datetime):
                seen += 1
                assert dtype.time_zone is None, f"{table}.{column} kept a zone: {dtype}"
    assert seen, "no timestamp column was stored"


def test_4_no_personal_identifier_is_stored(conformed):
    for token in conformed["identifiers"]:
        assert token in conformed["raw"], f"the {conformed['name']} fixture must contain {token!r} for this check to mean anything"
        assert token not in conformed["stored"], f"{token!r} from the {conformed['name']} export was stored"


def test_5_every_source_row_is_accounted_for(conformed):
    """Per file and per table it feeds: every row read is stored, filtered by the mapping's
    conditions, or rejected with a reason. Nothing disappears unexplained."""
    res = conformed["result"]
    assert not res.get("unmapped_files") and not res.get("unreadable_files")
    files = res["file_coverage"]
    # "partly stored": some rows were rejected (and counted below), as an export's junk rows are.
    assert files and all(f["status"] in ("ingested", "partly stored") for f in files), files
    for f in files:
        assert f["rows_read"] > 0, f
        # Rejections are reported per reason ("missing case_id, opened_at for case": count, rows).
        rejected: dict[str, int] = {}
        for reason, detail in f["rejected"].items():
            table = reason.rsplit(" for ", 1)[-1]
            rejected[table] = rejected.get(table, 0) + int(detail["count"])
        for table in set(f["stored"]) | set(f["filtered"]) | set(rejected):
            accounted = f["stored"].get(table, 0) + f["filtered"].get(table, 0) + rejected.get(table, 0)
            assert accounted == f["rows_read"], f"{f['file']} -> {table}: {accounted} of {f['rows_read']} rows"


def test_6_the_report_says_which_rules_can_and_cannot_be_assessed(conformed):
    coverage = conformed["result"]["rule_coverage"][ENTITY]
    states = [set(coverage[k]) for k in ("assessed", "not_assessed", "degraded")]
    named = set().union(*states)
    assert sum(len(x) for x in states) == len(named), "a rule is in two states at once"
    # A rule that cannot be assessed names the tables it lacks; a degraded one, the empty columns.
    assert all(coverage["not_assessed"][rule] for rule in coverage["not_assessed"])
    assert all(coverage["degraded"][rule] for rule in coverage["degraded"])
    assert named == ALL_RULES, f"rules not accounted for: {sorted(ALL_RULES - named)}"
