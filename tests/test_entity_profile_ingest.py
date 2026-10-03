"""A submitted entity profile survives ingest (regression; found by the independent generator).

The pipeline registers a default record for each entity it has not seen before. It used to append
those defaults AFTER the submitted entity rows; the entity table keeps the newest non-null value per
column, so on a fresh store every submitted name, sector, size band and SOC model was replaced by
"<id> Operations" / "General Infrastructure" / "Medium" / "inhouse", and every entity fell into one
peer cohort.
"""

import csv

from satsa.ingest.pipeline import IngestionPipeline
from satsa.models.canonical import Entity
from satsa.peers.grouping import PeerResolver
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def _write(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _alert(eid, n):
    return {"entity_id": eid, "alert_id": f"A-{eid}-{n}", "rule_id": "R1", "category": "Malware",
            "severity_orig": "low", "severity_final": "low", "asset_id": "H1",
            "created_at": "2026-04-02T10:00:00", "closed_at": "2026-04-02T11:00:00",
            "closed_by": "op1", "closed_by_type": "human", "disposition": "benign", "status": "closed"}


def test_submitted_entity_profile_is_kept_and_unknown_entities_get_defaults(tmp_path):
    src = tmp_path / "csv"
    src.mkdir()
    _write(src / "entity.csv", [
        {"entity_id": "ORG-1", "name": "Grid One", "sector": "power", "size_band": "large",
         "soc_model": "mssp", "soc_provider": "MSSP-X", "timezone": "UTC", "declared_shift_hours": "24x7"},
        {"entity_id": "ORG-2", "name": "Bank Two", "sector": "banking", "size_band": "small",
         "soc_model": "hybrid", "soc_provider": "internal", "timezone": "UTC", "declared_shift_hours": "24x7"},
    ])
    # ORG-3 appears only in the alerts: it gets the default profile.
    _write(src / "alert.csv", [_alert("ORG-1", 1), _alert("ORG-2", 1), _alert("ORG-3", 1)])
    duck, sql = DuckDBStore(tmp_path / "store"), SQLiteStore(tmp_path / "store" / "t.db")
    try:
        IngestionPipeline(duck, sql).ingest_directory(src)
        duck.load_all_tables()
        rows = {r["entity_id"]: r for r in duck.query("SELECT * FROM entity").iter_rows(named=True)}
        assert (rows["ORG-1"]["name"], rows["ORG-1"]["sector"], rows["ORG-1"]["size_band"], rows["ORG-1"]["soc_model"]) == (
            "Grid One", "power", "large", "mssp")
        assert (rows["ORG-2"]["sector"], rows["ORG-2"]["size_band"]) == ("banking", "small")
        assert rows["ORG-3"]["sector"] == "General Infrastructure"
        # The peer resolver now sees distinct sectors, not one cohort for everybody.
        ents = [Entity(**r) for r in rows.values()]
        _, label, _ = PeerResolver().resolve_peers(next(e for e in ents if e.entity_id == "ORG-1"), ents)
        assert "General Infrastructure" not in label
    finally:
        duck.close()
        sql.close()


def test_reingesting_the_same_entity_keeps_its_profile(tmp_path):
    src = tmp_path / "csv"
    src.mkdir()
    _write(src / "entity.csv", [{"entity_id": "ORG-1", "name": "Grid One", "sector": "power", "size_band": "large",
                                  "soc_model": "inhouse", "soc_provider": "internal", "timezone": "UTC",
                                  "declared_shift_hours": "24x7"}])
    _write(src / "alert.csv", [_alert("ORG-1", 1)])
    duck, sql = DuckDBStore(tmp_path / "store"), SQLiteStore(tmp_path / "store" / "t.db")
    try:
        pipeline = IngestionPipeline(duck, sql)
        pipeline.ingest_directory(src)
        _write(src / "alert.csv", [_alert("ORG-1", 2)])
        (src / "entity.csv").unlink()
        pipeline.ingest_directory(src)  # a later batch without the entity file
        duck.load_all_tables()
        row = duck.query("SELECT * FROM entity WHERE entity_id = 'ORG-1'").to_dicts()[0]
        assert (row["name"], row["sector"]) == ("Grid One", "power")
    finally:
        duck.close()
        sql.close()
