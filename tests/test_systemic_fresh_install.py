"""Cross-entity (systemic) findings must fire on a FRESH install, and survive re-ingestion.

The shared-MSSP systemic finding is exactly the kind of feature that can quietly
depend on state accumulated in a long-lived dev database. These tests start from
empty temp stores: generate-data -> ingest -> run, and assert the finding fires
on the very first run. A second test re-ingests the same submission plus a
partial entity record (no soc_provider) -- the pattern that broke the systemic
finding in a long-lived dev DB during the hardening baseline, where each entity
partition had accumulated a second row with soc_provider=None and the row that
won on load was arbitrary.
"""

from pathlib import Path

import polars as pl
import pytest

from satsa.ingest.pipeline import IngestionPipeline
from satsa.rules.systemic import SystemicCorrelationDetector
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.synth.generator import SYSTEMIC_MSSP_GROUP, SYSTEMIC_MSSP_PROVIDER, SyntheticDataGenerator


@pytest.fixture(scope="module")
def fresh_dataset(tmp_path_factory):
    root = tmp_path_factory.mktemp("fresh_install")
    csv_dir, _ = SyntheticDataGenerator(seed=42, base_alerts_per_entity=1500).save_dataset(root / "generated")
    return root, Path(csv_dir)


def _fresh_stores(root: Path, name: str):
    store_dir = root / name
    assert not store_dir.exists(), "must start from a clean store"
    return DuckDBStore(store_dir), SQLiteStore(store_dir / "satsa.db")


def _assert_mssp_systemic_finding(sqlite_store: SQLiteStore, run_id: str) -> None:
    findings = sqlite_store.get_systemic_findings(run_id)
    assert findings, "expected a systemic finding on the first run of a fresh install"
    min_count = SystemicCorrelationDetector().min_entity_count
    for f in findings:
        assert f["shared_value"] != "internal"
        assert f["entity_count"] >= min_count == 3
    meridian = [f for f in findings if f["shared_value"] == SYSTEMIC_MSSP_PROVIDER]
    assert meridian, f"no systemic finding for {SYSTEMIC_MSSP_PROVIDER}"
    assert set(SYSTEMIC_MSSP_GROUP) <= set(meridian[0]["entity_ids"])


def test_systemic_finding_fires_on_first_run_of_fresh_install(fresh_dataset):
    root, csv_dir = fresh_dataset
    duck, lite = _fresh_stores(root, "store_first_run")
    assert lite.conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 0

    res = IngestionPipeline(duck, lite).ingest_directory(csv_dir)
    assert res["status"] == "success"
    run = AssessmentRunner(duck, lite).run_assessment(period="2026-Q1")
    assert run["status"] == "success"
    assert run["systemic_findings_count"] >= 1
    assert lite.conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 1  # truly the first run
    _assert_mssp_systemic_finding(lite, run["run_id"])
    duck.close()
    lite.close()


def test_systemic_finding_survives_reingest_with_partial_entity_rows(fresh_dataset):
    root, csv_dir = fresh_dataset
    duck, lite = _fresh_stores(root, "store_reingest")
    pipeline = IngestionPipeline(duck, lite)
    assert pipeline.ingest_directory(csv_dir)["status"] == "success"
    assert pipeline.ingest_directory(csv_dir)["status"] == "success"  # same submission again

    # A later partial record for existing entities that omits soc_provider (as
    # e.g. an entity re-registration or a thinner upload would) must not blank
    # out -- or randomly override -- the provider recorded earlier.
    partial = pl.DataFrame(
        [{"entity_id": eid, "name": f"{eid} (renamed)", "sector": "banking", "size_band": "large"}
         for eid in SYSTEMIC_MSSP_GROUP]
    )
    duck.write_partitioned_parquet("entity", partial)

    for eid in SYSTEMIC_MSSP_GROUP:
        part = root / "store_reingest" / "parquet" / "entity" / f"entity_id={eid}" / "data.parquet"
        rows = pl.read_parquet(part)
        assert rows.height == 1, f"{eid}: entity partition must hold exactly one row"
        assert rows["soc_provider"][0] == SYSTEMIC_MSSP_PROVIDER
        assert rows["name"][0] == f"{eid} (renamed)"  # newer non-null values do win

    run = AssessmentRunner(duck, lite).run_assessment(period="2026-Q1")
    _assert_mssp_systemic_finding(lite, run["run_id"])
    duck.close()
    lite.close()
