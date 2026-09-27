"""Test robust statistics, SPC, peer grouping, and DuckDB SQL metrics."""

from satsa.metrics.engine import MetricsEngine
from satsa.models.canonical import Entity
from satsa.peers.grouping import PeerResolver
from satsa.peers.robust_stats import RobustStats
from satsa.peers.spc import SPCDetector
from satsa.store.duckdb import DuckDBStore


def test_robust_statistics():
    data = [10.0, 12.0, 11.0, 13.0, 12.0, 100.0]  # Outlier 100
    med = RobustStats.median(data)
    mad = RobustStats.mad(data)
    assert med == 12.0
    assert mad == 1.0

    # Test robust z-score
    z_normal = RobustStats.robust_z_score(12.0, data)
    assert z_normal == 0.0
    z_outlier = RobustStats.robust_z_score(100.0, data)
    assert z_outlier > 50.0  # Massive z-score for outlier

    # Test percentile rank
    rank = RobustStats.percentile_rank(12.0, data)
    assert 40.0 <= rank <= 60.0

    _p25, _p50, _p75, iqr = RobustStats.iqr_bounds(data)
    assert iqr > 0


def test_spc_cusum_and_ewma():
    # Normal series followed by sudden downward shift
    normal_series = [100.0, 102.0, 98.0, 101.0, 99.0, 100.0, 103.0]
    dropped_series = [15.0, 14.0, 16.0, 15.0, 12.0]
    full_series = normal_series + dropped_series

    _, _, cusum_alarms = SPCDetector.cusum(full_series, threshold_h=3.0)
    assert len(cusum_alarms) > 0
    # Alarms should trigger after index 6 (during the drop)
    assert any(idx >= 7 for idx in cusum_alarms)

    _, _, ewma_alarms = SPCDetector.ewma(full_series)
    assert len(ewma_alarms) > 0


def test_peer_resolver():
    resolver = PeerResolver("config/peers.yaml")
    entities = [
        Entity(entity_id="CSE-01", name="E1", sector="power", size_band="large"),
        Entity(entity_id="CSE-02", name="E2", sector="banking", size_band="large"),
        Entity(entity_id="CSE-03", name="E3", sector="telecom", size_band="large"),
        Entity(entity_id="CSE-04", name="E4", sector="oil_and_gas", size_band="medium"),
        Entity(entity_id="CSE-06", name="E6", sector="power", size_band="medium"),
    ]
    target = entities[0]  # CSE-01 (power, large)
    peers, _cohort, is_weak = resolver.resolve_peers(target, entities)
    # Not enough power entities (only 1 other power entity), so falls back to all_sectors_large or all_entities_broad
    assert is_weak is True
    assert len(peers) >= 1


def test_metrics_engine_on_ingested_data():
    store = DuckDBStore("data")
    store.load_all_tables()
    engine = MetricsEngine(store)

    timing_df = engine.compute_timing_metrics()
    assert timing_df.shape[0] > 0

    wf_df = engine.compute_workflow_metrics()
    assert wf_df.shape[0] > 0

    sweep = engine.compute_metric_sweep()
    assert len(sweep) > 0
    # Check that ~50+ metrics computed per entity
    first_ent = next(iter(sweep.keys()))
    assert len(sweep[first_ent]) >= 30
    store.close()
