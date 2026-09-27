"""Tests for offline packaging, rule signer, and benchmark modules."""

from pathlib import Path

from satsa.bench.benchmark import BenchmarkRunner
from satsa.bundle.packager import OfflinePackager
from satsa.bundle.rules_signer import RulePackSigner
from satsa.store.sqlite import SQLiteStore


def test_offline_packager(tmp_path: Path):
    packager = OfflinePackager()
    archive = packager.create_bundle(output_tar=True)
    assert archive.exists()
    assert archive.stat().st_size > 1000
    assert (packager.bundle_dir / "Containerfile").exists()
    assert (packager.bundle_dir / "README_OFFLINE.md").exists()


def test_rule_pack_sign_and_verify(tmp_path: Path):
    sqlite_store = SQLiteStore("data/satsa.db")
    signer = RulePackSigner(default_secret="TEST_SECRET_2026")

    # Export
    out_tar = tmp_path / "rules_export.tar.gz"
    res_path = signer.export_rule_pack(
        config_dir="config", output_path=out_tar, version="2.0.0", secret_key="TEST_SECRET_2026"
    )
    assert res_path.exists()

    # Import into target dir
    target_dir = tmp_path / "imported_config"
    res_imp = signer.import_rule_pack(
        out_tar,
        target_config_dir=target_dir,
        secret_key="TEST_SECRET_2026",
        sqlite_store=sqlite_store,
    )
    assert res_imp["status"] == "success"
    assert res_imp["verified"] is True
    assert (target_dir / "rules.yaml").exists()

    sqlite_store.close()


def test_benchmark_runner():
    bench = BenchmarkRunner("data")
    res_col = bench.run_columnar_scan_benchmark([10_000])
    assert len(res_col) == 1
    assert res_col[0]["throughput_rows_per_sec"] > 100_000

    e2e = bench.run_end_to_end_assessment_benchmark()
    assert e2e["throughput_alerts_per_sec"] > 500
