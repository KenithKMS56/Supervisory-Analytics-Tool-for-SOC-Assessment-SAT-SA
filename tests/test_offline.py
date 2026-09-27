"""Air-gap verification test: ensures no non-loopback network access occurs."""

import socket
from pathlib import Path

import pytest

from satsa.report.generator import ReportGenerator
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore
from satsa.validate.harness import ValidationHarness


@pytest.fixture(autouse=False)
def airgap_socket_guard(monkeypatch):
    """Intercept all socket connections and fail if any target is non-loopback."""
    orig_connect = socket.socket.connect

    def guarded_connect(self, address):
        if isinstance(address, tuple):
            host = address[0]
        else:
            host = str(address)

        allowed_loopbacks = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
        if host not in allowed_loopbacks:
            raise ConnectionRefusedError(
                f"Air-gap violation! Attempted outbound network connection to '{host}'."
            )
        return orig_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


def test_airgap_guard_blocks_external(airgap_socket_guard):
    """Verify that socket guard correctly catches external network requests."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(ConnectionRefusedError, match="Air-gap violation"):
        s.connect(("8.8.8.8", 53))
    s.close()


def test_full_pipeline_airgapped(airgap_socket_guard, tmp_path: Path):
    """Verify that end-to-end evaluation, scoring, reporting, and validation run 100% offline."""
    duckdb_store = DuckDBStore("data")
    duckdb_store.load_all_tables()
    sqlite_store = SQLiteStore("data/satsa.db")

    # 1. Assessment Runner
    runner = AssessmentRunner(duckdb_store, sqlite_store)
    res = runner.run_assessment(period="2026-Q1")
    assert res["status"] == "success"

    # 2. Report Generation
    rep_gen = ReportGenerator(duckdb_store, sqlite_store)
    html_out = tmp_path / "CSE-03_test.html"
    rep_gen.generate_entity_html("CSE-03", html_out)
    assert html_out.exists()

    pdf_out = tmp_path / "CSE-03_test.pdf"
    rep_gen.generate_entity_pdf("CSE-03", pdf_out)
    assert pdf_out.exists()

    # 3. Validation Harness
    harness = ValidationHarness(duckdb_store, sqlite_store, "data/generated/ground_truth.json")
    val_res = harness.run_full_validation(res["run_id"])
    assert val_res["rule_detection"]["overall_recall"] >= 0.9
    assert val_res["audit"]["audit_chain_valid"] is True

    duckdb_store.close()
    sqlite_store.close()
