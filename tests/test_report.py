"""Tests for supervisory report generation module."""

from pathlib import Path

from satsa.report.generator import ReportGenerator
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def test_report_generation(tmp_path: Path):
    duckdb_store = DuckDBStore("data")
    duckdb_store.load_all_tables()
    sqlite_store = SQLiteStore("data/satsa.db")

    generator = ReportGenerator(duckdb_store, sqlite_store)

    # 1. Test entity HTML
    html_file = tmp_path / "CSE-02_report.html"
    res_html = generator.generate_entity_html("CSE-02", html_file)
    assert res_html.exists()
    content = res_html.read_text(encoding="utf-8")
    assert "CSE-02" in content
    assert (
        "indicators requiring supervisory review; not a compliance determination" in content.lower()
    )

    # 2. Test entity PDF
    pdf_file = tmp_path / "CSE-02_report.pdf"
    res_pdf = generator.generate_entity_pdf("CSE-02", pdf_file)
    assert res_pdf.exists()
    assert res_pdf.stat().st_size > 500

    # 3. Test portfolio HTML
    portfolio_file = tmp_path / "portfolio.html"
    res_port = generator.generate_portfolio_html(portfolio_file)
    assert res_port.exists()
    port_content = res_port.read_text(encoding="utf-8")
    assert "National SOC Supervisory Portfolio Report" in port_content
    assert (
        "indicators requiring supervisory review; not a compliance determination"
        in port_content.lower()
    )

    # 4. Test CSV exports
    f_csv = tmp_path / "findings.csv"
    generator.export_findings_csv(f_csv)
    assert f_csv.exists()
    assert f_csv.stat().st_size > 0

    q_csv = tmp_path / "queue.csv"
    generator.export_queue_csv(q_csv)
    assert q_csv.exists()
    assert q_csv.stat().st_size > 0

    m_csv = tmp_path / "metrics.csv"
    generator.export_metrics_csv(m_csv)
    assert m_csv.exists()

    duckdb_store.close()
    sqlite_store.close()
