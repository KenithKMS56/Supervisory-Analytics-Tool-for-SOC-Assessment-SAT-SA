"""The finding page answers, in order: what was found, why it matters, the evidence, how far to
trust it, and what to check next.

Checked for one finding of every rule that has a finding in the latest run of the test data, as
an examiner sees it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape
from reportlab import rl_config

from satsa.api import routes
from satsa.api.routes import app
from satsa.explain.finding_card import WHY_IT_MATTERS
from satsa.report.generator import ReportGenerator
from satsa.rules.registry import RuleRegistry
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

SECTIONS = ["1. What was found", "2. Why it matters", "3. Evidence", "4. Confidence and limitations", "5. Next step"]


def _examiner() -> TestClient:
    client = TestClient(app)
    resp = client.post(
        "/login", data={"username": "examiner", "password": "ChangeMe-Examiner#2026"}, follow_redirects=False
    )
    assert resp.status_code == 303, resp.text
    return client


def _one_finding_per_rule() -> dict[str, sqlite3.Row]:
    conn = sqlite3.connect("data/satsa.db")
    conn.row_factory = sqlite3.Row
    try:
        run = conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
        assert run is not None, "the test data has no assessment run"
        rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY rule_id, finding_id", (run["run_id"],)
        ).fetchall()
        evidence = {
            r["finding_id"]: r["record_id"]
            for r in conn.execute("SELECT finding_id, record_id FROM finding_evidences ORDER BY rowid DESC")
        }
    finally:
        conn.close()
    picked: dict[str, sqlite3.Row] = {}
    for row in rows:
        picked.setdefault(row["rule_id"], row)
    return {rule: row for rule, row in picked.items() if row["finding_id"] in evidence}


FINDINGS = _one_finding_per_rule()


def test_the_test_data_covers_most_rules():
    assert len(FINDINGS) >= 15, sorted(FINDINGS)


def test_every_rule_has_a_why_it_matters_statement():
    registered = set(RuleRegistry().rules)
    assert set(WHY_IT_MATTERS) == registered
    for rule_id, text in WHY_IT_MATTERS.items():
        assert len(text) > 60 and text.endswith("."), rule_id


@pytest.mark.parametrize("rule_id", sorted(FINDINGS))
def test_finding_page_has_the_five_sections_in_order(rule_id):
    finding = FINDINGS[rule_id]
    resp = _examiner().get(f"/finding/{finding['finding_id']}")
    assert resp.status_code == 200
    html = resp.text
    positions = [html.find(f"<span>{title}") for title in SECTIONS]
    assert all(p >= 0 for p in positions), dict(zip(SECTIONS, positions, strict=True))
    assert positions == sorted(positions)
    found, why, evidence, confidence, next_step = (
        html[a:b] for a, b in zip(positions, positions[1:] + [len(html)], strict=True)
    )
    assert str(escape(finding["rationale"])) in found
    assert str(escape(WHY_IT_MATTERS[rule_id])) in why
    conn = sqlite3.connect("data/satsa.db")
    try:
        record_ids = [r[0] for r in conn.execute(
            "SELECT record_id FROM finding_evidences WHERE finding_id = ?", (finding["finding_id"],)
        )]  # fmt: skip
    finally:
        conn.close()
    assert record_ids and all(str(escape(rid)) in evidence for rid in record_ids)
    assert 'id="rule-parameters"' in evidence or "No parameters are configured" in evidence
    assert 'id="config-status"' in evidence
    assert f"{round(finding['confidence'] * 100)}%" in confidence
    assert str(escape(finding["examiner_check"])) in next_step


def test_parameters_are_the_rules_and_the_page_says_whether_the_run_used_them(tmp_path, monkeypatch):
    rule_id = "EG01" if "EG01" in FINDINGS else min(FINDINGS)
    finding = FINDINGS[rule_id]
    params = RuleRegistry().get_rule(rule_id).params
    assert params, f"{rule_id} has no parameters to show"
    conn = sqlite3.connect("data/satsa.db")
    try:
        (run_hash,) = conn.execute("SELECT config_hash FROM runs WHERE run_id = ?", (finding["run_id"],)).fetchone()
    finally:
        conn.close()

    client = _examiner()
    page = client.get(f"/finding/{finding['finding_id']}").text
    for name, value in params.items():
        assert f"<td>{escape(name)}</td><td><code>{escape(str(value))}</code></td>" in page
    unchanged = routes._config_status(run_hash)["unchanged"]
    assert ("unchanged since the run" in page) is unchanged

    # The same page against a configuration that differs from the run's.
    changed = tmp_path / "rules.yaml"
    changed.write_bytes(Path("config/rules.yaml").read_bytes() + b"\n# edited after the run\n")
    monkeypatch.setattr(routes, "RULES_CONFIG_PATH", changed)
    page = client.get(f"/finding/{finding['finding_id']}").text
    assert "has changed since this run" in page and "unchanged since the run" not in page
    assert run_hash in page


def test_the_finding_pdf_states_why_it_matters(tmp_path, monkeypatch):
    monkeypatch.setattr(rl_config, "pageCompression", 0)  # text readable in the file
    rule_id = min(FINDINGS)
    duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    try:
        duck.load_all_tables()
        pdf = ReportGenerator(duck, sql).generate_finding_pdf(FINDINGS[rule_id]["finding_id"], tmp_path / "f.pdf")
        data = pdf.read_bytes()
    finally:
        duck.close()
        sql.close()
    assert b"Why it matters" in data
    first_words = " ".join(WHY_IT_MATTERS[rule_id].split()[:4])
    assert first_words.encode() in data
