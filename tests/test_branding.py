"""Configurable branding (docs/product_brief.md section 1: "Product branding must be configurable
and must not imply government endorsement").

Neither portal names an organisation unless the deployment configured one; the name is set at
first-run setup or with `satsa deployment brand`, audited, and shown in page chrome and reports.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from deploy_utils import copy_deployment
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from satsa.api import routes
from satsa.deployment import SetupError, branding, set_branding
from satsa.store.sqlite import SQLiteStore

TEMPLATES = Path(routes.__file__).resolve().parents[1]
# What may still say NCIIPC in a template: stored role names (option values and comparisons),
# the demonstration accounts' published names, and internal identifiers no one reads.
ALLOWED = re.compile(
    r"value=\"NCIIPC [A-Za-z ]+\"|'NCIIPC [A-Za-z ]+'|NCIIPC_[A-Z_]+|nciipc_admin|ChangeMe-NCIIPC#2026"
    r"|nciipc_theme|nciipc[A-Z][A-Za-z]+\(|<!--.*?-->"
)


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    store = SQLiteStore("data/satsa.db")
    try:
        set_branding(store, "", actor="test")  # start from neutral wording
    finally:
        store.close()
    return root


def _analyst() -> TestClient:
    c = TestClient(routes.app)
    assert c.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                  follow_redirects=False).status_code == 303
    return c


def test_no_template_hard_codes_an_organisation():
    offenders = []
    for path in sorted(TEMPLATES.glob("**/templates/*.html")):
        text = ALLOWED.sub("", path.read_text(encoding="utf-8"))
        for n, line in enumerate(text.splitlines(), start=1):
            if "NCIIPC" in line or "National Critical Information Infrastructure" in line:
                offenders.append(f"{path.name}:{n}: {line.strip()[:100]}")
    assert offenders == []


def test_without_a_configured_name_the_wording_is_neutral(deployment):
    assert branding(values={}) == {"org": "", "prefix": "", "authority": "the supervisory authority",
                                   "admin_portal": "Administration Portal", "deployment_name": ""}
    page = _analyst().get("/portfolio").text
    assert "NCIIPC Analyst" not in page and ">Analyst<" in page
    from satsa.admin.app import app as admin_app

    with TestClient(admin_app) as portal:
        login = portal.get("/login").text
    assert "<title>Administration Login</title>" in login and "<h1>Control Portal</h1>" in login
    assert "Supervisory Analytics Tool for SOC Assessment" in login


def test_a_configured_name_appears_in_both_portals_and_is_audited(deployment):
    store = SQLiteStore("data/satsa.db")
    try:
        brand = set_branding(store, "  Example   Authority ", actor="test-admin")
        audit = store.conn.execute("SELECT details_json FROM audit_log WHERE action = 'branding_changed' "
                                   "ORDER BY rowid DESC LIMIT 1").fetchone()[0]
    finally:
        store.close()
    assert brand["org"] == "Example Authority" and brand["admin_portal"] == "Example Authority Administration Portal"
    assert '"after": "Example Authority"' in audit
    page = _analyst().get("/portfolio").text
    assert "Example Authority Analyst" in page
    from satsa.admin.app import app as admin_app

    with TestClient(admin_app) as portal:
        login = portal.get("/login").text
    assert "<title>Example Authority Administration Login</title>" in login
    assert "<p>Example Authority</p>" in login


@pytest.mark.parametrize("bad", ["<script>", "a" * 81, "{{ 7*7 }}", "back\\slash"])
def test_a_name_with_markup_or_too_long_is_refused(deployment, bad):
    store = SQLiteStore("data/satsa.db")
    try:
        with pytest.raises(SetupError):
            set_branding(store, bad, actor="test")
        assert branding(store)["org"] == ""
    finally:
        store.close()


def test_the_portfolio_pdf_title_carries_the_configured_name(deployment):
    from satsa.report.generator import ReportGenerator
    from satsa.store.duckdb import DuckDBStore

    duck, store = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    try:
        gen = ReportGenerator(duck, store)
        assert gen._brand_title("SUPERVISORY PORTFOLIO REPORT") == "SUPERVISORY PORTFOLIO REPORT"
        set_branding(store, "Example & Co", actor="test")
        assert gen._brand_title("SUPERVISORY PORTFOLIO REPORT") == "EXAMPLE &amp; CO  |  SUPERVISORY PORTFOLIO REPORT"
    finally:
        duck.close()
        store.close()


def test_the_cli_sets_and_clears_the_name(deployment):
    from satsa.cli import app

    runner = CliRunner()
    done = runner.invoke(app, ["deployment", "brand", "--organisation", "Example Authority", "--actor", "ops"])
    assert done.exit_code == 0, done.output
    assert "Example Authority Administration Portal" in done.output
    cleared = runner.invoke(app, ["deployment", "brand", "--organisation", "", "--actor", "ops"])
    assert cleared.exit_code == 0 and "Portals now show: Administration Portal" in cleared.output
    refused = runner.invoke(app, ["deployment", "brand", "--organisation", "<b>x</b>", "--actor", "ops"])
    assert refused.exit_code == 1
