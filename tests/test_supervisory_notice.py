"""Wherever a finding is shown or exported, it says what it is: an indicator requiring
supervisory review, not a compliance determination.

Swept over every page of the web app, every page of every PDF, the HTML reports, and the
JSON and CSV exports. The notice used to be on the finding page and the HTML reports only.
"""

import csv
import io
import re

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from reportlab import rl_config
from route_utils import iter_routes

from satsa import FINDING_NOTICE, SUPERVISORY_NOTICE
from satsa.api.routes import app
from satsa.explain.finding_card import FindingCard
from satsa.report.generator import ReportGenerator
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

PASSWORDS = {"analyst": "ChangeMe-Analyst#2026", "examiner": "ChangeMe-Examiner#2026"}


@pytest.fixture(autouse=True)
def _uncompressed_pdfs(monkeypatch):
    monkeypatch.setattr(rl_config, "pageCompression", 0)  # so PDF text can be read in the bytes


@pytest.fixture(scope="module")
def clients():
    out = {}
    for role, password in PASSWORDS.items():
        c = TestClient(app)
        r = c.post("/login", data={"username": role, "password": password}, follow_redirects=False)
        assert r.status_code == 303 and "error" not in r.headers["location"]
        out[role] = c
    return out


@pytest.fixture(scope="module")
def ids():
    store = SQLiteStore("data/satsa.db")
    row = store.conn.execute(
        "SELECT finding_id, entity_id, run_id FROM findings ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    store.close()
    assert row, "bootstrapped data required (satsa generate-data / ingest / run)"
    return dict(row)


def test_the_two_wordings():
    assert SUPERVISORY_NOTICE == "Indicators requiring supervisory review; not a compliance determination."
    assert FINDING_NOTICE == "Indicator requiring supervisory review; not a compliance determination."
    assert FindingCard.model_fields["statutory_wording"].default == FINDING_NOTICE


def _html_pages() -> list[str]:
    """Every GET route of the web app that renders a page."""
    pages = []
    for path, route in iter_routes(app.routes):
        if not isinstance(route, APIRoute) or "GET" not in route.methods:
            continue
        if path.startswith(("/api/", "/reports/", "/templates/", "/docs", "/openapi", "/tuning/export-pack")):
            continue
        pages.append(path)
    return sorted(set(pages))


def test_every_page_of_the_web_app_carries_the_notice(clients, ids):
    pages = _html_pages()
    # The pages that list or describe findings are all in the sweep.
    assert {"/portfolio", "/entity/{entity_id}", "/finding/{finding_id}", "/queue", "/blind-review"} <= set(pages)
    checked = 0
    for role, client in clients.items():
        for page in pages:
            url = page.replace("{entity_id}", ids["entity_id"]).replace("{finding_id}", ids["finding_id"])
            response = client.get(url)
            if response.status_code == 403:
                continue  # not this role's page
            assert response.status_code == 200, (role, url, response.status_code)
            assert "text/html" in response.headers["content-type"], url
            assert SUPERVISORY_NOTICE in response.text, f"{url} ({role}) shows no supervisory notice"
            checked += 1
    assert checked >= 20
    # Signed out as well: the login and welcome pages.
    for url in ("/login", "/splash"):
        assert SUPERVISORY_NOTICE in TestClient(app).get(url).text, url


def test_finding_page_states_it_for_the_finding_itself(clients, ids):
    html = clients["examiner"].get(f"/finding/{ids['finding_id']}").text
    assert f"<strong>Supervisory Notice:</strong> {FINDING_NOTICE}" in html


def test_json_exports_carry_the_notice_on_every_record(clients):
    for url in ("/api/v1/findings", "/api/v1/queue"):
        records = clients["examiner"].get(url).json()
        assert records, url
        assert all(r["supervisory_notice"] == FINDING_NOTICE for r in records), url


def test_csv_exports_carry_the_notice_on_every_row(clients):
    for url in ("/reports/export/findings-csv", "/reports/export/queue-csv", "/api/v1/export/queue.csv"):
        response = clients["analyst"].get(url)
        assert response.status_code == 200, url
        rows = list(csv.DictReader(io.StringIO(response.text)))
        assert rows, url
        assert all(r["supervisory_notice"] == FINDING_NOTICE for r in rows), url


def test_html_reports_carry_the_notice(clients, ids):
    for url in ("/reports/portfolio/html", f"/reports/entity/{ids['entity_id']}/html"):
        response = clients["examiner"].get(url)
        assert response.status_code == 200, url
        assert SUPERVISORY_NOTICE in response.text, url


def test_every_page_of_every_pdf_carries_the_notice(ids, tmp_path):
    duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    duck.load_all_tables()
    try:
        generator = ReportGenerator(duck, sql)
        pdfs = {
            "portfolio": generator.generate_portfolio_pdf(tmp_path / "p.pdf", ids["run_id"]),
            "entity": generator.generate_entity_pdf(ids["entity_id"], tmp_path / "e.pdf", ids["run_id"]),
            "finding": generator.generate_finding_pdf(ids["finding_id"], tmp_path / "f.pdf"),
        }
    finally:
        duck.close()
        sql.close()
    for name, path in pdfs.items():
        data = path.read_bytes()
        pages = len(re.findall(rb"/Type /Page[^s]", data))
        notices = data.count(f"({SUPERVISORY_NOTICE})".encode())
        assert pages >= 1 and notices == pages, f"{name} PDF: {notices} notices on {pages} pages"


def test_pdfs_served_by_the_app_carry_the_notice(clients, ids):
    for url in (
        "/reports/portfolio/pdf",
        f"/reports/entity/{ids['entity_id']}/pdf",
        f"/reports/finding/{ids['finding_id']}/pdf",
    ):
        response = clients["examiner"].get(url)
        assert response.status_code == 200, url
        assert f"({SUPERVISORY_NOTICE})".encode() in response.content, url


def test_no_page_claims_a_legal_basis_the_project_cannot_cite(clients, ids):
    """Wording removed after the legal traceability review (docs/legal_traceability.md): UI text
    attributed requirements to a rule and a section that do not say them."""
    for role, client in clients.items():
        for page in _html_pages():
            url = page.replace("{entity_id}", ids["entity_id"]).replace("{finding_id}", ids["finding_id"])
            response = client.get(url)
            if response.status_code != 200:
                continue
            for claim in ("Rule 3 of NCIIPC Rules", "Section 70A evidence standards", "under Sec 70A", "Section 70A Registry"):
                assert claim not in response.text, (role, url, claim)
