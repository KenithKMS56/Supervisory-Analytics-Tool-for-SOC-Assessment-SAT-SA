"""Every portfolio chart has a table with the same figures (docs/product_brief.md section 9:
"readable chart/table alternatives"), so the page does not depend on seeing colours."""

from __future__ import annotations

import re
import sqlite3

from fastapi.testclient import TestClient

from satsa.api.routes import app

ROW = re.compile(r'<tr><th scope="row"><a href="/entity/([^"]+)">[^<]+</a></th>(.*?)</tr>', re.DOTALL)
CELL = re.compile(r"<td>(.*?)</td>", re.DOTALL)
DOMAINS = ["Threat Detection", "Investigation", "Escalation", "Incident Response", "Security Operations",
           "Governance and Oversight", "Operational Discipline", "Cyber Resilience"]


def _page() -> str:
    c = TestClient(app)
    assert c.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                  follow_redirects=False).status_code == 303
    return c.get("/portfolio").text


def test_the_heatmap_table_holds_the_runs_domain_scores():
    html = _page()
    assert 'id="portfolioHeatmap" role="img"' in html and "Show the domain scores as a table" in html
    block = html[html.index("Show the domain scores as a table"):]
    block = block[: block.index("</details>")]
    rows = {eid: [c.strip() for c in CELL.findall(cells)] for eid, cells in ROW.findall(block)}
    assert rows, "the table lists the entities"

    conn = sqlite3.connect("file:data/satsa.db?mode=ro", uri=True)
    try:
        run_id = conn.execute("SELECT run_id FROM runs WHERE status = 'completed' ORDER BY created_at DESC LIMIT 1").fetchone()[0]
        scores = {(e, d): s for e, d, s in conn.execute(
            "SELECT entity_id, domain, score FROM domain_scores WHERE run_id = ?", (run_id,))}
    finally:
        conn.close()
    checked = 0
    for eid, cells in rows.items():
        assert len(cells) == len(DOMAINS), eid
        for domain, cell in zip(DOMAINS, cells, strict=True):
            stored = scores.get((eid, domain))
            if stored is None:
                assert "not assessed" in cell, (eid, domain, cell)
            else:
                assert cell == str(round(stored, 1)), (eid, domain, cell, stored)
                checked += 1
    assert checked > 0


def test_the_trend_chart_has_a_table_when_there_is_a_trend():
    html = _page()
    if 'id="trajectoryChart"' not in html:
        assert "Insufficient historical data" in html  # no chart, so no table is owed
        return
    assert 'id="trajectoryChart" role="img"' in html and "Show the trend as a table" in html
    block = html[html.index("Show the trend as a table"):]
    block = block[: block.index("</details>")]
    assert re.search(r'<th scope="row">[^<]+</th>(<td>[^<]*</td>)+', block)
