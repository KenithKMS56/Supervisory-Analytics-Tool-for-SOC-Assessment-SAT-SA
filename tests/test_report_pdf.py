"""PDF reporting layer: plain-language headlines, real-data PDFs, pagination and route errors.

PDFs are built uncompressed (rl_config.pageCompression = 0) so their text can be
checked in the raw bytes without adding a PDF-parsing dependency.
"""

import inspect
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from reportlab import rl_config
from reportlab.platypus import Flowable

import satsa.api.routes as satsa_routes
from satsa.api.routes import app as satsa_app
from satsa.report.generator import ReportGenerator, ReportNotFoundError
from satsa.report.pdf_layout import RunMeta, build_pdf
from satsa.report.plain_language import (
    HEADLINES,
    action_for,
    headline,
    paired_comparison,
)
from satsa.rules.registry import RuleRegistry
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

A4_MEDIABOX = (b"595.2756", b"841.8898")
GAP_CAPTION = b"The gap between the two bars is the finding."


@pytest.fixture(autouse=True)
def _uncompressed(monkeypatch):
    monkeypatch.setattr(rl_config, "pageCompression", 0)


def _page_count(pdf: bytes) -> int:
    return len(re.findall(rb"/Type /Page[^s]", pdf))


# --------------------------------------------------------------- headlines


def _sample(key: str):
    if key == "missing_categories":
        return ["Malware", "Phishing"]
    if key.endswith(("share", "rate", "ratio", "average")):
        return 0.4321
    return 17


def test_every_registered_rule_has_a_headline_template():
    rule_ids = {cls.id for cls in RuleRegistry.RULE_CLASSES}
    assert len(rule_ids) == 20
    assert rule_ids == set(HEADLINES)


@pytest.mark.parametrize("cls", RuleRegistry.RULE_CLASSES, ids=lambda c: c.id)
def test_headline_keys_are_ones_the_rule_actually_stores(cls):
    source = inspect.getsource(cls)
    _, formatters = HEADLINES[cls.id]
    for key in formatters:
        assert f'"{key}"' in source, f"{cls.id} never stores peer_comparison key {key!r}"


@pytest.mark.parametrize("rule_id", sorted(HEADLINES))
def test_headline_fills_from_peer_comparison_only(rule_id):
    _, formatters = HEADLINES[rule_id]
    pc = {k: _sample(k) for k in formatters}
    text = headline(rule_id, "CSE-XX", pc, "fallback title")
    assert text != "fallback title"
    assert "{" not in text and "}" not in text
    assert "CSE-XX" in text


def test_headline_falls_back_to_stored_title_when_data_missing():
    assert headline("EG01", "CSE-01", {}, "Stored title") == "Stored title"
    assert headline("EG01", "CSE-01", {"entity_share": None}, "Stored title") == "Stored title"
    assert headline("ZZ99", "CSE-01", {"x": 1}, "Stored title") == "Stored title"


def test_action_badges_follow_stored_severity():
    assert action_for("critical").label == "ESCALATE"
    assert action_for("high").label == "MONITOR"
    assert action_for("medium").label == "NOTE"
    assert action_for("low").label == "NOTE"
    assert action_for(None).label == "NOTE"
    assert action_for("critical").bg == "#fee2e2" and action_for("critical").fg == "#b91c1c"
    assert action_for("high").bg == "#fef9c3" and action_for("high").fg == "#854d0e"
    assert action_for("medium").bg == "#dcfce7" and action_for("medium").fg == "#15803d"


def test_paired_comparison_only_for_same_unit_rules():
    ns03 = paired_comparison("NS03", {"night_share": 0.01, "peer_average": 0.2})
    assert ns03 and ns03.baseline_label == "Portfolio average"
    assert ns03.entity_value == pytest.approx(1.0) and ns03.baseline_value == pytest.approx(20.0)
    eg10 = paired_comparison("EG10", {"declared_mttr_mins": 35.0, "empirical_mttr_mins": 77.0})
    assert eg10 and eg10.unit == "min"
    assert paired_comparison("EG01", {"entity_share": 0.3, "peer_p5_seconds": 211}) is None
    assert paired_comparison("NS03", {"night_share": 0.01}) is None


# ---------------------------------------------------------- real demo data


@pytest.fixture(scope="module")
def real():
    """Generator over the bootstrapped data, pinned to the run of the latest finding."""
    d = DuckDBStore("data")
    d.load_all_tables()
    s = SQLiteStore("data/satsa.db")
    row = s.conn.execute("SELECT run_id FROM findings ORDER BY rowid DESC LIMIT 1").fetchone()
    assert row, "bootstrapped data required (satsa generate-data / ingest / run)"
    yield ReportGenerator(d, s), row["run_id"]
    d.close()
    s.close()


def _findings(gen: ReportGenerator, where: str, params: tuple) -> list[dict]:
    rows = gen.sqlite_store.conn.execute(
        f"SELECT finding_id, entity_id, rule_id, severity FROM findings WHERE {where}", params
    ).fetchall()
    return [dict(r) for r in rows]


def _evidence_ids(gen: ReportGenerator, finding_id: str) -> list[str]:
    rows = gen.sqlite_store.conn.execute(
        "SELECT record_id FROM finding_evidences WHERE finding_id = ?", (finding_id,)
    ).fetchall()
    return [r["record_id"] for r in rows]


def test_portfolio_pdf_from_real_data(real, tmp_path):
    gen, run_id = real
    pdf = gen.generate_portfolio_pdf(tmp_path / "portfolio.pdf", run_id).read_bytes()
    assert pdf.startswith(b"%PDF")
    assert all(dim in pdf for dim in A4_MEDIABOX)
    assert b"Page 1 of" in pdf and b"require supervisory attention" in pdf

    scores = gen.sqlite_store.conn.execute(
        "SELECT risk_index FROM entity_scores WHERE run_id = ?", (run_id,)
    ).fetchall()
    attention = sum(1 for r in scores if r["risk_index"] >= 25)
    assert f"({attention})".encode() in pdf  # the cover's big "N of M" number
    assert f"of {len(scores)}".encode() in pdf

    critical = _findings(gen, "run_id = ? AND severity = 'critical'", (run_id,))
    if critical:
        assert b"(ESCALATE)" in pdf
    for f in critical:
        for record_id in _evidence_ids(gen, f["finding_id"]):
            assert record_id.encode() in pdf


def test_entity_pdf_badges_and_evidence_match_stored_findings(real, tmp_path):
    gen, run_id = real
    entity_id = gen.sqlite_store.conn.execute(
        "SELECT entity_id FROM findings WHERE run_id = ? GROUP BY entity_id "
        "ORDER BY count(*) DESC, entity_id LIMIT 1",
        (run_id,),
    ).fetchone()["entity_id"]
    pdf = gen.generate_entity_pdf(entity_id, tmp_path / "entity.pdf", run_id).read_bytes()
    assert all(dim in pdf for dim in A4_MEDIABOX) and b"Page 1 of" in pdf

    findings = _findings(gen, "run_id = ? AND entity_id = ?", (run_id, entity_id))
    expected = {action_for(f["severity"]).label for f in findings}
    for label in ("ESCALATE", "MONITOR", "NOTE"):
        assert (f"({label})".encode() in pdf) == (label in expected), label
    for f in findings:
        for record_id in _evidence_ids(gen, f["finding_id"]):
            assert record_id.encode() in pdf


def test_finding_pdf_omits_comparison_when_rule_has_none(real, tmp_path):
    gen, run_id = real
    no_cmp = _findings(gen, "run_id = ? AND rule_id NOT IN ('NS03', 'EG10')", (run_id,))
    assert no_cmp, "expected at least one finding without a paired comparison"
    f = no_cmp[0]
    pdf = gen.generate_finding_pdf(f["finding_id"], tmp_path / "f.pdf").read_bytes()
    assert GAP_CAPTION not in pdf and b"How this CSE compares" not in pdf
    assert f"({action_for(f['severity']).label})".encode() in pdf
    for record_id in _evidence_ids(gen, f["finding_id"]):
        assert record_id.encode() in pdf


def test_finding_pdf_shows_paired_bars_when_stored(real, tmp_path):
    gen, _ = real
    rows = _findings(gen, "rule_id IN ('NS03', 'EG10') ORDER BY rowid DESC LIMIT 1", ())
    if not rows:
        pytest.skip("no NS03/EG10 finding in this dataset")
    pdf = gen.generate_finding_pdf(rows[0]["finding_id"], tmp_path / "f.pdf").read_bytes()
    assert GAP_CAPTION in pdf


def test_missing_ids_raise_not_found(real, tmp_path):
    gen, run_id = real
    with pytest.raises(ReportNotFoundError):
        gen.generate_finding_pdf("FND-NOPE-X", tmp_path / "x.pdf")
    with pytest.raises(ReportNotFoundError):
        gen.generate_entity_pdf("CSE-99", tmp_path / "x.pdf", run_id)
    with pytest.raises(ReportNotFoundError):
        gen.generate_portfolio_pdf(tmp_path / "x.pdf", "RUN-DOES-NOT-EXIST")
    assert not list(tmp_path.iterdir())


# ------------------------------------------------------ long portfolio report


def _seed_large_portfolio(s: SQLiteStore, n_entities: int = 60) -> str:
    """Synthetic scores/findings in a TEMP store, only to exercise pagination."""
    run_id = "RUN-PAGINATION-TEST"
    domains = ["Threat Detection", "Investigation", "Escalation", "Cyber Resilience"]
    with s.conn:
        s.conn.execute(
            "INSERT INTO runs (run_id, period, created_at, config_hash, code_version, status) "
            "VALUES (?, 'TEST', '2026-01-01T00:00:00', 'cfg', 'test', 'completed')",
            (run_id,),
        )
        for i in range(n_entities):
            eid = f"ENT-{i:03d}"
            risk = (i * 37) % 100
            s.conn.execute(
                "INSERT INTO entity_scores VALUES (?, ?, ?, ?, ?, NULL)",
                (run_id, eid, float(risk), "band", 3),
            )
            for j, dom in enumerate(domains):
                s.conn.execute(
                    "INSERT INTO domain_scores VALUES (?, ?, ?, ?)",
                    (run_id, eid, dom, float((risk + j * 20) % 100)),
                )
            for k, sev in enumerate(("critical", "high", "medium")[: 1 + i % 3]):
                fid = f"FND-T{k}-{eid}"
                s.conn.execute(
                    "INSERT INTO findings (finding_id, run_id, entity_id, rule_id, rule_version, "
                    "domain, level, score, confidence, severity, title, rationale, "
                    "peer_comparison_json, examiner_check, created_at) "
                    "VALUES (?, ?, ?, 'EG12', '1.0.0', 'Security Operations', 'entity', ?, 1.0, "
                    "?, 'Seeded title', ?, ?, 'check', '2026-01-01T00:00:00')",
                    (
                        fid,
                        run_id,
                        eid,
                        90.0 - k,
                        sev,
                        "Markup-hostile rationale <b>&amp; <unclosed",
                        json.dumps({"skipped_cases_count": 3 + k}),
                    ),
                )
                s.conn.execute(
                    "INSERT INTO finding_evidences VALUES (?, 'case', ?, NULL)",
                    (fid, f"CASE-{eid}-{k}"),
                )
    return run_id


def test_long_portfolio_paginates_cleanly(tmp_path):
    s = SQLiteStore(tmp_path / "big.db")
    d = DuckDBStore(tmp_path / "store")
    try:
        run_id = _seed_large_portfolio(s)
        out = ReportGenerator(d, s).generate_portfolio_pdf(tmp_path / "big.pdf", run_id)
        pdf = out.read_bytes()
    finally:
        d.close()
        s.close()
    pages = _page_count(pdf)
    assert pages > 4
    assert f"Page {pages} of {pages}".encode() in pdf
    assert b"Entities 1" in pdf and b"Entities 31" in pdf and b"of 60" in pdf
    assert b"Markup-hostile rationale" in pdf  # escaped, not parsed as markup
    assert b"CASE-ENT-000-0" in pdf


def test_build_is_atomic_on_failure(tmp_path):
    class Boom(Flowable):
        def wrap(self, *_):
            raise RuntimeError("layout failure")

    target = tmp_path / "out.pdf"
    meta = RunMeta("RUN-X", "cfg", "P", "now")
    with pytest.raises(RuntimeError):
        build_pdf(target, [Boom()], meta, "Test")
    assert list(tmp_path.iterdir()) == []


# ------------------------------------------------------------------ routes


PDF_ROUTES = [
    "/reports/portfolio/pdf",
    "/reports/entity/{entity_id}/pdf",
    "/reports/finding/{finding_id}/pdf",
]


@pytest.fixture(scope="module")
def admin_client():
    c = TestClient(satsa_app)
    r = c.post(
        "/login",
        data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    return c


@pytest.fixture(scope="module")
def real_ids():
    s = SQLiteStore("data/satsa.db")
    row = s.conn.execute(
        "SELECT finding_id, entity_id, run_id FROM findings ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    s.close()
    return dict(row)


def _url(path: str, ids: dict) -> str:
    return path.replace("{entity_id}", ids["entity_id"]).replace(
        "{finding_id}", ids["finding_id"]
    )


def test_pdf_routes_serve_named_pdfs(admin_client, real_ids):
    run_id = real_ids["run_id"]
    r = admin_client.get("/reports/portfolio/pdf", params={"run_id": run_id})
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert f"SAT-SA_Portfolio_Report_{run_id}.pdf" in r.headers["content-disposition"]

    eid = real_ids["entity_id"]
    r = admin_client.get(f"/reports/entity/{eid}/pdf", params={"run_id": run_id})
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert f"SAT-SA_CSE_{eid}_Report_{run_id}.pdf" in r.headers["content-disposition"]

    fid = real_ids["finding_id"]
    r = admin_client.get(f"/reports/finding/{fid}/pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert f"SAT-SA_Finding_{fid}.pdf" in r.headers["content-disposition"]


@pytest.mark.parametrize(
    ("url", "status"),
    [
        ("/reports/finding/not-a-finding/pdf", 400),
        ("/reports/finding/FND-..-x/pdf", 400),
        ("/reports/finding/FND-EG01-NOPE-RUN-NOPE/pdf", 404),
        ("/reports/portfolio/pdf?run_id=bad", 400),
        ("/reports/portfolio/pdf?run_id=RUN-a/b", 400),
        ("/reports/portfolio/pdf?run_id=RUN-DOES-NOT-EXIST", 404),
        ("/reports/entity/CSE-01/pdf?run_id=bad", 400),
        ("/reports/entity/CSE-01/pdf?run_id=RUN-DOES-NOT-EXIST", 404),
        ("/reports/entity/CSE-99/pdf", 404),
        ("/reports/entity/CSE 99/pdf", 400),
    ],
)
def test_pdf_route_rejects_bad_ids_cleanly(admin_client, url, status):
    r = admin_client.get(url)
    assert r.status_code == status, r.text
    assert r.headers["content-type"].startswith("application/json")
    assert "detail" in r.json() and "Traceback" not in r.text


def test_pdf_routes_require_a_session(real_ids):
    anon = TestClient(satsa_app)
    for path in PDF_ROUTES:
        assert anon.get(_url(path, real_ids)).status_code == 401


@pytest.fixture
def cse_analyst_client():
    """A CSE-scoped SOC Analyst for CSE-01 in the live store (removed afterwards)."""
    username = "pdf_rbac_analyst"
    s = SQLiteStore("data/satsa.db")

    def cleanup():
        with s.conn:
            s.conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
            s.conn.execute("DELETE FROM identities WHERE username = ?", (username,))

    cleanup()
    s.create_user(username, "SOC Analyst", "Passphrase#12345", "ORG-POWER", "CSE-01")
    # CSE-scoped accounts are refused at SAT-SA's /login, so the session is made
    # directly: a stale or forged one must still be denied every report.
    c = TestClient(satsa_app)
    c.cookies.set(satsa_routes.SESSION_COOKIE_NAME, s.create_session(username, "SOC Analyst"))
    yield c
    cleanup()
    s.close()


def test_cse_scoped_role_is_denied_supervisory_pdfs(cse_analyst_client, real_ids):
    assert cse_analyst_client.get("/reports/portfolio/pdf").status_code == 403
    assert cse_analyst_client.get(_url(PDF_ROUTES[2], real_ids)).status_code == 403
    # Entity PDFs are refused too: SAT-SA serves only its analyst and examiner.
    assert cse_analyst_client.get("/reports/entity/CSE-02/pdf").status_code == 403


def test_generation_failure_is_a_clean_500_without_partial_file(
    admin_client, real_ids, monkeypatch
):
    run_id = real_ids["run_id"]
    target = Path("reports") / f"SAT-SA_Portfolio_Report_{run_id}.pdf"
    target.unlink(missing_ok=True)

    def boom(*_args, **_kwargs):
        raise RuntimeError("renderer exploded")

    monkeypatch.setattr(satsa_routes.ReportGenerator, "generate_portfolio_pdf", boom)
    r = admin_client.get("/reports/portfolio/pdf", params={"run_id": run_id})
    assert r.status_code == 500
    assert r.json() == {"detail": "Report generation failed."}
    assert "renderer exploded" not in r.text
    assert not target.exists()
    assert not list(Path("reports").glob("*.tmp"))
