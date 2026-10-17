"""B07 (docs/product_brief.md section 2): `/docs` must work with no network.

At 47f10c9 the page loaded Swagger UI's JavaScript and CSS from a CDN (and its favicon from
fastapi.tiangolo.com), so it rendered blank on an air-gapped machine. Every asset the page
references must be served by SAT-SA itself. The browser check with external DNS/HTTP blocked is
in tests/browser/test_offline_browser.py.
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from satsa.api.routes import app

ASSET_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+)["']|url\s*:\s*["']([^"']+)["']""", re.IGNORECASE)


def _analyst() -> TestClient:
    client = TestClient(app)
    r = client.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
                    follow_redirects=False)
    assert r.status_code == 303
    return client


def test_docs_page_references_only_local_assets_and_they_are_served():
    client = _analyst()
    page = client.get("/docs")
    assert page.status_code == 200
    assert "http://" not in page.text and "https://" not in page.text, "the page names an external URL"
    refs = [a or b for a, b in ASSET_RE.findall(page.text)]
    scripts_and_styles = [r for r in refs if r.endswith((".js", ".css"))]
    assert len(scripts_and_styles) >= 2, refs
    for ref in refs:
        assert ref.startswith("/"), f"{ref} is not served by SAT-SA"
        asset = client.get(ref)
        assert asset.status_code == 200 and asset.content, f"{ref} -> {asset.status_code}"


def test_swagger_validator_badge_is_disabled():
    """Swagger UI otherwise asks validator.swagger.io to validate the spec from the browser."""
    page = _analyst().get("/docs")
    assert re.search(r"validatorUrl['\"]?\s*:\s*null", page.text), page.text[:2000]


def test_docs_and_schema_need_a_session():
    anonymous = TestClient(app)
    assert anonymous.get("/openapi.json").status_code == 401
    r = anonymous.get("/docs", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
