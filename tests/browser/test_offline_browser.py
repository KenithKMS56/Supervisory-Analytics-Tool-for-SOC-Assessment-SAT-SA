"""B07 in a real browser with external DNS/HTTP unavailable: `/docs` renders the API reference
from local assets, and the main pages make no external request and raise no browser error."""

from __future__ import annotations

import pytest
from playwright.sync_api import Error

from .conftest import LiveServer, OfflinePage, sign_in


def test_docs_renders_offline(offline_page: OfflinePage, live_server: LiveServer):
    page = offline_page.page
    sign_in(page, live_server.base_url, "analyst", "ChangeMe-Analyst#2026")
    page.goto(f"{live_server.base_url}/docs")
    # Swagger UI built the operation list from /openapi.json: the JavaScript ran.
    page.wait_for_selector(".opblock", timeout=20_000)
    assert page.locator(".opblock").count() > 10
    assert page.locator("text=Periodic Batch Submission").count() >= 1
    assert offline_page.external_requests == []
    assert offline_page.page_errors == []
    assert offline_page.console_errors == []


def test_main_pages_make_no_external_requests(offline_page: OfflinePage, live_server: LiveServer):
    page = offline_page.page
    sign_in(page, live_server.base_url, "analyst", "ChangeMe-Analyst#2026")
    for path in ("/portfolio", "/queue", "/runs", "/upload", "/dq", "/tuning"):
        response = page.goto(f"{live_server.base_url}{path}")
        assert response is not None and response.status == 200, path
        page.wait_for_load_state("networkidle")
    assert offline_page.external_requests == []
    assert offline_page.page_errors == []
    assert offline_page.console_errors == [], offline_page.console_errors


def test_the_browser_really_is_offline(offline_page: OfflinePage):
    """Guard the guard: an external address does not load in this browser."""
    with pytest.raises(Error, match="ERR_NAME_NOT_RESOLVED"):
        offline_page.page.goto("https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css", timeout=15_000)
