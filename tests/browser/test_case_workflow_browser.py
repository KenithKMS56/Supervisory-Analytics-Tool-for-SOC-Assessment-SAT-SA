"""The examiner workflow in a real browser, offline (docs/examiner_workflow.md).

Two examiners in two browser sessions: one opens a case from a finding, assigns it and decides;
the other disagrees, and the page shows the disagreement blocking closure. Nothing leaves the
machine, nothing raises a browser error, and the case page fits a 390 px phone screen.
"""

from __future__ import annotations

import re

from case_fixtures import PASSPHRASE

from satsa.store.sqlite import SQLiteStore

from .conftest import LiveServer, OfflinePage, sign_in


def _form(page, action: str):
    return page.locator(f"form:has(input[name=action][value={action}])")


def _state(page, label: str) -> None:
    """Forms are posted in place (base.html swaps <main>): wait for the new state to show."""
    page.wait_for_selector(f".grid-4 .stat-val:text-is('{label}')")


def test_two_examiners_work_a_case_in_the_browser(offline_page: OfflinePage, live_server: LiveServer, chromium):
    store = SQLiteStore(live_server.root / "data" / "satsa.db")
    try:
        if not store.conn.execute("SELECT 1 FROM identities WHERE username = 'examiner2'").fetchone():
            store.create_user("examiner2", "examiner", PASSPHRASE)
        finding = store.conn.execute("SELECT finding_id FROM findings ORDER BY score DESC LIMIT 1").fetchone()[0]
    finally:
        store.close()

    page = offline_page.page
    sign_in(page, live_server.base_url, "examiner", "ChangeMe-Examiner#2026")
    page.goto(f"{live_server.base_url}/finding/{finding}")
    page.fill("#supervisory-case input[name=rationale]", "Off-shift handling looks wrong.")
    page.click("#supervisory-case button:has-text('Open supervisory case')")
    page.wait_for_url(re.compile(r".*/cases/CASE-[0-9A-F]{12}$"))
    case_url = page.url
    _state(page, "New concern")

    _form(page, "assign").locator("select[name=owner]").select_option("examiner")
    _form(page, "assign").locator("button[type=submit]").click()
    _state(page, "Assigned for review")

    page.click("summary:has-text('Decide')")
    decide = _form(page, "decide")
    decide.locator("select[name=outcome]").select_option("dismissed")
    decide.locator("textarea[name=rationale]").fill("Explained by the published maintenance window.")
    decide.locator("button[type=submit]").click()
    _state(page, "Dismissed")
    assert page.locator("summary:has-text('Close')").count() == 0  # the decider cannot sign off

    other = chromium.new_context(viewport={"width": 390, "height": 844})
    try:
        page2 = other.new_page()
        errors: list[str] = []
        page2.on("pageerror", lambda e: errors.append(str(e)))
        sign_in(page2, live_server.base_url, "examiner2", PASSPHRASE)
        page2.goto(case_url)
        page2.click("summary:has-text('Record review')")
        review = _form(page2, "record_review")
        review.locator("select[name=opinion]").select_option("disagree")
        review.locator("textarea[name=rationale]").fill("The window does not cover these hours.")
        review.locator("button[type=submit]").click()
        page2.wait_for_selector("text=Unresolved disagreement")
        assert page2.locator("summary:has-text('Close')").count() == 0  # blocked until adjudicated
        overflow = page2.evaluate("document.scrollingElement.scrollWidth - window.innerWidth")
        assert overflow <= 1, f"the case page scrolls sideways by {overflow}px at 390px"
        assert errors == []
    finally:
        other.close()

    page.reload()
    assert "Unresolved disagreement" in page.content()
    history = page.inner_text("#history")
    assert "decide" in history and "record review" in history and "examiner2" in history
    assert offline_page.external_requests == []
    assert offline_page.page_errors == []
