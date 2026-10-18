"""B08: representative screens fit desktop, laptop, tablet and phone widths (brief §9).

A table may scroll inside its own container, but the document itself must never scroll sideways,
and no screen may raise a browser error. Every page is loaded in a real Chromium with the outside
network unavailable, signed in as the role that uses it.
"""

from __future__ import annotations

import pytest

from satsa.store.sqlite import SQLiteStore

from .conftest import LiveServer, sign_in

WIDTHS = (1440, 1024, 768, 390)

# Measured in the page: how far the document scrolls sideways, and the widest element that
# sticks out past the right edge (so a failure names its culprit).
_OVERFLOW_JS = """
() => {
  const doc = document.scrollingElement;
  const over = doc.scrollWidth - window.innerWidth;
  let culprit = "";
  if (over > 1) {
    let worst = 0;
    for (const el of document.querySelectorAll("body *")) {
      const r = el.getBoundingClientRect();
      if (r.width === 0) continue;
      let p = el.parentElement, clipped = false;
      while (p && p !== document.body) {
        const s = getComputedStyle(p);
        if (s.overflowX === "auto" || s.overflowX === "scroll" || s.overflowX === "hidden") { clipped = true; break; }
        p = p.parentElement;
      }
      if (!clipped && r.right - window.innerWidth > worst) {
        worst = r.right - window.innerWidth;
        culprit = el.tagName.toLowerCase() + (el.id ? "#" + el.id : "") +
          (el.className && typeof el.className === "string" ? "." + el.className.trim().split(/\\s+/).join(".") : "");
      }
    }
  }
  return {over, culprit};
}
"""


# Every visible form field has an accessible name, and every help tooltip can be reached with the
# keyboard (a hover-only hint is invisible to a keyboard user).
_A11Y_JS = """
() => {
  const out = [];
  for (const el of document.querySelectorAll("main input, main select, main textarea")) {
    if (el.type === "hidden" || el.type === "submit" || el.type === "button") continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    const named = (el.labels && el.labels.length) || el.getAttribute("aria-label") ||
      el.getAttribute("aria-labelledby") || el.getAttribute("title");
    if (!named) out.push(`unlabelled ${el.tagName.toLowerCase()}[name=${el.name || el.id || "?"}]`);
  }
  for (const el of document.querySelectorAll("main .tooltip-hint")) {
    if (el.tabIndex < 0) out.push(`tooltip not keyboard-reachable: ${(el.textContent || "").trim().slice(0, 40)}`);
  }
  return out;
}
"""


def _ids(root) -> dict[str, str]:
    store = SQLiteStore(root / "data" / "satsa.db")
    try:
        finding = store.conn.execute(
            "SELECT finding_id, entity_id FROM findings WHERE run_id = "
            "(SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1) ORDER BY score DESC LIMIT 1"
        ).fetchone()
    finally:
        store.close()
    return {"finding_id": finding["finding_id"], "entity_id": finding["entity_id"]}


ANALYST_PAGES = (
    "/portfolio", "/entity/{entity_id}", "/finding/{finding_id}", "/queue", "/upload", "/runs",
    "/dq", "/rules", "/tuning", "/alerts", "/jobs", "/shadow-pilot", "/blind-review", "/cases",
)
EXAMINER_PAGES = ("/portfolio", "/entity/{entity_id}", "/finding/{finding_id}", "/queue", "/cases")


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize(
    ("username", "passphrase", "pages"),
    [
        ("analyst", "ChangeMe-Analyst#2026", ANALYST_PAGES),
        ("examiner", "ChangeMe-Examiner#2026", EXAMINER_PAGES),
    ],
    ids=["analyst", "examiner"],
)
def test_screens_fit_without_page_overflow_or_errors(
    chromium, live_server: LiveServer, width: int, username: str, passphrase: str, pages: tuple[str, ...]
):
    ids = _ids(live_server.root)
    context = chromium.new_context(viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        sign_in(page, live_server.base_url, username, passphrase)
        problems: list[str] = []
        for template in pages:
            path = template.format(**ids)
            errors.clear()
            response = page.goto(f"{live_server.base_url}{path}")
            page.wait_for_load_state("networkidle")
            assert response is not None and response.status == 200, f"{path} returned {response and response.status}"
            measured = page.evaluate(_OVERFLOW_JS)
            if measured["over"] > 1:
                problems.append(f"{path} scrolls sideways by {measured['over']}px (widest: {measured['culprit']})")
            if errors:
                problems.append(f"{path} raised browser errors: {errors[:3]}")
            if width == WIDTHS[0]:
                problems.extend(f"{path}: {issue}" for issue in page.evaluate(_A11Y_JS))
        assert problems == [], f"at {width}px:\n" + "\n".join(problems)
    finally:
        context.close()


@pytest.mark.parametrize("width", WIDTHS)
def test_sign_in_screens_fit(chromium, live_server: LiveServer, width: int):
    context = chromium.new_context(viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        for path in ("/login", "/splash"):
            page.goto(f"{live_server.base_url}{path}")
            page.wait_for_load_state("networkidle")
            measured = page.evaluate(_OVERFLOW_JS)
            assert measured["over"] <= 1, f"{path} scrolls sideways by {measured['over']}px at {width}px"
        assert errors == []
    finally:
        context.close()
