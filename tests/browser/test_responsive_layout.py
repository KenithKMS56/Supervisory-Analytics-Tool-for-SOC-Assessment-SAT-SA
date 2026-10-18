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


_SCROLLBARS_JS = """
() => {
  const wrap = document.querySelector("main .table-responsive.has-hdock");
  if (!wrap) return null;
  const top = wrap.previousElementSibling, dock = wrap.nextElementSibling;
  const shown = el => !!el && !el.hidden && el.getBoundingClientRect().height > 0;
  return {
    top: top && top.className, dock: dock && dock.className,
    topShown: shown(top), dockShown: shown(dock),
    tabindex: wrap.getAttribute("tabindex"), role: wrap.getAttribute("role"),
    label: wrap.getAttribute("aria-label"), topHidden: top && top.getAttribute("aria-hidden"),
  };
}
"""


@pytest.mark.parametrize("width", (1440, 390))
def test_a_wide_table_scrolls_from_a_bar_above_it_below_it_and_the_keyboard(
    chromium, live_server: LiveServer, width: int
):
    context = chromium.new_context(viewport={"width": width, "height": 700})
    try:
        page = context.new_page()
        sign_in(page, live_server.base_url, "analyst", "ChangeMe-Analyst#2026")
        page.goto(f"{live_server.base_url}/queue")
        page.wait_for_load_state("networkidle")
        bars = page.evaluate(_SCROLLBARS_JS)
        assert bars is not None, "the review queue table is not wider than its container"
        assert bars["top"] == "hscroll-top" and bars["dock"] == "hscroll-dock"
        assert bars["topShown"] and bars["dockShown"]
        # The table is one keyboard stop with a name; the two bars are mouse-only copies.
        assert bars["tabindex"] == "0" and bars["role"] == "region" and bars["label"]
        assert bars["topHidden"] == "true"

        wrap = "document.querySelector('main .table-responsive.has-hdock')"
        # Dragging the top bar moves the table and the bottom bar with it.
        page.evaluate(f"{wrap}.previousElementSibling.scrollLeft = 150")
        page.wait_for_function(
            f"Math.abs({wrap}.scrollLeft - 150) <= 1 && Math.abs({wrap}.nextElementSibling.scrollLeft - 150) <= 1"
        )
        # Scrolling the table (here from the bottom bar) moves the top bar back.
        page.evaluate(f"{wrap}.nextElementSibling.scrollLeft = 0")
        page.wait_for_function(f"{wrap}.scrollLeft <= 1 && {wrap}.previousElementSibling.scrollLeft <= 1")

        # Arrow keys scroll the focused table.
        page.focus("main .table-responsive.has-hdock")
        page.keyboard.press("ArrowRight")
        page.keyboard.press("ArrowRight")
        page.wait_for_function(f"{wrap}.scrollLeft > 0 && {wrap}.previousElementSibling.scrollLeft > 0")

        # Halfway down the table the top bar is pinned to the top of the window, just under the
        # demonstration banner if there is one, and nothing covers it.
        page.evaluate(f"window.scrollTo(0, {wrap}.getBoundingClientRect().top + window.scrollY + 300)")
        pinned = page.evaluate(
            f"""() => {{
              const bar = {wrap}.previousElementSibling, r = bar.getBoundingClientRect();
              const banner = document.getElementById('demoBanner');
              const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
              return {{top: r.top, expected: banner ? banner.getBoundingClientRect().bottom : 0,
                       visible: !!hit && (hit === bar || bar.contains(hit)), hit: hit && hit.outerHTML.slice(0, 80)}};
            }}"""
        )
        assert abs(pinned["top"] - pinned["expected"]) <= 1, f"top bar not pinned: {pinned}"
        assert pinned["visible"], f"top bar is covered by {pinned['hit']}"
    finally:
        context.close()
