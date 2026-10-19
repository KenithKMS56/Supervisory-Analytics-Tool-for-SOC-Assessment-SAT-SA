"""Review queue: an evidence card per cited record, and one queue per examiner disposition."""

import csv
import io
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from satsa.api.routes import QUEUE_STATUS_FILTERS, app

client = TestClient(app)
examiner = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def _signed_in():
    """Sign in when this module's tests start, not when the module is imported: a session opened
    at collection can pass the idle timeout before a long suite reaches these tests."""
    for c, user, password in (
        (client, "analyst", "ChangeMe-Analyst#2026"),
        (examiner, "examiner", "ChangeMe-Examiner#2026"),
    ):
        assert c.post("/login", data={"username": user, "password": password},
                      follow_redirects=False).status_code == 303

ROW = re.compile(r"<tr>(.*?)</tr>", re.DOTALL)
QUEUE_ID = re.compile(r'name="queue_id" value="([^"]+)"')
FINDING = re.compile(r'href="/finding/([^"]+)"')


def _rows(html: str) -> list[tuple[str, list[str]]]:
    """(queue_id, finding ids linked) for each queue row of the examiner's view."""
    out = []
    for body in ROW.findall(html):
        qid = QUEUE_ID.search(body)
        if qid:
            out.append((qid.group(1), FINDING.findall(body)))
    return out


def _queue() -> dict[str, dict]:
    return {q["queue_id"]: q for q in client.get("/api/v1/queue").json()}


def test_evidence_cards_are_the_findings_that_cite_the_record():
    rows = _rows(examiner.get("/queue").text)
    queue = _queue()
    linked = [(qid, fids) for qid, fids in rows if fids]
    assert linked, "no queue row links an evidence card"

    conn = sqlite3.connect("data/satsa.db")
    try:
        for qid, fids in linked[:20]:
            item = queue[qid]
            assert not item["is_random"]
            for fid in fids:
                cited = conn.execute(
                    """SELECT 1 FROM finding_evidences e JOIN findings f ON f.finding_id = e.finding_id
                       WHERE e.finding_id = ? AND e.record_type = ? AND e.record_id = ?
                         AND f.run_id = ? AND f.entity_id = ?""",
                    (
                        fid,
                        item["record_type"],
                        item["record_id"],
                        item["run_id"],
                        item["entity_id"],
                    ),
                ).fetchone()
                assert cited, f"{fid} does not cite {qid}"
    finally:
        conn.close()

    fid = linked[0][1][0]
    page = examiner.get(f"/finding/{fid}")
    assert page.status_code == 200


def test_random_controls_have_no_evidence_card():
    html = examiner.get("/queue").text
    queue = _queue()
    shown_random = [fids for qid, fids in _rows(html) if queue[qid]["is_random"]]
    assert all(fids == [] for fids in shown_random)
    if shown_random:
        assert "Random control: no finding cites it" in html


def test_each_filter_shows_only_its_disposition():
    queue = _queue()
    target = next(q for q in queue.values() if q["examiner_status"] == "pending")
    resp = examiner.post(
        "/api/v1/feedback",
        data={"queue_id": target["queue_id"], "status": "not_an_issue", "return_status": "pending"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/queue?status=pending"  # back to the view it was made from

    queue = _queue()
    for status in QUEUE_STATUS_FILTERS:
        page = examiner.get(f"/queue?status={status}")
        assert page.status_code == 200
        shown = [qid for qid, _ in _rows(page.text)]
        assert all(queue[qid]["examiner_status"] == status for qid in shown), status
        assert (
            f'value="{status}" class="queue-filter-btn queue-filter-{status} active"' in page.text
        )

    justified = [qid for qid, _ in _rows(examiner.get("/queue?status=not_an_issue").text)]
    assert target["queue_id"] in justified
    pending = [qid for qid, _ in _rows(examiner.get("/queue?status=pending").text)]
    assert target["queue_id"] not in pending


def test_unknown_filter_is_the_whole_queue():
    everything = _rows(examiner.get("/queue").text)
    assert _rows(examiner.get("/queue?status=bogus").text) == everything
    resp = examiner.post(
        "/api/v1/feedback",
        data={"queue_id": everything[0][0], "status": "confirmed", "return_status": "/evil"},
        follow_redirects=False,
    )
    assert resp.headers["location"] == "/queue"


def test_wide_tables_get_one_sticky_scrollbar_above_them():
    html = client.get("/queue").text
    assert '<div class="table-responsive" data-keep-scroll>' in html
    assert "window.satsaDockScrollbars = function" in html
    assert "window.satsaDockScrollbars(main)" in html  # rebuilt after an in-place swap
    # One bar, above the table and pinned to the top of the window (tests/browser checks it
    # scrolls the table); no second bar below.
    assert "bar.className = 'hscroll-top'" in html and "hscroll-dock" not in html
    css = client.get("/static/style.css").text
    assert ".hscroll-dock" not in css
    top = css[css.index(".hscroll-top {") :]
    assert "position: sticky" in top[: top.index("}")]
    assert "top: var(--sticky-top, 0px)" in top[: top.index("}")]  # under the demo banner, if any


STAT = re.compile(
    r'<div class="stat-label">([^<]+)</div>\s*<div class="stat-value"[^>]*>(\d+)</div>'
)
SHOWN = re.compile(r"Showing (\d+) of (\d+) records")


def _stats(html: str) -> dict[str, int]:
    return {label: int(n) for label, n in STAT.findall(html)}


def _latest_run_id(conn: sqlite3.Connection) -> str:
    return conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()[0]


def test_stat_cards_count_the_whole_queue_not_the_rows_shown():
    conn = sqlite3.connect("data/satsa.db")
    try:
        total, random, confirmed = conn.execute(
            """SELECT COUNT(*), SUM(is_random), SUM(examiner_status = 'confirmed')
               FROM review_queue WHERE run_id = ?""",
            (_latest_run_id(conn),),
        ).fetchone()
    finally:
        conn.close()
    html = examiner.get("/queue").text
    stats = _stats(html)
    assert stats["Total Queue Candidates"] == total
    assert stats["Random Controls"] == random
    assert stats["Cited by Findings"] == total - random
    assert stats["Confirmed concern"] == confirmed
    shown, of = map(int, SHOWN.search(html).groups())
    assert of == total
    assert shown == min(total, 200) == len(_rows(html))


def test_a_disposition_moves_a_record_between_counts_and_keeps_the_total():
    before = _stats(examiner.get("/queue").text)
    pending_before = int(SHOWN.search(examiner.get("/queue?status=pending").text).group(2))
    target = next(q for q in _queue().values() if q["examiner_status"] == "pending")
    examiner.post(
        "/api/v1/feedback",
        data={"queue_id": target["queue_id"], "status": "confirmed"},
        follow_redirects=False,
    )
    after = _stats(examiner.get("/queue").text)
    # A decision is recorded against the record; the record stays in the queue.
    assert after["Total Queue Candidates"] == before["Total Queue Candidates"]
    assert after["Confirmed concern"] == before["Confirmed concern"] + 1
    pending_after = int(SHOWN.search(examiner.get("/queue?status=pending").text).group(2))
    assert pending_after == pending_before - 1


def test_the_page_and_exports_show_only_the_latest_runs_queue():
    conn = sqlite3.connect("data/satsa.db")
    try:
        latest = _latest_run_id(conn)
    finally:
        conn.close()
    queue = _queue()
    assert queue and {q["run_id"] for q in queue.values()} == {latest}
    shown = [qid for qid, _ in _rows(examiner.get("/queue").text)]
    assert shown and all(queue[qid]["run_id"] == latest for qid in shown)
    # One row per record: an earlier run's copy of the same record is not repeated.
    keys = [(q["entity_id"], q["record_type"], q["record_id"]) for q in queue.values()]
    assert len(keys) == len(set(keys))
    assert latest in examiner.get("/queue").text
    rows = list(csv.DictReader(io.StringIO(client.get("/api/v1/export/queue.csv").text)))
    csv_ids = {r["queue_id"] for r in rows}
    assert csv_ids == set(queue)


def _counts() -> tuple[int, int]:
    conn = sqlite3.connect("data/satsa.db")
    try:
        return (
            conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
        )
    finally:
        conn.close()


def test_a_decision_that_is_not_one_of_the_three_is_refused():
    target = next(iter(_queue().values()))
    before = _counts()
    for status in ("abc", "pending", ""):
        resp = examiner.post(
            "/api/v1/feedback",
            data={"queue_id": target["queue_id"], "status": status},
            follow_redirects=False,
        )
        assert resp.status_code in (400, 422), status
    assert _counts() == before
    assert _queue()[target["queue_id"]]["examiner_status"] == target["examiner_status"]


def test_a_decision_on_a_record_that_is_not_in_the_queue_is_refused():
    before = _counts()
    resp = examiner.post(
        "/api/v1/feedback",
        data={"queue_id": "Q-NO-SUCH-RECORD", "status": "confirmed"},
        follow_redirects=False,
    )
    assert resp.status_code == 404
    assert _counts() == before


def test_deciding_again_adds_to_the_history():
    target = next(iter(_queue().values()))
    before = _counts()[0]
    for status in ("confirmed", "needs_more_data", "confirmed"):
        examiner.post(
            "/api/v1/feedback",
            data={"queue_id": target["queue_id"], "status": status},
            follow_redirects=False,
        )
    assert _counts()[0] == before + 3
    assert _queue()[target["queue_id"]]["examiner_status"] == "confirmed"


def test_a_new_run_keeps_the_decision_on_a_record_it_selects_again():
    from satsa.models.outputs import ReviewQueueItem
    from satsa.store.sqlite import SQLiteStore

    target = next(q for q in _queue().values() if q["examiner_status"] == "pending")
    examiner.post(
        "/api/v1/feedback",
        data={"queue_id": target["queue_id"], "status": "not_an_issue", "notes": "carried"},
        follow_redirects=False,
    )
    store = SQLiteStore("data/satsa.db")
    fields = {
        k: target[k]
        for k in ("entity_id", "record_type", "record_id", "severity", "score", "selection_reason")
    }
    again = ReviewQueueItem(
        queue_id="Q-TEST-NEXT-RUN", run_id="RUN-TEST-NEXT", is_random=False, **fields
    )
    other = ReviewQueueItem(
        queue_id="Q-TEST-NEXT-RUN-OTHER",
        run_id="RUN-TEST-NEXT",
        is_random=False,
        **{**fields, "record_id": "NEVER-DECIDED"},
    )
    try:
        store.save_review_queue([again, other])
        rows = {
            r["queue_id"]: (r["examiner_status"], r["examiner_note"])
            for r in store.conn.execute("SELECT * FROM review_queue WHERE run_id = 'RUN-TEST-NEXT'")
        }
        assert rows == {
            "Q-TEST-NEXT-RUN": ("not_an_issue", "carried"),
            "Q-TEST-NEXT-RUN-OTHER": ("pending", None),
        }
    finally:
        with store.conn:
            store.conn.execute("DELETE FROM review_queue WHERE run_id = 'RUN-TEST-NEXT'")
        store.close()
