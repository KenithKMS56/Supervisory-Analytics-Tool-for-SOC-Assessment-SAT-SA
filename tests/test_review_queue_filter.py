"""Review queue: an evidence card per cited record, and one queue per examiner disposition."""

import re
import sqlite3

from fastapi.testclient import TestClient

from satsa.api.routes import QUEUE_STATUS_FILTERS, app

client = TestClient(app)
examiner = TestClient(app)
for _c, _user, _pass in (
    (client, "analyst", "ChangeMe-Analyst#2026"),
    (examiner, "examiner", "ChangeMe-Examiner#2026"),
):
    assert (
        _c.post(
            "/login", data={"username": _user, "password": _pass}, follow_redirects=False
        ).status_code
        == 303
    )

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


def test_wide_tables_get_a_scrollbar_pinned_to_the_window_bottom():
    html = client.get("/queue").text
    assert '<div class="table-responsive" data-keep-scroll>' in html
    assert "window.satsaDockScrollbars = function" in html
    assert "window.satsaDockScrollbars(main)" in html  # rebuilt after an in-place swap
    css = client.get("/static/style.css").text
    dock = css[css.index(".hscroll-dock {") :]
    assert "position: sticky" in dock[: dock.index("}")]
    assert "bottom: 0" in dock[: dock.index("}")]
