"""The whole supervisory workflow in a real browser, offline (docs/product_brief.md section 9).

An analyst registers a CSE, uploads its submission, sees why the batch was held, publishes it and
gets an assessment run; the evidence behind a finding is on screen; an examiner opens a case,
requests an explanation (downloading the request package), records a decision; the CSE report is
exported. A real worker process runs the jobs, as in a deployment, and the job state survives a
page refresh. Nothing leaves the machine and no page raises a browser error.
"""

from __future__ import annotations

import csv
import io
import os
import re
import subprocess
import sys
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from satsa.store.sqlite import SQLiteStore
from satsa.synth.generator import SyntheticDataGenerator

from .conftest import LiveServer, OfflinePage, sign_in

ENTITY = "E2E-01"
SOURCE_ENTITY = "CSE-03"  # the generator injects fast closures (EG01) here, so the run has a finding
PERIOD = "2026-H1"
BAD_ALERT = "E2E-BAD-TIMESTAMP"


@pytest.fixture(scope="module")
def worker(live_server: LiveServer) -> Iterator[subprocess.Popen[bytes]]:
    log = live_server.root / "worker.log"
    with open(log, "wb") as out:
        process = subprocess.Popen(
            [sys.executable, "-m", "satsa.cli", "worker", "--poll-seconds", "0.5"],
            cwd=live_server.root, stdout=out, stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
    try:
        yield process
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()


def _submission(tmp: Path) -> bytes:
    """One synthetic CSE's half-year as a ZIP, renamed to ENTITY, plus one alert whose timestamp
    cannot be read (so the batch is held for review rather than published at once)."""
    csv_dir, _ = SyntheticDataGenerator(seed=42, base_alerts_per_entity=300).save_dataset(tmp)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(csv_dir.glob("*.csv")):
            with open(path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                header = list(reader.fieldnames or [])
                rows = list(reader)
            if "entity_id" in header:
                rows = [r | {"entity_id": ENTITY} for r in rows if r["entity_id"] == SOURCE_ENTITY]
            if path.stem == "alert" and rows:
                rows.append(rows[0] | {"alert_id": BAD_ALERT, "created_at": "the third of never"})
            out = io.StringIO()
            writer = csv.DictWriter(out, fieldnames=header, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            z.writestr(path.name, out.getvalue())
    return buf.getvalue()


def _wait_for_job(page, timeout: float = 240) -> str:
    """The job page refreshes itself while the job is queued or running; wait for its outcome."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = page.inner_text("main")
        if "refreshes itself" not in text:
            return text
        page.wait_for_timeout(1500)
        page.reload()
    pytest.fail(f"the job did not finish in {timeout}s:\n{page.inner_text('main')[:2000]}")


def _completed_run(root: Path, period: str, after: str) -> dict | None:
    store = SQLiteStore(root / "data" / "satsa.db")
    try:
        row = store.conn.execute(
            "SELECT run_id, status FROM runs WHERE period = ? AND created_at > ? ORDER BY created_at DESC LIMIT 1",
            (period, after)).fetchone()
        return dict(row) if row else None
    finally:
        store.close()


def _now(root: Path) -> str:
    store = SQLiteStore(root / "data" / "satsa.db")
    try:
        return store.conn.execute("SELECT strftime('%Y-%m-%dT%H:%M:%f', 'now')").fetchone()[0]
    finally:
        store.close()


def test_upload_to_report_in_the_browser(offline_page: OfflinePage, live_server: LiveServer, chromium, worker,
                                         tmp_path: Path):
    page = offline_page.page
    page.on("dialog", lambda d: d.accept())  # the "publish as is?" confirmation
    base = live_server.base_url
    bundle = tmp_path / "e2e_submission.zip"
    bundle.write_bytes(_submission(tmp_path / "synthetic"))

    # 1. The analyst registers the CSE.
    sign_in(page, base, "analyst", "ChangeMe-Analyst#2026")
    page.goto(f"{base}/upload")
    page.fill("#reg-entity-id", ENTITY)
    page.select_option("#sector_select", index=1)
    page.fill("#reg-name", "End-to-end check CSE")
    # Wait for the form's own navigation: the POST redirects back to /upload, and "network idle"
    # can be reached before the redirect starts on a loaded machine.
    with page.expect_navigation():
        page.click("form[action='/upload/add-entity'] button[type=submit]")
    page.goto(f"{base}/upload")
    assert page.locator(f"#upload-target-entity option[value='{ENTITY}']").count() == 1

    # 2. Uploads the submission for the half-year; the worker validates it and holds it.
    page.select_option("#upload-target-entity", ENTITY)
    page.fill("#upload-period", PERIOD)
    page.set_input_files("#file-input", str(bundle))
    assert "e2e_submission.zip" in page.inner_text("#file-list")
    page.click("form[action='/upload'] button[type=submit]")
    page.wait_for_url(re.compile(r".*/jobs/JOB-[^/]+$"))
    job_url = page.url
    outcome = _wait_for_job(page)
    assert "held" in outcome.lower(), outcome
    # Refreshing (or coming back later) shows the same recorded outcome.
    page.goto(job_url)
    assert "held" in page.inner_text("main").lower()

    # 3. The upload page says why it was held, and the analyst publishes it as it is.
    page.goto(f"{base}/upload")
    held = page.locator("#held-submissions tr", has_text=ENTITY)
    assert held.count() == 1
    why = held.inner_text()
    assert PERIOD in why and re.search(r"reject|unreadable|timestamp|created_at", why, re.IGNORECASE), why
    before = _now(live_server.root)
    with page.expect_navigation():  # the POST redirects back to /upload with the outcome
        held.locator("button:has-text('Publish as is')").click()
    assert "Assessment queued as job" in page.inner_text("main")

    # 4. The worker runs the assessment of the half-year.
    deadline = time.monotonic() + 300
    run = None
    while time.monotonic() < deadline:
        run = _completed_run(live_server.root, PERIOD, before)
        if run and run["status"] in ("completed", "failed"):
            break
        time.sleep(1)
    assert run and run["status"] == "completed", f"no completed {PERIOD} run: {run}\n" + \
        (live_server.root / "worker.log").read_text(encoding="utf-8", errors="replace")[-3000:]
    page.goto(f"{base}/runs")
    assert run["run_id"] in page.inner_text("main")

    # 5. The CSE's page lists its findings; a finding shows the evidence behind it.
    page.goto(f"{base}/entity/{ENTITY}")
    assert ENTITY in page.inner_text("main")
    store = SQLiteStore(live_server.root / "data" / "satsa.db")
    try:
        finding = store.conn.execute(
            "SELECT finding_id, rule_id FROM findings WHERE run_id = ? AND entity_id = ? ORDER BY score DESC LIMIT 1",
            (run["run_id"], ENTITY)).fetchone()
    finally:
        store.close()
    assert finding is not None, f"the {PERIOD} run found nothing for {ENTITY}"
    page.goto(f"{base}/finding/{finding['finding_id']}")
    text = page.inner_text("main")
    assert finding["rule_id"] in text and re.search(r"evidence", text, re.IGNORECASE)
    assert BAD_ALERT not in text  # the rejected row never reached the evidence

    # 6. An examiner opens a case, requests an explanation and records a decision.
    examiner_ctx = chromium.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
    try:
        ex = examiner_ctx.new_page()
        errors: list[str] = []
        ex.on("pageerror", lambda e: errors.append(str(e)))
        sign_in(ex, base, "examiner", "ChangeMe-Examiner#2026")
        ex.goto(f"{base}/finding/{finding['finding_id']}")
        ex.fill("#supervisory-case input[name=rationale]", "Closures without investigation need explaining.")
        ex.click("#supervisory-case button:has-text('Open supervisory case')")
        ex.wait_for_url(re.compile(r".*/cases/CASE-[0-9A-F]{12}$"))
        _case_action(ex, "assign", owner="examiner")
        ex.wait_for_selector(".grid-4 .stat-val:text-is('Assigned for review')")

        ex.click("summary:has-text('Request explanation')")
        req = ex.locator("form:has(input[name=action][value=request_explanation])")
        req.locator("input[name=due_date]").fill("2026-12-31")
        req.locator("textarea[name=rationale]").fill("Explain the closures without an investigation event.")
        req.locator("button[type=submit]").click()
        ex.wait_for_selector(".grid-4 .stat-val:text-is('Explanation requested')")
        with ex.expect_download() as dl:
            ex.click("form[action$='/request-package'] button[type=submit]")
        package = Path(dl.value.path())
        with zipfile.ZipFile(package) as z:
            assert any(n.endswith(".json") for n in z.namelist())

        ex.click("summary:has-text('Decide')")
        decide = ex.locator("form:has(input[name=action][value=decide])")
        decide.locator("select[name=outcome]").select_option("confirmed")
        decide.locator("textarea[name=rationale]").fill("No explanation covers the closures.")
        decide.locator("button[type=submit]").click()
        ex.wait_for_selector(".grid-4 .stat-val:text-is('Confirmed concern')")
        history = ex.inner_text("#history")
        assert "Request explanation" in history or "explanation" in history.lower()
        assert errors == []
    finally:
        examiner_ctx.close()

    # 7. The analyst exports the CSE report from the CSE's page.
    page.goto(f"{base}/entity/{ENTITY}")
    page.click("details.export-menu summary")  # the Export Report menu
    with page.expect_download() as dl:
        page.click(f"a[href='/reports/entity/{ENTITY}/pdf']")
    pdf = Path(dl.value.path()).read_bytes()
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000
    report = page.request.get(f"{base}/reports/entity/{ENTITY}/html")
    assert report.status == 200 and ENTITY in report.text() and run["run_id"] in report.text()

    assert offline_page.external_requests == []
    assert offline_page.page_errors == []


def _case_action(page, action: str, **fields: str) -> None:
    form = page.locator(f"form:has(input[name=action][value={action}])")
    for name, value in fields.items():
        form.locator(f"select[name={name}]").select_option(value)
    form.locator("button[type=submit]").click()
