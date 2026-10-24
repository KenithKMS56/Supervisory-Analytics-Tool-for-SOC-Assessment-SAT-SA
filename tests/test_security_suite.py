"""Security verification suite (docs/product_brief.md section 10 and 13; docs/security/asvs_checklist.md).

Hostile input against both portals on a private copy of the deployment: cross-site scripting
(stored, reflected and through the Admin Portal's live feed), SQL injection through every list
filter, path traversal through file-serving routes, archive bombs, request bodies with and without
a declared length, open redirects and the response headers every page carries. Each attack is
paired with a check that the legitimate request still works, so a route cannot pass by refusing
everything.
"""

from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import zipfile
from pathlib import Path

import pytest
from deploy_utils import copy_deployment
from fastapi.testclient import TestClient

from satsa.api import routes
from satsa.ingest import uploads
from satsa.ingest.uploads import check_zip_limits
from satsa.security import safe_local_path
from satsa.store.sqlite import SQLiteStore
from satsa.web_security import CONTENT_SECURITY_POLICY

SCRIPT = "<script>alert('xss')</script>"
IMG = '"><img src=x onerror=alert(1)>'
SQL_PAYLOADS = ["' OR '1'='1", "1; DROP TABLE runs;--", "' UNION SELECT * FROM users--", "%' OR 1=1 --"]
DB_ERROR_MARKERS = ("sqlite3.", "duckdb.", "OperationalError", "ParserException", "Traceback")


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    return root


def _client(username: str = "analyst", password: str = "ChangeMe-Analyst#2026") -> TestClient:
    client = TestClient(routes.app)
    r = client.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return client


def _admin_portal(root: Path) -> TestClient:
    from satsa.admin.app import app as admin_app

    return TestClient(admin_app)


def _no_raw(text: str, *payloads: str) -> None:
    for p in payloads:
        assert p not in text, f"unescaped payload in the page: {p!r}"


# ---------------------------------------------------------------- response headers


def test_every_response_carries_the_security_headers(deployment):
    anonymous = TestClient(routes.app)
    analyst = _client()
    responses = {
        "page": analyst.get("/portfolio"),
        "static file": anonymous.get("/static/style.css"),
        "json api": analyst.get("/api/v1/queue"),
        "login page": anonymous.get("/login"),
        "refused api": anonymous.get("/api/v1/findings"),
        "not found": analyst.get("/no-such-page"),
    }
    for name, r in responses.items():
        assert r.headers.get("content-security-policy") == CONTENT_SECURITY_POLICY, name
        assert r.headers.get("x-content-type-options") == "nosniff", name
        assert r.headers.get("x-frame-options") == "DENY", name
        assert r.headers.get("referrer-policy") == "same-origin", name
    assert responses["refused api"].status_code == 401
    # The policy keeps every page on the portal: no external origin may serve script, style or data.
    for directive in ("default-src 'self'", "connect-src 'self'", "object-src 'none'", "frame-ancestors 'none'",
                      "form-action 'self'"):
        assert directive in CONTENT_SECURITY_POLICY
    assert "http" not in CONTENT_SECURITY_POLICY and "*" not in CONTENT_SECURITY_POLICY


def test_the_admin_portal_carries_them_too(deployment):
    with _admin_portal(deployment) as portal:
        r = portal.get("/login")
    assert r.status_code == 200
    assert r.headers.get("content-security-policy") == CONTENT_SECURITY_POLICY
    assert r.headers.get("x-frame-options") == "DENY"


def test_the_offline_api_docs_still_render_under_the_policy(deployment):
    # /docs initialises Swagger UI with an inline script from local files only.
    r = _client().get("/docs")
    assert r.status_code == 200 and "/static/vendor/swagger-ui/" in r.text
    assert r.headers.get("content-security-policy") == CONTENT_SECURITY_POLICY


# ---------------------------------------------------------------- request bodies


def _alerts(n: int, marker: str = "BODY") -> list[dict]:
    return [{"alert_id": f"{marker}-{i}", "rule_id": "R-1", "category": "malware", "severity_orig": "high",
             "severity_final": "high", "asset_id": "A-1", "created_at": "2026-07-02T10:00:00Z"} for i in range(n)]


def _submission(alerts: list[dict], period: str = "2026-Q3") -> dict:
    return {"entity_id": "CSE-01", "period": period, "run_assessment_now": False, "alerts": alerts}


def _batches() -> int:
    conn = sqlite3.connect("data/catalog.db")
    try:
        return conn.execute("SELECT COUNT(*) FROM batches").fetchone()[0]
    finally:
        conn.close()


def test_a_chunked_body_without_a_length_is_cut_off_at_the_cap(deployment, monkeypatch):
    """A body sent in chunks declares no Content-Length, so a check of the header alone lets it
    through; the cap counts the bytes that actually arrive."""
    monkeypatch.setattr(routes, "MAX_API_BODY_BYTES", 4096)
    analyst = _client()
    before = _batches()
    raw = json.dumps(_submission(_alerts(200))).encode()
    assert len(raw) > 4096

    def chunks():
        for i in range(0, len(raw), 512):
            yield raw[i:i + 512]

    r = analyst.post("/api/v1/submissions", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413, r.text
    assert "larger than" in r.json()["detail"]
    assert _batches() == before, "a refused body must not create a batch"
    # The same cap lets an ordinary submission through.
    small = analyst.post("/api/v1/submissions", json=_submission(_alerts(2)))
    assert small.status_code in (200, 201, 202), small.text


def test_a_declared_length_over_the_cap_is_refused_before_the_body_is_read(deployment, monkeypatch):
    monkeypatch.setattr(routes, "MAX_API_BODY_BYTES", 1024)
    analyst = _client()
    r = analyst.post("/cases/CASE-000000000000/actions", content=b"x" * 2048,
                     headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    bogus = analyst.post("/api/v1/submissions", content=b"{}",
                         headers={"content-type": "application/json", "content-length": "abc"})
    assert bogus.status_code in (400, 413)


def test_an_upload_streamed_past_the_upload_limit_is_refused(deployment, monkeypatch):
    monkeypatch.setattr(routes, "MAX_UPLOAD_BYTES", 64 * 1024)
    monkeypatch.setattr(routes, "UPLOAD_FORM_SLACK_BYTES", 1024)
    analyst = _client()
    jobs = len(list(Path("data/jobs").glob("*"))) if Path("data/jobs").is_dir() else 0
    big = b"alert_id,entity_id\n" + b"A,CSE-01\n" * 20000
    r = analyst.post("/upload", files={"files": ("alerts.csv", big, "text/csv")}, follow_redirects=False)
    assert r.status_code == 413
    assert (len(list(Path("data/jobs").glob("*"))) if Path("data/jobs").is_dir() else 0) == jobs


# ---------------------------------------------------------------- archives


def _zip(members: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, data in members.items():
            z.writestr(name, data)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def test_a_highly_compressed_member_is_refused_as_a_bomb():
    with pytest.raises(ValueError, match="expands more than"):
        check_zip_limits(_zip({"alerts.csv": b"\0" * (8 * 1024 * 1024)}))


def test_an_archive_with_too_many_members_is_refused(monkeypatch):
    monkeypatch.setattr(uploads, "MAX_ZIP_ENTRIES", 10)
    with pytest.raises(ValueError, match="members"):
        check_zip_limits(_zip({f"f{i}.csv": b"a" for i in range(11)}))


def test_an_archive_that_expands_past_the_limit_is_refused(monkeypatch):
    monkeypatch.setattr(uploads, "MAX_ZIP_UNCOMPRESSED_BYTES", 1024)
    with pytest.raises(ValueError, match="expands to"):
        check_zip_limits(_zip({"a.csv": b"x" * 800, "b.csv": b"y" * 800}, zipfile.ZIP_STORED))


@pytest.mark.parametrize("name", ["../evil.csv", "/etc/passwd", "a/../../evil.csv", "C:/evil.csv", "..\\evil.csv"])
def test_an_archive_member_outside_the_archive_is_refused(name):
    with pytest.raises(ValueError):
        check_zip_limits(_zip({name: b"x"}))


def test_a_member_whose_header_understates_its_size_cannot_expand_past_it():
    """The limits read the sizes the archive declares. A forged header that understates a member
    must not let extraction write more than declared: zipfile stops at the declared size and the
    checksum then fails."""
    payload = b"A" * (2 * 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("alerts.csv", payload)
    raw = bytearray(buf.getvalue())
    # Rewrite the uncompressed size in the local header (offset 22) and the central directory
    # entry (offset 24 from its signature) to 1 KiB.
    small = (1024).to_bytes(4, "little")
    raw[22:26] = small
    cd = raw.rfind(b"PK\x01\x02")
    raw[cd + 24:cd + 28] = small
    z = zipfile.ZipFile(io.BytesIO(bytes(raw)))
    check_zip_limits(z)  # within every limit, as declared
    # zipfile decompresses no more than the declared 1 KiB, then the checksum of those bytes fails.
    with pytest.raises(zipfile.BadZipFile, match="CRC"):
        z.read("alerts.csv")
    with z.open("alerts.csv") as member, pytest.raises(zipfile.BadZipFile):
        member.read(4 * 1024 * 1024)
    with zipfile.ZipFile(io.BytesIO(bytes(raw))) as again, pytest.raises(zipfile.BadZipFile):
        again.extractall(Path(tempfile.mkdtemp()))


def test_an_uploaded_bomb_is_refused_and_queues_nothing(deployment):
    analyst = _client()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("alerts.csv", b"\0" * (16 * 1024 * 1024))
    jobs_before = _job_count()
    r = analyst.post("/upload", files={"files": ("bundle.zip", buf.getvalue(), "application/zip")},
                     follow_redirects=False)
    assert r.status_code == 303 and "expands" in r.headers["location"]
    assert _job_count() == jobs_before


def _job_count() -> int:
    store = SQLiteStore("data/satsa.db")
    try:
        return store.conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    finally:
        store.close()


# ---------------------------------------------------------------- cross-site scripting


def test_submitted_text_is_escaped_where_it_is_shown(deployment):
    """Stored XSS: record identifiers come from the submitting CSE and are shown to examiners."""
    analyst = _client()
    marker = "XSSMARK"
    alert = _alerts(1, marker)[0] | {"alert_id": f"{marker}{SCRIPT}", "rule_id": f"{marker}{IMG}"}
    r = analyst.post("/api/v1/submissions", json=_submission([alert], "2026-Q4"))
    assert r.status_code in (200, 201, 202), r.text
    page = analyst.get("/alerts", params={"q": marker})
    assert page.status_code == 200
    assert marker in page.text, "the submitted alert should be listed"
    _no_raw(page.text, SCRIPT, IMG)
    assert "&lt;script&gt;" in page.text


def test_an_entity_name_and_a_case_note_are_escaped(deployment):
    analyst = _client()
    examiner = _client("examiner", "ChangeMe-Examiner#2026")
    r = analyst.post("/upload/add-entity", data={"entity_id": "XSS-01", "name": f"Evil {SCRIPT}",
                                                 "sector": "power", "size_band": "Small"}, follow_redirects=False)
    assert r.status_code == 303
    for path in ("/upload", "/entity/XSS-01"):
        page = analyst.get(path)
        assert page.status_code == 200, path
        _no_raw(page.text, SCRIPT)

    store = SQLiteStore("data/satsa.db")
    try:
        finding = store.conn.execute("SELECT finding_id FROM findings WHERE run_id = "
                                     "(SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1) LIMIT 1").fetchone()[0]
    finally:
        store.close()
    opened = examiner.post("/cases", data={"finding_id": finding, "rationale": f"Opened {IMG}"}, follow_redirects=False)
    assert opened.status_code == 303, opened.text
    case_page = examiner.get(opened.headers["location"])
    assert case_page.status_code == 200 and "Opened" in case_page.text
    _no_raw(case_page.text, IMG)


def test_an_uploaded_file_name_is_escaped_on_the_job_page(deployment):
    analyst = _client()
    name = '<img src=x onerror=alert(1)>.csv'
    r = analyst.post("/upload", data={"target_entity": "CSE-01"},
                     files={"files": (name, b"alert_id,entity_id\nA-1,CSE-01\n", "text/csv")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/jobs/")
    page = analyst.get(r.headers["location"])
    assert page.status_code == 200
    _no_raw(page.text, "<img src=x")
    jobs = analyst.get("/jobs")
    _no_raw(jobs.text, "<img src=x")


@pytest.mark.parametrize(("path", "param"), [
    ("/upload", "message"), ("/alerts", "q"), ("/portfolio", "q"), ("/rules", "q"),
    ("/queue", "status"), ("/cases", "state"), ("/login", "error"), ("/login", "next"),
])
def test_reflected_parameters_are_escaped(deployment, path, param):
    client = TestClient(routes.app) if path == "/login" else _client()
    for payload in (SCRIPT, IMG):
        r = client.get(path, params={param: payload})
        assert r.status_code in (200, 400), (path, r.status_code)
        _no_raw(r.text, payload)


def test_templates_never_bypass_escaping():
    """`| safe` and `Markup` switch Jinja's escaping off; none of the templates may use them."""
    root = Path(routes.__file__).resolve().parents[1]
    offenders = [str(p) for p in root.glob("**/templates/*.html")
                 if "| safe" in p.read_text(encoding="utf-8") or "|safe" in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_the_admin_live_feed_escapes_what_it_renders():
    """The Admin Portal draws live events with innerHTML in the browser; every value from an
    event or a session goes through esc() first (an analyst controls file names and ids)."""
    root = Path(routes.__file__).resolve().parents[1]
    html = (root / "admin" / "templates" / "admin_overview.html").read_text(encoding="utf-8")
    script = html[html.index("function renderEventHTML"):html.index("function processIncoming")]
    import re

    raw = re.findall(r"\+\s*((?:ev|op)\.[a-z_.]+)\s*\+", script)
    assert raw == [], f"values put into HTML without esc(): {raw}"
    assert "function esc(value)" in html


# ---------------------------------------------------------------- SQL injection


@pytest.mark.parametrize(("path", "param"), [
    ("/alerts", "q"), ("/alerts", "severity"), ("/alerts", "actor_type"), ("/portfolio", "q"),
    ("/portfolio", "sort"), ("/portfolio", "band"), ("/queue", "status"), ("/cases", "state"),
    ("/rules", "q"), ("/rules", "domain"), ("/api/v1/cases", "entity_id"), ("/api/v1/findings", "entity_id"),
    ("/api/v1/queue", "status"), ("/runs", "period"), ("/jobs", "state"),
])
def test_list_filters_bind_hostile_values_as_data(deployment, path, param):
    analyst = _client()
    baseline = analyst.get(path)
    assert baseline.status_code == 200
    for payload in SQL_PAYLOADS:
        r = analyst.get(path, params={param: payload})
        assert r.status_code in (200, 400, 422), (path, param, payload, r.status_code)
        for marker in DB_ERROR_MARKERS:
            assert marker not in r.text, (path, param, payload)
    # Nothing was dropped or altered.
    store = SQLiteStore("data/satsa.db")
    try:
        assert store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] > 0
        assert store.conn.execute("SELECT COUNT(*) FROM identities").fetchone()[0] > 0
    finally:
        store.close()


def test_a_hostile_filter_never_widens_the_result(deployment):
    analyst = _client()
    everything = analyst.get("/api/v1/findings").json()
    assert everything
    for payload in SQL_PAYLOADS:
        r = analyst.get("/api/v1/findings", params={"entity_id": payload})
        assert r.status_code in (200, 400, 422)
        if r.status_code == 200:
            assert r.json() == [], payload


# ---------------------------------------------------------------- path traversal


SECRET_MARKERS = ("rules:", "BEGIN", "satsa_salt", "[extensions]", "root:")


@pytest.mark.parametrize("path", [
    "/static/../config/rules.yaml", "/static/%2e%2e/%2e%2e/config/rules.yaml", "/static/..%2f..%2fconfig%2frules.yaml",
    "/static/..%5c..%5cconfig%5crules.yaml", "/templates/..%2f..%2fconfig%2frules.yaml", "/templates/../../pyproject.toml",
    "/reports/..%2f..%2fdata%2fsatsa.db", "/jobs/..%2f..%2fdata", "/cases/CASE-1/attachments/..%2f..%2fsatsa.db",
    "/static/%2e%2e%2f%2e%2e%2fdata%2fsecrets%2fpseudonym.key",
])
def test_file_routes_do_not_leave_their_directory(deployment, path):
    r = _client().get(path)
    assert r.status_code in (400, 401, 403, 404, 405, 422), (path, r.status_code)
    body = r.content[:4096].decode("latin-1")
    for marker in SECRET_MARKERS:
        assert marker not in body, (path, marker)


def test_the_upload_keeps_only_a_file_names_last_part(deployment):
    analyst = _client()
    r = analyst.post("/upload", data={"target_entity": "CSE-01"},
                     files={"files": ("../../../escape.csv", b"alert_id,entity_id\nA-1,CSE-01\n", "text/csv")},
                     follow_redirects=False)
    assert r.status_code == 303
    assert not (deployment / "escape.csv").exists() and not (deployment / "data" / "escape.csv").exists()


# ---------------------------------------------------------------- open redirect


@pytest.mark.parametrize("target", [
    "https://evil.example/", "//evil.example/", "/\\evil.example/", "\\\\evil.example", "/\t/evil.example",
    "javascript:alert(1)", "evil.example", "",
])
def test_a_sign_in_never_redirects_off_the_portal(deployment, target):
    r = TestClient(routes.app).post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026",
                                                    "next": target}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/portfolio", (target, r.headers["location"])


def test_a_local_next_is_kept(deployment):
    assert safe_local_path("/queue?status=pending") == "/queue?status=pending"
    assert safe_local_path("/entity/CSE-01") == "/entity/CSE-01"
    r = TestClient(routes.app).post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026",
                                                    "next": "/queue"}, follow_redirects=False)
    assert r.headers["location"] == "/queue"
