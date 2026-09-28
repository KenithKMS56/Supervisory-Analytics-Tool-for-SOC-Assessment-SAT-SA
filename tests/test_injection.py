"""Regression tests for SQL injection and path traversal via externally supplied IDs.

Every call site fixed in hardening Step 1 is covered: all 20 rules, the rules-engine
routes (/entity, /alerts, /blind-review, /reports, /templates, delete-entity), the
admin portal's {username} routes, ingestion, and upload archive handling. Each test
asserts that a malicious value is rejected (or bound safely as a parameter) AND that
a legitimate value still works.
"""

import csv
import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from satsa.api.routes import app
from satsa.ingest.pipeline import IngestionPipeline
from satsa.rules.registry import RuleRegistry
from satsa.security import (
    is_valid_entity_id,
    is_valid_username,
    safe_archive_member,
    safe_join,
)
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

MALICIOUS_IDS = ["' OR '1'='1", "*", "../../etc/passwd", "..\\..\\x", "CSE-01'; DROP TABLE alert;--"]
LEGIT_IDS = [f"CSE-{i:02d}" for i in range(1, 11)]


def _login(c: TestClient, username: str = "admin", password: str = "ChangeMe-Admin#2026") -> None:
    resp = c.post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )
    assert resp.status_code == 303, f"login failed: {resp.text}"


def _partition_dirs() -> set[str]:
    root = Path("data/parquet")
    return {str(p) for p in root.glob("*/entity_id=*")} if root.exists() else set()


# ---------------------------------------------------------------- security.py units


@pytest.mark.parametrize("bad", MALICIOUS_IDS + ["", " CSE-01", "a" * 65, "CSE..01", None, 42])
def test_entity_id_validator_rejects_malicious(bad):
    assert not is_valid_entity_id(bad)


@pytest.mark.parametrize("good", LEGIT_IDS + ["CSE-DEMO", "STRESS-01", "a", "x.y_z-1"])
def test_entity_id_validator_accepts_legit(good):
    assert is_valid_entity_id(good)


def test_username_validator():
    assert is_valid_username("nciipc_admin")
    for bad in ["' OR '1'='1", "*", "../x", "ab", "a b c"]:
        assert not is_valid_username(bad)


@pytest.mark.parametrize("name", ["../x", "a/../../x", "/etc/passwd", "C:/x", "a\\b", ""])
def test_safe_archive_member_rejects(name):
    with pytest.raises(ValueError):
        safe_archive_member(name)


def test_safe_join(tmp_path):
    assert safe_join(tmp_path, "a/b.txt") == (tmp_path / "a" / "b.txt").resolve()
    with pytest.raises(ValueError):
        safe_join(tmp_path, "../escape.txt")


# ---------------------------------------------------------------- all 20 rules


class _RecordingStore:
    """Wraps DuckDBStore.query to record (sql, params) for every executed query."""

    def __init__(self, inner: DuckDBStore):
        self.inner = inner
        self.calls: list[tuple[str, list | None]] = []

    def query(self, sql, params=None):
        self.calls.append((sql, params))
        return self.inner.query(sql, params)


@pytest.fixture(scope="module")
def data_store():
    store = DuckDBStore("data")
    store.load_all_tables()
    yield store
    store.close()


ALL_RULES = RuleRegistry("config/rules.yaml").get_all_rules()


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
@pytest.mark.parametrize("payload", MALICIOUS_IDS)
def test_rule_binds_entity_id_as_parameter(rule, payload, data_store):
    """A malicious ID behaves exactly like an unknown (valid) ID.

    The executed SQL text must be byte-identical to the text executed for an
    unknown entity -- i.e. the payload never alters the query, it is only ever a
    bound parameter -- and the outcome must match too (it matches no rows).
    NS02/NS08 legitimately flag an entity with NO data as having missing
    categories / months, so "no finding" is not the invariant; "same as an
    unknown entity" is.
    """
    unknown = "NO-SUCH-ENTITY"
    rec_bad = _RecordingStore(data_store)
    rec_ref = _RecordingStore(data_store)
    bad_findings, _ = rule.evaluate(payload, rec_bad, [], "RUN-TEST")  # type: ignore[arg-type]
    ref_findings, _ = rule.evaluate(unknown, rec_ref, [], "RUN-TEST")  # type: ignore[arg-type]

    assert rec_bad.calls, "rule executed no queries"
    assert [sql for sql, _ in rec_bad.calls] == [sql for sql, _ in rec_ref.calls]
    assert any(params and payload in params for _, params in rec_bad.calls)
    assert len(bad_findings) == len(ref_findings)
    for bad, ref in zip(bad_findings, ref_findings):
        assert bad.rationale.replace(payload, unknown) == ref.rationale


def test_rules_still_fire_for_legit_entities(data_store):
    """Parameterization must not break detection: the dataset's firing rules still fire."""
    fired: set[str] = set()
    for rule in ALL_RULES:
        for eid in LEGIT_IDS:
            findings, _ = rule.evaluate(eid, data_store, [], "RUN-TEST")
            if findings:
                assert findings[0].entity_id == eid
                fired.add(rule.id)
    # The synthetic dataset injects defects for many rules; parameterized queries
    # must still detect them (a broken placeholder would silently return nothing).
    assert len(fired) >= 10, f"only {sorted(fired)} fired"


# ---------------------------------------------------------------- rules-engine routes


@pytest.fixture(scope="module")
def admin_client():
    c = TestClient(app)
    _login(c)
    return c


@pytest.mark.parametrize("payload", MALICIOUS_IDS)
def test_entity_profile_rejects_malicious(admin_client, payload):
    resp = admin_client.get(f"/entity/{payload}", follow_redirects=False)
    assert resp.status_code in (400, 404)


def test_entity_profile_legit(admin_client):
    assert admin_client.get("/entity/CSE-03").status_code == 200


@pytest.mark.parametrize("payload", MALICIOUS_IDS)
def test_alerts_filter_rejects_malicious(admin_client, payload):
    resp = admin_client.get("/alerts", params={"entity": payload})
    assert resp.status_code == 400


def test_alerts_filters_are_parameterized(admin_client):
    # Injection attempts in the other filters are bound as values: they match nothing
    # instead of widening the WHERE clause.
    resp = admin_client.get("/alerts", params={"severity": "x' OR '1'='1"})
    assert resp.status_code == 200
    assert "0 of 0" in resp.text or "No alerts" in resp.text or "Showing 0" in resp.text
    resp = admin_client.get("/alerts", params={"q": "' OR 1=1 --"})
    assert resp.status_code == 200
    assert admin_client.get("/alerts", params={"entity": "CSE-01"}).status_code == 200


@pytest.mark.parametrize("payload", MALICIOUS_IDS)
def test_blind_review_rejects_malicious(admin_client, payload):
    assert admin_client.get("/blind-review", params={"entity_id": payload}).status_code == 400


def test_blind_review_legit(admin_client):
    assert admin_client.get("/blind-review", params={"entity_id": "CSE-02"}).status_code == 200


@pytest.mark.parametrize("payload", ["' OR '1'='1", "*", "..\\..\\x"])
def test_reports_reject_malicious(admin_client, payload):
    before = set(Path(".").glob("*"))
    resp = admin_client.get(f"/reports/entity/{payload}/html")
    assert resp.status_code == 400
    assert set(Path(".").glob("*")) == before


@pytest.mark.parametrize("name", ["..\\..\\evil", "..%5C..%5Cevil", "passwd", "evil.csv"])
def test_templates_allow_list(admin_client, name):
    resp = admin_client.get(f"/templates/{name}")
    assert resp.status_code == 404
    assert not Path("evil.csv").exists() and not Path("data/evil.csv").exists()


def test_templates_legit(admin_client):
    assert admin_client.get("/templates/alerts.csv").status_code == 200
    assert admin_client.get("/templates/canonical_soc_submission_bundle.zip").status_code == 200


@pytest.mark.parametrize("payload", MALICIOUS_IDS)
def test_delete_entity_rejects_malicious(admin_client, payload):
    before = _partition_dirs()
    resp = admin_client.post(f"/upload/delete-entity/{payload}", follow_redirects=False)
    assert resp.status_code in (400, 404)
    assert _partition_dirs() == before, "a malicious ID must not delete any partition"


def test_delete_entity_only_removes_its_own_partitions(admin_client):
    tmp_id = "ZZTEST-DEL"
    resp = admin_client.post(
        "/upload/add-entity",
        data={"entity_id": tmp_id, "name": "Throwaway", "sector": "power", "size_band": "Small"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    mine = {p for p in _partition_dirs() if p.endswith(f"entity_id={tmp_id}")}
    assert mine, "add-entity should have created partitions"
    others_before = _partition_dirs() - mine

    resp = admin_client.post(f"/upload/delete-entity/{tmp_id}", follow_redirects=False)
    assert resp.status_code == 303
    after = _partition_dirs()
    assert not (after & mine)
    assert others_before <= after, "deleting one entity must not remove another's data"


def test_add_entity_rejects_malicious(admin_client):
    before = _partition_dirs()
    resp = admin_client.post(
        "/upload/add-entity",
        data={"entity_id": "../../evil", "name": "x", "sector": "power", "size_band": "Small"},
        follow_redirects=False,
    )
    assert resp.status_code == 303 and "Error" in resp.headers["location"]
    assert _partition_dirs() == before


def test_upload_zip_slip_rejected(admin_client, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../zip_slip_evil.csv", "alert_id,entity_id\nA1,CSE-01\n")
    resp = admin_client.post(
        "/upload",
        files={"files": ("bundle.zip", buf.getvalue(), "application/zip")},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error" in resp.headers["location"].lower()
    assert not Path("zip_slip_evil.csv").exists()


def test_upload_rejects_malicious_target_entity(admin_client):
    resp = admin_client.post(
        "/upload",
        data={"target_entity": "' OR '1'='1"},
        files={"files": ("a.csv", b"alert_id\nA1\n", "text/csv")},
        follow_redirects=False,
    )
    assert resp.status_code == 303 and "Error" in resp.headers["location"]


# ---------------------------------------------------------------- admin portal


@pytest.fixture
def admin_portal(tmp_path):
    from satsa.admin.app import app as admin_app

    store = SQLiteStore(tmp_path / "admin.db")
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    admin_app.state.store = store
    c = TestClient(admin_app)
    resp = c.post(
        "/login",
        data={"username": "nciipc_admin", "password": "ChangeMe-NCIIPC#2026"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    yield c, store
    store.close()


@pytest.mark.parametrize("payload", ["' OR '1'='1", "*", "..\\..\\x", "a%27%20OR%201%3D1"])
def test_admin_username_routes_reject_malicious(admin_portal, payload):
    c, store = admin_portal
    before = [(u["username"], u["status"]) for u in store.list_admin_users()]
    resp = c.post(f"/users/{payload}/block", follow_redirects=False)
    assert resp.status_code in (400, 404)
    assert [(u["username"], u["status"]) for u in store.list_admin_users()] == before


def test_admin_username_route_legit(admin_portal):
    c, store = admin_portal
    store.create_user("victim_1", "examiner", "Passphrase#12345")
    resp = c.post("/users/victim_1/block", follow_redirects=False)
    assert resp.status_code == 303
    assert store.get_user("victim_1")["status"] == "BLOCKED"


# ---------------------------------------------------------------- ingestion


def test_ingestion_drops_malformed_entity_rows(tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    with open(src / "alert.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["alert_id", "entity_id", "created_at", "severity_final"])
        w.writerow(["A1", "GOOD-01", "2026-01-01T00:00:00", "high"])
        w.writerow(["A2", "' OR '1'='1", "2026-01-01T00:00:00", "high"])
        w.writerow(["A3", "../../escape", "2026-01-01T00:00:00", "high"])
    duck = DuckDBStore(tmp_path / "store")
    lite = SQLiteStore(tmp_path / "store" / "t.db")
    res = IngestionPipeline(duck, lite).ingest_directory(src)
    assert res["status"] == "success"
    assert res["entities"] == ["GOOD-01"]
    parts = {p.name for p in (tmp_path / "store" / "parquet").glob("*/entity_id=*")}
    assert parts <= {"entity_id=GOOD-01"}
    assert not (tmp_path / "escape").exists()
    issues = lite.conn.execute(
        "SELECT count FROM dq_issues WHERE check_name = 'invalid_entity_id'"
    ).fetchall()
    assert issues and issues[0][0] == 2
    duck.close()
    lite.close()


def test_ingestion_rejects_malicious_default_entity(tmp_path):
    duck = DuckDBStore(tmp_path / "store")
    lite = SQLiteStore(tmp_path / "store" / "t.db")
    with pytest.raises(ValueError):
        IngestionPipeline(duck, lite).ingest_directory(tmp_path, default_entity_id="../x")
    duck.close()
    lite.close()


def test_parquet_writer_guard(tmp_path):
    import polars as pl

    duck = DuckDBStore(tmp_path)
    with pytest.raises(ValueError):
        duck.write_partitioned_parquet("alert", pl.DataFrame([{"entity_id": "../../x"}]))
    assert not (tmp_path / "x").exists()
    duck.close()


# ---------------------------------------------------------------- session cookie flags


def _set_cookie_header(resp, name: str) -> str:
    for value in resp.headers.get_list("set-cookie"):
        if value.startswith(f"{name}="):
            return value.lower()
    raise AssertionError(f"{name} cookie not set")


def test_satsa_session_cookie_flags():
    c = TestClient(app)
    resp = c.post(
        "/login",
        data={"username": "examiner", "password": "ChangeMe-Examiner#2026"},
        follow_redirects=False,
    )
    header = _set_cookie_header(resp, "satsa_session")
    assert "httponly" in header and "samesite=lax" in header


def test_admin_session_cookie_flags(tmp_path):
    from satsa.admin.app import app as admin_app

    store = SQLiteStore(tmp_path / "admin.db")
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    admin_app.state.store = store
    resp = TestClient(admin_app).post(
        "/login",
        data={"username": "nciipc_admin", "password": "ChangeMe-NCIIPC#2026"},
        follow_redirects=False,
    )
    header = _set_cookie_header(resp, "nciipc_admin_session")
    assert "httponly" in header and "samesite=strict" in header
    store.close()
