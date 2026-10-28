"""Secure defaults (docs/product_brief.md sections 9-10): production starts empty with no published
passphrases and is set up through a one-time local token; demo mode is opt-in, isolated and
labelled. These tests run with the real seeding behaviour (`first_login_enforced`) and without
the suite's demo environment."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from satsa import deployment
from satsa.store.sqlite import SQLiteStore, forget_schema_checks


@pytest.fixture
def production_env(monkeypatch, first_login_enforced):
    monkeypatch.delenv("SATSA_DEMO", raising=False)


@pytest.fixture
def demo_env(monkeypatch, first_login_enforced):
    monkeypatch.setenv("SATSA_DEMO", "1")


def test_a_demoted_admin_account_stays_demoted_after_a_restart(tmp_path, demo_env):
    """Extra defect: seed_default_admin re-promoted and re-activated `admin` on every start."""
    store = SQLiteStore(tmp_path / "satsa.db")
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    with store.transaction():
        store.conn.execute(
            "UPDATE identities SET role = 'examiner', is_admin_user = 0, status = 'BLOCKED', is_blocked = 1 "
            "WHERE username = 'admin'"
        )
    store.close()

    restarted = SQLiteStore(tmp_path / "satsa.db")  # what each portal does at start
    restarted.seed_default_organisations_and_cses()
    restarted.seed_default_admin()
    row = restarted.conn.execute(
        "SELECT role, is_admin_user, status, is_blocked FROM identities WHERE username = 'admin'"
    ).fetchone()
    restarted.close()
    assert dict(row) == {"role": "examiner", "is_admin_user": 0, "status": "BLOCKED", "is_blocked": 1}


# ---------------------------------------------------------------- production


@pytest.fixture
def production_root(tmp_path, monkeypatch, production_env):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _store() -> SQLiteStore:
    return SQLiteStore("data/satsa.db")


def test_production_starts_with_no_accounts_and_no_published_passphrase(production_root):
    store = _store()
    try:
        assert deployment.mode(store) == deployment.PRODUCTION
        assert store.conn.execute("SELECT count(*) FROM identities").fetchone()[0] == 0
        store.seed_default_organisations_and_cses()
        store.seed_default_admin()  # what the Admin Portal does at start: nothing, in production
        assert store.conn.execute("SELECT count(*) FROM identities").fetchone()[0] == 0
        assert deployment.setup_pending(store)
    finally:
        store.close()


def test_start_up_issues_one_setup_token_and_seeds_nothing(production_root):
    lines = deployment.prepare_deployment("data")
    token = lines[2].strip()
    token_file = Path("data/secrets/setup_token")
    assert token_file.read_text(encoding="utf-8") == token and len(token) >= 24
    assert deployment.prepare_deployment("data")[2].strip() == token, "a restart keeps the same token"
    store = _store()
    try:
        assert store.conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0, "no demo data in production"
        assert store.conn.execute("SELECT count(*) FROM identities").fetchone()[0] == 0
    finally:
        store.close()


def _admin_client(store: SQLiteStore) -> TestClient:
    from satsa.admin.app import app as admin_app

    admin_app.state.store = store
    return TestClient(admin_app)


SETUP_FORM = {"username": "ops-admin", "password": "Setup-Passphrase#2026", "confirm_password": "Setup-Passphrase#2026",
              "deployment_name": "Test deployment", "timezone": "Asia/Kolkata", "job_inputs_days": "30", "backups_keep": "7"}


def test_first_run_setup_creates_the_administrator_with_the_token_once(production_root):
    token = deployment.prepare_deployment("data")[2].strip()
    store = _store()
    try:
        client = _admin_client(store)
        r = client.get("/login", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/setup"
        assert client.get("/setup").status_code == 200

        assert client.post("/setup", data={**SETUP_FORM, "token": "wrong"}).status_code == 400
        weak = {**SETUP_FORM, "token": token, "password": "short", "confirm_password": "short"}
        assert "at least" in client.post("/setup", data=weak).text
        published = {**SETUP_FORM, "token": token, "password": "ChangeMe-Admin#2026",
                     "confirm_password": "ChangeMe-Admin#2026"}
        assert "published default passphrase" in client.post("/setup", data=published).text
        assert store.conn.execute("SELECT count(*) FROM identities").fetchone()[0] == 0

        r = client.post("/setup", data={**SETUP_FORM, "token": token}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"
        assert not Path("data/secrets/setup_token").exists(), "the token is consumed"
        assert client.get("/setup").status_code == 404
        assert client.post("/setup", data={**SETUP_FORM, "token": token}).status_code == 404

        r = client.post("/login", data={"username": "ops-admin", "password": SETUP_FORM["password"]},
                        follow_redirects=False)
        # Production requires a second factor for administrators: enrolment comes first.
        assert r.status_code == 303 and r.headers["location"] == "/mfa/setup"
        values = deployment.settings(store)
        assert values["deployment_name"] == "Test deployment" and values["timezone"] == "Asia/Kolkata"
        assert values["retention_job_inputs_days"] == "30" and "setup_token_sha256" not in values
        actions = [r[0] for r in store.conn.execute("SELECT action FROM audit_log")]
        assert "first_run_setup_completed" in actions
        admin_actions = [r[0] for r in store.conn.execute("SELECT action FROM admin_audit_log")]
        assert admin_actions.count("SETUP_FAILED") == 3 and "FIRST_RUN_SETUP" in admin_actions
    finally:
        store.close()


def test_setup_token_guessing_is_throttled(production_root):
    token = deployment.prepare_deployment("data")[2].strip()
    store = _store()
    try:
        client = _admin_client(store)
        for _ in range(5):
            assert client.post("/setup", data={**SETUP_FORM, "token": "guess"}).status_code == 400
        assert client.post("/setup", data={**SETUP_FORM, "token": token}).status_code == 429
        assert deployment.setup_pending(store)
    finally:
        store.close()


def test_production_pages_show_no_demo_credentials_and_refuse_demo_data(production_root):
    store = _store()
    try:
        store.create_user("prod-analyst", "analyst", "Analyst-Passphrase#2026")
    finally:
        store.close()
    from satsa.api.routes import app

    client = TestClient(app)
    page = client.get("/login").text
    assert "ChangeMe" not in page and "issued by your deployment administrator" in page
    assert "DEMONSTRATION DEPLOYMENT" not in page
    r = client.post("/login", data={"username": "prod-analyst", "password": "Analyst-Passphrase#2026"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert "Load Demonstration Data" not in client.get("/upload").text
    assert client.post("/upload/trigger-demo", follow_redirects=False).status_code == 403


def test_the_cli_sets_up_a_deployment_without_the_token(production_root):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "SATSA_SETUP_PASSPHRASE": "Cli-Setup-Passphrase#2026"}
    env.pop("SATSA_DEMO", None)
    done = subprocess.run(
        [sys.executable, "-m", "satsa.cli", "setup", "--admin-username", "cli-admin", "--deployment-name", "CLI box"],
        cwd=production_root, env=env, capture_output=True, text=True, check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    store = _store()
    try:
        assert not deployment.setup_pending(store)
        assert store.get_identity("cli-admin")["role"] == deployment.SETUP_ADMIN_ROLE
    finally:
        store.close()


# ---------------------------------------------------------------- demo


def test_demo_is_labelled_seeded_and_loads_its_data_through_one_job(tmp_path, monkeypatch, demo_env):
    monkeypatch.chdir(tmp_path)
    deployment.prepare_deployment("data")
    deployment.prepare_deployment("data")  # a restart does not queue a second load
    store = _store()
    try:
        assert deployment.is_demo(store)
        flags = dict(store.conn.execute("SELECT username, force_password_change FROM identities").fetchall())
        # Published for one-click sign-in, so no change is owed (test_first_login_password_change.py).
        assert set(flags) >= {"admin", "analyst", "examiner", "nciipc_admin"} and set(flags.values()) == {0}
        jobs = store.conn.execute("SELECT kind, state FROM jobs").fetchall()
        assert [tuple(j) for j in jobs] == [("demo_seed", "queued")]
    finally:
        store.close()
    from satsa.api.routes import app

    page = TestClient(app).get("/login").text
    assert "DEMONSTRATION DEPLOYMENT" in page and "ChangeMe-Analyst#2026" in page


def test_a_demo_process_refuses_production_data(tmp_path, monkeypatch, production_env):
    monkeypatch.chdir(tmp_path)
    deployment.prepare_deployment("data")  # a production deployment
    monkeypatch.setenv("SATSA_DEMO", "1")
    with pytest.raises(deployment.DemoIsolationError, match="production deployment"):
        deployment.prepare_deployment("data")
    store = _store()
    try:
        assert store.conn.execute("SELECT count(*) FROM identities").fetchone()[0] == 0
        assert deployment.mode(store) == deployment.PRODUCTION, "the mode never flips"
    finally:
        store.close()


def test_a_database_from_before_modes_is_recorded_as_production_and_already_set_up(tmp_path, demo_env):
    db = tmp_path / "satsa.db"
    store = SQLiteStore(db)
    with store.transaction():
        store.conn.execute("DELETE FROM deployment_settings")  # as written by a release without modes
    store.close()
    forget_schema_checks()  # the file now stands for one an older release wrote
    reopened = SQLiteStore(db)
    try:
        values = deployment.settings(reopened)
        assert values["mode"] == deployment.PRODUCTION and "before deployment modes" in values["mode_origin"]
        assert not deployment.setup_pending(reopened)
    finally:
        reopened.close()
