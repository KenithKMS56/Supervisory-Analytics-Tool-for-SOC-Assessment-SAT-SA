"""Rule-configuration lifecycle: draft -> approved (by someone else) -> active -> retired
(satsa.rules.lifecycle; docs/product_brief.md section 6, "rule-pack governance").

Production enforcement is tested on a private copy of the deployment set to production mode, so
nothing here relies on a test-suite bypass; demo mode's single-person activation is tested apart.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from urllib.parse import unquote_plus

import pytest
from deploy_utils import copy_deployment
from fastapi.testclient import TestClient

from satsa.api import routes
from satsa.deployment import DEMO, PRODUCTION, set_settings
from satsa.rules import lifecycle
from satsa.store.sqlite import SQLiteStore

RULES = Path("config/rules.yaml")
SECOND_ANALYST = "analyst2"
PASSPHRASE = "Second-Analyst-Passphrase#2026"


def _set_mode(mode: str) -> None:
    store = SQLiteStore("data/satsa.db")
    try:
        set_settings(store, {"mode": mode}, actor="test")
        if not store.conn.execute("SELECT 1 FROM identities WHERE username = ?", (SECOND_ANALYST,)).fetchone():
            store.create_user(SECOND_ANALYST, "analyst", PASSPHRASE)
    finally:
        store.close()


@pytest.fixture
def production(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    _set_mode(PRODUCTION)
    return root


@pytest.fixture
def demo(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    _set_mode(DEMO)
    return root


def _client(user: str, password: str) -> TestClient:
    c = TestClient(routes.app)
    r = c.post("/login", data={"username": user, "password": password}, follow_redirects=False)
    assert r.status_code == 303 and "error" not in r.headers["location"], user
    return c


def _analyst() -> TestClient:
    return _client("analyst", "ChangeMe-Analyst#2026")


def _examiner() -> TestClient:
    return _client("examiner", "ChangeMe-Examiner#2026")


def _versions() -> list[dict]:
    store = SQLiteStore("data/satsa.db")
    try:
        return lifecycle.versions(store)
    finally:
        store.close()


def _jobs() -> int:
    store = SQLiteStore("data/satsa.db")
    try:
        return store.conn.execute("SELECT count(*) FROM jobs").fetchone()[0]
    finally:
        store.close()


def _propose(client: TestClient, value: str = "0.31") -> int:
    r = client.post("/tuning/save", data={"EG04__max_comment_hash_share": value}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return int(re.search(r"Draft version (\d+)", unquote_plus(r.headers["location"])).group(1))


def test_a_saved_change_is_a_draft_that_changes_nothing(production):
    before, jobs = RULES.read_bytes(), _jobs()
    n = _propose(_analyst())
    assert RULES.read_bytes() == before, "a draft must not touch config/rules.yaml"
    assert _jobs() == jobs, "nothing is re-assessed for a draft"
    draft = next(v for v in _versions() if v["version_no"] == n)
    assert draft["state"] == "draft" and draft["created_by"] == "analyst"
    assert draft["changes"] == [{"field": "EG04.max_comment_hash_share", "old": 0.25, "new": 0.31}]
    assert "max_comment_hash_share: 0.31" in draft["rules_yaml"]


def test_approval_by_another_person_then_activation_puts_it_in_force(production):
    analyst, examiner = _analyst(), _examiner()
    n = _propose(analyst)
    # The author cannot approve their own change.
    assert analyst.post(f"/tuning/versions/{n}/approve", follow_redirects=False).status_code == 403
    # Nor can an unapproved draft be put in force.
    assert analyst.post(f"/tuning/versions/{n}/activate", follow_redirects=False).status_code == 409
    r = examiner.post(f"/tuning/versions/{n}/approve", data={"note": "Checked the preview"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/rule-versions")
    # Examiners decide, analysts run the engine: an examiner cannot put it in force.
    assert examiner.post(f"/tuning/versions/{n}/activate", follow_redirects=False).status_code == 403

    old_active = next(v for v in _versions() if v["state"] == "active")["version_no"]
    jobs = _jobs()
    r = analyst.post(f"/tuning/versions/{n}/activate", follow_redirects=False)
    assert r.status_code == 303 and "Re-assessment" in unquote_plus(r.headers["location"])
    assert "max_comment_hash_share: 0.31" in RULES.read_text(encoding="utf-8")
    states = {v["version_no"]: v for v in _versions()}
    assert states[n]["state"] == "active" and states[n]["approved_by"] == "examiner"
    assert states[old_active]["state"] == "retired" and states[old_active]["retired_at"]
    assert _jobs() == jobs + 1
    store = SQLiteStore("data/satsa.db")
    try:
        actions = [r[0] for r in store.conn.execute("SELECT action FROM audit_log ORDER BY rowid")]
    finally:
        store.close()
    for action in ("rule_version_proposed", "rule_version_approved", "rule_version_activated"):
        assert action in actions


def test_a_draft_based_on_an_older_version_cannot_overwrite_a_newer_one(production):
    analyst, second, examiner = _analyst(), _client(SECOND_ANALYST, PASSPHRASE), _examiner()
    first = _propose(analyst, "0.31")
    other = _propose(second, "0.4")  # both drafts start from the same active version
    for n in (first, other):
        assert examiner.post(f"/tuning/versions/{n}/approve", follow_redirects=False).status_code == 303
    assert analyst.post(f"/tuning/versions/{first}/activate", follow_redirects=False).status_code == 303
    r = analyst.post(f"/tuning/versions/{other}/activate", follow_redirects=False)
    assert r.status_code == 409 and "propose it again" in r.json()["detail"]
    assert "max_comment_hash_share: 0.31" in RULES.read_text(encoding="utf-8")


def test_a_rejection_needs_a_reason_and_ends_the_draft(production):
    analyst, examiner = _analyst(), _examiner()
    n = _propose(analyst)
    assert examiner.post(f"/tuning/versions/{n}/reject", data={"note": ""}, follow_redirects=False).status_code == 422
    assert examiner.post(f"/tuning/versions/{n}/reject", data={"note": "Raises EG04 noise"},
                         follow_redirects=False).status_code == 303
    assert examiner.post(f"/tuning/versions/{n}/approve", follow_redirects=False).status_code == 409
    assert analyst.post(f"/tuning/versions/{n}/activate", follow_redirects=False).status_code == 409


def test_the_database_refuses_self_approval_and_two_active_versions(production):
    n = _propose(_analyst())
    conn = sqlite3.connect("data/satsa.db")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE rule_pack_versions SET approved_by = created_by WHERE version_no = ?", (n,))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE rule_pack_versions SET state = 'active' WHERE version_no = ?", (n,))
    finally:
        conn.close()


def test_an_examiner_sees_the_versions_but_not_the_engine_room(production):
    examiner = _examiner()
    n = _propose(_analyst())
    page = examiner.get("/rule-versions")
    assert page.status_code == 200 and f"v{n}" in page.text and "Approve" in page.text
    assert examiner.get("/tuning", follow_redirects=False).status_code == 403
    assert examiner.post("/tuning/save", data={"EG04__max_comment_hash_share": "0.5"},
                         follow_redirects=False).status_code == 403


def test_an_edit_outside_the_lifecycle_is_recorded_and_flagged(production):
    analyst = _analyst()
    analyst.get("/tuning")  # the configuration in force is on record
    RULES.write_text(RULES.read_text(encoding="utf-8").replace("max_comment_hash_share: 0.25",
                                                               "max_comment_hash_share: 0.27"), encoding="utf-8")
    page = analyst.get("/tuning").text
    assert "changed outside the rule-change lifecycle" in page
    current = next(v for v in _versions() if v["state"] == "active")
    assert current["source"] == "external_edit" and "0.27" in current["rules_yaml"]
    assert "changed outside the rule-change lifecycle" not in analyst.get("/tuning").text  # flagged once


def test_a_demonstration_deployment_applies_a_change_at_once_and_says_so(demo):
    jobs = _jobs()
    r = _analyst().post("/tuning/save", data={"EG04__max_comment_hash_share": "0.33"}, follow_redirects=False)
    assert r.status_code == 303 and "Parameters updated!" in unquote_plus(r.headers["location"])
    assert "max_comment_hash_share: 0.33" in RULES.read_text(encoding="utf-8")
    current = next(v for v in _versions() if v["state"] == "active")
    assert current["approved_by"] is None and current["note"] == lifecycle.DEMO_ACTIVATION_NOTE
    assert _jobs() == jobs + 1


def test_an_imported_signed_pack_is_recorded_as_approved_by_its_signature(production, monkeypatch, tmp_path):
    from satsa.bundle.rules_signer import RulePackSigner

    monkeypatch.setenv("SATSA_RULEPACK_SECRET", "unit-test-rulepack-secret-0123456789abcdef")
    analyst = _analyst()
    analyst.get("/tuning")
    staged = tmp_path / "pack_config"
    staged.mkdir()
    (staged / "rules.yaml").write_text(RULES.read_text(encoding="utf-8").replace(
        "max_comment_hash_share: 0.25", "max_comment_hash_share: 0.29"), encoding="utf-8")
    pack = tmp_path / "pack.tar.gz"
    RulePackSigner().export_rule_pack(config_dir=staged, output_path=pack, version="2.0.0")
    r = analyst.post("/tuning/import-pack", files={"pack_file": ("pack.tar.gz", pack.read_bytes(), "application/gzip")},
                     follow_redirects=False)
    assert r.status_code == 303 and "approved by the pack's signature" in unquote_plus(r.headers["location"])
    current = next(v for v in _versions() if v["state"] == "active")
    assert current["source"] == "signed_pack" and current["approved_by"].startswith("signature:")
    assert "0.29" in current["rules_yaml"]
