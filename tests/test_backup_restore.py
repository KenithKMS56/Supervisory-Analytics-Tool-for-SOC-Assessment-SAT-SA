"""Backup, restore, readiness, retention and diagnostics (docs/product_brief.md section 11).

The acceptance criterion this covers: "an independently restored instance reproduces a selected
assessment". A backup of a private copy of the deployment is restored into a new directory and a
run is replayed there, through the CLI as an operator would."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from deploy_utils import copy_deployment
from fastapi.testclient import TestClient

from satsa import ops
from satsa.backup import BackupError, create_backup, prune_backups, restore_backup
from satsa.keys import keyring_path
from satsa.store.catalog import Catalog
from satsa.store.sqlite import SQLiteStore

ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}
PASSPHRASE = "Backup-Passphrase#2026"


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    return root


def _latest_run(data: Path) -> str:
    store = SQLiteStore(data / "satsa.db")
    try:
        return str(store.conn.execute(
            "SELECT run_id FROM runs WHERE fingerprint IS NOT NULL ORDER BY created_at DESC LIMIT 1").fetchone()[0])
    finally:
        store.close()


def test_a_restored_instance_reproduces_an_assessment(deployment, tmp_path):
    run_id = _latest_run(deployment / "data")
    (deployment / "data" / "secrets" / "setup_token").parent.mkdir(parents=True, exist_ok=True)
    (deployment / "data" / "secrets" / "setup_token").write_text("not-for-backups", encoding="utf-8")
    made = subprocess.run([sys.executable, "-m", "satsa.cli", "backup", "--dest", str(tmp_path / "backups")],
                          cwd=deployment, env=ENV, capture_output=True, text=True, check=False)
    assert made.returncode == 0, made.stdout + made.stderr
    (backup,) = (tmp_path / "backups").iterdir()
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["published_files"] > 0 and manifest["counts"]["runs"] > 0
    assert "data/secrets/setup_token" not in manifest["files"], "the one-time setup token is not backed up"
    assert "data/satsa.db" in manifest["files"] and "data/catalog.db" in manifest["files"]

    restored = tmp_path / "restored"
    done = subprocess.run([sys.executable, "-m", "satsa.cli", "restore", str(backup), "--target", str(restored),
                           "--replay", run_id], cwd=tmp_path, env=ENV, capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"Replay of {run_id}: reproduced" in done.stdout
    assert keyring_path(restored / "data").read_bytes() == keyring_path(deployment / "data").read_bytes()
    assert (restored / "config" / "rules.yaml").read_bytes() == (deployment / "config" / "rules.yaml").read_bytes()


def test_a_damaged_backup_is_refused_before_anything_is_restored(deployment, tmp_path):
    backup = create_backup("data", tmp_path / "b")
    victim = next((backup / "data" / "parquet").rglob("*.parquet"))
    victim.write_bytes(victim.read_bytes()[:-1] + b"\0")
    with pytest.raises(BackupError, match="does not match its recorded SHA-256"):
        restore_backup(backup, tmp_path / "target")
    assert not (tmp_path / "target").exists() or not any((tmp_path / "target").iterdir())

    extra = create_backup("data", tmp_path / "c")
    (extra / "data" / "planted.txt").write_text("x", encoding="utf-8")
    with pytest.raises(BackupError, match="not in the manifest"):
        restore_backup(extra, tmp_path / "target2")


def test_restore_never_overwrites_an_existing_deployment(deployment, tmp_path):
    backup = create_backup("data", tmp_path / "b")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("mine", encoding="utf-8")
    with pytest.raises(BackupError, match="not empty"):
        restore_backup(backup, occupied)
    assert (occupied / "keep.txt").read_text(encoding="utf-8") == "mine"


def test_an_encrypted_backup_round_trips_and_detects_tampering(deployment, tmp_path):
    enc = create_backup("data", tmp_path / "enc", passphrase=PASSPHRASE)
    assert enc.suffix == ".satsa-backup" and enc.is_file()
    blob = enc.read_bytes()
    assert b"SQLite format 3" not in blob and b"PAR1" not in blob, "contents must not be readable"

    report = restore_backup(enc, tmp_path / "ok", passphrase=PASSPHRASE)
    assert report["files_verified"] > 0 and report["counts"]["runs"] > 0

    with pytest.raises(BackupError, match="Wrong passphrase"):
        restore_backup(enc, tmp_path / "wrong", passphrase="Another-Passphrase#2026")
    flipped = tmp_path / "flipped.satsa-backup"
    middle = len(blob) // 2
    flipped.write_bytes(blob[:middle] + bytes([blob[middle] ^ 1]) + blob[middle + 1:])
    with pytest.raises(BackupError, match="altered"):
        restore_backup(flipped, tmp_path / "f", passphrase=PASSPHRASE)
    truncated = tmp_path / "truncated.satsa-backup"
    truncated.write_bytes(blob[: len(blob) - 100])
    with pytest.raises(BackupError):
        restore_backup(truncated, tmp_path / "t", passphrase=PASSPHRASE)
    with pytest.raises(BackupError, match="12 characters"):
        create_backup("data", tmp_path / "weak", passphrase="short")


def test_a_held_batch_can_still_be_decided_after_a_restore(deployment, tmp_path):
    from satsa.ingest.pipeline import IngestionPipeline
    from satsa.store.duckdb import DuckDBStore

    src = tmp_path / "in"
    src.mkdir()
    (src / "alerts.csv").write_text(
        "entity_id,alert_id,created_at,severity_final\nCSE-01,HELD-1,2026-05-01T10:00:00Z,high\n"
        "CSE-02,HELD-2,2026-05-01T10:00:00Z,high\n", encoding="utf-8")
    duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    try:
        res = IngestionPipeline(duck, sql).ingest_directory(src, bound_entity="CSE-01", policy="if_clean",
                                                            period="2026-05", transport="upload")
    finally:
        duck.close()
        sql.close()
    assert res["status"] == "held"
    backup = create_backup("data", tmp_path / "b")
    restore_backup(backup, tmp_path / "r")
    catalog = Catalog(tmp_path / "r" / "data")
    try:
        assert catalog.publish_held(res["batch_id"], actor="test") > 0
        assert catalog.verify() == []
    finally:
        catalog.close()


def test_prune_keeps_the_newest_backups_only(tmp_path):
    for stamp in ("20260101T000000Z", "20260102T000000Z", "20260103T000000Z"):
        (tmp_path / f"satsa-backup-{stamp}").mkdir()
    (tmp_path / "unrelated").mkdir()
    removed = prune_backups(tmp_path, keep=2)
    assert [p.name for p in removed] == ["satsa-backup-20260101T000000Z"]
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "satsa-backup-20260102T000000Z", "satsa-backup-20260103T000000Z", "unrelated"]


# ---------------------------------------------------------------- health and readiness


def test_health_and_readiness(deployment, monkeypatch):
    from satsa.api.routes import app

    client = TestClient(app)
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz")
    assert ready.status_code == 200, ready.json()
    body = ready.json()
    assert set(body["checks"]) == {"database", "schema", "catalog", "disk"}
    assert body["worker"]["alive"] is False  # reported, not fatal: reads still work
    monkeypatch.setattr(ops, "MIN_FREE_DISK_BYTES", 1 << 62)
    low = client.get("/readyz")
    assert low.status_code == 503 and low.json()["checks"]["disk"]["ok"] is False


# ---------------------------------------------------------------- retention


def test_retention_removes_only_old_job_inputs_and_audits_it(deployment):
    from satsa.jobs.queue import JobQueue

    store = SQLiteStore("data/satsa.db")
    try:
        queue = JobQueue(store)
        old = queue.enqueue("import", {"files": ["a.csv"]}, "analyst")
        recent = queue.enqueue("import", {"files": ["b.csv"]}, "analyst")
        for job in (old, recent):
            queue.cancel(job["job_id"])
            (Path("data/jobs") / job["job_id"] / "input").mkdir(parents=True)
        long_ago = (dt.datetime.now(dt.UTC) - dt.timedelta(days=400)).isoformat()
        with store.transaction():
            store.conn.execute("UPDATE jobs SET finished_at = ? WHERE job_id = ?", (long_ago, old["job_id"]))
        runs_before = store.conn.execute("SELECT count(*) FROM runs").fetchone()[0]
    finally:
        store.close()
    files_before = _verify("data")

    preview = ops.apply_retention("data", dry_run=True)
    assert preview["job_inputs_removed"] == [old["job_id"]]
    assert (Path("data/jobs") / old["job_id"]).exists(), "a dry run removes nothing"

    done = ops.apply_retention("data", actor="test")
    assert done["job_inputs_removed"] == [old["job_id"]]
    assert not (Path("data/jobs") / old["job_id"]).exists()
    assert (Path("data/jobs") / recent["job_id"]).exists()
    store = SQLiteStore("data/satsa.db")
    try:
        assert store.conn.execute("SELECT count(*) FROM runs").fetchone()[0] == runs_before
        assert store.conn.execute("SELECT count(*) FROM audit_log WHERE action = 'retention_applied'").fetchone()[0] == 1
    finally:
        store.close()
    assert _verify("data") == files_before == []


def _verify(data: str) -> list[str]:
    catalog = Catalog(data)
    try:
        return catalog.verify()
    finally:
        catalog.close()


# ---------------------------------------------------------------- diagnostics


def test_the_diagnostics_package_holds_no_data_secrets_or_usernames(deployment, tmp_path):
    from satsa.jobs.queue import JobQueue

    store = SQLiteStore("data/satsa.db")
    try:
        JobQueue(store).enqueue("assessment", {"period": "2026-Q1"}, "analyst")
    finally:
        store.close()
    out = ops.diagnostics_bundle(tmp_path / "diag.zip", "data")
    with zipfile.ZipFile(out) as z:
        text = "\n".join(z.read(n).decode("utf-8") for n in z.namelist())
        names = set(z.namelist())
    assert {"environment.json", "schema.json", "jobs.json", "readiness.json", "table_counts.json"} <= names
    key_hex = json.loads(keyring_path("data").read_text(encoding="utf-8"))["keys"]["1"]["key_hex"]
    assert key_hex not in text
    for secret_like in ("analyst", "examiner", "nciipc_admin", "pass_hash", "setup_token", "ChangeMe"):
        assert secret_like not in text, secret_like
    assert "actor-" in text  # actors are present only as package-local hashes
