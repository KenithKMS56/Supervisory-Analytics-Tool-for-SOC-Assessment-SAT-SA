"""Pseudonymisation keys persist with the data, never regenerate silently, and rotate visibly
(docs/product_brief.md section 2 source-review concern and section 10; satsa.keys)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from satsa.ingest.pipeline import IngestionPipeline
from satsa.keys import PseudonymKeyMissing, current_key, keyring_path, rotate, status
from satsa.store.catalog import Catalog
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

ALERTS = (
    "entity_id,alert_id,created_at,closed_at,severity_final,disposition,closed_by\n"
    "CSE-K,K-{n},2026-01-0{n}T10:00:00Z,2026-01-0{n}T11:00:00Z,high,true_positive,Jane Analyst\n"
)


def _ingest(data: Path, workdir: Path, n: int) -> str:
    """Ingest one alert closed by 'Jane Analyst' with the deployment key; return its pseudonym."""
    src = workdir / f"in{n}"
    src.mkdir(parents=True)
    (src / "alerts.csv").write_text(ALERTS.format(n=n), encoding="utf-8")
    duck, sql = DuckDBStore(data), SQLiteStore(data / "satsa.db")
    try:
        res = IngestionPipeline(duck, sql).ingest_directory(src)
        assert res["status"] == "success", res
        duck.load_all_tables()
        return str(duck.query(f"SELECT closed_by FROM alert WHERE alert_id = 'K-{n}'").item())
    finally:
        duck.close()
        sql.close()


def test_a_recreated_process_in_another_directory_keeps_the_pseudonyms(tmp_path, monkeypatch):
    """Like a recreated container: same data volume, different working directory, no .satsa_salt."""
    volume = tmp_path / "volume"
    volume.mkdir()
    data = volume / "data"
    monkeypatch.chdir(volume)
    first = _ingest(data, tmp_path, 1)
    assert first and "Jane" not in first
    assert keyring_path(data).exists()
    assert not Path(".satsa_salt").exists(), "the key must not be written to the working directory"

    elsewhere = tmp_path / "recreated"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    second = _ingest(data, tmp_path, 2)
    assert second == first


def test_a_legacy_salt_is_imported_byte_for_byte_and_left_in_place(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    legacy = os.urandom(32)
    Path(".satsa_salt").write_bytes(legacy)
    key = current_key(tmp_path / "data")
    assert key.key == legacy and key.version == 1
    assert Path(".satsa_salt").read_bytes() == legacy
    assert "imported from legacy salt" in status(tmp_path / "data")["versions"][0]["origin"]


def test_no_new_key_while_earlier_pseudonymised_data_exists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "data"
    _ingest(data, tmp_path, 1)
    keyring_path(data).unlink()  # the key is lost, e.g. a volume restored without data/secrets
    with pytest.raises(PseudonymKeyMissing, match="Restore data/secrets"):
        current_key(data)
    assert not keyring_path(data).exists()
    duck, sql = DuckDBStore(data), SQLiteStore(data / "satsa.db")
    try:
        with pytest.raises(PseudonymKeyMissing):
            IngestionPipeline(duck, sql)
    finally:
        duck.close()
        sql.close()


def test_each_batch_records_its_key_and_rotation_is_visible(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "data"
    before = _ingest(data, tmp_path, 1)
    old_id = current_key(data).key_id
    new = rotate(data)
    after = _ingest(data, tmp_path, 2)
    assert new.version == 2 and new.key_id != old_id
    assert after != before, "a rotated key must not reproduce the old pseudonyms"
    catalog = Catalog(data)
    try:
        used = [r[0] for r in catalog.conn.execute(
            "SELECT pseudonym_key_id FROM batches WHERE transport != 'direct' ORDER BY received_at")]
    finally:
        catalog.close()
    assert used == [old_id, new.key_id]
    assert [v["key_id"] for v in status(data)["versions"]] == [old_id, new.key_id]
    text = keyring_path(data).read_text(encoding="utf-8")
    assert "key_hex" in text  # kept for old batches
    assert "key_hex" not in str(status(data))  # never shown


def test_the_cli_refuses_to_rotate_without_confirmation_and_audits_rotation(tmp_path):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    data = tmp_path / "data"
    run = [sys.executable, "-m", "satsa.cli", "keys"]
    assert subprocess.run([*run, "init", "--data-dir", str(data)], env=env, cwd=tmp_path, check=False).returncode == 0
    refused = subprocess.run([*run, "rotate", "--data-dir", str(data)], env=env, cwd=tmp_path, capture_output=True, check=False)
    assert refused.returncode == 2
    done = subprocess.run([*run, "rotate", "--data-dir", str(data), "--i-understand-pseudonyms-will-not-link"],
                          env=env, cwd=tmp_path, capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    sql = SQLiteStore(data / "satsa.db")
    try:
        actions = [r[0] for r in sql.conn.execute("SELECT action FROM audit_log")]
    finally:
        sql.close()
    assert "pseudonym_key_rotated" in actions


def test_the_secrets_directory_is_not_served(tmp_path):
    """Keys sit under data/, which no static mount exposes."""
    from satsa.api.routes import STATIC_DIR

    assert Path("data").resolve() not in Path(STATIC_DIR).resolve().parents
