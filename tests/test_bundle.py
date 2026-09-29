"""Tests for offline packaging, rule signer, and benchmark modules."""

import hashlib
import hmac
import io
import json
import tarfile
from pathlib import Path

import pytest

from satsa.bench.benchmark import BenchmarkRunner
from satsa.bundle.packager import OfflinePackager
from satsa.bundle.rules_signer import RulePackKeyError, RulePackSigner
from satsa.store.sqlite import SQLiteStore


def test_offline_packager(tmp_path: Path):
    packager = OfflinePackager()
    archive = packager.create_bundle(output_tar=True)
    assert archive.exists()
    assert archive.stat().st_size > 1000
    assert (packager.bundle_dir / "Containerfile").exists()
    assert (packager.bundle_dir / "README_OFFLINE.md").exists()


TEST_SECRET = "unit-test-rulepack-secret-0123456789abcdef"


def test_rule_pack_sign_and_verify(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SATSA_RULEPACK_SECRET", TEST_SECRET)
    sqlite_store = SQLiteStore("data/satsa.db")
    signer = RulePackSigner()

    out_tar = tmp_path / "rules_export.tar.gz"
    res_path = signer.export_rule_pack(config_dir="config", output_path=out_tar, version="2.0.0")
    assert res_path.exists()

    target_dir = tmp_path / "imported_config"
    res_imp = signer.import_rule_pack(
        out_tar, target_config_dir=target_dir, sqlite_store=sqlite_store, actor="pytest"
    )
    assert res_imp["status"] == "success"
    assert res_imp["verified"] is True
    assert (target_dir / "rules.yaml").read_bytes() == Path("config/rules.yaml").read_bytes()
    assert (target_dir / "mappings" / "cse_splunk.yaml").exists()
    sqlite_store.close()


def test_rule_pack_fails_loudly_without_secret(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SATSA_RULEPACK_SECRET", raising=False)
    with pytest.raises(RulePackKeyError, match="SATSA_RULEPACK_SECRET"):
        RulePackSigner()


@pytest.mark.parametrize("secret", ["SATSA_RULEPACK_NCIIPC_2026", "too-short"])
def test_rule_pack_rejects_burned_or_weak_secret(secret, monkeypatch):
    monkeypatch.setenv("SATSA_RULEPACK_SECRET", secret)
    with pytest.raises(RulePackKeyError):
        RulePackSigner()


def test_rules_cli_exits_nonzero_without_secret(tmp_path: Path, monkeypatch):
    from typer.testing import CliRunner

    from satsa.cli import app as cli_app

    monkeypatch.delenv("SATSA_RULEPACK_SECRET", raising=False)
    out = tmp_path / "pack.tar.gz"
    result = CliRunner().invoke(cli_app, ["rules", "export", "--output", str(out)])
    assert result.exit_code == 1
    assert "SATSA_RULEPACK_SECRET" in result.output
    assert not out.exists()


def test_rule_pack_routes_return_503_without_secret(monkeypatch):
    from fastapi.testclient import TestClient

    from satsa.api.routes import app

    monkeypatch.delenv("SATSA_RULEPACK_SECRET", raising=False)
    c = TestClient(app)
    r = c.post("/login", data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
               follow_redirects=False)
    assert r.status_code == 303
    assert c.get("/tuning/export-pack").status_code == 503


def _build_pack(path: Path, members: dict[str, bytes], secret: str | None, extra=None) -> None:
    """Hand-build a rule pack; signs manifest.json with `secret` if given."""
    files = dict(members)
    if secret is not None and "rule_pack/manifest.json" in files:
        sig = hmac.new(secret.encode(), files["rule_pack/manifest.json"], hashlib.sha256).hexdigest()
        files["rule_pack/signature.sig"] = sig.encode()
    with tarfile.open(path, "w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info in extra or []:
            tar.addfile(info)


def _manifest(files: dict[str, bytes]) -> bytes:
    return json.dumps(
        {"pack_version": "9.9.9", "files": {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}},
        sort_keys=True,
    ).encode()


@pytest.mark.parametrize(
    "evil_name",
    ["rule_pack/../../evil.yaml", "../evil.yaml", "/tmp/evil.yaml", r"rule_pack/..\evil.yaml", "other/evil.yaml"],
)
def test_rule_pack_rejects_malicious_member_paths(tmp_path: Path, monkeypatch, evil_name):
    monkeypatch.setenv("SATSA_RULEPACK_SECRET", TEST_SECRET)
    arc = tmp_path / "evil.tar.gz"
    good = {"rules.yaml": b"rules: {}\n"}
    members = {f"rule_pack/{k}": v for k, v in good.items()}
    members["rule_pack/manifest.json"] = _manifest(good)
    members[evil_name] = b"pwned"
    _build_pack(arc, members, TEST_SECRET)

    target = tmp_path / "target" / "config"
    with pytest.raises(ValueError):
        RulePackSigner().import_rule_pack(arc, target_config_dir=target)
    assert not target.exists()
    assert not (tmp_path / "evil.yaml").exists() and not (tmp_path / "target" / "evil.yaml").exists()


def test_rule_pack_rejects_signed_manifest_with_traversal_path(tmp_path: Path, monkeypatch):
    """Even a correctly SIGNED manifest can't direct a write outside the target dir."""
    monkeypatch.setenv("SATSA_RULEPACK_SECRET", TEST_SECRET)
    arc = tmp_path / "signed_evil.tar.gz"
    manifest = json.dumps(
        {"pack_version": "1", "files": {"../escape.yaml": hashlib.sha256(b"x").hexdigest()}}
    ).encode()
    _build_pack(arc, {"rule_pack/manifest.json": manifest, "rule_pack/escape.yaml": b"x"}, TEST_SECRET)
    target = tmp_path / "target"
    with pytest.raises(ValueError):
        RulePackSigner().import_rule_pack(arc, target_config_dir=target)
    assert not (tmp_path / "escape.yaml").exists()
    assert not target.exists()


def test_rule_pack_rejects_symlink_member(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SATSA_RULEPACK_SECRET", TEST_SECRET)
    arc = tmp_path / "link.tar.gz"
    link = tarfile.TarInfo("rule_pack/rules.yaml")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    _build_pack(arc, {"rule_pack/manifest.json": _manifest({})}, TEST_SECRET, extra=[link])
    with pytest.raises(ValueError, match="non-regular"):
        RulePackSigner().import_rule_pack(arc, target_config_dir=tmp_path / "t")


def test_rule_pack_bad_signature_rejected_before_any_write(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SATSA_RULEPACK_SECRET", TEST_SECRET)
    arc = tmp_path / "forged.tar.gz"
    good = {"rules.yaml": b"rules: {}\n"}
    members = {f"rule_pack/{k}": v for k, v in good.items()}
    members["rule_pack/manifest.json"] = _manifest(good)
    _build_pack(arc, members, "attacker-guessed-secret-000000000000000000")
    target = tmp_path / "target"
    with pytest.raises(PermissionError):
        RulePackSigner().import_rule_pack(arc, target_config_dir=target)
    assert not target.exists()


def test_benchmark_runner():
    bench = BenchmarkRunner("data")
    res_col = bench.run_columnar_scan_benchmark([10_000])
    assert len(res_col) == 1
    assert res_col[0]["throughput_rows_per_sec"] > 100_000

    e2e = bench.run_end_to_end_assessment_benchmark()
    assert e2e["throughput_alerts_per_sec"] > 500
