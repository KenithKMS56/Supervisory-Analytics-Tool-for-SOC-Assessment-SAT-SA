"""Release metadata of the offline bundle: SBOM, licence notices, checksums and an Ed25519
signature (docs/product_brief.md section 11; satsa.bundle.release; docs/offline_install.md)."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from satsa.bundle import release
from satsa.bundle.packager import OfflinePackager
from satsa.cli import app


def _locked_version(name: str) -> str:
    lock = tomllib.loads(Path("uv.lock").read_text(encoding="utf-8"))
    return next(p["version"] for p in lock["package"] if p["name"] == name)


@pytest.fixture(scope="module")
def keys(tmp_path_factory) -> tuple[Path, Path]:
    return release.generate_keypair(tmp_path_factory.mktemp("keys"))


@pytest.fixture(scope="module")
def signed_bundle(tmp_path_factory, keys) -> Path:
    packager = OfflinePackager(dist_dir=tmp_path_factory.mktemp("signed"))
    packager.wheelhouse = None
    packager.create_bundle(output_tar=False, signing_key=keys[0])
    return packager.bundle_dir


def test_the_sbom_lists_the_locked_runtime_closure_only():
    bom = release.sbom("uv.lock", "0.1.0")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    versions = {c["name"]: c["version"] for c in bom["components"]}
    assert versions["fastapi"] == _locked_version("fastapi")
    assert versions["duckdb"] == _locked_version("duckdb")
    assert "starlette" in versions, "transitive runtime dependencies are included"
    for dev_only in ("pytest", "playwright", "ruff", "mypy", "hypothesis"):
        assert dev_only not in versions, f"{dev_only} is a development tool, not shipped"
    duckdb = next(c for c in bom["components"] if c["name"] == "duckdb")
    assert duckdb["purl"] == f"pkg:pypi/duckdb@{_locked_version('duckdb')}"
    assert duckdb["hashes"] and all(len(h["content"]) == 64 for h in duckdb["hashes"])


def test_the_bundle_carries_release_metadata_and_checksums_cover_every_file(signed_bundle):
    for name in ("sbom.cdx.json", "THIRD_PARTY_LICENSES.txt", "RELEASE.json", "uv.lock",
                 release.SUMS_FILE, release.SIG_FILE, "docs/offline_install.md"):
        assert (signed_bundle / name).is_file(), name
    facts = json.loads((signed_bundle / "RELEASE.json").read_text(encoding="utf-8"))
    assert facts["lockfile_sha256"] and facts["tested_targets"] and facts["untested_targets"]
    listed = {line.split("  ", 1)[1] for line in
              (signed_bundle / release.SUMS_FILE).read_text(encoding="utf-8").splitlines()}
    present = {p.relative_to(signed_bundle).as_posix() for p in signed_bundle.rglob("*") if p.is_file()}
    assert listed == present - {release.SUMS_FILE, release.SIG_FILE}
    assert "fastapi" in (signed_bundle / "THIRD_PARTY_LICENSES.txt").read_text(encoding="utf-8")


def test_a_signed_bundle_verifies_with_its_public_key(signed_bundle, keys):
    result = release.verify(signed_bundle, keys[1])
    assert result["signature_verified"] and result["files"] > 50


def test_verification_rejects_tampering_a_wrong_key_and_extra_or_missing_files(signed_bundle, keys, tmp_path):
    import shutil

    (tmp_path / "other").mkdir()
    other_private, other_public = release.generate_keypair(tmp_path / "other")
    with pytest.raises(release.ReleaseVerificationError, match="signature"):
        release.verify(signed_bundle, other_public)

    copy = tmp_path / "copy"
    shutil.copytree(signed_bundle, copy)
    target = copy / "src" / "satsa" / "scoring" / "scorer.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    with pytest.raises(release.ReleaseVerificationError, match="scorer.py"):
        release.verify(copy, keys[1])

    shutil.rmtree(copy)
    shutil.copytree(signed_bundle, copy)
    (copy / "src" / "satsa" / "planted.py").write_text("print('x')\n", encoding="utf-8")
    with pytest.raises(release.ReleaseVerificationError, match="not in SHA256SUMS"):
        release.verify(copy, keys[1])

    shutil.rmtree(copy)
    shutil.copytree(signed_bundle, copy)
    (copy / "RELEASE.json").unlink()
    with pytest.raises(release.ReleaseVerificationError, match="missing"):
        release.verify(copy, keys[1])

    # Re-signing the edited SHA256SUMS needs the private key: a re-hashed manifest alone fails.
    shutil.rmtree(copy)
    shutil.copytree(signed_bundle, copy)
    (copy / "src" / "satsa" / "planted.py").write_text("print('x')\n", encoding="utf-8")
    release.write_checksums(copy)
    with pytest.raises(release.ReleaseVerificationError, match="signature"):
        release.verify(copy, keys[1])
    release.sign(copy, other_private)
    with pytest.raises(release.ReleaseVerificationError, match="signature"):
        release.verify(copy, keys[1])


def test_unsigned_bundles_report_that_the_signature_was_not_checked(tmp_path):
    packager = OfflinePackager(dist_dir=tmp_path)
    packager.wheelhouse = None
    packager.create_bundle(output_tar=False)
    assert not (packager.bundle_dir / release.SIG_FILE).exists()
    assert release.verify(packager.bundle_dir, None)["signature_verified"] is False
    with pytest.raises(release.ReleaseVerificationError, match="not signed"):
        release.verify(packager.bundle_dir, tmp_path / "unused.pem")


def test_a_non_ed25519_signing_key_is_refused(tmp_path, signed_bundle):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "ec.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    with pytest.raises(TypeError, match="Ed25519"):
        release.sign(signed_bundle, path)


def test_release_cli_keygen_and_verify(signed_bundle, keys, tmp_path):
    runner = CliRunner()
    made = runner.invoke(app, ["release", "keygen", "--out", str(tmp_path / "k")])
    assert made.exit_code == 0 and "Fingerprint" in made.output
    again = runner.invoke(app, ["release", "keygen", "--out", str(tmp_path / "k")])
    assert again.exit_code == 1, "an existing private key is never overwritten"

    ok = runner.invoke(app, ["release", "verify", str(signed_bundle), "--public-key", str(keys[1])])
    assert ok.exit_code == 0 and "Signature valid" in ok.output, ok.output
    wrong = runner.invoke(app, ["release", "verify", str(signed_bundle), "--public-key",
                                str(tmp_path / "k" / "release_public_key.pem")])
    assert wrong.exit_code == 1 and "Verification failed" in wrong.output
