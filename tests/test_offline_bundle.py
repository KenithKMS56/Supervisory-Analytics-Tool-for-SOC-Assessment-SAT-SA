"""The offline bundle installs from its wheelhouse and nothing else.

Before the quality pass both install scripts and the Containerfile ended in a `pip install .`
fallback, so a bundle without a wheelhouse quietly went to PyPI on the "air-gapped" machine,
and no wheelhouse was ever put in the bundle (docs/CHANGES_quality_pass.md, M17).
"""

from __future__ import annotations

import os
import re
import subprocess
import tarfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from satsa.bundle.packager import OfflinePackager, WheelhouseError
from satsa.cli import app

PIP_INSTALL = re.compile(r"\bpip install\b[^\n]*")


def _fake_wheelhouse(directory: Path, with_satsa: bool = True) -> Path:
    directory.mkdir(parents=True)
    (directory / "requirements.txt").write_text("pyyaml==6.0.3 --hash=sha256:00\n", encoding="utf-8")
    (directory / "pyyaml-6.0.3-cp311-cp311-win_amd64.whl").write_bytes(b"not really a wheel")
    if with_satsa:
        (directory / "satsa-0.1.0-py3-none-any.whl").write_bytes(b"not really a wheel either")
    return directory


def _install_commands(text: str) -> list[str]:
    return PIP_INSTALL.findall(text)


@pytest.fixture(scope="module")
def bare_bundle(tmp_path_factory) -> OfflinePackager:
    """A bundle built with no wheelhouse at all."""
    packager = OfflinePackager(dist_dir=tmp_path_factory.mktemp("bare"))
    packager.wheelhouse = None  # even if this checkout has a wheelhouse/ of its own
    packager.create_bundle(output_tar=False)
    return packager


def test_no_install_path_falls_back_to_the_network(bare_bundle, tmp_path):
    generated = tmp_path / "Containerfile"
    bare_bundle._write_containerfile(generated)
    sources = {
        "Containerfile (repository)": Path("Containerfile").read_text(encoding="utf-8"),
        "Containerfile (generated)": generated.read_text(encoding="utf-8"),
        "install_offline.sh": (bare_bundle.bundle_dir / "install_offline.sh").read_text(encoding="utf-8"),
        "install_offline.bat": (bare_bundle.bundle_dir / "install_offline.bat").read_text(encoding="utf-8"),
    }
    for name, text in sources.items():
        commands = _install_commands(text)
        assert len(commands) == 2, (name, commands)
        for command in commands:
            assert "--no-index" in command, (name, command)
            assert "--find-links=wheelhouse" in command, (name, command)
        assert "|| pip" not in text and "pip install .\n" not in text, name
        assert not re.search(r"pip install \.(\s|$)", text), name


def test_the_repository_containerfile_is_the_one_the_packager_writes(bare_bundle, tmp_path):
    generated = tmp_path / "Containerfile"
    bare_bundle._write_containerfile(generated)
    repository = Path("Containerfile").read_text(encoding="utf-8").splitlines()
    assert generated.read_text(encoding="utf-8").splitlines() == repository


def test_dependencies_are_installed_with_their_hashes_checked(bare_bundle):
    for name in ("install_offline.sh", "install_offline.bat"):
        text = (bare_bundle.bundle_dir / name).read_text(encoding="utf-8")
        requirements, own = _install_commands(text)
        assert "--require-hashes -r wheelhouse/requirements.txt" in requirements
        assert re.search(r"--no-index --no-deps --find-links=wheelhouse satsa(\s|$)", own), own


def test_install_script_refuses_to_run_without_a_wheelhouse(bare_bundle):
    bundle = bare_bundle.bundle_dir
    if os.name == "nt":
        command = ["cmd", "/c", str(bundle / "install_offline.bat")]
    else:
        command = ["bash", str(bundle / "install_offline.sh")]
    done = subprocess.run(command, cwd=bundle.parent, capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 1, done
    assert "No wheelhouse" in done.stderr
    assert not (bundle / ".venv").exists(), "the script went on to create an environment"
    assert "wheelhouse: NOT included" in (bundle / "README_OFFLINE.md").read_text(encoding="utf-8")


def test_the_wheelhouse_is_copied_into_the_bundle_and_archive(tmp_path):
    wheelhouse = _fake_wheelhouse(tmp_path / "wh")
    packager = OfflinePackager(dist_dir=tmp_path / "out", wheelhouse=wheelhouse)
    archive = packager.create_bundle(output_tar=True)
    copied = packager.bundle_dir / "wheelhouse"
    assert sorted(p.name for p in copied.iterdir()) == sorted(p.name for p in wheelhouse.iterdir())
    assert (copied / "requirements.txt").read_bytes() == (wheelhouse / "requirements.txt").read_bytes()
    with tarfile.open(archive) as tar:
        names = set(tar.getnames())
    assert "satsa_offline_bundle/wheelhouse/satsa-0.1.0-py3-none-any.whl" in names
    assert "satsa_offline_bundle/wheelhouse/requirements.txt" in names
    assert "wheelhouse: included" in (packager.bundle_dir / "README_OFFLINE.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("broken", ["no requirements", "no wheels", "no satsa wheel"])
def test_a_directory_that_is_not_a_built_wheelhouse_is_refused(tmp_path, broken):
    wheelhouse = _fake_wheelhouse(tmp_path / "wh", with_satsa=broken != "no satsa wheel")
    if broken == "no requirements":
        (wheelhouse / "requirements.txt").unlink()
    elif broken == "no wheels":
        for wheel in wheelhouse.glob("*.whl"):
            wheel.unlink()
    with pytest.raises(WheelhouseError):
        OfflinePackager(dist_dir=tmp_path / "out", wheelhouse=wheelhouse).create_bundle(output_tar=False)


def test_offline_bundle_command_honours_output_dir_and_wheelhouse(tmp_path):
    wheelhouse = _fake_wheelhouse(tmp_path / "wh")
    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["offline-bundle", "--output-dir", str(out), "--wheelhouse", str(wheelhouse)])
    assert result.exit_code == 0, result.output
    assert (out / "satsa_offline_bundle.tar.gz").exists()
    assert (out / "satsa_offline_bundle" / "wheelhouse" / "satsa-0.1.0-py3-none-any.whl").exists()

    bad = CliRunner().invoke(app, ["offline-bundle", "--output-dir", str(out), "--wheelhouse", str(tmp_path)])
    assert bad.exit_code == 1
    assert "is not a wheelhouse" in " ".join(bad.output.split())
