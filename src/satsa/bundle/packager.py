"""Offline bundling and distribution package creator for SAT-SA."""

import os
import shutil
import tarfile
import zipfile
from pathlib import Path

# Both install paths take every package from the bundled wheelhouse and nothing else: there is
# no "pip install ." fallback, which would reach for PyPI whenever the wheelhouse was missing.
# The wheelhouse comes from scripts/build_wheelhouse.sh (or .bat); see docs/offline_install.md.
PIP_INSTALL_REQUIREMENTS = (
    "pip install --no-index --find-links=wheelhouse --require-hashes -r wheelhouse/requirements.txt"
)
PIP_INSTALL_SATSA = "pip install --no-index --no-deps --find-links=wheelhouse satsa"


class WheelhouseError(ValueError):
    """The wheelhouse given to the packager is not one scripts/build_wheelhouse.sh produced."""


class OfflinePackager:
    """Packages SAT-SA into a self-contained air-gapped deployment bundle."""

    def __init__(
        self,
        root_dir: Path | str = ".",
        dist_dir: Path | str | None = None,
        wheelhouse: Path | str | None = None,
    ):
        self.root_dir = Path(root_dir).resolve()
        self.dist_dir = Path(dist_dir).resolve() if dist_dir is not None else self.root_dir / "dist"
        self.bundle_dir = self.dist_dir / "satsa_offline_bundle"
        # Default: the root's wheelhouse/ when there is one (the build scripts' default output).
        if wheelhouse is None and (self.root_dir / "wheelhouse").is_dir():
            wheelhouse = self.root_dir / "wheelhouse"
        self.wheelhouse = Path(wheelhouse).resolve() if wheelhouse is not None else None

    def create_bundle(self, output_tar: bool = True) -> Path:
        """Assemble all source, configs, vendored assets, containerfiles, and offline scripts."""
        self.dist_dir.mkdir(parents=True, exist_ok=True)
        if self.bundle_dir.exists():
            shutil.rmtree(self.bundle_dir)
        self.bundle_dir.mkdir(parents=True, exist_ok=True)

        # 1. Copy src
        shutil.copytree(self.root_dir / "src", self.bundle_dir / "src")

        # 2. Copy config
        shutil.copytree(self.root_dir / "config", self.bundle_dir / "config")

        # 3. Copy project files
        for f in ["pyproject.toml", "README.md", "LICENSE"]:
            src_f = self.root_dir / f
            if src_f.exists():
                shutil.copy(src_f, self.bundle_dir / f)

        # 4. Copy or write Containerfile
        containerfile_path = self.root_dir / "Containerfile"
        if not containerfile_path.exists():
            self._write_containerfile(self.root_dir / "Containerfile")
        shutil.copy(self.root_dir / "Containerfile", self.bundle_dir / "Containerfile")

        # 5. Copy the wheelhouse, the only package source the install scripts use
        if self.wheelhouse is not None:
            self._copy_wheelhouse(self.wheelhouse, self.bundle_dir / "wheelhouse")

        # 6. Create offline install scripts and instructions
        self._write_offline_scripts(self.bundle_dir)

        # 7. Create archive
        if output_tar:
            archive_path = self.dist_dir / "satsa_offline_bundle.tar.gz"
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(self.bundle_dir, arcname="satsa_offline_bundle")
            return archive_path
        else:
            archive_path = self.dist_dir / "satsa_offline_bundle.zip"
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zip_f:
                for root, _, files in os.walk(self.bundle_dir):
                    for file in files:
                        abs_p = Path(root) / file
                        rel_p = abs_p.relative_to(self.dist_dir)
                        zip_f.write(abs_p, rel_p)
            return archive_path

    @staticmethod
    def _copy_wheelhouse(source: Path, target: Path) -> None:
        """Copy requirements.txt and the wheels; refuse anything that is not a built wheelhouse."""
        requirements = source / "requirements.txt"
        wheels = sorted(source.glob("*.whl"))
        if not requirements.is_file() or not wheels:
            raise WheelhouseError(
                f"{source} is not a wheelhouse: it needs requirements.txt and the wheels that "
                "scripts/build_wheelhouse.sh writes (see docs/offline_install.md)"
            )
        if not any(w.name.startswith("satsa-") for w in wheels):
            raise WheelhouseError(f"{source} has no satsa wheel; rebuild it with scripts/build_wheelhouse.sh")
        target.mkdir(parents=True)
        shutil.copy(requirements, target / "requirements.txt")
        for wheel in wheels:
            shutil.copy(wheel, target / wheel.name)

    def _write_containerfile(self, target_path: Path) -> None:
        """Write production air-gapped Containerfile."""
        content = f"""# SAT-SA Air-Gapped OCI Container
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PIP_NO_CACHE_DIR=1 \\
    PIP_NO_INDEX=1 \\
    SATSA_AIRGAPPED=1

WORKDIR /app

# Copy bundle
COPY . /app

# Install from the bundled wheelhouse only (Linux wheels: docs/offline_install.md). There is
# no network fallback: without a wheelhouse the build stops here.
RUN {PIP_INSTALL_REQUIREMENTS} && \\
    {PIP_INSTALL_SATSA}

EXPOSE 8000

# Default command launches offline web UI and REST API. Inside the container it listens on
# every container interface so the port can be published; publish it on the host's loopback
# unless other machines are meant to reach it:  -p 127.0.0.1:8000:8000
ENTRYPOINT ["satsa"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
"""
        target_path.write_text(content, encoding="utf-8")

    def _write_offline_scripts(self, target_dir: Path) -> None:
        """Write offline setup helper scripts."""
        sh_script = f"""#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "=========================================================="
echo "Installing SAT-SA in Air-Gapped Environment"
echo "=========================================================="

if [ ! -f wheelhouse/requirements.txt ]; then
    echo "[!] No wheelhouse/ in this bundle. Build one on a connected machine with" >&2
    echo "    scripts/build_wheelhouse.sh, then rebuild the bundle (docs/offline_install.md)." >&2
    echo "    Nothing is downloaded: this script never uses the network." >&2
    exit 1
fi

export PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1
python3 -m venv .venv
source .venv/bin/activate

python -m {PIP_INSTALL_REQUIREMENTS}
python -m {PIP_INSTALL_SATSA}

echo "[+] Installation complete. Verifying air-gap operation..."
satsa version
echo "[+] Ready. Run 'satsa serve' to start offline dashboard."
"""
        (target_dir / "install_offline.sh").write_text(sh_script, encoding="utf-8", newline="\n")

        bat_script = f"""@echo off
cd /d "%~dp0"
echo ==========================================================
echo Installing SAT-SA in Air-Gapped Windows Environment
echo ==========================================================

if not exist wheelhouse\\requirements.txt (
    echo [!] No wheelhouse\\ in this bundle. Build one on a connected machine with 1>&2
    echo     scripts\\build_wheelhouse.bat, then rebuild the bundle ^(docs\\offline_install.md^). 1>&2
    echo     Nothing is downloaded: this script never uses the network. 1>&2
    exit /b 1
)

set PIP_NO_INDEX=1
set PIP_DISABLE_PIP_VERSION_CHECK=1
python -m venv .venv || exit /b 1
call .venv\\Scripts\\activate.bat

python -m {PIP_INSTALL_REQUIREMENTS} || exit /b 1
python -m {PIP_INSTALL_SATSA} || exit /b 1

echo [+] Installation complete.
satsa version
echo [+] Run 'satsa serve' to launch offline dashboard.
"""
        (target_dir / "install_offline.bat").write_text(bat_script, encoding="utf-8", newline="\r\n")

        wheelhouse_state = "included" if (target_dir / "wheelhouse").is_dir() else "NOT included in this bundle"
        readme_offline = f"""# SAT-SA Air-Gapped Deployment Guide

## 1. Prerequisites
- Target host OS: Linux (RHEL 8/9, Ubuntu 22.04+) or Windows Server.
- Python 3.11+ runtime, the same minor version and OS family the wheelhouse was built for.
- No Internet or network access required: every package comes from `wheelhouse/` in this
  bundle (wheelhouse: {wheelhouse_state}). The install scripts stop with an error when it is
  missing; they never fall back to downloading.

## 2. Installation
### Linux:
```bash
tar -xzf satsa_offline_bundle.tar.gz
cd satsa_offline_bundle
bash install_offline.sh
```

### Windows:
```cmd
tar -xzf satsa_offline_bundle.tar.gz
cd satsa_offline_bundle
install_offline.bat
```

### Container Deployment:
The image installs from `wheelhouse/` too, so that wheelhouse must hold Linux wheels
(`TARGET_PLATFORM=manylinux2014_x86_64 TARGET_PYTHON=3.11`), and the `python:3.11-slim` base
image must already be loaded on the host (`podman load`).
```bash
podman build -t satsa:latest -f Containerfile .
podman run -d --name satsa-soc -p 127.0.0.1:8000:8000 satsa:latest
```

## 3. Operations
1. Ingest submission: `satsa ingest --data-dir /path/to/csv`
2. Run assessment: `satsa run --period 2026-Q1`
3. Launch UI: `satsa serve --host 127.0.0.1 --port 8000`
4. Verify audit: `satsa audit verify`
"""
        (target_dir / "README_OFFLINE.md").write_text(readme_offline, encoding="utf-8")
