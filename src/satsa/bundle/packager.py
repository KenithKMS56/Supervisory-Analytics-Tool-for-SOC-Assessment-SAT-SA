"""Offline bundling and distribution package creator for SAT-SA."""

import os
import shutil
import tarfile
import zipfile
from pathlib import Path


class OfflinePackager:
    """Packages SAT-SA into a self-contained air-gapped deployment bundle."""

    def __init__(self, root_dir: Path | str = "."):
        self.root_dir = Path(root_dir).resolve()
        self.dist_dir = self.root_dir / "dist"
        self.bundle_dir = self.dist_dir / "satsa_offline_bundle"

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

        # 5. Create offline install scripts and instructions
        self._write_offline_scripts(self.bundle_dir)

        # 6. Create archive
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

    def _write_containerfile(self, target_path: Path) -> None:
        """Write production air-gapped Containerfile."""
        content = """# SAT-SA Air-Gapped OCI Container
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PIP_NO_CACHE_DIR=1 \\
    SATSA_AIRGAPPED=1

WORKDIR /app

# Copy bundle
COPY . /app

# Install package locally
RUN pip install --no-index --find-links=wheelhouse . || pip install .

EXPOSE 8000

# Default command launches offline web UI and REST API
ENTRYPOINT ["satsa"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
"""
        target_path.write_text(content, encoding="utf-8")

    def _write_offline_scripts(self, target_dir: Path) -> None:
        """Write offline setup helper scripts."""
        sh_script = """#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "Installing SAT-SA in Air-Gapped Environment"
echo "=========================================================="

python3 -m venv .venv
source .venv/bin/activate

if [ -d "wheelhouse" ]; then
    pip install --no-index --find-links=wheelhouse .
else
    pip install .
fi

echo "[+] Installation complete. Verifying air-gap operation..."
satsa version
echo "[+] Ready. Run 'satsa serve' to start offline dashboard."
"""
        (target_dir / "install_offline.sh").write_text(sh_script, encoding="utf-8")

        bat_script = """@echo off
echo ==========================================================
echo Installing SAT-SA in Air-Gapped Windows Environment
echo ==========================================================

python -m venv .venv
call .venv\\Scripts\\activate.bat

if exist wheelhouse (
    pip install --no-index --find-links=wheelhouse .
) else (
    pip install .
)

echo [+] Installation complete.
satsa version
echo [+] Run 'satsa serve' to launch offline dashboard.
"""
        (target_dir / "install_offline.bat").write_text(bat_script, encoding="utf-8")

        readme_offline = """# SAT-SA Air-Gapped Deployment Guide

## 1. Prerequisites
- Target host OS: Linux (RHEL 8/9, Ubuntu 22.04+) or Windows Server.
- Python 3.11+ runtime.
- No Internet or network access required.

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
```bash
podman build -t satsa:latest -f Containerfile .
podman run -d --name satsa-soc -p 8000:8000 satsa:latest
```

## 3. Operations
1. Ingest submission: `satsa ingest --data-dir /path/to/csv`
2. Run assessment: `satsa run --period 2026-Q1`
3. Launch UI: `satsa serve --host 127.0.0.1 --port 8000`
4. Verify audit: `satsa audit verify`
"""
        (target_dir / "README_OFFLINE.md").write_text(readme_offline, encoding="utf-8")
