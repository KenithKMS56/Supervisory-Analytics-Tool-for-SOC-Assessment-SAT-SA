# Offline installation

SAT-SA is installed on the air-gapped machine from a **wheelhouse**: a directory with every
runtime dependency as a binary wheel, a `requirements.txt` that pins each one with its SHA-256
hash (taken from `uv.lock`), and SAT-SA's own wheel. Nothing is downloaded during installation:
every `pip install` below and in the bundle's scripts runs with `--no-index`, and none of them
falls back to the network when a package is missing. A missing or mismatched wheel stops the
install with an error.

## 1. Build the wheelhouse (on a machine with network access)

Requirements: a checkout of this repository, [uv](https://docs.astral.sh/uv/), and a Python
with `pip` of the **same minor version and OS family as the target machine**. A uv project
environment (`.venv`) has no pip, so point `PYTHON` at a regular interpreter.

```bash
# Linux target, built on Linux
PYTHON=python3.11 scripts/build_wheelhouse.sh wheelhouse

# Linux target, built on another OS: ask pip for Linux wheels
TARGET_PLATFORM=manylinux2014_x86_64 TARGET_PYTHON=3.11 PYTHON=python3 \
  scripts/build_wheelhouse.sh wheelhouse
```

```bat
rem Windows target, built on Windows
set PYTHON=C:\Python311\python.exe
scripts\build_wheelhouse.bat wheelhouse
```

The script runs `uv export --frozen --no-dev` (runtime dependencies only, exactly as locked),
`pip download --only-binary=:all: --require-hashes` (pip refuses any file whose hash differs
from the lock), and `uv build --wheel` for SAT-SA itself.

## 2. Package it

```bash
uv run satsa offline-bundle --wheelhouse wheelhouse --output-dir dist
```

This writes `dist/satsa_bundle.tar.gz` with the sources, `config/`, the wheelhouse, the
`Containerfile`, `install_offline.sh`, `install_offline.bat` and `README_OFFLINE.md`. Without
`--wheelhouse` the command uses `./wheelhouse` if it exists; otherwise it builds a bundle
without one, warns, and the install scripts in that bundle refuse to run.

Move the archive to the air-gapped machine on approved media.

## 3. Install (on the air-gapped machine)

```bash
tar -xzf satsa_bundle.tar.gz
cd satsa_bundle
bash install_offline.sh          # Windows: install_offline.bat
```

The script creates `.venv`, installs the pinned dependencies with their hashes checked, then
SAT-SA's wheel with `--no-deps`. By hand, the same steps are:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --find-links=wheelhouse --require-hashes -r wheelhouse/requirements.txt
.venv/bin/python -m pip install --no-index --no-deps --find-links=wheelhouse satsa
```

## 4. Verify

```bash
.venv/bin/satsa version          # SAT-SA version 0.1.0 (Air-gapped, No AI/ML)
.venv/bin/python -m pip check    # No broken requirements found.
```

SAT-SA reads `config/` from the working directory, so run it from the bundle directory (or a
directory holding a copy of `config/`).

## 5. Container

The `Containerfile` installs from the same `wheelhouse/` and has no network fallback either.
The wheelhouse must therefore hold **Linux** wheels for Python 3.11
(`TARGET_PLATFORM=manylinux2014_x86_64 TARGET_PYTHON=3.11`), and the `python:3.11-slim` base
image must already be on the host (`podman save` it on the connected machine, `podman load` it
on the air-gapped one).

## What was checked, and where

| Check | Where | Result |
|---|---|---|
| Build the wheelhouse, then install it into a fresh venv with `--no-index` and run `satsa version`, `pip check`, and `generate-data` / `ingest` / `run` from a directory holding only `config/` | Windows 11, CPython 3.11, 2026-10-02 (this quality pass) | 36 wheels; installed; all commands succeeded |
| `satsa offline-bundle --wheelhouse`, then `install_offline.bat` in the extracted bundle, with `PIP_INDEX_URL` pointed at a closed local port | same | installed; `satsa version` and `pip check` succeeded |
| `install_offline.sh` / `.bat` in a bundle without a wheelhouse | `tests/test_offline_bundle.py` (and Git Bash, by hand) | exit 1 with an explanation; no `.venv` created |
| Build and install with the network namespace removed (`unshare --net`) | CI job `offline-install` (`.github/workflows/test.yml`) | defined in this pass; **not run here**, since no CI run was executed from this machine |

On Windows the network was not physically disconnected during the manual checks; `--no-index`
and the closed `PIP_INDEX_URL` mean pip had no index to fall back to. The CI job is the check
that runs with no network at all.

## Limits

- One wheelhouse serves one OS family and one Python minor version (compiled wheels such as
  `duckdb`, `pyarrow` and `cryptography` are platform-specific). Build one per target.
- `--require-hashes` checks the wheels against `uv.lock`; it does not check the lock itself.
  Review changes to `uv.lock` as you would code.
- Development tools (pytest, ruff, mypy, hypothesis) are not in the wheelhouse: it is built with
  `--no-dev`. To run the test suite offline, build a second wheelhouse with
  `uv export --frozen --only-group dev` and the same `pip download` command.
