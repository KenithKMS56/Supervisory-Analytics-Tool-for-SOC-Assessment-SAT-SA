#!/usr/bin/env sh
# Build an offline wheelhouse for SAT-SA. Run on a machine WITH network access; the result
# installs on the air-gapped machine with no network at all (docs/offline_install.md).
#
#   scripts/build_wheelhouse.sh [OUT_DIR]          (default OUT_DIR: wheelhouse)
#
# What it writes to OUT_DIR:
#   requirements.txt  the runtime dependencies pinned by uv.lock, with their SHA-256 hashes
#   *.whl             a binary wheel for each of them (pip checks every hash), and SAT-SA's own
#
# Environment:
#   PYTHON           interpreter whose pip downloads the wheels (default: python3); it needs pip,
#                    so not a uv project environment. Use the same
#                    OS family and Python minor version as the target machine: a dependency's
#                    platform markers are evaluated for the machine that runs this script.
#   TARGET_PLATFORM  optional pip platform tag for another target, e.g. manylinux2014_x86_64
#   TARGET_PYTHON    optional target Python version, e.g. 3.11 (with TARGET_PLATFORM)
set -eu

OUT="${1:-wheelhouse}"
PY="${PYTHON:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cd "$ROOT"

uv export --frozen --no-dev --no-emit-project --no-header --format requirements-txt -o "$OUT/requirements.txt" >/dev/null

set -- --only-binary=:all: --require-hashes -r "$OUT/requirements.txt" -d "$OUT"
if [ -n "${TARGET_PLATFORM:-}" ]; then set -- "$@" --platform "$TARGET_PLATFORM"; fi
if [ -n "${TARGET_PYTHON:-}" ]; then set -- "$@" --python-version "$TARGET_PYTHON"; fi
"$PY" -m pip download "$@"

uv build --wheel --out-dir "$OUT"

# Optional, online only: SATSA_AUDIT=1 checks the pinned dependencies against the public advisory
# database with pip-audit (it must be installed for $PY). It sends the package names and versions
# to that service, so it never runs unless asked for.
if [ "${SATSA_AUDIT:-}" = "1" ]; then
  "$PY" -m pip_audit --require-hashes --disable-pip -r "$OUT/requirements.txt" > "$OUT/pip-audit.txt"
  echo "Dependency audit written to $OUT/pip-audit.txt"
fi

echo "Wheelhouse ready: $OUT ($(ls "$OUT"/*.whl | wc -l | tr -d ' ') wheels)"
echo "Install offline:  see docs/offline_install.md"
