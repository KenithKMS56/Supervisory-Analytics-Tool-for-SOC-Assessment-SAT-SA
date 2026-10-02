@echo off
rem Build an offline wheelhouse for SAT-SA on Windows. Run on a machine WITH network access;
rem the result installs on the air-gapped machine with no network (docs\offline_install.md).
rem
rem   scripts\build_wheelhouse.bat [OUT_DIR]          (default OUT_DIR: wheelhouse)
rem
rem Writes OUT_DIR\requirements.txt (runtime dependencies pinned by uv.lock, with SHA-256
rem hashes), a binary wheel for each, and SAT-SA's own wheel. Set PYTHON to the interpreter
rem whose pip downloads the wheels (default: python; it needs pip, so not a uv project
rem environment); use the same Python minor version as the target machine.
setlocal

set "OUT=%~1"
if "%OUT%"=="" set "OUT=wheelhouse"
if "%PYTHON%"=="" set "PYTHON=python"
set "ROOT=%~dp0.."

if not exist "%OUT%" mkdir "%OUT%" || exit /b 1
for %%I in ("%OUT%") do set "OUT=%%~fI"
pushd "%ROOT%" || exit /b 1

uv export --frozen --no-dev --no-emit-project --no-header --format requirements-txt -o "%OUT%\requirements.txt" >nul || goto :fail
"%PYTHON%" -m pip download --only-binary=:all: --require-hashes -r "%OUT%\requirements.txt" -d "%OUT%" || goto :fail
uv build --wheel --out-dir "%OUT%" || goto :fail

popd
echo Wheelhouse ready: %OUT%
echo Install offline: see docs\offline_install.md
exit /b 0

:fail
popd
echo Building the wheelhouse failed. 1>&2
exit /b 1
