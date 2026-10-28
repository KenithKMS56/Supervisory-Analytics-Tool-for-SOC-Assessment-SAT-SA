@echo off
setlocal enabledelayedexpansion

:: Demonstration deployment: synthetic data, published passphrases and one-click sign-in on
:: both login pages. Everything lives in demo-run\ ; the production data\ is never touched.
:: Uses Docker when it is installed and running, otherwise this project's Python.
:: Stop it with stop-demo.bat. Run stop.bat first if the production platform is running:
:: both use ports 8000 and 8001.

cd /d "%~dp0"

echo ============================================
echo     SAT-SA + NCIIPC ADMINISTRATION (DEMO)
echo ============================================
echo.

where docker >nul 2>&1
if %ERRORLEVEL% neq 0 goto python_demo
docker info >nul 2>&1
if %ERRORLEVEL% neq 0 goto python_demo

:: ---------------------------------------------------------------- Docker
echo [OK] Docker detected
if not exist "demo-run\config" xcopy /E /I /Q "config" "demo-run\config" >nul
set SATSA_DEMO=1
set SATSA_DATA_DIR=./demo-run/data
set SATSA_REPORTS_DIR=./demo-run/reports
set SATSA_CONFIG_DIR=./demo-run/config
set SATSA_CONTAINER_NAME=satsa-demo
echo [*] Starting demo containers...
docker compose -p satsa-demo up -d --build
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Docker compose failed to start the demo. If the production platform is
    echo         running, stop it first with stop.bat.
    pause
    exit /b 1
)
goto wait_ports

:: ---------------------------------------------------------------- Python
:python_demo
set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY (
    where python >nul 2>&1
    if !ERRORLEVEL! equ 0 set "PY=python"
)
if not defined PY (
    echo [ERROR] Neither Docker nor Python was found. Install Docker Desktop, or create the
    echo         project's environment first: see README.md, Getting Started.
    pause
    exit /b 1
)
echo [OK] Docker not available: starting the demo with %PY%
echo      It runs in the window titled "SAT-SA demo". Close it, or run stop-demo.bat, to stop.
start "SAT-SA demo" "%PY%" entrypoint.py --demo

:: ---------------------------------------------------------------- both
:wait_ports
echo [*] Waiting for portals to become responsive...
set /a port_attempts=0
:wait_loop
ping -n 3 127.0.0.1 >nul
powershell -NoProfile -Command "try { $r0 = Invoke-WebRequest -Uri 'http://localhost:8000/healthz' -UseBasicParsing -TimeoutSec 2; $r1 = Invoke-WebRequest -Uri 'http://localhost:8001/healthz' -UseBasicParsing -TimeoutSec 2; if ($r0.StatusCode -eq 200 -and $r1.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if %ERRORLEVEL% equ 0 goto portals_ready
set /a port_attempts+=1
if !port_attempts! geq 45 (
    echo [!] Warning: Portals took longer than expected to report ready.
    goto portals_ready
)
goto wait_loop

:portals_ready
echo [OK] NCIIPC Admin Portal   http://localhost:8000   (click nciipc_admin or admin)
echo [OK] SAT-SA Portal         http://localhost:8001   (click Analyst or Examiner)
echo      The demonstration data loads in the background on the first start.
echo.
start http://localhost:8000
start http://localhost:8001
echo ============================================
echo [OK] Demo is running. Stop it with stop-demo.bat
echo ============================================
echo.
