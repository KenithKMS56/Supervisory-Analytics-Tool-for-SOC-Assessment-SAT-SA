@echo off
:: Stops the demonstration deployment started by start-demo.bat (Docker or Python).
:: Its data stays in demo-run\ ; delete that folder to start the demo afresh.

cd /d "%~dp0"

echo ============================================
echo      STOPPING SAT-SA DEMONSTRATION
echo ============================================
echo.

where docker >nul 2>&1
if %ERRORLEVEL% neq 0 goto python_demo
docker info >nul 2>&1
if %ERRORLEVEL% neq 0 goto python_demo
set SATSA_CONTAINER_NAME=satsa-demo
docker compose -p satsa-demo down

:python_demo
taskkill /FI "WINDOWTITLE eq SAT-SA demo*" /T /F >nul 2>&1
echo [OK] Demo stopped. Its data is kept in demo-run\
echo.
