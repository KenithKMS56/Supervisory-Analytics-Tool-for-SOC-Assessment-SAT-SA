@echo off
echo ============================================
echo      STOPPING SAT-SA + NCIIPC PLATFORM
echo ============================================
echo.
echo [*] Stopping and removing containers...
docker compose down
if %ERRORLEVEL% equ 0 (
    echo.
    echo [OK] Platform stopped cleanly.
    echo      Persistent data preserved in ./data and ./reports.
) else (
    echo.
    echo [!] Error stopping platform containers.
)
echo.
