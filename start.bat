@echo off
setlocal enabledelayedexpansion

echo ============================================
echo        SAT-SA + NCIIPC ADMINISTRATION
echo ============================================
echo.

:: 1. Check if Docker CLI is installed and in PATH
where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker is not installed or not found in system PATH.
    echo Please install Docker Desktop from:
    echo https://www.docker.com/products/docker-desktop/
    echo.
    pause
    exit /b 1
)

:: 2. Check if Docker daemon is running; if not, try launching Docker Desktop
docker info >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [*] Docker Desktop is not currently running. Starting Docker Desktop...
    
    if exist "%LOCALAPPDATA%\Programs\DockerDesktop\Docker Desktop.exe" (
        start "" "%LOCALAPPDATA%\Programs\DockerDesktop\Docker Desktop.exe"
    ) else if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
        start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    ) else (
        echo [!] Docker Desktop executable not found in standard paths.
        echo Please launch Docker Desktop manually, then run start.bat again.
        echo.
        pause
        exit /b 1
    )

    echo [*] Waiting for Docker daemon to initialize...
    set /a attempts=0
    :wait_docker
    ping -n 4 127.0.0.1 >nul
    docker info >nul 2>&1
    if %ERRORLEVEL% equ 0 goto docker_ready
    set /a attempts+=1
    if !attempts! geq 35 (
        echo [ERROR] Timed out waiting for Docker daemon to become responsive.
        echo Please ensure Docker Desktop is running properly and try again.
        echo.
        pause
        exit /b 1
    )
    goto wait_docker
)

:docker_ready
echo [OK] Docker detected

:: 3. Build and launch Docker Compose services
echo [*] Starting platform containers...
docker compose up -d --build >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Retrying with verbose output...
    docker compose up -d --build
    if %ERRORLEVEL% neq 0 (
        echo.
        echo [ERROR] Docker compose failed to build or start the platform.
        pause
        exit /b 1
    )
)

echo [OK] Container started

:: 4. Wait for services to be ready (both ports 8000 and 8001 responding HTTP 200)
echo [*] Waiting for portals to become responsive...
set /a port_attempts=0
:wait_ports
ping -n 3 127.0.0.1 >nul
powershell -NoProfile -Command "try { $r0 = Invoke-WebRequest -Uri 'http://localhost:8000/splash' -UseBasicParsing -TimeoutSec 2; $r1 = Invoke-WebRequest -Uri 'http://localhost:8001/splash' -UseBasicParsing -TimeoutSec 2; if ($r0.StatusCode -eq 200 -and $r1.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if %ERRORLEVEL% equ 0 goto portals_ready
set /a port_attempts+=1
if !port_attempts! geq 45 (
    echo [!] Warning: Portals took longer than expected to report ready.
    goto portals_ready
)
goto wait_ports

:portals_ready
echo [OK] NCIIPC Admin Portal
echo      http://localhost:8000
echo [OK] SAT-SA Portal
echo      http://localhost:8001
echo.
echo Opening portals...

start http://localhost:8000
start http://localhost:8001

echo.
echo ============================================
echo [OK] Platform is actively running.
echo      To stop the deployment, run stop.bat
echo ============================================
echo.
