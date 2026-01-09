@echo off
REM CyberForensics Toolkit - Windows Deployment Script
REM Run this script to automatically deploy the toolkit

echo ========================================
echo CyberForensics Toolkit Deployment
echo ========================================
echo.

REM Check if Docker is installed
echo [1/6] Checking Docker installation...
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not installed or not in PATH
    echo.
    echo Please install Docker Desktop for Windows from:
    echo https://www.docker.com/products/docker-desktop/
    echo.
    pause
    exit /b 1
)
echo Docker found:
docker --version
echo.

REM Check if Docker daemon is running
echo [2/6] Checking Docker daemon...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker daemon is not running
    echo.
    echo Please start Docker Desktop and try again
    echo.
    pause
    exit /b 1
)
echo Docker daemon is running
echo.

REM Stop existing containers
echo [3/6] Stopping existing containers (if any)...
docker-compose down >nul 2>&1
echo Existing containers stopped
echo.

REM Build containers
echo [4/6] Building Docker containers...
echo This may take 3-5 minutes on first run...
docker-compose build
if %errorlevel% neq 0 (
    echo ERROR: Failed to build containers
    echo.
    pause
    exit /b 1
)
echo Build successful
echo.

REM Start containers
echo [5/6] Starting all services...
docker-compose up -d
if %errorlevel% neq 0 (
    echo ERROR: Failed to start containers
    echo.
    pause
    exit /b 1
)
echo.

REM Wait for services to be ready
echo [6/6] Waiting for services to start...
timeout /t 5 /nobreak >nul
echo.

REM Check status
echo ========================================
echo Service Status:
echo ========================================
docker-compose ps
echo.

REM Display access information
echo ========================================
echo Deployment Complete!
echo ========================================
echo.
echo Web Portal:     http://localhost:5000
echo Reports Viewer: http://localhost:8080/reports
echo.
echo Opening web portal in your browser...
timeout /t 2 /nobreak >nul
start http://localhost:5000
echo.
echo To stop the toolkit, run: docker-compose down
echo To view logs, run: docker-compose logs -f
echo.
echo Press any key to exit...
pause >nul
