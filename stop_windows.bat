@echo off
REM CyberForensics Toolkit - Stop Script
REM Run this script to stop all services

echo ========================================
echo Stopping CyberForensics Toolkit
echo ========================================
echo.

docker-compose down

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo All services stopped successfully
    echo ========================================
    echo.
    echo To start again, run: deploy_windows.bat
    echo or: docker-compose up -d
) else (
    echo.
    echo ERROR: Failed to stop services
    echo Make sure Docker Desktop is running
)

echo.
echo Press any key to exit...
pause >nul
