@echo off
REM ============================================================
REM  NetAnalyzer Pro — Windows Setup Script
REM  Run this ONCE to create the virtual environment and install
REM  all dependencies.
REM
REM  Usage:  Double-click setup.bat  OR  run from cmd as:
REM          cd network_analyzer && setup.bat
REM ============================================================

setlocal

echo.
echo ============================================================
echo   NetAnalyzer Pro - Environment Setup
echo ============================================================
echo.

REM Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

echo [1/4] Python found:
python --version

REM Create virtual environment if it doesn't exist
if not exist "venv\Scripts\activate.bat" (
    echo.
    echo [2/4] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo       Done.
) else (
    echo [2/4] Virtual environment already exists — skipping creation.
)

REM Activate and install dependencies
echo.
echo [3/4] Installing dependencies (this may take a minute)...
call venv\Scripts\activate.bat
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERROR] pip install failed. Check requirements.txt and your internet connection.
    pause
    exit /b 1
)
echo       Done.

echo.
echo [4/4] Checking Npcap / WinPcap (required for packet capture)...
echo       If scapy cannot capture packets, install Npcap from:
echo       https://npcap.com/#download
echo       (Select "Install Npcap in WinPcap API-compatible Mode")

echo.
echo ============================================================
echo   Setup complete! Run:  run.bat
echo ============================================================
echo.

pause
endlocal
