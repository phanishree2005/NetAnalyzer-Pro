@echo off
REM ============================================================
REM  NetAnalyzer Pro — Windows Launch Script
REM
REM  Launches the Streamlit dashboard with administrator privileges
REM  (required for raw packet capture on Windows).
REM
REM  Usage:
REM    run.bat               — UI mode (default)
REM    run.bat --cli         — Headless CLI mode
REM    run.bat --cli -d 30   — CLI mode, auto-stop after 30s
REM ============================================================

setlocal

REM Check venv exists
if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found.
    echo         Run setup.bat first to install dependencies.
    pause
    exit /b 1
)

REM Activate venv
call venv\Scripts\activate.bat

echo.
echo ============================================================
echo   NetAnalyzer Pro - Starting
echo ============================================================

REM Pass through any arguments to main.py
if "%~1"=="" (
    echo   Mode: Streamlit UI  [http://localhost:8501]
    echo   Press Ctrl+C to stop.
    echo ============================================================
    echo.
    python main.py
) else (
    python main.py %*
)

endlocal
