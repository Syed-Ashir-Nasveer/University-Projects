@echo off
echo ================================================================
echo      Network Security Tool - Quick Start
echo ================================================================
echo.

echo [1/4] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found
    pause
    exit /b 1
)
echo [OK] Python found
echo.

echo [2/4] Creating virtual environment...
python -m venv venv
call venv\Scripts\activate.bat
echo [OK] Virtual environment activated
echo.

echo [3/4] Installing dependencies...
python -m pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo [OK] Dependencies installed
echo.

echo [4/4] Starting application...
echo [OK] Launching Network Security Tool
echo.
echo ================================================================
echo.

python main.py

pause
