@echo off
setlocal
cd /d "%~dp0"

py --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python launcher not found. Install Python 3.11+.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    py -m venv .venv
)

echo Installing dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt

if "%SECRET_KEY%"=="" set "SECRET_KEY=dev-local-secret-change-me"
if "%ADMIN_PASSWORD%"=="" set "ADMIN_PASSWORD=admin123"
if "%APP_NAME%"=="" set "APP_NAME=VTK Kokshetau"
if "%APP_HOST%"=="" set "APP_HOST=0.0.0.0"
if "%APP_PORT%"=="" set "APP_PORT=5000"
if "%FLASK_DEBUG%"=="" set "FLASK_DEBUG=1"

echo.
echo Server: http://%APP_HOST%:%APP_PORT%
echo Admin: admin / admin123
echo Press Ctrl+C to stop
echo.

cd app
"..\.venv\Scripts\python.exe" app.py
