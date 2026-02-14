@echo off
setlocal
cd /d "%~dp0"

if not exist "requirements.txt" (
    echo [ERROR] requirements.txt not found.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment .venv ...
    py -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create venv. Ensure Python is installed.
        pause
        exit /b 1
    )
)

echo Installing/updating dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install requirements.
    pause
    exit /b 1
)

if "%SECRET_KEY%"=="" set "SECRET_KEY=dev-local-secret-change-me"
if "%ADMIN_PASSWORD%"=="" set "ADMIN_PASSWORD=admin123"
if "%APP_NAME%"=="" set "APP_NAME=VTK Kokshetau"
if "%APP_HOST%"=="" set "APP_HOST=0.0.0.0"
if "%APP_PORT%"=="" set "APP_PORT=5000"
if "%FLASK_DEBUG%"=="" set "FLASK_DEBUG=1"

echo.
echo Starting local server at http://%APP_HOST%:%APP_PORT%
echo Press Ctrl+C to stop.
cd app
"..\.venv\Scripts\python.exe" app.py
