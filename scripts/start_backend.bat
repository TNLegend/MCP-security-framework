@echo off
setlocal

set "ROOT=%~dp0.."
if not exist "%ROOT%\backend\.venv\Scripts\python.exe" (
    echo Backend environment is missing. Running project setup...
    cd /d "%ROOT%" || exit /b 1
    python scripts\setup_local_environment.py || exit /b 1
)

cd /d "%ROOT%" || exit /b 1
"%ROOT%\backend\.venv\Scripts\python.exe" -m uvicorn app.main:app --app-dir backend --reload
