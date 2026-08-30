@echo off
setlocal

set "ROOT=%~dp0.."
if not exist "%ROOT%\frontend\node_modules" (
    echo Frontend dependencies are missing. Running project setup...
    cd /d "%ROOT%" || exit /b 1
    python scripts\setup_local_environment.py || exit /b 1
)

cd /d "%ROOT%\frontend" || exit /b 1
echo Starting frontend development server...
call npm.cmd run dev
