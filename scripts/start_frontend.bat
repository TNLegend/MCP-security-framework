@echo off
setlocal

cd /d "%~dp0..\frontend" || exit /b 1

echo Installing frontend dependencies...
call npm install || exit /b 1

echo Starting frontend development server...
call npm run dev

pause
