@echo off
cd /d "%~dp0"
title AgentShield AI
echo ========================================================
echo   AgentShield AI — Universal Security Gateway
echo ========================================================
echo.
echo [1/2] Checking backend service...
netstat -ano | findstr :8000 >nul
if %ERRORLEVEL% NEQ 0 (
    echo Starting AgentShield backend API...
    start /b "" "C:\Users\ajayv\AppData\Local\Python\pythoncore-3.14-64\python.exe" -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
    timeout /t 3 /nobreak >nul
) else (
    echo Backend service is already running on port 8000.
)

echo [2/2] Launching AgentShield Desktop UI...
start "" "C:\Users\ajayv\AppData\Local\Python\pythoncore-3.14-64\python.exe" apps\desktop\main.py
echo.
echo Application started. You can close this window.
