@echo off
cd /d "%~dp0"
title AgentShield AI
echo ========================================================
echo   AgentShield AI — Universal Security Gateway
echo ========================================================
echo.
echo Launching desktop management interface...
"C:\Users\ajayv\AppData\Local\Python\pythoncore-3.14-64\python.exe" apps\desktop\main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Application exited with error code %ERRORLEVEL%.
    pause
)
