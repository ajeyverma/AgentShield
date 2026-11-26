@echo off
cd /d "%~dp0"
title AgentShield AI — Autonomous Agent Chatbot
echo ========================================================
echo   AgentShield AI — Autonomous Agent Chatbot
echo ========================================================
echo.
echo Launching Chatbot Interface...
"C:\Users\ajayv\AppData\Local\Python\pythoncore-3.14-64\python.exe" demos\agent\chatbot_ui.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Application exited with error code %ERRORLEVEL%.
    pause
)
