@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo  First run - setting up the environment ...
    call "%~dp0OASIP - Setup.bat"
    if errorlevel 1 exit /b 1
)
title OASIP Dashboard  -  http://127.0.0.1:8123
echo.
echo  Starting OASIP dashboard at http://127.0.0.1:8123
echo  Your browser opens automatically when ready. Press Ctrl+C to stop.
echo.
".venv\Scripts\python.exe" -m oasip dashboard --port 8123 --open
echo.
echo  Dashboard stopped.
pause