@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo  First run - setting up the environment ...
    call "%~dp0OASIP - Setup.bat"
    if errorlevel 1 exit /b 1
)
title OASIP New Scan
echo.
echo  ==============================================
echo   OASIP - New reconnaissance scan
echo  ==============================================
echo.
set /p TARGET=Target domain (e.g. example.com): 
if "%TARGET%"=="" (
    echo  No target entered. Aborting.
    pause
    exit /b 1
)
set /p ORG=Organization name (optional, Enter to skip): 
echo.
echo  IMPORTANT: only scan domains you own or have explicit written
echo  authorization to test. Unauthorized scanning may be illegal.
set /p CONSENT=Type YES to confirm and continue: 
if /i not "%CONSENT%"=="YES" (
    echo  Aborted - no scan was run.
    pause
    exit /b 1
)
echo.
echo  Scanning %TARGET% ... this usually takes 2-10 minutes.
echo.
".venv\Scripts\python.exe" -m oasip scan "%TARGET%" --org "%ORG%" --authorized --report
echo.
echo  Scan finished. Reports are saved in the "reports" folder.
echo.
explorer "%~dp0reports"
pause