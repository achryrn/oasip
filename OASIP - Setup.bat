@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo  ==============================================
echo   OASIP one-time setup  (creates the .venv)
echo  ==============================================
echo.
where py >nul 2>nul
if %errorlevel%==0 (
    set "PYTHON=py -3.12"
) else (
    set "PYTHON=python"
)
echo  [1/3] Preparing virtual environment ...
if not exist ".venv\Scripts\python.exe" (
    %PYTHON% -m venv .venv
    if errorlevel 1 goto :fail
)
echo  [2/3] Installing dependencies (about 1-2 minutes) ...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :fail
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :fail
echo  [3/3] Verifying install ...
".venv\Scripts\python.exe" -c "import fastapi, uvicorn, sqlalchemy, httpx, dnspython, jinja2, cryptography; print('deps OK')"
if errorlevel 1 goto :fail
echo.
echo  Setup complete. Double-click "OASIP - Dashboard.bat" to start.
echo.
pause
exit /b 0

:fail
echo.
echo  Setup FAILED. Install Python 3.11 or newer from python.org and make
echo  sure "py" or "python" is on your PATH, then run this again.
echo.
pause
exit /b 1