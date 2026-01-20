@echo off
echo ========================================================
echo      IPTV Manager Pro - FAST Build Script
echo ========================================================
echo.
echo This script creates a clean virtual environment to speed up building.
echo.

:: 1. Create Virtual Environment if it doesn't exist
if not exist "venv" (
    echo [1/3] Creating virtual environment (venv)...
    python -m venv venv
) else (
    echo [1/3] Virtual environment found.
)

:: 2. Activate and Install Requirements
echo [2/3] Installing dependencies into venv...
call venv\Scripts\activate
pip install -r requirements.txt --disable-pip-version-check
if %ERRORLEVEL% NEQ 0 (
    echo Error installing dependencies.
    pause
    exit /b %ERRORLEVEL%
)

:: 3. Build
echo [3/3] Building Executable (Clean Environment)...
echo.
echo NOTE: If this is still slow, please temporarily disable
echo Real-time Protection in Windows Defender/Antivirus.
echo.

pyinstaller --clean --noconsole --onefile --name="IPTV_Manager_Pro" --icon="icon.ico" --add-data="icon.ico;." --collect-all="pychromecast" IPTV_Manager_Pro.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED!
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ========================================================
echo   BUILD SUCCESSFUL!
echo ========================================================
echo Executable: dist\IPTV_Manager_Pro.exe
echo.
pause
