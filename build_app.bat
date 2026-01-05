@echo off
echo ========================================================
echo      IPTV Manager Pro - Build Script (Windows)
echo ========================================================
echo.

echo [1/2] Installing/Verifying dependencies from requirements.txt...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo Error installing dependencies. Please check your internet connection or python environment.
    pause
    exit /b %ERRORLEVEL%
)
echo Dependencies checked.
echo.

echo [2/2] Building Executable with PyInstaller...
echo This may take a few minutes...

:: --clean: Cleans PyInstaller cache
:: --noconsole: Hides the command window (GUI only)
:: --onefile: Bundles everything into a single .exe
:: --name: Sets the output filename
:: --icon: Sets the .exe icon
:: --add-data: Includes the icon file inside the bundle (format: source;dest)
:: --collect-all: Collects all data/imports for pychromecast to ensure discovery works
pyinstaller --clean --noconsole --onefile --name="IPTV_Manager_Pro" --icon="icon.ico" --add-data="icon.ico;." --collect-all="pychromecast" IPTV_Manager_Pro.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ========================================================
    echo   BUILD FAILED!
    echo ========================================================
    echo Please check the error messages above.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ========================================================
echo   BUILD SUCCESSFUL!
echo ========================================================
echo The new executable is located in the 'dist' folder:
echo dist\IPTV_Manager_Pro.exe
echo.
pause
