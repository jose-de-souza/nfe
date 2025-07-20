@echo off
setlocal

:: Set the working directory to the script's location (C:\madeiras\erp)
cd /d "%~dp0"

echo.
echo [INFO] Setting up test environment in %CD%...
echo.

:: Set environment variables for OpenSSL
set OPENSSL_CONF=cfg\openssl.cnf
set OPENSSL_MODULES=libs
set PATH=%PATH%;%CD%\libs

echo [INFO] Environment variables set.
echo.

:: Start the Python nfe-service in a new, minimized window
echo [INFO] Starting local nfe-service.py...
start "NFe Service" /min python service\nfe_service.py

:: Give the server a moment to initialize
echo [INFO] Waiting 5 seconds for the server to start...
timeout /t 5 >nul

:: Check if the test executable exists
if exist test_libnfe.exe (
    echo [INFO] Running test_libnfe.exe...
    echo -------------------------------------------------
    test_libnfe.exe
    echo -------------------------------------------------
) else (
    echo [ERROR] test_libnfe.exe not found! Please run the build task first.
    goto :cleanup
)

:cleanup
echo.
echo [INFO] Test run finished. Shutting down nfe-service.
:: Find and kill the Python process we started
taskkill /F /IM python.exe /FI "WINDOWTITLE eq NFe Service*" >nul 2>&1

echo [INFO] Cleanup complete.
endlocal
pause
