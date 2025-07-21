@echo off
setlocal

cd /d "%~dp0"

echo.
echo [INFO] Setting up test environment in %CD%...
echo.

set OPENSSL_CONF=%CD%\cfg\openssl.cnf
set OPENSSL_MODULES=%CD%\libs
set PATH=%PATH%;%CD%\libs;%ProgramFiles(x86)%\OpenSSL-Win32\bin
set LIBNFE_CONFIG_DIR=%CD%\cfg
set LIBNFE_TEST_DIR=%CD%\test
set LIBNFE_LIBS_DIR=%CD%\libs

echo [INFO] Environment variables set.
echo.

echo [INFO] Starting local nfe-service.py...
start "NFe Service" /min python service\nfe_service.py

echo [INFO] Waiting 5 seconds for the server to start...
timeout /t 5 >nul
netstat -an | findstr ":5001" >nul
if errorlevel 1 (
    echo [ERROR] Failed to start nfe_service.py on port 5001
    goto :cleanup
)

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
for /f "tokens=2" %%i in ('tasklist /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq NFe Service*" /FO CSV /NH') do set PYTHON_PID=%%i
if defined PYTHON_PID taskkill /F /PID %PYTHON_PID% >nul 2>&1

echo [INFO] Cleanup complete.
endlocal
pause