@echo off
setlocal

:: Set ERP_HOME and change working directory
set ERP_HOME=C:\madeiras\erp
cd /d "%ERP_HOME%"
if not "%CD%"=="%ERP_HOME%" (
    echo [ERROR] Failed to set working directory to %ERP_HOME%
    exit /b 1
)

echo.
echo [INFO] Setting up test environment in %CD%...
echo [DEBUG] test_libnfe.bat version: 9b8a7c6d-5e4f-4a3b-9f2c-1d0e9f8a7b6c
echo.

set OPENSSL_CONF=%ERP_HOME%\cfg\openssl.cnf
set OPENSSL_MODULES=%ERP_HOME%\libs
set PATH=%PATH%;%ERP_HOME%\libs;%ProgramFiles(x86)%\OpenSSL-Win32\bin
set LIBNFE_CONFIG_DIR=%ERP_HOME%\cfg
set LIBNFE_TEST_DIR=%ERP_HOME%\test
set LIBNFE_LIBS_DIR=%ERP_HOME%\libs

echo [INFO] Environment variables set.
echo [DEBUG] LIBNFE_CONFIG_DIR=%LIBNFE_CONFIG_DIR%
echo [DEBUG] PATH=%PATH%
echo.

echo [INFO] Starting local nfe_service.py...
start "NFe Service" /min python %ERP_HOME%\service\nfe_service.py

echo [INFO] Waiting 5 seconds for the server to start...
timeout /t 5 >nul
netstat -an | findstr ":5001" >nul
if errorlevel 1 (
    echo [ERROR] Failed to start nfe_service.py on port 5001
    goto :cleanup
)

if exist %ERP_HOME%\test_libnfe.exe (
    echo [INFO] Running test_libnfe.exe...
    echo -------------------------------------------------
    %ERP_HOME%\test_libnfe.exe
    echo -------------------------------------------------
) else (
    echo [ERROR] test_libnfe.exe not found! Please run the build task first.
    goto :cleanup
)

:cleanup
echo.
echo [INFO] Test run finished. Shutting down nfe_service.py...
echo [DEBUG] Checking for nfe_service.py process...
tasklist /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq NFe Service*" /FO CSV /NH
set PYTHON_PID=
for /f "tokens=2 delims=," %%i in ('tasklist /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq NFe Service*" /FO CSV /NH') do set PYTHON_PID=%%i
if defined PYTHON_PID (
    set PYTHON_PID=%PYTHON_PID:"=%
    echo [DEBUG] Found nfe_service.py with PID %PYTHON_PID%
    taskkill /F /PID %PYTHON_PID% >nul 2>&1
    if errorlevel 1 (
        echo [WARNING] Failed to terminate nfe_service.py (PID %PYTHON_PID%)
    ) else (
        echo [INFO] nfe_service.py (PID %PYTHON_PID%) terminated successfully
    )
) else (
    echo [INFO] No nfe_service.py process found
)

echo [INFO] Cleanup complete.
endlocal
