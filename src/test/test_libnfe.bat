@echo off
setlocal EnableDelayedExpansion

echo [INFO] Setting up test environment in C:\madeiras\erp...
echo [DEBUG] test_libnfe.bat version: 9b8a7c6d-5e4f-4a3b-9f2c-1d0e9f8a7b6c

:: Set environment variables
set "LIBNFE_CONFIG_DIR=C:\madeiras\erp\cfg"
set "PATH=%PATH%;C:\madeiras\erp\libs;C:\Program Files (x86)\OpenSSL-Win32\bin"

echo [INFO] Environment variables set.
echo [DEBUG] LIBNFE_CONFIG_DIR=%LIBNFE_CONFIG_DIR%
echo [DEBUG] PATH=%PATH%

:: Verify certificate.pfx exists
if not exist "C:\madeiras\erp\certificates\certificate.pfx" (
    echo [ERROR] Certificate file C:\madeiras\erp\certificates\certificate.pfx not found.
    exit /b 1
)

:: Calculate the SHA-256 thumbprint of certificate.pfx
echo [INFO] Calculating thumbprint for C:\madeiras\erp\certificates\certificate.pfx...
set "CERT_PEM=C:\madeiras\erp\certificates\cert_temp.pem"
set "THUMBPRINT_FILE=C:\madeiras\erp\certificates\thumbprint.txt"

:: Extract certificate to PEM format
echo [DEBUG] Running: openssl pkcs12 -in C:\madeiras\erp\certificates\certificate.pfx -out %CERT_PEM% -nokeys -passin pass:123
openssl pkcs12 -in C:\madeiras\erp\certificates\certificate.pfx -out %CERT_PEM% -nokeys -passin pass:123 >nul 2>%THUMBPRINT_FILE%.err
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to extract certificate from certificate.pfx.
    type %THUMBPRINT_FILE%.err
    del %THUMBPRINT_FILE%.err >nul 2>&1
    exit /b 1
)
del %THUMBPRINT_FILE%.err >nul 2>&1

:: Calculate SHA-256 thumbprint
echo [DEBUG] Running: openssl x509 -in %CERT_PEM% -outform der | openssl dgst -sha256
openssl x509 -in %CERT_PEM% -outform der | openssl dgst -sha256 > %THUMBPRINT_FILE% 2>%THUMBPRINT_FILE%.err
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to calculate certificate thumbprint.
    type %THUMBPRINT_FILE%.err
    del %CERT_PEM% >nul 2>&1
    del %THUMBPRINT_FILE% >nul 2>&1
    del %THUMBPRINT_FILE%.err >nul 2>&1
    exit /b 1
)
del %THUMBPRINT_FILE%.err >nul 2>&1

:: Parse thumbprint using PowerShell
:: Extract 64-character hex string, handling variations in output format
for /f "tokens=*" %%a in ('powershell -Command "Get-Content %THUMBPRINT_FILE% | ForEach-Object { if ($_ -match '([0-9a-fA-F]{64})') { $Matches[1] } }"') do (
    set "TEST_CLIENT_THUMBPRINT=%%a"
)
if not defined TEST_CLIENT_THUMBPRINT (
    echo [ERROR] Failed to parse certificate thumbprint from %THUMBPRINT_FILE%.
    type %THUMBPRINT_FILE%
    del %CERT_PEM% >nul 2>&1
    del %THUMBPRINT_FILE% >nul 2>&1
    exit /b 1
)

echo [INFO] Certificate thumbprint: %TEST_CLIENT_THUMBPRINT%

:: Clean up temporary files
del %CERT_PEM% >nul 2>&1
del %THUMBPRINT_FILE% >nul 2>&1

:: Start the local server in the background
echo [INFO] Starting local nfe_service.py...
start /b python C:\madeiras\erp\service\nfe_service.py
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to start nfe_service.py.
    exit /b 1
)

:: Wait for the server to start
echo [INFO] Waiting 5 seconds for the server to start...
ping 127.0.0.1 -n 6 >nul

:: Run the test executable
echo [INFO] Running test_libnfe.exe...
echo -------------------------------------------------
C:\madeiras\erp\test_libnfe.exe
if %ERRORLEVEL% neq 0 (
    echo [ERROR] test_libnfe.exe failed with error code %ERRORLEVEL%.
)

echo -------------------------------------------------
echo [INFO] Test run finished. Shutting down nfe_service.py...

:: Find and terminate the server process
for /f "tokens=2 delims=," %%a in ('tasklist /fi "IMAGENAME eq python.exe" /fo csv ^| findstr /i "nfe_service.py"') do (
    echo [DEBUG] Found nfe_service.py with PID %%a
    taskkill /PID %%a /F
    if %ERRORLEVEL% equ 0 (
        echo [INFO] nfe_service.py (PID %%a) terminated successfully
    ) else (
        echo [ERROR] Failed to terminate nfe_service.py (PID %%a).
    )
)

echo [INFO] Cleanup complete.
endlocal