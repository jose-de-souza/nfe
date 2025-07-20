@echo off
set OPENSSL_CONF=C:\madeiras\erp\cfg\openssl.cnf
set OPENSSL_MODULES=C:\madeiras\erp\libs
set PATH=%PATH%;C:\madeiras\erp\libs

if exist build\test_libnfe.exe (
    build\test_libnfe.exe
) else (
    echo test_libnfe.exe not found in build directory. Please run build.bat first.
    exit /b 1
)