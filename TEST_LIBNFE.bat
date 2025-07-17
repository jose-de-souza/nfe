:: Set environment variables for development
@echo off
set OPENSSL_MODULES=C:\madeiras\erp\libs
set PATH=%PATH%;C:\madeiras\erp\libs

:: Run the test program
if exist build\test_libnfe.exe (
    cd build
    test_libnfe.exe
    cd ..
) else (
    echo test_libnfe.exe not found in build directory. Please run build.bat first.
    exit /b 1
)