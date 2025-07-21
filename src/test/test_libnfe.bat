@echo off
setlocal EnableDelayedExpansion

:: Set ERP_HOME and change working directory
set ERP_HOME=C:\madeiras\erp
cd /d %ERP_HOME%
if not "%CD%"=="%ERP_HOME%" (
    echo [ERROR] Failed to set working directory to %ERP_HOME%
    exit /b 1
)

:: Start nfe_service.py in the background
echo Starting nfe_service.py...
start /b python %ERP_HOME%\service\nfe_service.py
if errorlevel 1 (
    echo [ERROR] Failed to start nfe_service.py
    exit /b 1
)

:: Wait for the server to start (up to 10 seconds)
set retries=0
:wait_server
timeout /t 1 >nul
netstat -an | findstr ":5001" >nul
if errorlevel 1 (
    set /a retries+=1
    if !retries! lss 10 (
        goto :wait_server
    )
    echo [ERROR] Server did not start after 10 seconds
    exit /b 1
)

:: Run test_libnfe.exe
echo Running test_libnfe.exe...
%ERP_HOME%\test_libnfe.exe
if errorlevel 1 (
    echo [ERROR] test_libnfe.exe failed
    exit /b 1
)

:: Cleanup
echo Tests completed successfully.
exit /b 0
