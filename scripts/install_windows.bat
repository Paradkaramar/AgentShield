@echo off
setlocal enabledelayedexpansion

echo =======================================================================
echo          AgentShield Installable Personal Device Security Platform
echo                        Windows Guided Installer (v1.2.0)
echo =======================================================================
echo.
echo PRIVILEGE DISCLOSURE:
echo - Standard User Privileges: Used for process inventory, socket monitoring,
echo   and desktop dashboard telemetry.
echo - Administrator (UAC) Elevation: Required ONLY if you choose to inspect or
echo   configure host Windows Defender Firewall profiles.
echo - Covert Persistence: AgentShield DOES NOT install hidden backdoors or
echo   covert rootkits. All scheduled jobs are registered under your account.
echo.

:: 1. Check Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python 3 is not found in your PATH.
    echo Please install Python 3.10 or newer from python.org and rerun this installer.
    pause
    exit /b 1
)

echo [OK] Python detected.

:: 2. Check Virtual Environment
if not exist "..\backend\.venv" (
    echo [*] Creating Python virtual environment in backend/.venv...
    python -m venv ..\backend\.venv
)

echo [*] Activating virtual environment...
call ..\backend\.venv\Scripts\activate.bat

echo [*] Installing required endpoint dependencies (psutil, fastapi, etc.)...
python -m pip install --upgrade pip --quiet
python -m pip install -r ..\backend\requirements.txt --quiet
python -m pip install psutil --quiet

echo [OK] Dependencies verified.
echo.

:: 3. Device Enrollment
echo -----------------------------------------------------------------------
echo                        DEVICE ENROLLMENT STEP
echo -----------------------------------------------------------------------
echo An enrollment token connects this computer securely to your AgentShield dashboard.
echo (Press ENTER to use demo token: SHIELD-ENROLL-DEMO-2026)
set /p USER_TOKEN="Enter Enrollment Token: "
if "%USER_TOKEN%"=="" (
    set USER_TOKEN=SHIELD-ENROLL-DEMO-2026
)

set /p DEV_NAME="Enter Friendly Device Name (e.g. My-Laptop): "
if "%DEV_NAME%"=="" (
    set DEV_NAME=%COMPUTERNAME%
)

echo.
echo [*] Enrolling device '%DEV_NAME%' with token '%USER_TOKEN%'...
python -m backend.app.agent_daemon.daemon --enroll %USER_TOKEN% --device-name "%DEV_NAME%"

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Enrollment failed. Check the token validity or backend connection.
    pause
    exit /b 1
)

echo.
echo [OK] Initializing local endpoint security database...
python -m backend.app.agent_daemon.daemon --once

echo.
echo -----------------------------------------------------------------------
echo                     BACKGROUND SERVICE CONFIGURATION
echo -----------------------------------------------------------------------
echo Would you like to register AgentShield as a Windows Scheduled Task
echo so it monitors security events continuously in the background?
set /p INSTALL_TASK="Register background scheduled task? (Y/N, default Y): "
if "%INSTALL_TASK%"=="" set INSTALL_TASK=Y

if /i "%INSTALL_TASK%"=="Y" (
    echo [*] Registering scheduled task 'AgentShieldEndpointAgent'...
    schtasks /create /tn "AgentShieldEndpointAgent" /tr "\"%CD%\..\backend\.venv\Scripts\python.exe\" -m backend.app.agent_daemon.daemon --daemon" /sc onlogon /f >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        echo [OK] Scheduled task registered successfully! Runs on user logon.
    ) else (
        echo [NOTE] Scheduled task registration required elevated prompt. You can run daemon manually:
        echo        python -m backend.app.agent_daemon.daemon --daemon
    )
)

echo.
echo =======================================================================
echo               AGENTSHIELD INSTALLATION COMPLETED!
echo =======================================================================
echo Device Status:
python -m backend.app.agent_daemon.daemon --status
echo.
echo To start the desktop dashboard:
echo   cd ../frontend && npm run dev
echo.
echo To run the agent daemon manually:
echo   python -m backend.app.agent_daemon.daemon --daemon
echo.
pause
