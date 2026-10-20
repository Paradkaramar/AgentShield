@echo off
setlocal

echo =======================================================================
echo          AgentShield Personal Device Security Platform
echo                     Windows Uninstaller (v1.2.0)
echo =======================================================================
echo.
echo This utility safely uninstalls the AgentShield background agent, removes
echo scheduled tasks, and cleans local cached tokens.
echo.

set /p CONFIRM="Are you sure you want to uninstall AgentShield? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo Uninstallation cancelled.
    exit /b 0
)

echo [*] Removing scheduled task 'AgentShieldEndpointAgent'...
schtasks /delete /tn "AgentShieldEndpointAgent" /f >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [OK] Scheduled task removed.
) else (
    echo [INFO] No scheduled task found.
)

echo [*] Terminating running AgentShield agent daemon processes...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq AgentShield*" >nul 2>nul

echo [*] Cleaning local identity cache (%USERPROFILE%\.agentshield)...
if exist "%USERPROFILE%\.agentshield" (
    rmdir /S /Q "%USERPROFILE%\.agentshield"
    echo [OK] Local identity cache deleted.
)

echo.
echo =======================================================================
echo          AgentShield has been completely uninstalled from this PC.
echo =======================================================================
pause
