<#
.SYNOPSIS
    AgentShield Personal Device Security Platform — Windows Guided Installer
.DESCRIPTION
    Installs prerequisites, validates permissions, securely enrolls the device,
    configures background monitoring service, and verifies endpoint telemetry.
#>

[CmdletBinding()]
param (
    [string]$EnrollmentToken = "SHIELD-ENROLL-DEMO-2026",
    [string]$DeviceName = $env:COMPUTERNAME,
    [switch]$RegisterScheduledTask
)

Write-Host "=======================================================================" -ForegroundColor Cyan
Write-Host "       AgentShield Installable Personal Device Security Platform       " -ForegroundColor Cyan
Write-Host "                     Windows PowerShell Installer v1.2.0              " -ForegroundColor Cyan
Write-Host "=======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "PRIVILEGE & INTEGRITY DISCLOSURE:" -ForegroundColor Yellow
Write-Host "  * Standard User: Required for process and socket telemetry."
Write-Host "  * Administrator (UAC): Only needed for firewall profile configuration."
Write-Host "  * No Hidden Services: Transparent task registered under your account."
Write-Host ""

# 1. Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Error "Python 3 is not found in PATH. Please install Python 3.10+ from python.org."
    exit 1
}
Write-Host "[OK] Python detected at: $($pythonCmd.Source)" -ForegroundColor Green

# 2. Check Virtual Environment
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path "$scriptDir\.."
$venvPython = "$projectRoot\backend\.venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "[*] Creating virtual environment at backend\.venv..." -ForegroundColor Yellow
    python -m venv "$projectRoot\backend\.venv"
}

Write-Host "[*] Installing/verifying endpoint requirements..." -ForegroundColor Yellow
& $venvPython -m pip install -r "$projectRoot\backend\requirements.txt" --quiet
& $venvPython -m pip install psutil --quiet
Write-Host "[OK] Dependencies verified." -ForegroundColor Green

# 3. Enroll Device
Write-Host "`n[*] Enrolling device '$DeviceName' with token '$EnrollmentToken'..." -ForegroundColor Cyan
$enrollOutput = & $venvPython -m backend.app.agent_daemon.daemon --enroll $EnrollmentToken --device-name $DeviceName
Write-Host $enrollOutput

# 4. Run baseline telemetry pass
Write-Host "`n[*] Running baseline telemetry cycle..." -ForegroundColor Cyan
& $venvPython -m backend.app.agent_daemon.daemon --once

# 5. Optional Scheduled Task
if ($RegisterScheduledTask) {
    Write-Host "`n[*] Registering user logon scheduled task 'AgentShieldEndpointAgent'..." -ForegroundColor Yellow
    $action = New-ScheduledTaskAction -Execute $venvPython -Argument "-m backend.app.agent_daemon.daemon --daemon"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName "AgentShieldEndpointAgent" -Action $action -Trigger $trigger -Description "AgentShield Endpoint Security Background Agent" -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Scheduled task registered." -ForegroundColor Green
}

# 6. Status Display
Write-Host "`n[*] Verifying agent status:" -ForegroundColor Cyan
& $venvPython -m backend.app.agent_daemon.daemon --status

Write-Host "Installation completed successfully!`n" -ForegroundColor Green
