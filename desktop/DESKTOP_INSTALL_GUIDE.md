# AgentShield Desktop Application & Endpoint Agent Installation Guide

## 1. Overview

AgentShield is an installable, zero-trust personal device security platform.
Unlike traditional endpoint detection products that install hidden rootkits, deep packet inspection drivers, or opaque kernel services, AgentShield operates with **strict user consent, transparent process boundaries, and verifiable security telemetry**.

AgentShield supports:
- **Windows 11 / Windows 10 (x64 / ARM64)**
- **Ubuntu Linux 20.04 / 22.04 / 24.04 LTS & Debian 11 / 12**
- **macOS Sonoma / Sequoia (POSIX compatibility mode)**

---

## 2. Privilege Model & Transparency Disclosure

AgentShield explicitly separates standard user operations from administrative operations:

| Component | Privilege Level | Why Privilege Is Required |
| :--- | :--- | :--- |
| **Desktop Application (GUI)** | Standard User | Rendering UI, dashboard synchronization, consent management. |
| **Agent Daemon** | Standard User | Process metadata (`psutil`), open socket connections, CPU/memory telemetry. |
| **Scheduled Task / User Unit** | Standard User | Autostart on user logon via Windows Task Scheduler or systemd user unit. |
| **Firewall Profile Probe** | Standard User / Read-only | Querying Windows Defender Firewall (`netsh advfirewall show allprofiles state`) or `ufw status`. |
| **Firewall Rule Modification** | Elevated Admin (UAC / Polkit) | **Explicitly requested only when the user authorizes** a host firewall change or quarantine rule. Requires typing `"APPROVE"`. |

### Zero Covert Persistence Guarantee
- No hidden drivers, kernel hooks, or covert registry run keys.
- No raw audio recording, webcam access, or transmission of user document contents.
- Transparent removal scripts (`uninstall_windows.bat`, `uninstall_linux.sh`) delete all scheduled jobs and identity files cleanly.

---

## 3. Quick Installation

### Windows 11 / 10

1. **Clone or Download Repository**:
   ```cmd
   git clone https://github.com/your-org/agentshield.git
   cd agentshield
   ```

2. **Run the Guided Installer**:
   Double click `scripts\install_windows.bat` or run in PowerShell:
   ```powershell
   .\scripts\install_windows.ps1 -EnrollmentToken "SHIELD-ENROLL-DEMO-2026" -RegisterScheduledTask
   ```

3. **Consent & Verification**:
   The installer verifies Python, installs dependencies, enrolls the device with an authorized enrollment token, and prints the agent status.

4. **Launch the Desktop Application**:
   ```cmd
   cd desktop
   npm start
   ```

---

### Ubuntu / Debian Linux

1. **Run the Linux Guided Installer**:
   ```bash
   chmod +x scripts/install_linux.sh scripts/uninstall_linux.sh
   ./scripts/install_linux.sh
   ```

2. **Review Systemd Status**:
   ```bash
   systemctl --user status agentshield-agent.service
   ```

3. **View Logs**:
   ```bash
   journalctl --user-u agentshield-agent.service -f
   ```

---

## 4. Permission & Consent Lifecycle

On initial enrollment, AgentShield requests explicit consent for 8 granular capabilities:
1. `device_identification` (Mandatory): Hardware specs, OS release, unique machine UUID.
2. `network_monitoring` (Optional): Local socket connections and remote egress ports.
3. `process_metadata` (Optional): Running processes, command-line arguments, CPU/RAM usage.
4. `firewall_inspection` (Optional): Active firewall profile states and inbound/outbound policies.
5. `security_events` (Optional): Alert correlation and failed authentication signals.
6. `suspicious_file_scan` (Optional): On-demand heuristic hashing and magic byte verification.
7. `central_dashboard` (Optional): Encrypted synchronization with the AgentShield control plane.
8. `diagnostic_telemetry` (Optional): Daemon uptime, memory footprint, and CPU consumption.

Any optional permission can be **granted, revoked, or updated at any time** through the AgentShield dashboard under `Device Security -> Permissions Manager`.

---

## 5. Clean Uninstallation

### Windows:
Run `scripts\uninstall_windows.bat` or delete the scheduled task:
```cmd
schtasks /delete /tn "AgentShieldEndpointAgent" /f
rmdir /s /q "%USERPROFILE%\.agentshield"
```

### Linux:
```bash
./scripts/uninstall_linux.sh
```
