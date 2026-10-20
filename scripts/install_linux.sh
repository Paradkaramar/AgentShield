#!/usr/bin/env bash
# AgentShield Personal Device Security Platform — Linux Guided Installer
# Supported on Ubuntu 20.04/22.04/24.04 LTS and Debian 11/12

set -euo pipefail

echo "======================================================================="
echo "       AgentShield Installable Personal Device Security Platform       "
echo "                     Linux Guided Installer v1.2.0                    "
echo "======================================================================="
echo ""
echo "PRIVILEGE & INTEGRITY DISCLOSURE:"
echo "  * Standard User: Runs the endpoint agent daemon and desktop UI."
echo "  * Root/Sudo (Polkit): Required ONLY if installing system-wide systemd unit"
echo "    or inspecting UFW firewall rules."
echo "  * Transparency: No hidden background scripts or binary blobs."
echo ""

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 is required. Run 'sudo apt update && sudo apt install -y python3 python3-venv python3-pip'"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# 2. Virtualenv setup
if [ ! -d "${PROJECT_ROOT}/backend/.venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv "${PROJECT_ROOT}/backend/.venv"
fi

echo "[*] Installing dependencies..."
"${PROJECT_ROOT}/backend/.venv/bin/pip" install --upgrade pip --quiet
"${PROJECT_ROOT}/backend/.venv/bin/pip" install -r "${PROJECT_ROOT}/backend/requirements.txt" --quiet
"${PROJECT_ROOT}/backend/.venv/bin/pip" install psutil --quiet

# 3. Enrollment Token
read -r -p "Enter Enrollment Token [default: SHIELD-ENROLL-DEMO-2026]: " USER_TOKEN
USER_TOKEN=${USER_TOKEN:-SHIELD-ENROLL-DEMO-2026}

read -r -p "Enter Device Friendly Name [default: $(hostname)]: " DEV_NAME
DEV_NAME=${DEV_NAME:-$(hostname)}

echo "[*] Enrolling device '${DEV_NAME}'..."
"${PROJECT_ROOT}/backend/.venv/bin/python" -m backend.app.agent_daemon.daemon --enroll "${USER_TOKEN}" --device-name "${DEV_NAME}"

# 4. Baseline Telemetry Pass
echo "[*] Executing initial telemetry pass..."
"${PROJECT_ROOT}/backend/.venv/bin/python" -m backend.app.agent_daemon.daemon --once

# 5. systemd Service Setup
read -r -p "Do you want to install user-level systemd service? (y/n) [default: y]: " INSTALL_SYSTEMD
INSTALL_SYSTEMD=${INSTALL_SYSTEMD:-y}

if [[ "${INSTALL_SYSTEMD}" =~ ^[Yy]$ ]]; then
    USER_SYSTEMD_DIR="${HOME}/.config/systemd/user"
    mkdir -p "${USER_SYSTEMD_DIR}"
    
    cat > "${USER_SYSTEMD_DIR}/agentshield-agent.service" << EOF
[Unit]
Description=AgentShield Personal Device Security Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_ROOT}
ExecStart=${PROJECT_ROOT}/backend/.venv/bin/python -m backend.app.agent_daemon.daemon --daemon --interval 30
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

    systemctl --user daemon-reload
    systemctl --user enable agentshield-agent.service
    systemctl --user start agentshield-agent.service
    echo "[OK] Systemd user service installed and started!"
fi

echo ""
echo "======================================================================="
echo "                INSTALLATION COMPLETED SUCCESSFULLY!                  "
echo "======================================================================="
"${PROJECT_ROOT}/backend/.venv/bin/python" -m backend.app.agent_daemon.daemon --status
