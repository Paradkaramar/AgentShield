#!/usr/bin/env bash
# AgentShield Personal Device Security Platform — Linux Uninstaller
set -euo pipefail

echo "======================================================================="
echo "       AgentShield Personal Device Security Platform — Uninstaller     "
echo "======================================================================="

read -r -p "Are you sure you want to uninstall AgentShield? (y/n): " CONFIRM
if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
    echo "Uninstallation cancelled."
    exit 0
fi

USER_SERVICE="${HOME}/.config/systemd/user/agentshield-agent.service"
if [ -f "${USER_SERVICE}" ]; then
    echo "[*] Stopping and disabling systemd service..."
    systemctl --user stop agentshield-agent.service || true
    systemctl --user disable agentshield-agent.service || true
    rm -f "${USER_SERVICE}"
    systemctl --user daemon-reload
    echo "[OK] Service removed."
fi

echo "[*] Stopping any active daemon processes..."
pkill -f "backend.app.agent_daemon.daemon" || true

echo "[*] Cleaning local identity cache (${HOME}/.agentshield)..."
rm -rf "${HOME}/.agentshield"

echo "[OK] AgentShield uninstalled cleanly."
