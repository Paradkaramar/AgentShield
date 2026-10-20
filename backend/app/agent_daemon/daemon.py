"""
AgentShield Endpoint Security Agent Daemon CLI & Service Runner
Usage:
  python -m backend.app.agent_daemon.daemon --enroll <token> [--device-name <name>]
  python -m backend.app.agent_daemon.daemon --daemon [--interval <seconds>]
  python -m backend.app.agent_daemon.daemon --once
  python -m backend.app.agent_daemon.daemon --status
  python -m backend.app.agent_daemon.daemon --scan-file <path>
"""

import sys
import time
import argparse
import logging
import signal
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..services.endpoint_agent import EndpointAgent, now_iso
from ..db.database import connect

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [AgentShield-Daemon] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("agentshield.daemon")

stop_requested = False

def sig_handler(signum, frame):
    global stop_requested
    logger.info("Termination signal received. Gracefully stopping AgentShield daemon...")
    stop_requested = True

signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)


def enroll_device(token: str, device_name: str = None) -> bool:
    """Enroll this computer using an authorized enrollment token."""
    agent = EndpointAgent()
    hw = agent.get_hardware_and_os_info()
    dev_name = device_name or hw["device_name"]
    now = now_iso()

    with connect() as db:
        # 1. Verify token
        tok_row = db.execute(
            "SELECT token, expires_at, used FROM device_enrollment_tokens WHERE token = ?",
            (token,)
        ).fetchone()

        if not tok_row:
            logger.error(f"Enrollment rejected: Token '{token}' is invalid.")
            return False

        if tok_row["used"]:
            logger.error("Enrollment rejected: Token has already been used.")
            return False

        if tok_row["expires_at"] < now:
            logger.error("Enrollment rejected: Token has expired.")
            return False

        # 2. Generate secure device token
        raw_device_secret = f"{agent.device_id}:{token}:{time.time()}"
        device_token_hash = hashlib.sha256(raw_device_secret.encode()).hexdigest()

        # 3. Create or update enrolled device record
        db.execute(
            """INSERT INTO enrolled_devices (
                id, device_name, hostname, os_type, os_release, os_version,
                agent_version, device_token_hash, enrolled_at, last_heartbeat,
                monitoring_status, is_revoked, revocation_reason, ip_address,
                mac_address, cpu_cores, total_memory_mb
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, NULL, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                device_name = excluded.device_name,
                device_token_hash = excluded.device_token_hash,
                last_heartbeat = excluded.last_heartbeat,
                monitoring_status = 'ACTIVE',
                is_revoked = 0,
                ip_address = excluded.ip_address""",
            (
                agent.device_id, dev_name, hw["hostname"], hw["os_type"],
                hw["os_release"], hw["os_version"], agent.agent_version,
                device_token_hash, now, now, hw["ip_address"], hw["mac_address"],
                hw["cpu_cores"], hw["total_memory_mb"]
            )
        )

        # 4. Mark token used
        db.execute(
            "UPDATE device_enrollment_tokens SET used = 1, used_by_device_id = ? WHERE token = ?",
            (agent.device_id, token)
        )

        # 5. Populate initial granular consent records
        consent_items = [
            ("device_identification", "Device Identification & Registration", "Unique machine ID, hardware specs, OS version", 1, 1, 0),
            ("network_monitoring", "Local Network Connection Monitoring", "Active socket metadata, source/dest IPs and ports", 0, 1, 0),
            ("process_metadata", "Process & Service Metadata Collection", "Running processes, PIDs, executables, CPU/memory usage", 0, 1, 0),
            ("firewall_inspection", "Host Firewall Status Inspection", "Inspection of active firewall profiles and default policy", 0, 1, 1),
            ("security_events", "Security Event Telemetry", "System security events, failed logons, credential alerts", 0, 1, 1),
            ("suspicious_file_scan", "Suspicious File Scanning", "Signature and hash-based scanning of flagged suspicious binaries", 0, 0, 0),
            ("central_dashboard", "AgentShield Central Dashboard Sync", "Encrypted telemetry synchronization with the central dashboard", 0, 1, 0),
            ("diagnostic_telemetry", "Diagnostic & Health Telemetry", "Agent daemon memory, CPU load, and uptime telemetry", 0, 1, 0),
        ]
        for pkey, dname, desc, is_mand, is_grant, req_admin in consent_items:
            db.execute(
                """INSERT INTO device_consent_records (
                    device_id, permission_key, display_name, description,
                    is_mandatory, granted, requires_admin, updated_at, consent_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, permission_key) DO UPDATE SET
                    updated_at = excluded.updated_at""",
                (
                    agent.device_id, pkey, dname, desc, is_mand, is_grant, req_admin, now,
                    hashlib.sha256(f"{agent.device_id}:{pkey}:{is_grant}".encode()).hexdigest()
                )
            )

        # 6. Audit log
        db.execute(
            """INSERT INTO device_audit_logs (
                device_id, action, actor, details_json, timestamp
            ) VALUES (?, 'DEVICE_ENROLLED', 'daemon', ?, ?)""",
            (agent.device_id, json.dumps({"token": token, "device_name": dev_name, "os": f"{hw['os_type']} {hw['os_release']}"}), now)
        )

        # Save local credentials securely in user's home cache
        agent.save_local_identity({
            "device_id": agent.device_id,
            "device_token": raw_device_secret,
            "enrolled_at": now
        })

    logger.info(f"Enrollment SUCCESSFUL! Device ID: {agent.device_id}")
    logger.info(f"Device Name: {dev_name} | OS: {hw['os_type']} {hw['os_release']}")
    return True


def show_status():
    """Print local device security agent status."""
    agent = EndpointAgent()
    hw = agent.get_hardware_and_os_info()
    consent = agent.get_active_consent()
    fw = agent.inspect_firewall_status()

    with connect() as db:
        dev_row = db.execute(
            "SELECT monitoring_status, is_revoked, last_heartbeat FROM enrolled_devices WHERE id = ?",
            (agent.device_id,)
        ).fetchone()

        alerts_count = db.execute(
            "SELECT COUNT(*) FROM device_security_alerts WHERE device_id = ? AND status = 'OPEN'",
            (agent.device_id,)
        ).fetchone()[0]

    print("\n=======================================================")
    print("  AgentShield Endpoint Security Agent Status")
    print("=======================================================")
    print(f"Device ID:          {agent.device_id}")
    print(f"Host / OS:          {hw['hostname']} ({hw['os_type']} {hw['os_release']})")
    print(f"Agent Version:      {agent.agent_version}")
    print(f"IP / MAC:           {hw['ip_address']} / {hw['mac_address']}")
    print(f"CPU / Memory:       {hw['cpu_cores']} cores / {hw['total_memory_mb']} MB")
    
    if dev_row:
        print(f"Enrollment Status:  ENROLLED (Status: {dev_row['monitoring_status']})")
        print(f"Revoked:            {'YES' if dev_row['is_revoked'] else 'NO'}")
        print(f"Last Heartbeat:     {dev_row['last_heartbeat']}")
    else:
        print("Enrollment Status:  NOT ENROLLED (Run with --enroll <token>)")

    print(f"Active Alerts:      {alerts_count} open alerts")
    print(f"Host Firewall:      {fw['os_firewall_type']} (Active: {'YES' if fw['is_enabled'] else 'NO'})")
    print("\nActive Permission Consent:")
    for k, v in consent.items():
        status_sym = "[x] GRANTED" if v else "[ ] WITHHELD"
        print(f"  {status_sym:<16} {k}")
    print("=======================================================\n")


def run_daemon(interval_sec: int = 30):
    """Run continuous monitoring background loop."""
    agent = EndpointAgent()
    logger.info(f"Starting AgentShield background monitoring service for device: {agent.device_id}")
    logger.info(f"Scan interval: {interval_sec} seconds. Press Ctrl+C to stop.")

    while not stop_requested:
        try:
            res = agent.sync_telemetry_to_local_db()
            logger.info(
                f"Telemetry pass complete: procs={res.get('processes_count', 0)}, "
                f"conns={res.get('connections_count', 0)}, alerts={res.get('alerts_generated', 0)}"
            )
        except Exception as e:
            logger.error(f"Error during telemetry pass: {e}")

        # Sleep with periodic stop check
        for _ in range(interval_sec):
            if stop_requested:
                break
            time.sleep(1)

    logger.info("AgentShield daemon service stopped cleanly.")


def main():
    parser = argparse.ArgumentParser(description="AgentShield Endpoint Security Daemon")
    parser.add_argument("--enroll", help="Enroll device with provided enrollment token")
    parser.add_argument("--device-name", help="Custom display name for this computer")
    parser.add_argument("--daemon", action="store_true", help="Run continuous monitoring service")
    parser.add_argument("--interval", type=int, default=30, help="Monitoring interval in seconds (default: 30)")
    parser.add_argument("--once", action="store_true", help="Perform a single monitoring pass and exit")
    parser.add_argument("--status", action="store_true", help="Display local agent status and consent")
    parser.add_argument("--scan-file", help="Perform heuristic security scan on specified file")

    args = parser.parse_args()

    if args.enroll:
        success = enroll_device(args.enroll, args.device_name)
        sys.exit(0 if success else 1)
    elif args.status:
        show_status()
    elif args.scan_file:
        agent = EndpointAgent()
        res = agent.scan_file_heuristics(args.scan_file)
        print(json.dumps(res, indent=2))
    elif args.once:
        agent = EndpointAgent()
        res = agent.sync_telemetry_to_local_db()
        print(json.dumps(res, indent=2))
    elif args.daemon:
        run_daemon(interval_sec=args.interval)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
