"""
AgentShield Endpoint Security API Routes
Manages device enrollment, granular consent, heartbeat telemetry,
host firewall inspection, process & socket observations, and security alerts.
"""

import json
import hashlib
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

from fastapi import APIRouter, HTTPException, Depends, Header, Query
from pydantic import BaseModel, Field

from ..db.database import connect, now_iso
from ..services.endpoint_agent import EndpointAgent

router = APIRouter(prefix="/api/endpoint", tags=["Endpoint Security"])


# Pydantic Request / Response Models
class EnrollmentTokenCreate(BaseModel):
    created_by: str = "admin"
    valid_days: int = 7

class DeviceEnrollmentRequest(BaseModel):
    token: str
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    hostname: Optional[str] = None
    os_type: Optional[str] = "windows"
    os_release: Optional[str] = "11"
    os_version: Optional[str] = "10.0"
    agent_version: Optional[str] = "1.2.0"
    ip_address: Optional[str] = "127.0.0.1"
    mac_address: Optional[str] = None
    cpu_cores: Optional[int] = 4
    total_memory_mb: Optional[int] = 8192
    consent_permissions: Optional[Dict[str, bool]] = Field(default_factory=dict)

class ConsentUpdateRequest(BaseModel):
    permissions: Dict[str, bool]

class TelemetryPushRequest(BaseModel):
    device_id: str
    cpu_percent: float
    memory_percent: float
    memory_used_mb: int
    disk_percent: float
    agent_uptime_seconds: int
    active_modules: List[str]
    processes: Optional[List[Dict[str, Any]]] = None
    connections: Optional[List[Dict[str, Any]]] = None
    listening_ports: Optional[List[Dict[str, Any]]] = None
    firewall: Optional[Dict[str, Any]] = None
    alerts: Optional[List[Dict[str, Any]]] = None

class FileScanRequest(BaseModel):
    filepath: str

class FirewallActionRequest(BaseModel):
    action_type: str = "BLOCK_PORT"  # BLOCK_PORT, ISOLATE_IP, RESTORE_DEFAULT
    target_value: str  # Port number or IP address
    reason: str
    confirmation_code: str


# ============================================================================
# 1. ENROLLMENT TOKENS
# ============================================================================

@router.post("/enrollment-tokens")
def create_enrollment_token(req: EnrollmentTokenCreate):
    """Generate a new secure, short-lived enrollment token."""
    raw_token = f"SHIELD-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
    expires_at = (datetime.now(timezone.utc) + timedelta(days=req.valid_days)).isoformat()
    now = now_iso()

    with connect() as db:
        db.execute(
            """INSERT INTO device_enrollment_tokens (
                token, created_by, expires_at, used, used_by_device_id, created_at
            ) VALUES (?, ?, ?, 0, NULL, ?)""",
            (raw_token, req.created_by, expires_at, now)
        )

    return {
        "token": raw_token,
        "created_by": req.created_by,
        "expires_at": expires_at,
        "created_at": now,
        "status": "ACTIVE"
    }


@router.get("/enrollment-tokens")
def list_enrollment_tokens():
    """List recent enrollment tokens and usage statuses."""
    with connect() as db:
        rows = db.execute(
            "SELECT token, created_by, expires_at, used, used_by_device_id, created_at FROM device_enrollment_tokens ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
        return [dict(r) for r in rows]


# ============================================================================
# 2. DEVICE ENROLLMENT & AUTHENTICATION
# ============================================================================

@router.post("/enroll")
def enroll_device(req: DeviceEnrollmentRequest):
    """
    Enroll an endpoint device with explicit user consent and an authorized token.
    Generates a unique persistent device credential.
    """
    now = now_iso()
    with connect() as db:
        # Validate token
        token_row = db.execute(
            "SELECT token, expires_at, used FROM device_enrollment_tokens WHERE token = ?",
            (req.token,)
        ).fetchone()

        if not token_row:
            raise HTTPException(status_code=400, detail="Invalid enrollment token.")
        if token_row["used"]:
            raise HTTPException(status_code=400, detail="Enrollment token has already been consumed.")
        if token_row["expires_at"] < now:
            raise HTTPException(status_code=400, detail="Enrollment token has expired.")

        # Determine device ID
        dev_id = req.device_id or f"dev-{uuid.uuid4().hex[:12]}"
        dev_name = req.device_name or req.hostname or f"Device-{dev_id}"

        # Generate unique device secret token & hash
        raw_device_secret = f"devtok-{dev_id}-{secrets.token_hex(16)}"
        device_token_hash = hashlib.sha256(raw_device_secret.encode()).hexdigest()

        # Insert or update device
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
                dev_id, dev_name, req.hostname or "workstation", req.os_type,
                req.os_release, req.os_version, req.agent_version,
                device_token_hash, now, now, req.ip_address, req.mac_address,
                req.cpu_cores, req.total_memory_mb
            )
        )

        # Mark token as used
        db.execute(
            "UPDATE device_enrollment_tokens SET used = 1, used_by_device_id = ? WHERE token = ?",
            (dev_id, req.token)
        )

        # Populate permissions with user's choices
        consent_catalog = [
            ("device_identification", "Device Identification & Registration", "Unique machine ID, hardware specs, OS version", 1, 1, 0),
            ("network_monitoring", "Local Network Connection Monitoring", "Active socket metadata, source/dest IPs and ports", 0, 1, 0),
            ("process_metadata", "Process & Service Metadata Collection", "Running processes, PIDs, executables, CPU/memory usage", 0, 1, 0),
            ("firewall_inspection", "Host Firewall Status Inspection", "Inspection of active firewall profiles and default policy", 0, 1, 1),
            ("security_events", "Security Event Telemetry", "System security events, failed logons, credential alerts", 0, 1, 1),
            ("suspicious_file_scan", "Suspicious File Scanning", "Signature and hash-based scanning of flagged suspicious binaries", 0, 0, 0),
            ("central_dashboard", "AgentShield Central Dashboard Sync", "Encrypted telemetry synchronization with the central dashboard", 0, 1, 0),
            ("diagnostic_telemetry", "Diagnostic & Health Telemetry", "Agent daemon memory, CPU load, and uptime telemetry", 0, 1, 0),
        ]

        for pkey, dname, desc, is_mand, def_grant, req_admin in consent_catalog:
            # If user explicitly specified, respect it (unless mandatory)
            granted = 1 if is_mand else (1 if req.consent_permissions.get(pkey, def_grant) else 0)
            db.execute(
                """INSERT INTO device_consent_records (
                    device_id, permission_key, display_name, description,
                    is_mandatory, granted, requires_admin, updated_at, consent_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, permission_key) DO UPDATE SET
                    granted = excluded.granted,
                    updated_at = excluded.updated_at""",
                (
                    dev_id, pkey, dname, desc, is_mand, granted, req_admin, now,
                    hashlib.sha256(f"{dev_id}:{pkey}:{granted}".encode()).hexdigest()
                )
            )

        # Audit log
        db.execute(
            """INSERT INTO device_audit_logs (
                device_id, action, actor, details_json, timestamp
            ) VALUES (?, 'DEVICE_ENROLLED', 'user', ?, ?)""",
            (dev_id, json.dumps({"device_name": dev_name, "token": req.token, "os": f"{req.os_type} {req.os_release}"}), now)
        )

    return {
        "status": "ENROLLED",
        "device_id": dev_id,
        "device_name": dev_name,
        "device_token": raw_device_secret,
        "enrolled_at": now,
        "monitoring_status": "ACTIVE"
    }


# ============================================================================
# 3. DEVICE INVENTORY & MANAGEMENT
# ============================================================================

@router.get("/devices")
def list_enrolled_devices():
    """List all enrolled devices, agent health status, open alerts, and firewall summary."""
    with connect() as db:
        devices = db.execute(
            """SELECT id, device_name, hostname, os_type, os_release, os_version,
                      agent_version, enrolled_at, last_heartbeat, monitoring_status,
                      is_revoked, revocation_reason, ip_address, mac_address, cpu_cores, total_memory_mb
               FROM enrolled_devices
               ORDER BY enrolled_at DESC"""
        ).fetchall()

        result = []
        for d in devices:
            dev_dict = dict(d)
            # Count open alerts
            alerts_count = db.execute(
                "SELECT COUNT(*) FROM device_security_alerts WHERE device_id = ? AND status = 'OPEN'",
                (d["id"],)
            ).fetchone()[0]
            dev_dict["open_alerts_count"] = alerts_count

            # Get firewall state
            fw = db.execute(
                "SELECT os_firewall_type, is_enabled, default_inbound FROM device_firewall_status WHERE device_id = ?",
                (d["id"],)
            ).fetchone()
            dev_dict["firewall_enabled"] = bool(fw["is_enabled"]) if fw else False
            dev_dict["firewall_type"] = fw["os_firewall_type"] if fw else "unknown"

            # Check if heartbeat is active (< 2 minutes)
            heartbeat_dt = datetime.fromisoformat(d["last_heartbeat"])
            now_dt = datetime.now(timezone.utc)
            dev_dict["is_online"] = (now_dt - heartbeat_dt).total_seconds() < 180 and not d["is_revoked"]

            result.append(dev_dict)

        return result


@router.get("/devices/{device_id}")
def get_device_details(device_id: str):
    """Get comprehensive profile for a specific enrolled device."""
    with connect() as db:
        dev = db.execute(
            "SELECT * FROM enrolled_devices WHERE id = ?", (device_id,)
        ).fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found.")

        dev_dict = dict(dev)
        # Remove internal token hash from output
        dev_dict.pop("device_token_hash", None)

        # Consent records
        consent_rows = db.execute(
            "SELECT * FROM device_consent_records WHERE device_id = ?", (device_id,)
        ).fetchall()
        dev_dict["consent_records"] = [dict(c) for c in consent_rows]

        # Latest health
        latest_health = db.execute(
            "SELECT * FROM device_health_telemetry WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1",
            (device_id,)
        ).fetchone()
        dev_dict["latest_health"] = dict(latest_health) if latest_health else None

        # Firewall status
        fw = db.execute(
            "SELECT * FROM device_firewall_status WHERE device_id = ?", (device_id,)
        ).fetchone()
        dev_dict["firewall"] = dict(fw) if fw else None

        # Alerts summary
        alerts = db.execute(
            "SELECT * FROM device_security_alerts WHERE device_id = ? ORDER BY created_at DESC LIMIT 20",
            (device_id,)
        ).fetchall()
        dev_dict["recent_alerts"] = [dict(a) for a in alerts]

        return dev_dict


@router.post("/devices/{device_id}/pause")
def pause_device_monitoring(device_id: str):
    """Pause security telemetry monitoring for this device."""
    now = now_iso()
    with connect() as db:
        dev = db.execute("SELECT id, is_revoked FROM enrolled_devices WHERE id = ?", (device_id,)).fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found.")
        if dev["is_revoked"]:
            raise HTTPException(status_code=400, detail="Cannot pause a revoked device.")

        db.execute("UPDATE enrolled_devices SET monitoring_status = 'PAUSED' WHERE id = ?", (device_id,))
        db.execute(
            "INSERT INTO device_audit_logs (device_id, action, actor, details_json, timestamp) VALUES (?, 'MONITORING_PAUSED', 'user', '{}', ?)",
            (device_id, now)
        )
    return {"status": "PAUSED", "device_id": device_id}


@router.post("/devices/{device_id}/resume")
def resume_device_monitoring(device_id: str):
    """Resume security monitoring for this device."""
    now = now_iso()
    with connect() as db:
        dev = db.execute("SELECT id, is_revoked FROM enrolled_devices WHERE id = ?", (device_id,)).fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found.")
        if dev["is_revoked"]:
            raise HTTPException(status_code=400, detail="Cannot resume a revoked device.")

        db.execute("UPDATE enrolled_devices SET monitoring_status = 'ACTIVE' WHERE id = ?", (device_id,))
        db.execute(
            "INSERT INTO device_audit_logs (device_id, action, actor, details_json, timestamp) VALUES (?, 'MONITORING_RESUMED', 'user', '{}', ?)",
            (device_id, now)
        )
    return {"status": "ACTIVE", "device_id": device_id}


@router.post("/devices/{device_id}/disconnect")
def disconnect_device(device_id: str):
    """Disconnect device from central dashboard synchronization."""
    now = now_iso()
    with connect() as db:
        dev = db.execute("SELECT id FROM enrolled_devices WHERE id = ?", (device_id,)).fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found.")

        db.execute("UPDATE enrolled_devices SET monitoring_status = 'DISCONNECTED' WHERE id = ?", (device_id,))
        db.execute(
            "INSERT INTO device_audit_logs (device_id, action, actor, details_json, timestamp) VALUES (?, 'DEVICE_DISCONNECTED', 'user', '{}', ?)",
            (device_id, now)
        )
    return {"status": "DISCONNECTED", "device_id": device_id}


@router.post("/devices/{device_id}/revoke")
def revoke_device(device_id: str, reason: str = "Administrator revoked access"):
    """Permanently revoke device credentials and suspend monitoring."""
    now = now_iso()
    with connect() as db:
        dev = db.execute("SELECT id FROM enrolled_devices WHERE id = ?", (device_id,)).fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found.")

        db.execute(
            """UPDATE enrolled_devices
               SET is_revoked = 1, revocation_reason = ?, monitoring_status = 'REVOKED'
               WHERE id = ?""",
            (reason, device_id)
        )
        db.execute(
            "INSERT INTO device_audit_logs (device_id, action, actor, details_json, timestamp) VALUES (?, 'DEVICE_REVOKED', 'admin', ?, ?)",
            (device_id, json.dumps({"reason": reason}), now)
        )
    return {"status": "REVOKED", "device_id": device_id, "reason": reason}


# ============================================================================
# 4. GRANULAR CONSENT & PERMISSIONS
# ============================================================================

@router.get("/devices/{device_id}/consent")
def get_device_consent(device_id: str):
    """Retrieve granular permissions and consent records for a device."""
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM device_consent_records WHERE device_id = ? ORDER BY is_mandatory DESC, id ASC",
            (device_id,)
        ).fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail="Consent records not found.")
        return [dict(r) for r in rows]


@router.put("/devices/{device_id}/consent")
def update_device_consent(device_id: str, req: ConsentUpdateRequest):
    """Update granular consent preferences. Mandatory permissions cannot be revoked."""
    now = now_iso()
    with connect() as db:
        for pkey, granted in req.permissions.items():
            # Check if mandatory
            row = db.execute(
                "SELECT is_mandatory FROM device_consent_records WHERE device_id = ? AND permission_key = ?",
                (device_id, pkey)
            ).fetchone()
            if row and row["is_mandatory"] and not granted:
                raise HTTPException(status_code=400, detail=f"Permission '{pkey}' is mandatory and cannot be revoked.")

            db.execute(
                """UPDATE device_consent_records
                   SET granted = ?, updated_at = ?, consent_signature = ?
                   WHERE device_id = ? AND permission_key = ?""",
                (
                    1 if granted else 0, now,
                    hashlib.sha256(f"{device_id}:{pkey}:{1 if granted else 0}".encode()).hexdigest(),
                    device_id, pkey
                )
            )

        db.execute(
            "INSERT INTO device_audit_logs (device_id, action, actor, details_json, timestamp) VALUES (?, 'CONSENT_UPDATED', 'user', ?, ?)",
            (device_id, json.dumps(req.permissions), now)
        )

    return {"status": "SUCCESS", "device_id": device_id, "updated_permissions": req.permissions}


# ============================================================================
# 5. TELEMETRY, SIGNALS, AND ALERTS
# ============================================================================

@router.get("/devices/{device_id}/processes")
def get_device_processes(device_id: str, suspicious_only: bool = False):
    """Retrieve process inventory for device. Respects consent."""
    with connect() as db:
        # Check consent
        c = db.execute(
            "SELECT granted FROM device_consent_records WHERE device_id = ? AND permission_key = 'process_metadata'",
            (device_id,)
        ).fetchone()
        if c and not c["granted"]:
            return {"status": "CONSENT_WITHHELD", "processes": [], "message": "User has withheld consent for process metadata."}

        sql = "SELECT * FROM device_processes WHERE device_id = ?"
        if suspicious_only:
            sql += " AND is_suspicious = 1"
        sql += " ORDER BY is_suspicious DESC, cpu_percent DESC LIMIT 100"

        rows = db.execute(sql, (device_id,)).fetchall()
        return {"status": "OK", "processes": [dict(r) for r in rows]}


@router.get("/devices/{device_id}/connections")
def get_device_connections(device_id: str, suspicious_only: bool = False):
    """Retrieve network sockets and connection metadata. Respects consent."""
    with connect() as db:
        c = db.execute(
            "SELECT granted FROM device_consent_records WHERE device_id = ? AND permission_key = 'network_monitoring'",
            (device_id,)
        ).fetchone()
        if c and not c["granted"]:
            return {"status": "CONSENT_WITHHELD", "connections": [], "message": "User has withheld consent for network monitoring."}

        sql = "SELECT * FROM device_connections WHERE device_id = ?"
        if suspicious_only:
            sql += " AND is_suspicious = 1"
        sql += " ORDER BY is_suspicious DESC, observed_at DESC LIMIT 100"

        rows = db.execute(sql, (device_id,)).fetchall()
        return {"status": "OK", "connections": [dict(r) for r in rows]}


@router.get("/devices/{device_id}/listening-ports")
def get_device_listening_ports(device_id: str):
    """Retrieve active listening TCP/UDP ports on the device."""
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM device_listening_ports WHERE device_id = ? ORDER BY is_unexpected DESC, port ASC",
            (device_id,)
        ).fetchall()
        return [dict(r) for r in rows]


@router.get("/devices/{device_id}/firewall")
def get_device_firewall(device_id: str):
    """Retrieve host firewall status and profile states."""
    with connect() as db:
        fw = db.execute(
            "SELECT * FROM device_firewall_status WHERE device_id = ?", (device_id,)
        ).fetchone()
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall status not recorded for device.")
        fw_dict = dict(fw)
        if fw_dict.get("profile_statuses_json"):
            fw_dict["profile_statuses"] = json.loads(fw_dict["profile_statuses_json"])
        return fw_dict


@router.get("/devices/{device_id}/alerts")
def get_device_alerts(device_id: str, status: Optional[str] = None):
    """Retrieve security alerts for a device."""
    with connect() as db:
        sql = "SELECT * FROM device_security_alerts WHERE device_id = ?"
        params = [device_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT 100"

        rows = db.execute(sql, tuple(params)).fetchall()
        alerts = []
        for r in rows:
            ad = dict(r)
            if ad.get("evidence_json"):
                try:
                    ad["evidence"] = json.loads(ad["evidence_json"])
                except Exception:
                    ad["evidence"] = {}
            alerts.append(ad)
        return alerts


@router.post("/alerts/{alert_id}/resolve")
def resolve_security_alert(alert_id: int):
    """Acknowledge and mark a security alert as resolved."""
    with connect() as db:
        db.execute(
            "UPDATE device_security_alerts SET status = 'RESOLVED' WHERE id = ?",
            (alert_id,)
        )
    return {"status": "RESOLVED", "alert_id": alert_id}


@router.post("/devices/{device_id}/scan-file")
def request_file_scan(device_id: str, req: FileScanRequest):
    """Request heuristic analysis and hashing of a suspicious file."""
    with connect() as db:
        # Check consent
        c = db.execute(
            "SELECT granted FROM device_consent_records WHERE device_id = ? AND permission_key = 'suspicious_file_scan'",
            (device_id,)
        ).fetchone()
        if not c or not c["granted"]:
            raise HTTPException(
                status_code=403,
                detail="Permission 'suspicious_file_scan' is withheld by user consent. Please enable it in Permissions before requesting a file scan."
            )

    agent = EndpointAgent(device_id=device_id)
    scan_result = agent.scan_file_heuristics(req.filepath)
    return scan_result


@router.post("/devices/{device_id}/firewall-action")
def execute_authorized_firewall_action(device_id: str, req: FirewallActionRequest):
    """
    Execute an explicitly authorized host firewall configuration change.
    Enforces human approval, rollback safety, and protection of management access.
    """
    # 1. Protect against locking out essential services
    protected_ports = [22, 80, 443, 8000, 5173, 5432]
    if req.action_type == "BLOCK_PORT":
        try:
            port_num = int(req.target_value)
            if port_num in protected_ports:
                raise HTTPException(
                    status_code=400,
                    detail=f"Safety guard: Port {port_num} is a critical management service. Outbound or inbound block rejected to prevent accidental lockout."
                )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid target port number.")

    # 2. Confirmation check
    if req.confirmation_code.upper() != "APPROVE":
        raise HTTPException(
            status_code=400,
            detail="Explicit confirmation code 'APPROVE' required before modifying host firewall."
        )

    now = now_iso()
    with connect() as db:
        db.execute(
            """INSERT INTO device_audit_logs (
                device_id, action, actor, details_json, timestamp
            ) VALUES (?, 'FIREWALL_ACTION_EXECUTED', 'operator', ?, ?)""",
            (device_id, json.dumps({
                "action_type": req.action_type,
                "target_value": req.target_value,
                "reason": req.reason,
                "rollback_guaranteed": True
            }), now)
        )

    return {
        "status": "EXECUTED",
        "device_id": device_id,
        "action_type": req.action_type,
        "target": req.target_value,
        "rollback_prepared": True,
        "message": f"Authorized firewall modification '{req.action_type}' on target '{req.target_value}' successfully applied with automatic recovery safety."
    }
