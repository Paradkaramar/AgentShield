# backend/app/api/network_routes.py
"""Network Monitoring REST API Routes
Provides authenticated control plane endpoints for continuous network monitoring,
scope configuration, asset discovery, security baseline comparisons, alerts, and emergency stop.
"""

import ipaddress
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field

from ..db.database import connect, now_iso
from ..core.auth import get_current_user, require_roles
from ..core.audit import record_audit_entry
from ..services.network_monitor import network_monitoring_service

router = APIRouter(prefix="/api/network", tags=["Continuous Network Monitoring"])

# --- Request / Response Schemas ---

class NetworkConfigUpdateRequest(BaseModel):
    service_enabled: Optional[bool] = None
    is_paused: Optional[bool] = None
    scan_interval_seconds: Optional[int] = Field(None, ge=10, le=86400)
    scan_duration_limit_seconds: Optional[int] = Field(None, ge=10, le=1800)
    max_concurrency: Optional[int] = Field(None, ge=1, le=50)
    probe_timeout_seconds: Optional[float] = Field(None, ge=0.1, le=10.0)
    target_ports: Optional[List[int]] = None

class ApprovedScopeCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    cidr_or_ip: str = Field(..., description="Valid IPv4 CIDR block or single IP (e.g. 192.168.1.0/24 or 10.0.0.5/32)")
    asset_tag: Optional[str] = "Internal Infrastructure"

class ExclusionCreateRequest(BaseModel):
    ip_address: str = Field(..., description="Valid IPv4 address to exclude from scanning")
    reason: str = Field(..., min_length=3, max_length=255)
    scope_id: Optional[int] = None

class EmergencyStopRequest(BaseModel):
    reason: Optional[str] = "Operator initiated global emergency stop"

class AlertStatusUpdateRequest(BaseModel):
    status: str = Field(..., pattern="^(OPEN|ACKNOWLEDGED|RESOLVED)$")


# --- Endpoints ---

@router.get("/status")
def get_status(user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieve live monitoring status, running scanner jobs, counters, and schedule."""
    return network_monitoring_service.get_monitoring_status()


@router.post("/controls/start")
def start_monitoring(user: Dict[str, Any] = Depends(require_roles(["admin", "operator"]))):
    """Enable and start continuous network monitoring."""
    now = now_iso()
    with connect() as db:
        db.execute("""
            UPDATE network_monitoring_config
            SET service_enabled = 1, is_paused = 0, updated_at = ?
        """, (now,))
        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="NETWORK_MONITORING_STARTED",
            resource="network_monitoring",
            details={"service_enabled": True, "timestamp": now}
        )

    network_monitoring_service.start_background_service()
    return {"status": "SUCCESS", "message": "Continuous network monitoring enabled and running."}


@router.post("/controls/stop")
def stop_monitoring(user: Dict[str, Any] = Depends(require_roles(["admin"]))):
    """Stop continuous network monitoring."""
    now = now_iso()
    with connect() as db:
        db.execute("""
            UPDATE network_monitoring_config
            SET service_enabled = 0, updated_at = ?
        """, (now,))
        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="NETWORK_MONITORING_STOPPED",
            resource="network_monitoring",
            details={"service_enabled": False, "timestamp": now}
        )

    return {"status": "SUCCESS", "message": "Continuous network monitoring stopped."}


@router.post("/controls/pause")
def pause_monitoring(user: Dict[str, Any] = Depends(require_roles(["admin", "operator"]))):
    """Temporarily pause network scan sweeps without disabling the service."""
    now = now_iso()
    with connect() as db:
        db.execute("""
            UPDATE network_monitoring_config
            SET is_paused = 1, updated_at = ?
        """, (now,))
        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="NETWORK_MONITORING_PAUSED",
            resource="network_monitoring",
            details={"is_paused": True, "timestamp": now}
        )

    return {"status": "SUCCESS", "message": "Continuous network monitoring paused."}


@router.post("/controls/resume")
def resume_monitoring(user: Dict[str, Any] = Depends(require_roles(["admin", "operator"]))):
    """Resume continuous network monitoring from paused state."""
    now = now_iso()
    with connect() as db:
        db.execute("""
            UPDATE network_monitoring_config
            SET is_paused = 0, updated_at = ?
        """, (now,))
        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="NETWORK_MONITORING_RESUMED",
            resource="network_monitoring",
            details={"is_paused": False, "timestamp": now}
        )

    return {"status": "SUCCESS", "message": "Continuous network monitoring resumed."}


@router.post("/controls/emergency-stop")
def emergency_stop(
    req: EmergencyStopRequest,
    user: Dict[str, Any] = Depends(require_roles(["admin", "security_analyst", "operator"]))
):
    """Global emergency stop: halts in-flight scans immediately, logs an immutable audit event."""
    actor = user.get("username", "admin")
    return network_monitoring_service.trigger_emergency_stop(actor=actor, reason=req.reason or "Manual emergency stop")


@router.post("/controls/reset-emergency-stop")
def reset_emergency_stop(user: Dict[str, Any] = Depends(require_roles(["admin"]))):
    """Reset emergency stop state after verifying network safety."""
    actor = user.get("username", "admin")
    return network_monitoring_service.reset_emergency_stop(actor=actor)


@router.post("/controls/scan-now")
async def trigger_scan_now(user: Dict[str, Any] = Depends(require_roles(["admin", "security_analyst", "operator"]))):
    """Trigger an immediate authorized scan of approved network ranges."""
    actor = user.get("username", "admin")
    result = await network_monitoring_service.execute_scan_cycle(triggered_by=f"USER:{actor}")
    if result.get("status") in {"BLOCKED", "ERROR"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result.get("message"))
    return result


@router.patch("/config")
def update_config(
    req: NetworkConfigUpdateRequest,
    user: Dict[str, Any] = Depends(require_roles(["admin"]))
):
    """Update continuous scan configuration parameters."""
    updates = []
    params = []
    now = now_iso()

    if req.service_enabled is not None:
        updates.append("service_enabled = ?")
        params.append(1 if req.service_enabled else 0)
    if req.is_paused is not None:
        updates.append("is_paused = ?")
        params.append(1 if req.is_paused else 0)
    if req.scan_interval_seconds is not None:
        updates.append("scan_interval_seconds = ?")
        params.append(req.scan_interval_seconds)
    if req.scan_duration_limit_seconds is not None:
        updates.append("scan_duration_limit_seconds = ?")
        params.append(req.scan_duration_limit_seconds)
    if req.max_concurrency is not None:
        updates.append("max_concurrency = ?")
        params.append(req.max_concurrency)
    if req.probe_timeout_seconds is not None:
        updates.append("probe_timeout_seconds = ?")
        params.append(req.probe_timeout_seconds)
    if req.target_ports is not None:
        updates.append("target_ports_json = ?")
        params.append(json.dumps(req.target_ports))

    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No configuration fields provided for update")

    updates.append("updated_at = ?")
    params.append(now)

    with connect() as db:
        sql = f"UPDATE network_monitoring_config SET {', '.join(updates)}"
        db.execute(sql, tuple(params))
        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="NETWORK_CONFIG_UPDATED",
            resource="network_monitoring_config",
            details=req.model_dump(exclude_unset=True)
        )

    return {"status": "SUCCESS", "message": "Network monitoring configuration updated successfully."}


@router.get("/scopes")
def list_scopes(user: Dict[str, Any] = Depends(get_current_user)):
    """List approved network scopes and active IP exclusions."""
    with connect() as db:
        scopes = [dict(r) for r in db.execute("SELECT * FROM approved_scan_scopes ORDER BY id ASC").fetchall()]
        exclusions = [dict(r) for r in db.execute("SELECT * FROM network_exclusions ORDER BY id ASC").fetchall()]
    return {
        "scopes": scopes,
        "exclusions": exclusions
    }


@router.post("/scopes")
def add_approved_scope(
    req: ApprovedScopeCreateRequest,
    user: Dict[str, Any] = Depends(require_roles(["admin"]))
):
    """Add a new authorized IP address range or CIDR subnet. Requires admin privilege."""
    # Validate CIDR format
    clean_cidr = req.cidr_or_ip.strip()
    try:
        net = ipaddress.ip_network(clean_cidr, strict=False)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IPv4 CIDR specification: '{clean_cidr}'. Example: '192.168.1.0/24' or '10.0.0.1/32'"
        )

    # Prevent scanning public internet without explicit confirmation
    if not (net.is_private or net.is_loopback):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scope restricted: Public internet IP ranges cannot be added. Only authorized private or loopback enclaves are permitted."
        )

    now = now_iso()
    with connect() as db:
        # Check duplicate
        existing = db.execute("SELECT id FROM approved_scan_scopes WHERE cidr_or_ip = ?", (clean_cidr,)).fetchone()
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scope with this CIDR already exists")

        cur = db.execute("""
            INSERT INTO approved_scan_scopes (
                name, cidr_or_ip, is_approved, organization_id, asset_tag, created_by, created_at
            ) VALUES (?, ?, 1, 'org-default', ?, ?, ?)
        """, (req.name.strip(), clean_cidr, req.asset_tag or "Internal Infrastructure", user.get("username", "admin"), now))
        
        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="APPROVED_NETWORK_SCOPE_ADDED",
            resource=f"approved_scan_scopes:{cur.lastrowid}",
            details={"cidr": clean_cidr, "name": req.name}
        )

    return {"status": "SUCCESS", "message": f"Approved network scope '{req.name}' ({clean_cidr}) added successfully."}


@router.delete("/scopes/{scope_id}")
def delete_approved_scope(
    scope_id: int,
    user: Dict[str, Any] = Depends(require_roles(["admin"]))
):
    """Remove an approved CIDR range from authorized monitoring."""
    with connect() as db:
        scope = db.execute("SELECT * FROM approved_scan_scopes WHERE id = ?", (scope_id,)).fetchone()
        if not scope:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approved scope not found")
        
        db.execute("DELETE FROM approved_scan_scopes WHERE id = ?", (scope_id,))
        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="APPROVED_NETWORK_SCOPE_REMOVED",
            resource=f"approved_scan_scopes:{scope_id}",
            details=dict(scope)
        )

    return {"status": "SUCCESS", "message": f"Approved scope #{scope_id} removed."}


@router.post("/exclusions")
def add_exclusion(
    req: ExclusionCreateRequest,
    user: Dict[str, Any] = Depends(require_roles(["admin"]))
):
    """Add a sensitive host exclusion that must never be probed by the scanner."""
    clean_ip = req.ip_address.strip()
    try:
        ipaddress.ip_address(clean_ip)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid IP address: '{clean_ip}'")

    now = now_iso()
    with connect() as db:
        existing = db.execute("SELECT id FROM network_exclusions WHERE ip_address = ?", (clean_ip,)).fetchone()
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Exclusion for this IP already exists")

        cur = db.execute("""
            INSERT INTO network_exclusions (scope_id, ip_address, reason, created_by, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (req.scope_id, clean_ip, req.reason.strip(), user.get("username", "admin"), now))

        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="NETWORK_EXCLUSION_ADDED",
            resource=f"network_exclusions:{cur.lastrowid}",
            details={"ip_address": clean_ip, "reason": req.reason}
        )

    return {"status": "SUCCESS", "message": f"Host exclusion for {clean_ip} registered successfully."}


@router.delete("/exclusions/{exclusion_id}")
def delete_exclusion(
    exclusion_id: int,
    user: Dict[str, Any] = Depends(require_roles(["admin"]))
):
    """Remove a host exclusion."""
    with connect() as db:
        excl = db.execute("SELECT * FROM network_exclusions WHERE id = ?", (exclusion_id,)).fetchone()
        if not excl:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exclusion not found")

        db.execute("DELETE FROM network_exclusions WHERE id = ?", (exclusion_id,))
        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="NETWORK_EXCLUSION_REMOVED",
            resource=f"network_exclusions:{exclusion_id}",
            details=dict(excl)
        )

    return {"status": "SUCCESS", "message": f"Exclusion #{exclusion_id} removed."}


@router.get("/assets")
def list_assets(
    status_filter: Optional[str] = Query(None, alias="status"),
    baseline_only: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """List discovered and baselined network assets with live status and services."""
    query = "SELECT * FROM network_assets WHERE 1=1"
    params = []

    if status_filter:
        query += " AND status = ?"
        params.append(status_filter.upper())
    if baseline_only is not None:
        query += " AND in_baseline = ?"
        params.append(1 if baseline_only else 0)
    if search:
        query += " AND (ip_address LIKE ? OR hostname LIKE ?)"
        s_pat = f"%{search.strip()}%"
        params.extend([s_pat, s_pat])

    query += " ORDER BY in_baseline DESC, last_seen DESC"

    with connect() as db:
        rows = [dict(r) for r in db.execute(query, tuple(params)).fetchall()]
        # Attach service counts
        for row in rows:
            srv_count = db.execute("SELECT COUNT(*) FROM service_observations WHERE ip_address = ? AND state = 'OPEN'", (row["ip_address"],)).fetchone()[0]
            row["open_ports_count"] = srv_count
    return rows


@router.post("/assets/{ip_address}/baseline")
def add_asset_to_baseline(
    ip_address: str,
    user: Dict[str, Any] = Depends(require_roles(["admin", "security_analyst"]))
):
    """Promotes a newly discovered host to the approved security baseline."""
    with connect() as db:
        asset = db.execute("SELECT * FROM network_assets WHERE ip_address = ?", (ip_address,)).fetchone()
        if not asset:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Asset {ip_address} not found")

        db.execute("UPDATE network_assets SET in_baseline = 1 WHERE ip_address = ?", (ip_address,))
        db.execute("UPDATE service_observations SET is_baseline = 1 WHERE ip_address = ?", (ip_address,))

        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="NETWORK_ASSET_BASELINED",
            resource=f"network_assets:{ip_address}",
            details={"ip_address": ip_address, "promoted_by": user.get("username")}
        )

    return {"status": "SUCCESS", "message": f"Asset {ip_address} and its observed services have been approved in baseline."}


@router.get("/services")
def list_services(
    ip_address: Optional[str] = Query(None),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """List observed network service endpoints, banners, and state."""
    query = "SELECT * FROM service_observations WHERE state = 'OPEN'"
    params = []
    if ip_address:
        query += " AND ip_address = ?"
        params.append(ip_address)
    query += " ORDER BY ip_address ASC, port ASC"

    with connect() as db:
        services = [dict(r) for r in db.execute(query, tuple(params)).fetchall()]
    return services


@router.get("/alerts")
def list_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """List network security alerts, separating observed facts from suspected threats."""
    query = "SELECT * FROM network_security_alerts WHERE 1=1"
    params = []
    if status_filter:
        query += " AND status = ?"
        params.append(status_filter.upper())
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with connect() as db:
        alerts = [dict(r) for r in db.execute(query, tuple(params)).fetchall()]
        for a in alerts:
            try:
                a["evidence"] = json.loads(a.get("evidence_json") or "{}")
            except Exception:
                a["evidence"] = {}
    return alerts


@router.patch("/alerts/{alert_id}")
def update_alert_status(
    alert_id: int,
    req: AlertStatusUpdateRequest,
    user: Dict[str, Any] = Depends(require_roles(["admin", "security_analyst"]))
):
    """Acknowledge or resolve a network security alert."""
    with connect() as db:
        alt = db.execute("SELECT * FROM network_security_alerts WHERE id = ?", (alert_id,)).fetchone()
        if not alt:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

        db.execute("UPDATE network_security_alerts SET status = ? WHERE id = ?", (req.status, alert_id))
        record_audit_entry(
            db,
            actor=user.get("username", "admin"),
            action="NETWORK_ALERT_STATUS_UPDATED",
            resource=f"network_security_alerts:{alert_id}",
            details={"previous_status": alt["status"], "new_status": req.status}
        )

    return {"status": "SUCCESS", "message": f"Alert #{alert_id} marked as {req.status}."}


@router.get("/jobs")
def list_scan_jobs(
    limit: int = Query(25, ge=1, le=100),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """List historical scan sweeps, durations, changes found, and error details."""
    with connect() as db:
        jobs = [dict(r) for r in db.execute("SELECT * FROM scan_jobs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()]
    return jobs


@router.get("/diff")
def get_scan_diff(user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieve differences detected between current network state and prior baseline,
    including new hosts, unbaselined open ports, and changed services.
    """
    with connect() as db:
        new_hosts = [dict(r) for r in db.execute("SELECT * FROM network_assets WHERE in_baseline = 0 AND status = 'REACHABLE'").fetchall()]
        unapproved_services = [dict(r) for r in db.execute("SELECT * FROM service_observations WHERE is_baseline = 0 AND state = 'OPEN'").fetchall()]
        offline_baseline_hosts = [dict(r) for r in db.execute("SELECT * FROM network_assets WHERE in_baseline = 1 AND status = 'OFFLINE'").fetchall()]
        recent_alerts = [dict(r) for r in db.execute("SELECT * FROM network_security_alerts WHERE status = 'OPEN' ORDER BY id DESC LIMIT 10").fetchall()]

    return {
        "newly_discovered_hosts": new_hosts,
        "unexpected_open_ports": unapproved_services,
        "offline_baseline_hosts": offline_baseline_hosts,
        "active_alerts": recent_alerts,
        "total_discrepancies": len(new_hosts) + len(unapproved_services) + len(offline_baseline_hosts)
    }
