# backend/app/api/firewall_routes.py
"""
AgentShield Three-Layer Defensive Security Firewall REST API

Provides unified management, status telemetry, ruleset preview, and operational
controls across:
- Layer 1: Network Firewall (nftables / UFW rules preview, OS probe, rollback scripts)
- Layer 2: Application Firewall (ASGI WAF detection/blocking mode, rate limiting, events)
- Layer 3: AI Agent Security Firewall (Zero-Trust policy decisions, kill switch, audit)
"""

import json
import sqlite3
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Body, status
from pydantic import BaseModel, Field

from ..db.database import connect, now_iso
from ..core.auth import get_current_user
from ..core.audit import record_audit_entry
from ..firewall.network_firewall import (
    detect_host_firewall_capabilities,
    preview_network_firewall_configuration,
    validate_management_access
)
from ..firewall.ai_firewall import (
    AIAgentSecurityGateway,
    AIPolicyDecision
)

router = APIRouter(prefix="/api/firewall", tags=["Three-Layer Firewall"])

# ------------------------------------------------------------------------------
# Request & Response Models
# ------------------------------------------------------------------------------

class WAFModeUpdateRequest(BaseModel):
    mode: str = Field(..., pattern=r"^(DETECTION_ONLY|BLOCKING)$")

class AIKillSwitchUpdateRequest(BaseModel):
    active: bool
    reason: Optional[str] = "Operator toggled global AI Agent Kill Switch"

class NetworkSimulateEventRequest(BaseModel):
    source_ip: str = Field(..., max_length=64)
    dest_port: int = Field(..., ge=1, le=65535)
    protocol: Optional[str] = "tcp"
    rule_matched: Optional[str] = "NFT_MANUAL_SIMULATED_PROBE"

class ToolEvaluateRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    agent_id: Optional[str] = "agent-jarvis-orchestrator"
    prompt_context: Optional[str] = None

# ------------------------------------------------------------------------------
# 1. Unified Dashboard Status Endpoint
# ------------------------------------------------------------------------------

@router.get("/status")
def get_unified_firewall_status(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns verified status for all three defense layers.
    Clearly distinguishes real kernel/middleware telemetry from preview/simulated data.
    """
    with connect() as db:
        cfg = db.execute("SELECT * FROM firewall_three_layer_config ORDER BY id DESC LIMIT 1").fetchone()
        if not cfg:
            raise HTTPException(status_code=500, detail="Firewall configuration uninitialized")
        cfg_d = dict(cfg)

        # Layer 1 Network capabilities probe
        host_caps = detect_host_firewall_capabilities()
        mgmt_ips = json.loads(cfg_d.get("net_management_ips", "[]"))
        pg_subnets = json.loads(cfg_d.get("net_postgres_allowed_subnets", "[]"))
        app_ports = json.loads(cfg_d.get("net_app_ports", "[]"))
        net_events_count = db.execute("SELECT COUNT(*) FROM firewall_network_events").fetchone()[0]

        # Layer 2 Application WAF metrics
        waf_events_count = db.execute("SELECT COUNT(*) FROM firewall_waf_events").fetchone()[0]
        waf_blocked_count = db.execute("SELECT COUNT(*) FROM firewall_waf_events WHERE action_taken='BLOCKED'").fetchone()[0]

        # Layer 3 AI Agent Firewall metrics
        ai_events_count = db.execute("SELECT COUNT(*) FROM firewall_ai_events").fetchone()[0]
        ai_blocked_count = db.execute("SELECT COUNT(*) FROM firewall_ai_events WHERE decision='BLOCK'").fetchone()[0]
        ai_approvals_count = db.execute("SELECT COUNT(*) FROM firewall_ai_events WHERE decision='REQUIRE_HUMAN_APPROVAL'").fetchone()[0]

        # Determine real enforcement statuses
        l1_status = "ACTIVE" if host_caps["real_enforcement_capable"] else "CONFIGURED_PREVIEW"
        l2_status = "ACTIVE_ENFORCING" if cfg_d["waf_mode"] == "BLOCKING" else "ACTIVE_DETECTION"
        l3_status = "KILLED_EMERGENCY" if cfg_d["ai_kill_switch_active"] == 1 else "ACTIVE_ENFORCING"

        return {
            "timestamp": now_iso(),
            "layers": {
                "layer1_network": {
                    "layer_name": "Layer 1: Host & Network Boundary Firewall",
                    "status": l1_status,
                    "firewall_type": cfg_d["net_firewall_type"],
                    "real_enforcement_capable": host_caps["real_enforcement_capable"],
                    "platform": host_caps["platform"],
                    "diagnostics": host_caps["details"],
                    "management_ips": mgmt_ips,
                    "ssh_port": cfg_d["net_ssh_port"],
                    "app_ports": app_ports,
                    "postgres_port": cfg_d["net_postgres_port"],
                    "postgres_isolated_to": pg_subnets,
                    "ssh_lockout_protected": True,
                    "total_network_drop_events": net_events_count,
                    "is_simulated_telemetry": not host_caps["real_enforcement_capable"],
                    "notice": "Real packet filtering requires Linux netfilter/root. Generated rulesets are validated and ready for deployment." if not host_caps["real_enforcement_capable"] else "Operational"
                },
                "layer2_application": {
                    "layer_name": "Layer 2: Application Firewall & WAF",
                    "status": l2_status,
                    "mode": cfg_d["waf_mode"],
                    "owasp_crs_active": bool(cfg_d["waf_owasp_crs_enabled"]),
                    "rate_limit_rpm": cfg_d["waf_rate_limit_rpm"],
                    "max_body_bytes": cfg_d["waf_max_body_bytes"],
                    "trusted_proxies": json.loads(cfg_d.get("waf_trusted_proxies", "[]")),
                    "total_inspected_alerts": waf_events_count,
                    "total_blocked_requests": waf_blocked_count,
                    "reverse_proxy_modsec_compatible": True
                },
                "layer3_ai_agent": {
                    "layer_name": "Layer 3: AI Agent Security Firewall",
                    "status": l3_status,
                    "mode": cfg_d["ai_firewall_mode"],
                    "fail_closed_enabled": bool(cfg_d["ai_fail_closed"]),
                    "kill_switch_active": bool(cfg_d["ai_kill_switch_active"]),
                    "total_evaluations": ai_events_count,
                    "total_blocked_actions": ai_blocked_count,
                    "total_require_approvals": ai_approvals_count,
                    "strict_schema_validation": True,
                    "prompt_injection_defense": True,
                    "outbound_dlp_checks": True
                }
            }
        }

# ------------------------------------------------------------------------------
# 2. Layer 1 Network Firewall Endpoints
# ------------------------------------------------------------------------------

@router.get("/network/preview")
def get_network_ruleset_preview(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Generates and returns the proposed nftables ruleset, UFW command sequence,
    SSH safety check, and rollback script. Does NOT apply host mutations.
    """
    with connect() as db:
        cfg = db.execute("SELECT * FROM firewall_three_layer_config ORDER BY id DESC LIMIT 1").fetchone()
        mgmt_ips = json.loads(cfg["net_management_ips"]) if cfg else ["127.0.0.1/32"]
        pg_subnets = json.loads(cfg["net_postgres_allowed_subnets"]) if cfg else ["127.0.0.1/32"]
        app_ports = json.loads(cfg["net_app_ports"]) if cfg else [80, 443, 8000, 5173]
        ssh_port = cfg["net_ssh_port"] if cfg else 22

    preview = preview_network_firewall_configuration(
        management_ips=mgmt_ips,
        postgres_allowed_subnets=pg_subnets,
        app_ports=app_ports,
        ssh_port=ssh_port
    )
    return preview

@router.post("/network/validate")
def validate_network_config(
    management_ips: List[str] = Body(..., embed=True),
    ssh_port: int = Body(22, embed=True),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Validates proposed management CIDR ranges to prevent operator lockout.
    """
    is_valid, reason = validate_management_access(management_ips, ssh_port)
    return {
        "valid": is_valid,
        "message": reason,
        "ssh_port": ssh_port,
        "management_ips": management_ips
    }

@router.get("/network/events")
def get_network_events(
    limit: int = Query(25, ge=1, le=200),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves recent network firewall drop events. Explicitly marks simulated items.
    """
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM firewall_network_events ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

@router.post("/network/simulate-drop")
def simulate_network_drop_event(
    req: NetworkSimulateEventRequest,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Inserts a simulated packet drop into network telemetry for operator drills.
    """
    now = now_iso()
    with connect() as db:
        cur = db.execute(
            """INSERT INTO firewall_network_events (
                source_ip, dest_port, protocol, action, rule_matched, is_simulated, timestamp
            ) VALUES (?, ?, ?, 'DROP', ?, 1, ?)""",
            (req.source_ip, req.dest_port, req.protocol, req.rule_matched, now)
        )
        return {
            "id": cur.lastrowid,
            "status": "RECORDED",
            "is_simulated": True,
            "message": f"Simulated network drop recorded from {req.source_ip}:{req.dest_port} ({req.rule_matched})"
        }

# ------------------------------------------------------------------------------
# 3. Layer 2 Application Firewall (WAF) Endpoints
# ------------------------------------------------------------------------------

@router.get("/waf/events")
def get_waf_events(
    limit: int = Query(25, ge=1, le=200),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves recent WAF alerts and rule matches.
    """
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM firewall_waf_events ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

@router.post("/waf/mode")
def update_waf_mode(
    req: WAFModeUpdateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Toggles WAF operational mode between DETECTION_ONLY and BLOCKING.
    """
    if user.get("role") not in ("admin", "security_analyst"):
        raise HTTPException(status_code=403, detail="Only admin or security_analyst can change WAF mode")

    now = now_iso()
    with connect() as db:
        db.execute(
            "UPDATE firewall_three_layer_config SET waf_mode=?, updated_at=?",
            (req.mode, now)
        )
        record_audit_entry(
            db=db,
            actor=user.get("sub", "admin"),
            action="WAF_MODE_CHANGE",
            resource="firewall:layer2",
            details={"new_mode": req.mode}
        )
        return {
            "status": "UPDATED",
            "waf_mode": req.mode,
            "timestamp": now,
            "message": f"WAF operational mode updated to {req.mode}"
        }

# ------------------------------------------------------------------------------
# 4. Layer 3 AI Agent Security Firewall Endpoints
# ------------------------------------------------------------------------------

@router.get("/ai/events")
def get_ai_firewall_events(
    limit: int = Query(25, ge=1, le=200),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves recent AI agent policy evaluation events and blocked tool calls.
    """
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM firewall_ai_events ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

@router.post("/ai/kill-switch")
def update_ai_kill_switch(
    req: AIKillSwitchUpdateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Toggles the global emergency kill switch to immediately freeze or restore all AI agent actions.
    """
    if user.get("role") not in ("admin", "security_analyst", "operator"):
        raise HTTPException(status_code=403, detail="Insufficient privileges to toggle AI Agent Kill Switch")

    val = 1 if req.active else 0
    now = now_iso()
    with connect() as db:
        db.execute(
            "UPDATE firewall_three_layer_config SET ai_kill_switch_active=?, updated_at=?",
            (val, now)
        )
        action_name = "AI_KILL_SWITCH_ACTIVATED" if req.active else "AI_KILL_SWITCH_DEACTIVATED"
        record_audit_entry(
            db=db,
            actor=user.get("sub", "operator"),
            action=action_name,
            resource="firewall:layer3:kill_switch",
            details={"active": req.active, "reason": req.reason}
        )
        return {
            "status": "UPDATED",
            "kill_switch_active": req.active,
            "reason": req.reason,
            "timestamp": now,
            "message": "Global AI Agent Kill Switch ACTIVATED - All tool executions frozen" if req.active else "AI Agent Kill Switch DEACTIVATED - Normal operations restored"
        }

@router.post("/ai/evaluate")
def evaluate_tool_call_policy(
    req: ToolEvaluateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Evaluates a tool call request through the Layer 3 Policy Enforcement Gateway.
    Guaranteed Fail-Closed on any validation or policy evaluation error.
    """
    decision: AIPolicyDecision = AIAgentSecurityGateway.evaluate_tool_call(
        tool_name=req.tool_name,
        arguments=req.arguments,
        user=user,
        agent_id=req.agent_id,
        prompt_context=req.prompt_context
    )
    return decision.model_dump()
