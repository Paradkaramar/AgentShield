import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from ..db.database import connect, now_iso
from ..engines.risk_engine import predict_near_future_risk, calculate_dynamic_risk
from ..engines.policy_engine import detect_permission_drift
from ..engines.kill_switch import trigger_emergency_kill_switch
from ..core.audit import record_audit_entry

# Registry of supported tool definitions with schemas
TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "get_security_dashboard_metrics": {
        "description": "Retrieve high-level SOC dashboard metrics including active agents, blocked actions, open incidents, and risk posture.",
        "category": "read",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "list_agents": {
        "description": "List all registered AI agents with status, risk scores, trust scores, and models.",
        "category": "read",
        "parameters": {
            "status": {"type": "string", "description": "Filter by status: ACTIVE, SUSPENDED, KILLED, or ALL", "default": "ALL"},
            "min_risk": {"type": "integer", "description": "Filter agents with risk_score >= min_risk", "default": 0}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_agent_details": {
        "description": "Retrieve comprehensive details for a specific AI agent including permissions, tools, and recent events.",
        "category": "read",
        "parameters": {
            "agent_id": {"type": "string", "description": "Agent identifier (e.g. agent-finance-01) or agent name"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_alerts_and_incidents": {
        "description": "Retrieve critical, high, medium, and low security alerts and open incidents.",
        "category": "read",
        "parameters": {
            "severity": {"type": "string", "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, or ALL", "default": "ALL"},
            "limit": {"type": "integer", "description": "Maximum number of items to return", "default": 10}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "search_audit_logs": {
        "description": "Search the SHA-256 cryptographically chained immutable audit ledger.",
        "category": "read",
        "parameters": {
            "query": {"type": "string", "description": "Search term across actor, action, resource, or details"},
            "limit": {"type": "integer", "description": "Number of results to retrieve", "default": 15}
        },
        "allowed_roles": ["admin", "security_analyst", "auditor"]
    },
    "get_incident_details": {
        "description": "Retrieve timeline, root cause, evidence, and response playbook for a specific incident.",
        "category": "read",
        "parameters": {
            "incident_identifier": {"type": "string", "description": "Incident ID (e.g. 1) or incident number (e.g. INC-2026-001)"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "explain_risk_trust_scores": {
        "description": "Explain the calculation and factors contributing to an agent's dynamic risk score and continuous trust score.",
        "category": "read",
        "parameters": {
            "agent_id": {"type": "string", "description": "Target agent ID"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "inspect_permissions": {
        "description": "Inspect configured permissions, baseline instructions, and detect permission drift for an AI agent.",
        "category": "read",
        "parameters": {
            "agent_id": {"type": "string", "description": "Agent identifier"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "review_prompt_injections": {
        "description": "Review recent prompt injection attempts and multimodal heuristic detection signals.",
        "category": "read",
        "parameters": {
            "limit": {"type": "integer", "description": "Number of events to retrieve", "default": 10}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "review_dlp_events": {
        "description": "Review Data Loss Prevention (DLP) alerts, sensitive credential exposure, and exfiltration attempts.",
        "category": "read",
        "parameters": {
            "limit": {"type": "integer", "description": "Number of events to retrieve", "default": 10}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_attack_graph_and_delegations": {
        "description": "Retrieve topological attack graph nodes, delegation relationships, and intervention barriers.",
        "category": "read",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "summarize_sandbox_simulations": {
        "description": "Summarize red-team attack simulation runs and mitigation scorecards.",
        "category": "read",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "get_predictive_risk_report": {
        "description": "Forecast near-future agent risk trends and next-action probabilities.",
        "category": "read",
        "parameters": {
            "agent_id": {"type": "string", "description": "Agent identifier (optional, or overall fleet report)"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "generate_incident_report_draft": {
        "description": "Synthesize a structured forensic incident report draft with timeline, root cause, and remediation steps.",
        "category": "read",
        "parameters": {
            "incident_id": {"type": "string", "description": "Incident identifier or number"}
        },
        "allowed_roles": ["admin", "security_analyst"]
    },
    "navigate_frontend": {
        "description": "Navigate the AgentShield web application interface to a designated view or page.",
        "category": "navigation",
        "parameters": {
            "target_page": {"type": "string", "description": "Destination page name: Overview, Agents, Agent Lab, Approvals, Incidents & Alerts, Prompt Injection, DLP Policy & Events, Canary Tokens, Shadow AI Discovery, Attack Graph, Delegation Graph, Red-Team Simulation, Predictive Risk, Digital Twin Replay, Tool Proxy Gateway, Secret Manager, Behavioral Drift, Policy-as-Code & GitOps, Reverse Engineering, Forensic Dossiers, Cryptographic Audit, Settings & RBAC, JARVIS Assistant"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "prepare_kill_switch": {
        "description": "Prepare emergency kill switch quarantine for an agent (requires human confirmation before execution).",
        "category": "sensitive_action",
        "parameters": {
            "agent_id": {"type": "string", "description": "Agent to suspend/quarantine"},
            "reason": {"type": "string", "description": "Operational reason for kill switch activation"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "prepare_approval_decision": {
        "description": "Prepare decision (APPROVE or REJECT) for a pending human-in-the-loop approval request.",
        "category": "sensitive_action",
        "parameters": {
            "approval_id": {"type": "integer", "description": "ID of approval request"},
            "decision": {"type": "string", "description": "APPROVE or REJECT"},
            "reason": {"type": "string", "description": "Justification for decision"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    }
}

# --- Tool Execution Implementations ---

def execute_get_security_dashboard_metrics(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agents_count = db.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    active_count = db.execute("SELECT COUNT(*) FROM agents WHERE status='ACTIVE'").fetchone()[0]
    events_count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    blocked_count = db.execute("SELECT COUNT(*) FROM events WHERE decision='BLOCK'").fetchone()[0]
    pending_approvals = db.execute("SELECT COUNT(*) FROM approvals WHERE status='PENDING'").fetchone()[0]
    high_risk_count = db.execute("SELECT COUNT(*) FROM events WHERE risk_score >= 70").fetchone()[0]
    open_incidents = db.execute("SELECT COUNT(*) FROM incidents WHERE status != 'RESOLVED'").fetchone()[0]
    canary_trips = db.execute("SELECT COUNT(*) FROM canary_tokens WHERE triggered=1").fetchone()[0]
    shadow_ai_count = db.execute("SELECT COUNT(*) FROM shadow_ai_detections WHERE status='DETECTED'").fetchone()[0]
    
    avg_risk = db.execute("SELECT AVG(risk_score) FROM agents").fetchone()[0] or 15.0
    avg_trust = db.execute("SELECT AVG(trust_score) FROM agents").fetchone()[0] or 88.0

    return {
        "total_agents": agents_count,
        "active_agents": active_count,
        "suspended_or_quarantined": agents_count - active_count,
        "total_events_logged": events_count,
        "blocked_actions": blocked_count,
        "pending_human_approvals": pending_approvals,
        "high_risk_events": high_risk_count,
        "open_incidents": open_incidents,
        "triggered_canaries": canary_trips,
        "shadow_ai_processes": shadow_ai_count,
        "average_fleet_risk_score": round(float(avg_risk), 1),
        "average_fleet_trust_score": round(float(avg_trust), 1),
        "zero_trust_posture": "DEFAULT-DENY ZERO-TRUST ENFORCING",
        "system_status": "ONLINE & PROTECTED"
    }

def execute_list_agents(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    status_filter = params.get("status", "ALL").upper()
    min_risk = int(params.get("min_risk", 0))

    query = "SELECT id, name, model, purpose, status, risk_score, trust_score, permissions, tools, created_at FROM agents WHERE risk_score >= ?"
    args = [min_risk]

    if status_filter != "ALL":
        query += " AND status = ?"
        args.append(status_filter)

    query += " ORDER BY risk_score DESC"
    rows = db.execute(query, tuple(args)).fetchall()

    agents = []
    for r in rows:
        d = dict(r)
        d["permissions"] = json.loads(d["permissions"]) if isinstance(d["permissions"], str) else d["permissions"]
        d["tools"] = json.loads(d["tools"]) if isinstance(d["tools"], str) else d["tools"]
        agents.append(d)

    return {
        "count": len(agents),
        "agents": agents
    }

def execute_get_agent_details(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(params.get("agent_id", "")).strip()
    if not agent_id:
        return {"error": "Missing agent_id"}

    # Search by ID or exact/fuzzy name match
    row = db.execute("SELECT * FROM agents WHERE id = ? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
    if not row:
        return {"error": f"Agent '{agent_id}' was not found in the inventory"}

    agent = dict(row)
    agent["permissions"] = json.loads(agent["permissions"]) if isinstance(agent["permissions"], str) else agent["permissions"]
    agent["baseline_permissions"] = json.loads(agent["baseline_permissions"]) if isinstance(agent["baseline_permissions"], str) else agent["baseline_permissions"]
    agent["tools"] = json.loads(agent["tools"]) if isinstance(agent["tools"], str) else agent["tools"]

    # Fetch recent events for this agent
    recent_events = db.execute("SELECT id, action, target, decision, risk_score, reason, created_at FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 5", (agent["id"],)).fetchall()
    
    # Check for permission drift
    drift = detect_permission_drift(agent["baseline_permissions"], agent["permissions"])

    return {
        "agent": agent,
        "recent_events": [dict(e) for e in recent_events],
        "permission_drift": drift
    }

def execute_get_alerts_and_incidents(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    severity = params.get("severity", "ALL").upper()
    limit = int(params.get("limit", 10))

    inc_query = "SELECT id, incident_number, title, severity, status, agent_id, summary, root_cause, created_at FROM incidents WHERE 1=1"
    inc_args = []
    if severity != "ALL":
        inc_query += " AND severity = ?"
        inc_args.append(severity)
    inc_query += " ORDER BY id DESC LIMIT ?"
    inc_args.append(limit)

    incidents = [dict(r) for r in db.execute(inc_query, tuple(inc_args)).fetchall()]

    # Fetch critical / blocked events
    event_query = "SELECT id, agent_id, action, target, decision, risk_score, reason, created_at FROM events WHERE decision='BLOCK' OR risk_score >= 70 ORDER BY id DESC LIMIT ?"
    critical_events = [dict(r) for r in db.execute(event_query, (limit,)).fetchall()]

    return {
        "open_incidents": incidents,
        "blocked_and_critical_events": critical_events
    }

def execute_search_audit_logs(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    query_str = str(params.get("query", "")).strip()
    limit = int(params.get("limit", 15))

    if query_str:
        pattern = f"%{query_str}%"
        sql = """SELECT id, actor, action, resource, details_json, prev_hash, current_hash, timestamp 
                 FROM audit_log 
                 WHERE actor LIKE ? OR action LIKE ? OR resource LIKE ? OR details_json LIKE ?
                 ORDER BY id DESC LIMIT ?"""
        rows = db.execute(sql, (pattern, pattern, pattern, pattern, limit)).fetchall()
    else:
        sql = """SELECT id, actor, action, resource, details_json, prev_hash, current_hash, timestamp 
                 FROM audit_log ORDER BY id DESC LIMIT ?"""
        rows = db.execute(sql, (limit,)).fetchall()

    results = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d["details_json"]) if isinstance(d["details_json"], str) else d["details_json"]
        results.append(d)

    return {
        "count": len(results),
        "query": query_str,
        "audit_entries": results
    }

def execute_get_incident_details(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    ident = str(params.get("incident_identifier", "")).strip()
    if not ident:
        return {"error": "Missing incident_identifier"}

    row = None
    if ident.isdigit():
        row = db.execute("SELECT * FROM incidents WHERE id=?", (int(ident),)).fetchone()
    if not row:
        row = db.execute("SELECT * FROM incidents WHERE incident_number=? OR incident_number LIKE ?", (ident, f"%{ident}%")).fetchone()

    if not row:
        return {"error": f"Incident '{ident}' was not found"}

    item = dict(row)
    item["evidence"] = json.loads(item["evidence_json"]) if isinstance(item["evidence_json"], str) else item["evidence_json"]

    # Gather audit trail entries related to this incident
    related_audits = db.execute(
        "SELECT id, actor, action, resource, timestamp FROM audit_log WHERE resource LIKE ? ORDER BY id DESC LIMIT 5",
        (f"%incident:{item['id']}%",)
    ).fetchall()

    return {
        "incident": item,
        "related_audit_records": [dict(a) for a in related_audits]
    }

def execute_explain_risk_trust_scores(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(params.get("agent_id", "")).strip()
    if not agent_id:
        return {"error": "Missing agent_id"}

    agent = db.execute("SELECT * FROM agents WHERE id=? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
    if not agent:
        return {"error": f"Agent '{agent_id}' not found"}

    agent_d = dict(agent)
    events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 10", (agent_d["id"],)).fetchall()
    blocked_count = sum(1 for e in events if e["decision"] == "BLOCK")
    canary_count = db.execute("SELECT COUNT(*) FROM canary_tokens WHERE triggered=1").fetchone()[0]

    # Calculate explainable factor breakdown
    risk_factors = []
    if agent_d["status"] == "KILLED":
        risk_factors.append("Agent is currently in KILLED / QUARANTINED state (+100 Risk).")
    if blocked_count > 0:
        risk_factors.append(f"{blocked_count} recent policy block decisions in the last 10 actions (+{blocked_count * 15} Risk).")
    if canary_count > 0:
        risk_factors.append("Canary token tripwire detection detected on platform.")

    trust_factors = []
    if agent_d["trust_score"] < 70:
        trust_factors.append("Trust score decayed due to anomalous tool calls and policy violations.")
    else:
        trust_factors.append("Trust score is maintained through routine authorized actions within policy boundaries.")

    return {
        "agent_id": agent_d["id"],
        "agent_name": agent_d["name"],
        "status": agent_d["status"],
        "risk_score": agent_d["risk_score"],
        "trust_score": agent_d["trust_score"],
        "risk_posture": "CRITICAL" if agent_d["risk_score"] >= 80 else ("HIGH" if agent_d["risk_score"] >= 50 else "NORMAL"),
        "risk_factors": risk_factors or ["Routine behavior within normal operational parameters."],
        "trust_factors": trust_factors
    }

def execute_inspect_permissions(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(params.get("agent_id", "")).strip()
    agent = db.execute("SELECT * FROM agents WHERE id=? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
    if not agent:
        return {"error": f"Agent '{agent_id}' not found"}

    agent_d = dict(agent)
    curr_perms = json.loads(agent_d["permissions"]) if isinstance(agent_d["permissions"], str) else agent_d["permissions"]
    base_perms = json.loads(agent_d["baseline_permissions"]) if isinstance(agent_d["baseline_permissions"], str) else agent_d["baseline_permissions"]
    tools = json.loads(agent_d["tools"]) if isinstance(agent_d["tools"], str) else agent_d["tools"]

    drift = detect_permission_drift(base_perms, curr_perms)

    return {
        "agent_id": agent_d["id"],
        "agent_name": agent_d["name"],
        "current_permissions": curr_perms,
        "baseline_permissions": base_perms,
        "allowed_tools": tools,
        "baseline_instructions": agent_d["baseline_instructions"],
        "current_instructions": agent_d["current_instructions"],
        "permission_drift_detected": drift["has_drift"],
        "drift_summary": drift["summary"],
        "drifted_privileges": drift.get("added_privileges", {})
    }

def execute_review_prompt_injections(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    limit = int(params.get("limit", 10))
    rows = db.execute(
        """SELECT id, agent_id, action, target, decision, risk_score, reason, payload_sanitized, created_at 
           FROM events 
           WHERE reason LIKE '%injection%' OR reason LIKE '%LLM01%' OR reason LIKE '%Reverse Engineering%'
           ORDER BY id DESC LIMIT ?""",
        (limit,)
    ).fetchall()

    return {
        "count": len(rows),
        "injections_and_attacks": [dict(r) for r in rows]
    }

def execute_review_dlp_events(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    limit = int(params.get("limit", 10))
    rows = db.execute(
        """SELECT id, agent_id, action, target, decision, risk_score, reason, payload_sanitized, created_at 
           FROM events 
           WHERE reason LIKE '%DLP%' OR reason LIKE '%sensitive%' OR reason LIKE '%exfiltration%'
           ORDER BY id DESC LIMIT ?""",
        (limit,)
    ).fetchall()

    return {
        "count": len(rows),
        "dlp_events": [dict(r) for r in rows]
    }

def execute_get_attack_graph_and_delegations(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agents = db.execute("SELECT id, name, status, risk_score FROM agents").fetchall()
    events = db.execute("SELECT id, agent_id, action, target, decision, risk_score FROM events ORDER BY id DESC LIMIT 15").fetchall()
    delegations = db.execute("SELECT * FROM agent_delegations ORDER BY id DESC LIMIT 10").fetchall()

    nodes = []
    edges = []
    for a in agents:
        nodes.append({"id": a["id"], "label": a["name"], "type": "agent", "risk": a["risk_score"], "status": a["status"]})

    for e in events:
        target_node_id = f"res_{e['target']}"
        nodes.append({"id": target_node_id, "label": e["target"], "type": "resource", "action": e["action"]})
        edges.append({
            "from": e["agent_id"],
            "to": target_node_id,
            "action": e["action"],
            "decision": e["decision"],
            "risk": e["risk_score"]
        })

    return {
        "nodes_count": len(nodes),
        "edges_count": len(edges),
        "delegations": [dict(d) for d in delegations],
        "attack_path_summary": "Topological map reconstructed from real AgentShield audit and policy gateway events."
    }

def execute_summarize_sandbox_simulations(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    events = db.execute("SELECT * FROM events WHERE reason LIKE '%simulation%' OR reason LIKE '%Red-Team%' ORDER BY id DESC LIMIT 5").fetchall()
    twin_count = db.execute("SELECT COUNT(*) FROM digital_twins").fetchone()[0]
    
    return {
        "digital_twins_active": twin_count,
        "recent_simulation_runs": [dict(e) for e in events],
        "status": "Sandbox Replay and Red-Team Simulation Ready"
    }

def execute_get_predictive_risk_report(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = params.get("agent_id")
    if agent_id:
        agent = db.execute("SELECT * FROM agents WHERE id=? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
        if not agent:
            return {"error": f"Agent '{agent_id}' not found"}
        agent_d = dict(agent)
        pred = predict_near_future_risk(agent_d["id"], agent_d["risk_score"], agent_d["trust_score"])
        return {
            "agent_id": agent_d["id"],
            "name": agent_d["name"],
            "prediction": pred
        }
    else:
        # Fleetwide risk forecast
        agents = db.execute("SELECT id, name, risk_score, trust_score FROM agents ORDER BY risk_score DESC LIMIT 5").fetchall()
        reports = []
        for a in agents:
            p = predict_near_future_risk(a["id"], a["risk_score"], a["trust_score"])
            reports.append({"id": a["id"], "name": a["name"], "prediction": p})
        return {
            "fleet_risk_forecast": reports,
            "overall_posture": "MODERATE_ELEVATED" if any(a["risk_score"] > 60 for a in agents) else "STABLE"
        }

def execute_generate_incident_report_draft(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    inc_ident = str(params.get("incident_id", "")).strip()
    if not inc_ident:
        # Pick the latest open incident
        row = db.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
    elif inc_ident.isdigit():
        row = db.execute("SELECT * FROM incidents WHERE id=?", (int(inc_ident),)).fetchone()
    else:
        row = db.execute("SELECT * FROM incidents WHERE incident_number=? OR incident_number LIKE ?", (inc_ident, f"%{inc_ident}%")).fetchone()

    if not row:
        return {"error": "No incident found to draft a report for."}

    inc = dict(row)
    now = now_iso()
    evidence = json.loads(inc["evidence_json"]) if isinstance(inc["evidence_json"], str) else inc["evidence_json"]

    report_draft = {
        "report_id": f"REP-{inc['incident_number']}",
        "title": f"FORENSIC INVESTIGATION REPORT: {inc['title']}",
        "classification": "CONFIDENTIAL // AGENTSHIELD SOC",
        "generated_at": now,
        "incident_number": inc["incident_number"],
        "severity": inc["severity"],
        "status": inc["status"],
        "involved_agent": inc["agent_id"],
        "executive_summary": inc["summary"],
        "root_cause_analysis": inc.get("root_cause") or "Adversarial input or prompt injection triggering unauthorized tool invocation.",
        "attack_vector": inc.get("attack_vector") or "Direct Prompt Injection / Tool Privilege Escalation",
        "evidence_dossier": evidence,
        "applied_playbook": inc.get("response_playbook") or "Automated Containment & Quarantine",
        "remediation_actions": [
            "1. Quarantined compromised AI agent via Emergency Kill Switch.",
            "2. Revoked active credentials and isolated downstream API connectors.",
            "3. Enforced strict Zero-Trust policy gate on target endpoints.",
            "4. Appended non-repudiable audit event to cryptographic SHA-256 ledger."
        ]
    }
    return report_draft

def execute_navigate_frontend(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    target_page = params.get("target_page", "Overview")
    valid_pages = [
        "Overview", "Real-Time Monitor", "Agents", "Agent Lab", "Approvals",
        "Incidents & Alerts", "Prompt Injection", "DLP Policy & Events",
        "Canary Tokens", "Shadow AI Discovery", "Attack Graph", "Delegation Graph",
        "Red-Team Simulation", "Predictive Risk", "Digital Twin Replay",
        "Tool Proxy Gateway", "Secret Manager", "Behavioral Drift",
        "Policy-as-Code & GitOps", "Reverse Engineering", "Forensic Dossiers",
        "Cryptographic Audit", "Settings & RBAC", "JARVIS Assistant"
    ]
    matched = None
    for vp in valid_pages:
        if vp.lower() == target_page.lower() or target_page.lower() in vp.lower():
            matched = vp
            break

    if not matched:
        matched = "Overview"

    return {
        "status": "NAVIGATING",
        "target_page": matched,
        "message": f"Navigating to '{matched}' page."
    }

def execute_prepare_kill_switch(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(params.get("agent_id", "")).strip()
    reason = params.get("reason", "Operator activated emergency quarantine via JARVIS")
    agent = db.execute("SELECT * FROM agents WHERE id=? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
    if not agent:
        return {"error": f"Agent '{agent_id}' not found"}

    agent_d = dict(agent)
    action_id = f"act-{uuid.uuid4().hex[:12]}"
    idempotency_key = f"idemp-kill-{agent_d['id']}-{int(datetime.now(timezone.utc).timestamp())}"

    explanation = (
        f"You have requested to ACTIVATE THE EMERGENCY KILL SWITCH for {agent_d['name']} ({agent_d['id']}). "
        f"This action will immediately set status to KILLED, set Risk Score to 100, revoke all tool access tokens, "
        f"and log a CRITICAL incident in the audit ledger. Confirmation is required."
    )

    return {
        "requires_confirmation": True,
        "action_id": action_id,
        "action_type": "KILL_SWITCH",
        "target_id": agent_d["id"],
        "target_name": agent_d["name"],
        "risk_level": "CRITICAL",
        "impact_explanation": explanation,
        "idempotency_key": idempotency_key,
        "reason": reason
    }

def execute_prepare_approval_decision(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    approval_id = params.get("approval_id")
    decision = str(params.get("decision", "APPROVE")).upper()
    reason = params.get("reason", "Decided via JARVIS Assistant")

    approval = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    if not approval:
        return {"error": f"Approval request #{approval_id} not found"}

    action_id = f"act-{uuid.uuid4().hex[:12]}"
    idempotency_key = f"idemp-appr-{approval_id}-{decision}-{int(datetime.now(timezone.utc).timestamp())}"
    
    explanation = (
        f"Confirm decision to {decision} approval request #{approval_id} for agent {approval['agent_id']} "
        f"attempting action '{approval['action']}' on target '{approval['target']}'."
    )

    return {
        "requires_confirmation": True,
        "action_id": action_id,
        "action_type": "APPROVE_REQUEST" if decision == "APPROVE" else "REJECT_REQUEST",
        "target_id": str(approval_id),
        "target_name": f"Approval #{approval_id} ({approval['action']})",
        "risk_level": "HIGH" if decision == "APPROVE" else "MEDIUM",
        "impact_explanation": explanation,
        "idempotency_key": idempotency_key,
        "decision": decision,
        "reason": reason
    }

# Mapping of tool names to their execution functions
TOOL_HANDLERS = {
    "get_security_dashboard_metrics": execute_get_security_dashboard_metrics,
    "list_agents": execute_list_agents,
    "get_agent_details": execute_get_agent_details,
    "get_alerts_and_incidents": execute_get_alerts_and_incidents,
    "search_audit_logs": execute_search_audit_logs,
    "get_incident_details": execute_get_incident_details,
    "explain_risk_trust_scores": execute_explain_risk_trust_scores,
    "inspect_permissions": execute_inspect_permissions,
    "review_prompt_injections": execute_review_prompt_injections,
    "review_dlp_events": execute_review_dlp_events,
    "get_attack_graph_and_delegations": execute_get_attack_graph_and_delegations,
    "summarize_sandbox_simulations": execute_summarize_sandbox_simulations,
    "get_predictive_risk_report": execute_get_predictive_risk_report,
    "generate_incident_report_draft": execute_generate_incident_report_draft,
    "navigate_frontend": execute_navigate_frontend,
    "prepare_kill_switch": execute_prepare_kill_switch,
    "prepare_approval_decision": execute_prepare_approval_decision
}

def dispatch_tool(tool_name: str, arguments: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatches tool execution safely with error handling and real DB connection."""
    handler = TOOL_HANDLERS.get(tool_name)
    if not handler:
        return {"error": f"Tool '{tool_name}' is not registered or supported"}

    with connect() as db:
        try:
            result = handler(db, arguments)
            return result
        except Exception as e:
            return {"error": f"Execution error in tool '{tool_name}': {str(e)}"}
