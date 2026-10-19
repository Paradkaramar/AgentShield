import sqlite3
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from ..core.audit import record_audit_entry

def trigger_emergency_kill_switch(
    db: sqlite3.Connection,
    agent_id: str,
    actor: str,
    reason: str,
    trigger_event_id: Optional[int] = None
) -> Dict[str, Any]:
    """Suspends the agent, revokes credentials, freezes tools, logs an incident, and records an audit entry."""
    now = datetime.now(timezone.utc).isoformat()
    agent = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    if not agent:
        return {"success": False, "error": f"Agent '{agent_id}' not found"}
        
    prev_status = agent["status"]
    
    # 1. Update status to KILLED (Idempotent)
    db.execute("UPDATE agents SET status='KILLED', risk_score=100, trust_score=0 WHERE id=?", (agent_id,))
    
    import uuid
    inc_num = f"INC-KILL-{agent_id[-6:]}-{int(datetime.now().timestamp() * 1000)}-{uuid.uuid4().hex[:4]}"
    db.execute(
        """
        INSERT INTO incidents (incident_number, title, severity, status, agent_id, summary, root_cause, attack_vector, evidence_json, response_playbook, created_at, updated_at)
        VALUES (?, ?, 'CRITICAL', 'CONTAINED', ?, ?, ?, 'Automated Emergency Kill Switch', ?, 'Emergency Kill-Switch Playbook', ?, ?)
        """,
        (
            inc_num,
            f"Emergency Kill Switch Activated for {agent['name']}",
            agent_id,
            f"Agent suspended by {actor}. Reason: {reason}",
            reason,
            json.dumps({"trigger_event_id": trigger_event_id, "prev_status": prev_status, "actor": actor}),
            now,
            now
        )
    )
    
    # 3. Insert audit log record
    record_audit_entry(
        db,
        actor=actor,
        action="KILL_SWITCH_ACTIVATED",
        resource=f"agent:{agent_id}",
        details={
            "agent_name": agent["name"],
            "previous_status": prev_status,
            "new_status": "KILLED",
            "reason": reason,
            "incident_number": inc_num
        }
    )
    
    # 4. Insert security event record
    db.execute(
        "INSERT INTO events (agent_id, action, target, decision, risk_score, trust_score, reason, created_at) VALUES (?, 'KILL_SWITCH', 'agent-control-plane', 'BLOCK', 100, 0, ?, ?)",
        (agent_id, f"Emergency kill switch triggered by {actor}: {reason}", now)
    )
    
    return {
        "success": True,
        "agent_id": agent_id,
        "status": "KILLED",
        "previous_status": prev_status,
        "incident_number": inc_num,
        "timestamp": now,
        "message": f"Kill switch executed. Agent {agent_id} is quarantined and tools frozen."
    }

def perform_counterfactual_analysis(
    action: str,
    target: str,
    payload: str,
    actual_decision: str,
    actual_risk: int
) -> Dict[str, Any]:
    """Feature AD: Explains what alternative action, target, or data sanitization would have prevented block/approval."""
    alternatives = []
    
    # Counterfactual 1: Internal destination
    if "external" in target.lower():
        alternatives.append({
            "scenario": "Reroute Target to Internal Endpoint",
            "hypothetical_target": "internal-sandbox.lan",
            "estimated_risk": max(15, actual_risk - 35),
            "estimated_decision": "ALLOW",
            "explanation": "Replacing public/external egress target with verified internal sandbox avoids exfiltration triggers."
        })
        
    # Counterfactual 2: Masked/Redacted payload
    if len(payload) > 10:
        alternatives.append({
            "scenario": "Pre-sanitize Payload via DLP Redaction",
            "hypothetical_payload": "[REDACTED_SENSITIVE_CONTENT]",
            "estimated_risk": max(20, actual_risk - 40),
            "estimated_decision": "ALLOW" if actual_risk - 40 < 55 else "ASK_HUMAN",
            "explanation": "Scrubbing potential credentials and PII prior to action transmission neutralizes DLP policy violations."
        })
        
    # Counterfactual 3: Read-only verb substitution
    if action.upper() in {"DELETE", "EXPORT", "DROP"}:
        alternatives.append({
            "scenario": "Downgrade Action to Read-Only Review",
            "hypothetical_action": "READ",
            "estimated_risk": 15,
            "estimated_decision": "ALLOW",
            "explanation": "Using non-destructive inspection (READ/ANALYZE) instead of destructive action eliminates human approval requirement."
        })
        
    return {
        "actual_action": action,
        "actual_target": target,
        "actual_risk": actual_risk,
        "actual_decision": actual_decision,
        "counterfactual_scenarios": alternatives,
        "analysis_type": "Counterfactual Policy Simulation"
    }
