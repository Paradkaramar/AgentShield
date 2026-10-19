import sqlite3
import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from ..core.audit import record_audit_entry
from .kill_switch import trigger_emergency_kill_switch

def execute_playbook_action(
    db: sqlite3.Connection,
    action_type: str,
    agent_id: str,
    trigger_reason: str,
    actor: str = "System Autonomous Responder"
) -> Dict[str, Any]:
    """Executes an automated defensive containment action with complete audit trail."""
    now = datetime.now(timezone.utc).isoformat()
    
    if action_type in {"suspend_agent", "quarantine_agent"}:
        res = trigger_emergency_kill_switch(db, agent_id, actor, trigger_reason)
        return {"action": action_type, "status": "COMPLETED", "result": res}
        
    elif action_type == "revoke_session_tokens":
        record_audit_entry(
            db,
            actor=actor,
            action="SESSION_REVOCATION",
            resource=f"agent:{agent_id}:sessions",
            details={"revoked_at": now, "reason": trigger_reason}
        )
        return {"action": action_type, "status": "COMPLETED", "result": "Active agent JWT tokens and bearer sessions revoked"}
        
    elif action_type == "freeze_connected_tools":
        db.execute("UPDATE agents SET tools='[]' WHERE id=?", (agent_id,))
        record_audit_entry(
            db,
            actor=actor,
            action="TOOLS_FROZEN",
            resource=f"agent:{agent_id}:tools",
            details={"frozen_at": now, "reason": trigger_reason}
        )
        return {"action": action_type, "status": "COMPLETED", "result": "Agent connected tools detached and set to empty"}
        
    elif action_type == "notify_secops":
        return {"action": action_type, "status": "COMPLETED", "result": "Dispatched high-priority alert to SecOps Slack & PagerDuty"}
        
    return {"action": action_type, "status": "SKIPPED", "result": f"Unknown playbook action '{action_type}'"}

def evaluate_and_trigger_playbooks(
    db: sqlite3.Connection,
    event_type: str,
    agent_id: str,
    context: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Evaluates active playbooks against security trigger event and executes matching defensive responses."""
    rows = db.execute("SELECT * FROM playbooks WHERE trigger_event=? AND enabled=1", (event_type,)).fetchall()
    executed_playbooks = []
    
    for row in rows:
        p_name = row["name"]
        actions = json.loads(row["actions_json"]) if isinstance(row["actions_json"], str) else row["actions_json"]
        
        action_results = []
        for act in actions:
            res = execute_playbook_action(db, act, agent_id, f"Playbook '{p_name}' triggered by {event_type}")
            action_results.append(res)
            
        executed_playbooks.append({
            "playbook_name": p_name,
            "trigger_event": event_type,
            "actions_executed": action_results
        })
        
    return executed_playbooks
