import json
from datetime import datetime, timezone
from typing import Dict, Any, List

def create_agent_twin_snapshot(agent: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates an immutable digital twin snapshot capturing agent state, permissions, and recent traces."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "agent_id": agent["id"],
        "version": agent.get("version", "1.0.0"),
        "snapshot_timestamp": now,
        "configuration": {
            "name": agent["name"],
            "model": agent["model"],
            "purpose": agent["purpose"],
            "tools": json.loads(agent["tools"]) if isinstance(agent["tools"], str) else agent["tools"],
            "permissions": json.loads(agent["permissions"]) if isinstance(agent["permissions"], str) else agent["permissions"],
            "status": agent["status"],
            "risk_score": agent["risk_score"],
            "trust_score": agent.get("trust_score", 90)
        },
        "recorded_trace_count": len(recent_events),
        "recent_traces": [
            {
                "action": e.get("action"),
                "target": e.get("target"),
                "decision": e.get("decision"),
                "risk_score": e.get("risk_score"),
                "timestamp": e.get("created_at")
            }
            for e in recent_events[-10:]
        ]
    }

def replay_sandbox_session(
    snapshot: Dict[str, Any],
    alternative_policy_mode: str = "STRICT"
) -> Dict[str, Any]:
    """Replays recorded session traces in an isolated sandbox against alternative policy configurations."""
    traces = snapshot.get("recent_traces", [])
    replay_results = []
    differences = 0
    
    for trace in traces:
        action = trace.get("action", "")
        target = trace.get("target", "")
        original_decision = trace.get("decision", "ALLOW")
        
        # In STRICT mode, any sensitive action requires approval or is blocked
        if alternative_policy_mode == "STRICT":
            if action in {"EXPORT", "DELETE", "DROP"}:
                simulated_decision = "BLOCK"
            elif action in {"WRITE", "SEND"}:
                simulated_decision = "ASK_HUMAN"
            else:
                simulated_decision = "ALLOW"
        elif alternative_policy_mode == "PERMISSIVE":
            simulated_decision = "ALLOW"
        else:
            simulated_decision = original_decision
            
        changed = simulated_decision != original_decision
        if changed:
            differences += 1
            
        replay_results.append({
            "action": action,
            "target": target,
            "original_decision": original_decision,
            "simulated_decision": simulated_decision,
            "policy_outcome_diverged": changed
        })
        
    return {
        "agent_id": snapshot.get("agent_id"),
        "total_traces_replayed": len(traces),
        "policy_divergences": differences,
        "mode": alternative_policy_mode,
        "results": replay_results,
        "conclusion": f"Sandbox replay completed: {differences} out of {len(traces)} action outcomes differed under {alternative_policy_mode} policy rules."
    }
