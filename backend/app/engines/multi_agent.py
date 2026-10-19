from typing import Dict, Any, List, Tuple

def verify_agent_delegation(
    source_agent: Dict[str, Any],
    target_agent: Dict[str, Any],
    task_intent: str,
    hop_count: int = 1,
    existing_delegations: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Feature P & Z: Validates cross-agent delegation, enforces trust boundaries, and calculates hop decay."""
    source_id = source_agent["id"]
    target_id = target_agent["id"]
    
    # 1. Self-delegation check
    if source_id == target_id:
        return {
            "authorized": False,
            "status": "BLOCKED",
            "reason": "Circular delegation: Agent cannot delegate to itself",
            "effective_trust": 0
        }
        
    # 2. Status verification
    if source_agent.get("status") != "ACTIVE" or target_agent.get("status") != "ACTIVE":
        return {
            "authorized": False,
            "status": "BLOCKED",
            "reason": "One or both agents in delegation chain are not active",
            "effective_trust": 0
        }
        
    # 3. Hop decay calculation: Trust decays by 15% per hop
    source_trust = source_agent.get("trust_score", 90)
    decay_rate = 0.15
    effective_trust = int(source_trust * ((1.0 - decay_rate) ** hop_count))
    
    # 4. Privilege jump detection: If target agent has higher sensitivity tools than source
    source_tools = set(source_agent.get("tools", []))
    target_tools = set(target_agent.get("tools", []))
    
    privilege_jump = False
    critical_tools = {"tool-db", "tool-crm", "tool-shell"}
    if not (source_tools & critical_tools) and (target_tools & critical_tools):
        privilege_jump = True
        
    if privilege_jump and hop_count > 1:
        return {
            "authorized": False,
            "status": "BLOCKED",
            "reason": f"Privilege escalation detected: Unprivileged agent {source_id} delegating to privileged agent {target_id} across multiple hops",
            "effective_trust": effective_trust,
            "privilege_jump": True
        }
        
    status = "AUTHORIZED" if effective_trust >= 50 else "FLAGGED"
    return {
        "authorized": status == "AUTHORIZED",
        "status": status,
        "effective_trust": effective_trust,
        "privilege_jump": privilege_jump,
        "reason": f"Delegation verified: hop {hop_count}, effective trust {effective_trust}/100"
    }

def correlate_cross_agent_attacks(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Feature W: Correlates events across agents sharing resources, destinations, or attack patterns."""
    correlated_incidents = []
    
    # Group by shared targets or shared external domains within event window
    dest_map = {}
    for ev in events:
        target = ev.get("target", "").lower()
        if "external" in target or "http" in target or "database" in target:
            dest_map.setdefault(target, []).append(ev)
            
    for target, ev_list in dest_map.items():
        distinct_agents = set(e.get("agent_id") for e in ev_list)
        if len(distinct_agents) >= 2:
            correlated_incidents.append({
                "correlation_id": f"CORR-{abs(hash(target)) % 10000}",
                "pattern": "Coordinated Multi-Agent Target Access",
                "shared_resource": target,
                "involved_agents": list(distinct_agents),
                "event_count": len(ev_list),
                "severity": "HIGH",
                "recommendation": "Review shared target egress rules and potential coordinated prompt-injection campaign"
            })
            
    return correlated_incidents
