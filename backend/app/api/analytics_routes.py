from fastapi import APIRouter
from typing import Dict, Any, List
import json
from ..db.database import connect
from ..engines.risk_engine import forecast_next_actions, predict_near_future_risk

router = APIRouter(prefix="/api", tags=["SOC Analytics & Graph Engines"])

@router.get("/overview")
def get_soc_overview():
    with connect() as db:
        agents = db.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
        active = db.execute("SELECT COUNT(*) FROM agents WHERE status='ACTIVE'").fetchone()[0]
        events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        blocked = db.execute("SELECT COUNT(*) FROM events WHERE decision='BLOCK'").fetchone()[0]
        pending = db.execute("SELECT COUNT(*) FROM approvals WHERE status='PENDING'").fetchone()[0]
        high = db.execute("SELECT COUNT(*) FROM events WHERE risk_score >= 70").fetchone()[0]
        incidents = db.execute("SELECT COUNT(*) FROM incidents WHERE status != 'RESOLVED'").fetchone()[0]
        canary_trips = db.execute("SELECT COUNT(*) FROM canary_tokens WHERE triggered=1").fetchone()[0]
        shadow_ai = db.execute("SELECT COUNT(*) FROM shadow_ai_detections WHERE status='DETECTED'").fetchone()[0]
        
    return {
        "total_agents": agents,
        "active_agents": active,
        "total_events": events,
        "blocked_actions": blocked,
        "pending_approvals": pending,
        "high_risk_events": high,
        "open_incidents": incidents,
        "canary_trips": canary_trips,
        "shadow_ai_count": shadow_ai,
        "system_status": "ONLINE",
        "zero_trust_enforcement": "ACTIVE"
    }

@router.get("/analytics/risk-trends")
def get_risk_trends():
    with connect() as db:
        rows = db.execute("SELECT id, risk_score, trust_score, created_at FROM events ORDER BY id DESC LIMIT 30").fetchall()
        points = [{"id": r["id"], "risk": r["risk_score"], "trust": r["trust_score"], "time": r["created_at"]} for r in reversed(rows)]
        return {
            "history": points,
            "current_avg_risk": int(sum(p["risk"] for p in points) / len(points)) if points else 15,
            "current_avg_trust": int(sum(p["trust"] for p in points) / len(points)) if points else 92
        }

@router.get("/analytics/attack-graph")
def get_attack_graph():
    """Feature O: Returns graph nodes and directed edges illustrating prompts, agents, tools, destinations, and blocked intervention points."""
    with connect() as db:
        agents = db.execute("SELECT id, name, status, risk_score FROM agents").fetchall()
        events = db.execute("SELECT id, agent_id, action, target, decision, risk_score FROM events ORDER BY id DESC LIMIT 15").fetchall()
        
    nodes = []
    edges = []
    
    # Add agent nodes
    for a in agents:
        nodes.append({
            "id": a["id"],
            "label": a["name"],
            "type": "agent",
            "status": a["status"],
            "risk": a["risk_score"]
        })
        
    # Add target resource nodes and action edges
    added_targets = set()
    for ev in events:
        tgt_id = f"target-{abs(hash(ev['target'])) % 1000}"
        if tgt_id not in added_targets:
            nodes.append({
                "id": tgt_id,
                "label": ev["target"],
                "type": "resource" if "internal" in ev["target"] or "db" in ev["target"] else "destination",
                "risk": ev["risk_score"]
            })
            added_targets.add(tgt_id)
            
        edges.append({
            "source": ev["agent_id"],
            "target": tgt_id,
            "action": ev["action"],
            "decision": ev["decision"],
            "is_blocked": ev["decision"] == "BLOCK",
            "risk": ev["risk_score"]
        })
        
    return {
        "nodes": nodes,
        "edges": edges,
        "intervention_summary": "Policy Enforcement Gateway operates at edge between Agent and Target Resource."
    }

@router.get("/analytics/delegation-graph")
def get_delegation_graph():
    """Feature Z: Visualizes cross-agent trust boundaries and permitted task delegation paths."""
    with connect() as db:
        agents = db.execute("SELECT id, name, trust_score, tools FROM agents").fetchall()
        
    nodes = [
        {
            "id": a["id"],
            "label": a["name"],
            "trust": a["trust_score"],
            "tools_count": len(json.loads(a["tools"])) if isinstance(a["tools"], str) else len(a["tools"])
        }
        for a in agents
    ]
    
    # Default registered delegation edges between seeded agents
    edges = []
    if len(agents) >= 2:
        edges.append({
            "source": "agent-finance-01",
            "target": "agent-research-01",
            "relationship": "TASK_DELEGATION",
            "trust_decay": 0.15,
            "authorized": True
        })
    if len(agents) >= 3:
        edges.append({
            "source": "agent-support-01",
            "target": "agent-finance-01",
            "relationship": "QUERY_INVOICE",
            "trust_decay": 0.15,
            "authorized": True
        })
        
    return {
        "nodes": nodes,
        "edges": edges,
        "decay_policy": "15% linear trust decay per delegation hop"
    }

@router.get("/analytics/forecast/{agent_id}")
def get_agent_forecast(agent_id: str):
    with connect() as db:
        agent = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 15", (agent_id,)).fetchall()
        
    curr_risk = agent["risk_score"] if agent else 15
    tools = json.loads(agent["tools"]) if agent and isinstance(agent["tools"], str) else []
    
    risk_prediction = predict_near_future_risk([dict(e) for e in events], curr_risk)
    next_actions = forecast_next_actions(agent_id, [dict(e) for e in events], tools)
    
    return {
        "agent_id": agent_id,
        "predictive_risk": risk_prediction,
        "forecasted_actions": next_actions
    }
