from fastapi import APIRouter, HTTPException, Depends, status
from typing import Dict, Any, List
import json
import uuid
from ..core.auth import get_current_user, require_roles
from ..core.audit import record_audit_entry
from ..db.database import connect, now_iso
from ..schemas import AgentCreate, AgentUpdate, AgentStatus
from ..engines.kill_switch import trigger_emergency_kill_switch
from ..engines.policy_engine import detect_permission_drift
from ..engines.reverse_engineering import analyze_system_prompt_drift

router = APIRouter(prefix="/api/agents", tags=["AI Agent Identity Management"])

@router.get("")
def list_agents():
    with connect() as db:
        rows = db.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["tools"] = json.loads(item["tools"]) if isinstance(item["tools"], str) else item["tools"]
            item["permissions"] = json.loads(item["permissions"]) if isinstance(item["permissions"], str) else item["permissions"]
            result.append(item)
        return result

@router.post("", status_code=201)
def create_agent(body: AgentCreate, current_user: Dict[str, Any] = Depends(get_current_user)):
    agent_id = "agent-" + uuid.uuid4().hex[:10]
    now = now_iso()
    
    default_perms = body.permissions or {
        "read": ["internal:*"],
        "write": ["internal:sandbox"],
        "delete": [],
        "export": [],
        "execute": []
    }
    instructions = body.baseline_instructions or f"You are {body.name}. Adhere strictly to authorized tools and safety boundaries."
    
    with connect() as db:
        db.execute(
            """INSERT INTO agents (
                id, name, owner, org_id, model, purpose, tools, permissions,
                baseline_permissions, status, risk_score, trust_score,
                baseline_instructions, current_instructions, last_activity, version, created_at
            ) VALUES (?, ?, ?, 'org-default', ?, ?, ?, ?, ?, 'ACTIVE', 10, 95, ?, ?, ?, '1.0.0', ?)""",
            (
                agent_id, body.name, body.owner, body.model, body.purpose,
                json.dumps(body.tools), json.dumps(default_perms), json.dumps(default_perms),
                instructions, instructions, now, now
            )
        )
        
        # Initialize behavioral baseline
        db.execute(
            "INSERT INTO behavior_baselines (agent_id, allowed_call_rate, typical_tools_json, avg_payload_size, approved_destinations_json, drift_score, updated_at) VALUES (?, 30, ?, 512, '[]', 0.05, ?)",
            (agent_id, json.dumps(body.tools), now)
        )
        
        record_audit_entry(
            db,
            actor=current_user.get("username", "admin"),
            action="AGENT_REGISTERED",
            resource=f"agent:{agent_id}",
            details={"name": body.name, "model": body.model, "owner": body.owner}
        )
        
    return {"id": agent_id, "name": body.name, "message": "Agent registered successfully"}

@router.get("/{agent_id}")
def get_agent_detail(agent_id: str):
    with connect() as db:
        agent = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        item = dict(agent)
        item["tools"] = json.loads(item["tools"]) if isinstance(item["tools"], str) else item["tools"]
        item["permissions"] = json.loads(item["permissions"]) if isinstance(item["permissions"], str) else item["permissions"]
        item["baseline_permissions"] = json.loads(item["baseline_permissions"]) if isinstance(item["baseline_permissions"], str) else item["baseline_permissions"]
        
        recent_events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 15", (agent_id,)).fetchall()
        item["recent_events"] = [dict(e) for e in recent_events]
        
        return item

@router.patch("/{agent_id}")
def update_agent(agent_id: str, body: AgentUpdate, current_user: Dict[str, Any] = Depends(get_current_user)):
    with connect() as db:
        agent = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        updates = []
        params = []
        if body.name is not None:
            updates.append("name=?"); params.append(body.name)
        if body.owner is not None:
            updates.append("owner=?"); params.append(body.owner)
        if body.model is not None:
            updates.append("model=?"); params.append(body.model)
        if body.purpose is not None:
            updates.append("purpose=?"); params.append(body.purpose)
        if body.tools is not None:
            updates.append("tools=?"); params.append(json.dumps(body.tools))
        if body.permissions is not None:
            updates.append("permissions=?"); params.append(json.dumps(body.permissions))
        if body.current_instructions is not None:
            updates.append("current_instructions=?"); params.append(body.current_instructions)
            
        if updates:
            params.append(agent_id)
            db.execute(f"UPDATE agents SET {', '.join(updates)} WHERE id=?", tuple(params))
            
            record_audit_entry(
                db,
                actor=current_user.get("username", "admin"),
                action="AGENT_UPDATED",
                resource=f"agent:{agent_id}",
                details={"updated_fields": [u.split("=")[0] for u in updates]}
            )
            
    return {"message": "Agent updated successfully"}

@router.patch("/{agent_id}/status")
def update_agent_status(agent_id: str, body: AgentStatus, current_user: Dict[str, Any] = Depends(get_current_user)):
    status_u = body.status.upper()
    if status_u not in {"ACTIVE", "DISABLED", "KILLED", "QUARANTINED"}:
        raise HTTPException(400, "status must be ACTIVE, DISABLED, KILLED, or QUARANTINED")
        
    with connect() as db:
        if status_u == "KILLED":
            return trigger_emergency_kill_switch(db, agent_id, current_user.get("username", "admin"), "Manual status change to KILLED")
            
        cur = db.execute("UPDATE agents SET status=? WHERE id=?", (status_u, agent_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Agent not found")
            
        now = now_iso()
        db.execute(
            "INSERT INTO events (agent_id, action, target, decision, risk_score, trust_score, reason, created_at) VALUES (?, 'STATUS_CHANGE', 'agent-control-plane', ?, 15, 90, ?, ?)",
            (agent_id, "ALLOW" if status_u == "ACTIVE" else "BLOCK", f"Agent status changed to {status_u}", now)
        )
        
        record_audit_entry(
            db,
            actor=current_user.get("username", "admin"),
            action="AGENT_STATUS_CHANGE",
            resource=f"agent:{agent_id}",
            details={"new_status": status_u}
        )
        
    return {"message": f"Agent status set to {status_u}", "status": status_u}

@router.post("/{agent_id}/kill")
def kill_agent(agent_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    with connect() as db:
        res = trigger_emergency_kill_switch(db, agent_id, current_user.get("username", "admin"), "Emergency kill switch invoked via API/Dashboard")
        if not res.get("success"):
            raise HTTPException(404, detail=res.get("error"))
        return res

@router.delete("/{agent_id}")
def delete_agent(agent_id: str, current_user: Dict[str, Any] = Depends(require_roles(["admin"]))):
    with connect() as db:
        cur = db.execute("DELETE FROM agents WHERE id=?", (agent_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Agent not found")
            
        record_audit_entry(
            db,
            actor=current_user.get("username", "admin"),
            action="AGENT_DELETED",
            resource=f"agent:{agent_id}",
            details={"deleted_by": current_user.get("username")}
        )
    return {"message": f"Agent {agent_id} registration safely removed"}

@router.get("/{agent_id}/drift")
def check_agent_drift(agent_id: str):
    with connect() as db:
        agent = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(404, "Agent not found")
            
        curr_perms = json.loads(agent["permissions"]) if isinstance(agent["permissions"], str) else agent["permissions"]
        base_perms = json.loads(agent["baseline_permissions"]) if isinstance(agent["baseline_permissions"], str) else agent["baseline_permissions"]
        
        perm_drift = detect_permission_drift(curr_perms, base_perms)
        prompt_drift = analyze_system_prompt_drift(agent["baseline_instructions"], agent["current_instructions"])
        
        return {
            "agent_id": agent_id,
            "permission_drift": perm_drift,
            "system_prompt_drift": prompt_drift
        }
