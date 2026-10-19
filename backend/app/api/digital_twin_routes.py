from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
import json
from ..db.database import connect
from ..schemas import ReplayRequest
from ..engines.digital_twin import create_agent_twin_snapshot, replay_sandbox_session

router = APIRouter(prefix="/api/digital-twin", tags=["Digital Twin & Sandbox Replay"])

@router.get("/{agent_id}")
def get_digital_twin(agent_id: str):
    with connect() as db:
        agent = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        recent_events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 15", (agent_id,)).fetchall()
        snapshot = create_agent_twin_snapshot(dict(agent), [dict(e) for e in recent_events])
        return snapshot

@router.post("/replay")
def replay_session(body: ReplayRequest):
    with connect() as db:
        agent = db.execute("SELECT * FROM agents WHERE id=?", (body.agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        recent_events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 15", (body.agent_id,)).fetchall()
        snapshot = create_agent_twin_snapshot(dict(agent), [dict(e) for e in recent_events])
        
    replay_report = replay_sandbox_session(snapshot, alternative_policy_mode=body.alternative_policy_mode)
    return replay_report
