from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
import json
from ..db.database import connect
from ..engines.reverse_engineering import (
    reconstruct_behavior_timeline,
    analyze_system_prompt_drift,
    reverse_engineer_payload,
    generate_forensic_report_data
)

router = APIRouter(prefix="/api/forensics", tags=["Reverse Engineering & Forensics"])

@router.get("/timeline/{agent_id}")
def get_timeline(agent_id: str):
    with connect() as db:
        events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id ASC LIMIT 50", (agent_id,)).fetchall()
        return reconstruct_behavior_timeline([dict(e) for e in events])

@router.post("/payload-analysis")
def analyze_payload(body: Dict[str, str]):
    payload = body.get("payload", "")
    return reverse_engineer_payload(payload)

@router.post("/prompt-diff")
def diff_prompt(body: Dict[str, str]):
    baseline = body.get("baseline", "")
    current = body.get("current", "")
    return analyze_system_prompt_drift(baseline, current)

@router.get("/report/{incident_id}")
def get_forensic_report(incident_id: int):
    with connect() as db:
        inc = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        agent = db.execute("SELECT * FROM agents WHERE id=?", (inc["agent_id"],)).fetchone()
        events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id ASC LIMIT 30", (inc["agent_id"],)).fetchall()
        
    report = generate_forensic_report_data(dict(inc), dict(agent) if agent else {"id": inc["agent_id"]}, [dict(e) for e in events])
    return report
