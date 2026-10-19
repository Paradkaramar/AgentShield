from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
import uuid
import json
from ..db.database import connect, now_iso
from ..core.auth import get_current_user
from ..core.audit import record_audit_entry
from ..engines.shadow_ai import analyze_telemetry_for_shadow_ai

router = APIRouter(prefix="/api/shadow-ai", tags=["Shadow AI & Telemetry Discovery"])

@router.get("")
def list_shadow_ai():
    with connect() as db:
        rows = db.execute("SELECT * FROM shadow_ai_detections ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

@router.post("/scan")
def trigger_telemetry_scan(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Simulates active process and network egress telemetry ingestion to identify rogue AI agents."""
    sample_network_flows = [
        {"destination": "api.openai.com:443", "process": "local_scraper_script.py", "auth_header_prefix": "Bearer sk-991...", "headers": {}},
        {"destination": "api.anthropic.com:443", "process": "research_pipeline.py", "auth_header_prefix": "Bearer sk-ant-321...", "headers": {}}
    ]
    sample_processes = [
        {"name": "autogen_coordinator.exe", "command_line": "python autogen_task.py --agents 3", "pid": 4812, "is_registered": False}
    ]
    
    findings = analyze_telemetry_for_shadow_ai(sample_network_flows, sample_processes)
    now = now_iso()
    
    with connect() as db:
        for f in findings:
            # Check if already present
            existing = db.execute("SELECT id FROM shadow_ai_detections WHERE process_name=? AND destination_ip_host=?", (f["process_name"], f["destination_ip_host"])).fetchone()
            if not existing:
                db.execute(
                    """INSERT INTO shadow_ai_detections (process_name, destination_ip_host, token_signature, confidence, evidence, status, detected_at)
                       VALUES (?, ?, ?, ?, ?, 'DETECTED', ?)""",
                    (f["process_name"], f["destination_ip_host"], f["token_signature"], f["confidence"], f["evidence"], now)
                )
                
    return {
        "scan_status": "COMPLETED",
        "new_detections": len(findings),
        "findings": findings
    }

@router.post("/{detection_id}/register")
def register_shadow_ai(detection_id: int, current_user: Dict[str, Any] = Depends(get_current_user)):
    with connect() as db:
        row = db.execute("SELECT * FROM shadow_ai_detections WHERE id=?", (detection_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Detection record not found")
            
        new_agent_id = "agent-discovered-" + uuid.uuid4().hex[:8]
        now = now_iso()
        name = f"Discovered-{row['process_name'].replace('.exe', '').replace('.py', '')}"
        
        # Create registered agent
        db.execute(
            """INSERT INTO agents (
                id, name, owner, org_id, model, purpose, tools, permissions,
                baseline_permissions, status, risk_score, trust_score,
                baseline_instructions, current_instructions, last_activity, version, created_at
            ) VALUES (?, ?, 'Discovered Via Telemetry', 'org-default', 'External Discovered Model', 'Imported from Shadow AI Discovery',
                      '[\"tool-browser\"]', '{\"read\": [\"*\"], \"write\": [], \"delete\": [], \"export\": [], \"execute\": []}',
                      '{\"read\": [\"*\"], \"write\": [], \"delete\": [], \"export\": [], \"execute\": []}',
                      'ACTIVE', 35, 75, 'Discovered agent brought into control plane.', 'Discovered agent brought into control plane.', ?, '1.0.0', ?)""",
            (new_agent_id, name, now, now)
        )
        
        # Update shadow AI status
        db.execute("UPDATE shadow_ai_detections SET status='REGISTERED' WHERE id=?", (detection_id,))
        
        record_audit_entry(
            db,
            actor=current_user.get("username", "admin"),
            action="SHADOW_AI_REGISTERED",
            resource=f"agent:{new_agent_id}",
            details={"source_detection_id": detection_id, "process_name": row["process_name"]}
        )
        
    return {
        "message": f"Shadow AI instance '{row['process_name']}' successfully registered as managed agent {new_agent_id}",
        "agent_id": new_agent_id
    }
