from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
import json
from ..db.database import connect, now_iso
from ..core.auth import get_current_user
from ..core.audit import record_audit_entry

router = APIRouter(prefix="/api/incidents", tags=["Threat Alerts & Incident Response"])

@router.get("")
def list_incidents():
    with connect() as db:
        rows = db.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 100").fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["evidence"] = json.loads(item["evidence_json"]) if isinstance(item["evidence_json"], str) else item["evidence_json"]
            result.append(item)
        return result

@router.get("/{incident_id}")
def get_incident(incident_id: int):
    with connect() as db:
        row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        item = dict(row)
        item["evidence"] = json.loads(item["evidence_json"]) if isinstance(item["evidence_json"], str) else item["evidence_json"]
        return item

@router.patch("/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    body: Dict[str, str],
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    status_u = body.get("status", "").upper()
    if status_u not in {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"}:
        raise HTTPException(status_code=400, detail="Invalid status. Must be OPEN, INVESTIGATING, CONTAINED, or RESOLVED")
        
    with connect() as db:
        now = now_iso()
        cur = db.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?", (status_u, now, incident_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        record_audit_entry(
            db,
            actor=current_user.get("username", "analyst"),
            action="INCIDENT_STATUS_CHANGE",
            resource=f"incident:{incident_id}",
            details={"new_status": status_u}
        )
        
    return {"message": f"Incident {incident_id} status updated to {status_u}", "status": status_u}
