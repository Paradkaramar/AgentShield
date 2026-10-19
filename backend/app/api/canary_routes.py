from fastapi import APIRouter, Depends
from typing import Dict, Any, List
from ..db.database import connect
from ..core.auth import get_current_user
from ..core.audit import record_audit_entry
from ..schemas import CanaryCreate
from ..engines.canary import generate_canary_token

router = APIRouter(prefix="/api/canaries", tags=["Canary Tokens & Honeytokens"])

@router.get("")
def list_canary_tokens():
    with connect() as db:
        rows = db.execute("SELECT * FROM canary_tokens ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

@router.post("", status_code=201)
def create_canary_token(body: CanaryCreate, current_user: Dict[str, Any] = Depends(get_current_user)):
    token_data = generate_canary_token(body.token_type, body.location_tag)
    
    with connect() as db:
        cur = db.execute(
            """INSERT INTO canary_tokens (token_type, token_value, location_tag, triggered, last_triggered_at, trigger_details, created_at)
               VALUES (?, ?, ?, 0, NULL, '', ?)""",
            (token_data["token_type"], token_data["token_value"], token_data["location_tag"], token_data["created_at"])
        )
        
        record_audit_entry(
            db,
            actor=current_user.get("username", "admin"),
            action="CANARY_TOKEN_DEPLOYED",
            resource=f"canary:{cur.lastrowid}",
            details={"type": body.token_type, "location_tag": body.location_tag}
        )
        
    return {
        "id": cur.lastrowid,
        "token_type": token_data["token_type"],
        "token_value": token_data["token_value"],
        "location_tag": token_data["location_tag"],
        "message": "Canary token deployed. Monitoring for unauthorized access."
    }
