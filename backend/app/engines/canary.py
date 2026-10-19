import uuid
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import sqlite3

def generate_canary_token(token_type: str, location_tag: str) -> Dict[str, Any]:
    """Generates a synthetic honeytoken with unique high-entropy signature for tripwire detection."""
    now = datetime.now(timezone.utc).isoformat()
    rand_hex = secrets.token_hex(6).upper()
    
    if token_type == "AWS_KEY":
        token_val = f"AKIA-SHIELD-CANARY-{rand_hex}"
    elif token_type == "OPENAI_KEY":
        token_val = f"sk-canary-shield-{secrets.token_urlsafe(16)}"
    elif token_type == "DATABASE_CONN":
        token_val = f"postgres://canary_{rand_hex.lower()}:H0neyTr1p!@{rand_hex.lower()}.corp.lan:5432/core_vault"
    elif token_type == "CUSTOMER_SSN":
        token_val = f"999-{secrets.randbelow(89)+10:02d}-{secrets.randbelow(8999)+1000:04d}"
    else:
        token_val = f"canary-token-{uuid.uuid4().hex}"
        
    return {
        "token_type": token_type,
        "token_value": token_val,
        "location_tag": location_tag,
        "created_at": now
    }

def check_payload_for_canaries(
    db: sqlite3.Connection,
    agent_id: str,
    action: str,
    target: str,
    payload: str
) -> Optional[Dict[str, Any]]:
    """Inspects outbound payloads for known active canary tokens and triggers high-severity tripwire alerts."""
    if not payload:
        return None
        
    canaries = db.execute("SELECT id, token_type, token_value, location_tag FROM canary_tokens").fetchall()
    for row in canaries:
        t_id, t_type, t_val, loc_tag = row
        if t_val in payload:
            now = datetime.now(timezone.utc).isoformat()
            trigger_detail = f"Honeytoken '{t_val}' (type: {t_type}) exfiltrated by {agent_id} in action {action} to {target}"
            
            # Update canary status
            db.execute(
                "UPDATE canary_tokens SET triggered=1, last_triggered_at=?, trigger_details=? WHERE id=?",
                (now, trigger_detail, t_id)
            )
            
            # Automatically spawn a critical incident
            inc_num = f"INC-CANARY-{t_id}-{int(datetime.now().timestamp())}"
            db.execute(
                """
                INSERT INTO incidents (incident_number, title, severity, status, agent_id, summary, root_cause, attack_vector, evidence_json, response_playbook, created_at, updated_at)
                VALUES (?, ?, 'CRITICAL', 'OPEN', ?, ?, 'Honeytoken exfiltration tripwire triggered', 'Canary Breach Detection', ?, 'Canary Tripwire Response', ?, ?)
                """,
                (
                    inc_num,
                    f"CRITICAL: Canary Token Compromised by {agent_id}",
                    agent_id,
                    trigger_detail,
                    f'{{"token_id": {t_id}, "token_type": "{t_type}", "target": "{target}"}}',
                    now,
                    now
                )
            )
            
            return {
                "triggered": True,
                "token_id": t_id,
                "token_type": t_type,
                "location_tag": loc_tag,
                "incident_number": inc_num,
                "alert": f"CANARY TRIPWIRE TRIPPED: Synthetic credential '{t_type}' detected in egress payload!"
            }
            
    return None
