import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import sqlite3

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def calculate_audit_hash(prev_hash: str, timestamp: str, actor: str, action: str, resource: str, details_json: str) -> str:
    content = f"{prev_hash}|{timestamp}|{actor}|{action}|{resource}|{details_json}".encode("utf-8")
    return hashlib.sha256(content).hexdigest()

def record_audit_entry(
    db: sqlite3.Connection,
    actor: str,
    action: str,
    resource: str,
    details: Dict[str, Any]
) -> Dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()
    details_json = json.dumps(details, sort_keys=True)
    
    last_row = db.execute("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = last_row[0] if last_row and last_row[0] else GENESIS_HASH
    
    current_hash = calculate_audit_hash(prev_hash, timestamp, actor, action, resource, details_json)
    
    cur = db.execute(
        """
        INSERT INTO audit_log (actor, action, resource, details_json, prev_hash, current_hash, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (actor, action, resource, details_json, prev_hash, current_hash, timestamp)
    )
    
    return {
        "id": cur.lastrowid,
        "actor": actor,
        "action": action,
        "resource": resource,
        "details": details,
        "prev_hash": prev_hash,
        "current_hash": current_hash,
        "timestamp": timestamp
    }

def verify_audit_integrity(db: sqlite3.Connection) -> Dict[str, Any]:
    rows = db.execute(
        "SELECT id, actor, action, resource, details_json, prev_hash, current_hash, timestamp FROM audit_log ORDER BY id ASC"
    ).fetchall()
    
    if not rows:
        return {"status": "VALID", "records_verified": 0, "chain_intact": True, "details": "No audit records in ledger"}
        
    expected_prev = GENESIS_HASH
    tampered_records = []
    
    for row in rows:
        r_id, actor, action, resource, details_json, prev_hash, current_hash, timestamp = row
        if prev_hash != expected_prev:
            tampered_records.append({
                "id": r_id,
                "error": "Broken chain: prev_hash does not match previous record current_hash",
                "expected": expected_prev,
                "actual": prev_hash
            })
            
        recalculated = calculate_audit_hash(prev_hash, timestamp, actor, action, resource, details_json)
        if recalculated != current_hash:
            tampered_records.append({
                "id": r_id,
                "error": "Content signature mismatch: record data may have been altered",
                "expected_hash": recalculated,
                "stored_hash": current_hash
            })
            
        expected_prev = current_hash

    is_intact = len(tampered_records) == 0
    return {
        "status": "VALID" if is_intact else "TAMPERED",
        "records_verified": len(rows),
        "chain_intact": is_intact,
        "tampered_records": tampered_records,
        "genesis_hash": GENESIS_HASH,
        "latest_hash": expected_prev
    }
