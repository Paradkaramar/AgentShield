from fastapi import APIRouter, Depends
from typing import Dict, Any, List
import json
from ..db.database import connect
from ..core.audit import verify_audit_integrity

router = APIRouter(prefix="/api/audit", tags=["Complete Audit Trail & Integrity"])

@router.get("")
def list_audit_trail(limit: int = 150):
    with connect() as db:
        rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["details"] = json.loads(item["details_json"]) if isinstance(item["details_json"], str) else item["details_json"]
            result.append(item)
        return result

@router.get("/verify")
def check_audit_integrity():
    with connect() as db:
        return verify_audit_integrity(db)

@router.get("/export")
def export_audit_log():
    with connect() as db:
        rows = db.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]
