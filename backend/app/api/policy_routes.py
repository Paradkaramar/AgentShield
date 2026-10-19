from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
from ..db.database import connect, now_iso
from ..core.auth import get_current_user, require_roles
from ..core.audit import record_audit_entry
from ..schemas import PolicyCreate, PolicyVersionDeploy
from ..engines.policy_engine import validate_policy_as_code_yaml

router = APIRouter(prefix="/api/policies", tags=["Zero-Trust Policy & GitOps"])

@router.get("")
def list_policies():
    with connect() as db:
        rows = db.execute("SELECT * FROM policies ORDER BY priority ASC, id ASC").fetchall()
        return [dict(r) for r in rows]

@router.post("", status_code=201)
def create_policy(body: PolicyCreate, current_user: Dict[str, Any] = Depends(require_roles(["admin", "security_analyst"]))):
    now = now_iso()
    with connect() as db:
        cur = db.execute(
            """INSERT INTO policies (name, description, action, target_pattern, effect, risk_threshold, priority, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (body.name, body.description or "", body.action.upper(), body.target_pattern, body.effect.upper(), body.risk_threshold, body.priority, body.enabled, now)
        )
        
        record_audit_entry(
            db,
            actor=current_user.get("username", "admin"),
            action="POLICY_CREATED",
            resource=f"policy:{cur.lastrowid}",
            details={"name": body.name, "action": body.action, "effect": body.effect}
        )
        
    return {"id": cur.lastrowid, "message": "Policy created successfully"}

@router.delete("/{policy_id}")
def delete_policy(policy_id: int, current_user: Dict[str, Any] = Depends(require_roles(["admin"]))):
    with connect() as db:
        cur = db.execute("DELETE FROM policies WHERE id=?", (policy_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Policy not found")
            
        record_audit_entry(
            db,
            actor=current_user.get("username", "admin"),
            action="POLICY_DELETED",
            resource=f"policy:{policy_id}",
            details={"deleted_by": current_user.get("username")}
        )
    return {"message": f"Policy {policy_id} removed"}

@router.get("/versions")
def list_policy_versions():
    with connect() as db:
        rows = db.execute("SELECT * FROM policy_versions ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

@router.post("/deploy")
def deploy_policy_version(body: PolicyVersionDeploy, current_user: Dict[str, Any] = Depends(require_roles(["admin"]))):
    validation = validate_policy_as_code_yaml(body.policy_yaml)
    if not validation["valid"]:
        raise HTTPException(status_code=400, detail=f"Policy-as-Code schema validation failed: {validation.get('error')}")
        
    now = now_iso()
    with connect() as db:
        cur = db.execute(
            """INSERT INTO policy_versions (version, policy_yaml, author, status, change_summary, created_at)
               VALUES (?, ?, ?, 'DEPLOYED', ?, ?)""",
            (body.version, body.policy_yaml, current_user.get("username", "admin"), body.change_summary, now)
        )
        
        record_audit_entry(
            db,
            actor=current_user.get("username", "admin"),
            action="POLICY_VERSION_DEPLOYED",
            resource=f"policy_version:{body.version}",
            details={"version": body.version, "summary": body.change_summary, "rule_count": validation.get("rule_count")}
        )
        
    return {
        "message": f"Policy version {body.version} validated and deployed via GitOps",
        "version_id": cur.lastrowid,
        "rule_count": validation.get("rule_count")
    }
