from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
from ..db.database import connect, now_iso
from ..core.auth import get_current_user
from ..core.audit import record_audit_entry
from ..schemas import ApprovalDecision

router = APIRouter(prefix="/api/approvals", tags=["Human-in-the-Loop Approval Queue"])

@router.get("")
def list_approvals():
    with connect() as db:
        rows = db.execute("SELECT * FROM approvals ORDER BY id DESC LIMIT 200").fetchall()
        return [dict(r) for r in rows]

@router.post("/{approval_id}/decision")
def decide_approval(
    approval_id: int,
    body: ApprovalDecision,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    decision_u = body.decision.upper()
    if decision_u not in {"APPROVE", "REJECT"}:
        raise HTTPException(status_code=400, detail="Decision must be APPROVE or REJECT")
        
    with connect() as db:
        approval = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if not approval:
            raise HTTPException(status_code=404, detail="Approval request not found")
        if approval["status"] != "PENDING":
            raise HTTPException(status_code=409, detail=f"Approval request already resolved as {approval['status']}")
            
        now = now_iso()
        status_result = "APPROVED" if decision_u == "APPROVE" else "REJECTED"
        approver_name = current_user.get("username", "secops-operator")
        
        db.execute(
            "UPDATE approvals SET status=?, approver=?, decision_note=?, expires_at=? WHERE id=?",
            (status_result, approver_name, body.reason or f"Human review decision: {status_result}", now, approval_id)
        )
        
        # Insert security event reflecting human decision
        db.execute(
            """INSERT INTO events (agent_id, action, target, decision, risk_score, trust_score, reason, approver, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                approval["agent_id"],
                approval["action"],
                approval["target"],
                status_result,
                35 if decision_u == "APPROVE" else 85,
                90 if decision_u == "APPROVE" else 60,
                f"Human-in-the-Loop review by {approver_name}: {status_result}. Note: {body.reason or 'None'}",
                approver_name,
                now
            )
        )
        
        # Cryptographic audit ledger entry
        record_audit_entry(
            db,
            actor=approver_name,
            action=f"APPROVAL_{status_result}",
            resource=f"approval:{approval_id}",
            details={
                "agent_id": approval["agent_id"],
                "action": approval["action"],
                "target": approval["target"],
                "decision": status_result,
                "note": body.reason
            }
        )
        
    return {
        "message": f"Approval request {approval_id} {status_result.lower()} by {approver_name}",
        "status": status_result,
        "approval_id": approval_id
    }
