from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
import json
from ..db.database import connect, now_iso
from ..schemas import ActionRequest
from ..core.auth import get_current_user
from ..engines.prompt_injection import inspect_prompt
from ..engines.dlp import scan_payload_dlp, redact_sensitive_string
from ..engines.policy_engine import evaluate_zero_trust_policy
from ..engines.risk_engine import calculate_dynamic_risk, update_continuous_trust_score
from ..engines.explainable_analyst import generate_security_explanation
from ..engines.canary import check_payload_for_canaries
from ..engines.reverse_engineering import detect_defensive_reverse_engineering
from ..engines.playbooks import evaluate_and_trigger_playbooks
from ..engines.tool_proxy import execute_proxy_tool_call

router = APIRouter(prefix="/api/actions", tags=["Policy Evaluation & Execution Gateway"])

@router.post("/evaluate")
def evaluate_action(body: ActionRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    with connect() as db:
        agent = db.execute("SELECT * FROM agents WHERE id=?", (body.agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        stored_policies = [dict(r) for r in db.execute("SELECT * FROM policies WHERE enabled=1 ORDER BY priority ASC").fetchall()]
        recent_events = [dict(r) for r in db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 10", (body.agent_id,)).fetchall()]
        
        now = now_iso()
        all_reasons = []
        action_u = body.action.upper()
        target_clean = body.target.strip()
        
        # 1. Check for Defensive Reverse Engineering Probing (Feature AO)
        def_re = detect_defensive_reverse_engineering(action_u, target_clean, body.payload)
        if def_re["detected"]:
            all_reasons.append(f"Defensive Reverse Engineering Alert: Probing internal control plane guardrails ({', '.join(def_re['signatures_triggered'])})")
            
        # 2. Canary Tripwire Check (Feature AG)
        canary_hit = check_payload_for_canaries(db, body.agent_id, action_u, target_clean, body.payload)
        if canary_hit:
            all_reasons.append(canary_hit["alert"])
            
        # 3. Prompt Injection Detection (Feature D)
        injection_result = inspect_prompt(body.payload)
        if injection_result["is_injection"]:
            sig_rules = [s["rule"] for s in injection_result["signals"]]
            all_reasons.append(f"Prompt injection detected ({', '.join(sig_rules)}, confidence {injection_result['confidence']:.2f})")
            
        # 4. DLP and Secret Redaction (Feature J & I)
        dlp_result = scan_payload_dlp(body.payload)
        if dlp_result["has_sensitive_data"]:
            viol_descs = [v["description"] for v in dlp_result["violations"]]
            all_reasons.append(f"DLP Policy match: {', '.join(viol_descs)}")
            
        # 5. Zero-Trust Policy Engine (Feature B & C & Y)
        policy_eval = evaluate_zero_trust_policy(
            dict(agent), action_u, target_clean, body.payload, stored_policies, declared_intent=body.declared_intent
        )
        all_reasons.extend(policy_eval["reasons"])
        
        # Determine aggregate preliminary decision
        if def_re["detected"] or canary_hit or (injection_result["is_injection"] and injection_result["confidence"] >= 0.90):
            aggregate_decision = "BLOCK"
        elif policy_eval["decision"] == "BLOCK":
            aggregate_decision = "BLOCK"
        elif dlp_result["recommended_action"] == "BLOCK":
            aggregate_decision = "BLOCK"
        elif policy_eval["decision"] == "ASK_HUMAN" or dlp_result["recommended_action"] == "REQUIRE_HUMAN_APPROVAL" or (injection_result["is_injection"] and injection_result["confidence"] >= 0.65):
            aggregate_decision = "ASK_HUMAN"
        else:
            aggregate_decision = "ALLOW"
            
        # 6. Dynamic Risk Scoring & Continuous Trust Scoring (Feature K & S)
        dynamic_risk = calculate_dynamic_risk(
            dict(agent),
            recent_events,
            policy_eval["risk_score"],
            dlp_result["violations"],
            injection_result["confidence"],
            drift_score=0.08
        )
        risk_score = dynamic_risk["risk_score"]
        
        trust_update = update_continuous_trust_score(agent["trust_score"], aggregate_decision, risk_score)
        new_trust = trust_update["new_trust"]
        
        # 7. Generate Explainable Security Analysis (Feature N)
        analyst_report = generate_security_explanation(
            action=action_u,
            target=target_clean,
            decision=aggregate_decision,
            risk_score=risk_score,
            reasons=all_reasons,
            inspection_signals=injection_result,
            dlp_findings=dlp_result,
            agent_info=dict(agent)
        )
        
        # 8. Persist changes to database
        sanitized_preview = dlp_result["sanitized_text"][:250] if dlp_result["sanitized_text"] else ""
        reason_summary = "; ".join(all_reasons) if all_reasons else "Action verified and compliant with Zero-Trust baseline"
        
        db.execute("UPDATE agents SET risk_score=?, trust_score=?, last_activity=? WHERE id=?", (risk_score, new_trust, now, body.agent_id))
        
        cur = db.execute(
            """INSERT INTO events (agent_id, action, target, decision, risk_score, trust_score, reason, latency_ms, payload_sanitized, tool_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 18, ?, ?, ?)""",
            (body.agent_id, action_u, target_clean, aggregate_decision, risk_score, new_trust, reason_summary, sanitized_preview, body.tool_id or "tool-generic", now)
        )
        event_id = cur.lastrowid
        
        # 9. Create Human Approval Request if decision is ASK_HUMAN (Feature G)
        approval_id = None
        if aggregate_decision == "ASK_HUMAN":
            cur_ap = db.execute(
                """INSERT INTO approvals (agent_id, action, target, payload, reason, risk_score, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?)""",
                (body.agent_id, action_u, target_clean, sanitized_preview, reason_summary, risk_score, now)
            )
            approval_id = cur_ap.lastrowid
            
        # 10. Autonomous Response Playbooks (Feature U)
        triggered_playbooks = []
        if aggregate_decision == "BLOCK" and risk_score >= 85:
            triggered_playbooks = evaluate_and_trigger_playbooks(
                db, "PROMPT_INJECTION_HIGH" if injection_result["is_injection"] else "SECURITY_VIOLATION_BLOCK",
                body.agent_id, {"event_id": event_id, "risk_score": risk_score}
            )

        return {
            "event_id": event_id,
            "agent_id": body.agent_id,
            "action": action_u,
            "target": target_clean,
            "decision": aggregate_decision,
            "risk_score": risk_score,
            "trust_score": new_trust,
            "reasons": all_reasons,
            "prompt_injection": injection_result,
            "dlp": {
                "has_sensitive_data": dlp_result["has_sensitive_data"],
                "violations": dlp_result["violations"],
                "sanitized_preview": sanitized_preview
            },
            "approval_id": approval_id,
            "analyst_report": analyst_report,
            "playbooks_executed": triggered_playbooks,
            "inspection": {
                "prompt_injection": injection_result["is_injection"],
                "injection_signals": [s["rule"] for s in injection_result["signals"]],
                "sensitive_signals": [v["rule_id"] for v in dlp_result["violations"]]
            }
        }

@router.post("/proxy")
def proxy_action(body: ActionRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Secret-Aware Tool Proxy endpoint (Feature AB)."""
    with connect() as db:
        agent = db.execute("SELECT * FROM agents WHERE id=?", (body.agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        # First evaluate policy
        eval_res = evaluate_action(body, current_user)
        policy_allowed = eval_res["decision"] == "ALLOW"
        
        tool = db.execute("SELECT * FROM tools_registry WHERE id=?", (body.tool_id,)).fetchone() if body.tool_id else None
        allowed_dest = json.loads(tool["allowed_destinations"]) if tool and tool["allowed_destinations"] else ["*"]
        
        proxy_res = execute_proxy_tool_call(
            agent_id=body.agent_id,
            tool_id=body.tool_id or "tool-generic",
            action=body.action.upper(),
            target=body.target,
            payload=body.payload,
            allowed_destinations=allowed_dest,
            policy_authorized=policy_allowed,
            requires_vault_secret="OPENAI_API_KEY" if "openai" in body.target.lower() else None
        )
        
        return {
            "evaluation": eval_res,
            "proxy_result": proxy_res
        }

@router.get("/lab-sample")
def get_lab_sample():
    with connect() as db:
        agent = db.execute("SELECT id, name FROM agents WHERE status='ACTIVE' ORDER BY created_at LIMIT 1").fetchone()
        tools = db.execute("SELECT id, name, category, risk_level FROM tools_registry WHERE enabled=1").fetchall()
        return {
            "agent_id": agent["id"] if agent else "",
            "actions": ["READ", "ANALYZE", "WRITE", "SEND", "EXPORT", "DELETE", "EXECUTE", "TRANSFER"],
            "registered_tools": [dict(t) for t in tools]
        }
