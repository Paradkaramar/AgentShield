from .engines.prompt_injection import inspect_prompt, INJECTION_PATTERNS
from .engines.dlp import scan_payload_dlp, DLP_PATTERNS
from .engines.policy_engine import evaluate_zero_trust_policy

def inspect_payload(payload: str):
    p_res = inspect_prompt(payload)
    d_res = scan_payload_dlp(payload)
    return {
        "prompt_injection": p_res["is_injection"],
        "injection_signals": [s["rule"] for s in p_res["signals"]],
        "sensitive_signals": [v["rule_id"] for v in d_res["violations"]]
    }

def assess_action(action: str, target: str, payload: str, agent_status: str, allowed_tools: list[str]):
    agent_mock = {"status": agent_status, "permissions": {}, "trust_score": 90}
    p_eval = evaluate_zero_trust_policy(agent_mock, action, target, payload, [])
    return p_eval["risk_score"], p_eval["decision"], p_eval["reasons"]
