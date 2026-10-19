import fnmatch
import json
import yaml
from typing import Dict, Any, List, Tuple, Optional

# Standard sensitive actions requiring strict permission validation
SENSITIVE_ACTIONS = {"WRITE", "DELETE", "EXPORT", "SEND", "EXECUTE", "TRANSFER", "DROP"}

def match_target(pattern: str, target: str) -> bool:
    """Matches target against a glob pattern, case-insensitive."""
    if pattern == "*" or pattern == target:
        return True
    return fnmatch.fnmatch(target.lower(), pattern.lower())

def check_agent_permissions(
    permissions: Dict[str, List[str]],
    action: str,
    target: str
) -> Tuple[bool, str]:
    """Verifies whether the agent's fine-grained permission set authorizes the action and target."""
    action_key = action.lower()
    allowed_resources = permissions.get(action_key, [])
    
    if "*" in allowed_resources:
        return True, f"Permission granted via wildcard rule for action {action}"
        
    for res in allowed_resources:
        if match_target(res, target):
            return True, f"Permission granted: target '{target}' matches allowed pattern '{res}'"
            
    # Default to deny for sensitive actions if no explicit permission is listed
    if action.upper() in SENSITIVE_ACTIONS:
        return False, f"Permission denied: Agent lacks '{action_key}' permission for resource '{target}'"
        
    # Read actions on internal resources may be permitted if read list is empty or generic
    if action.upper() in {"READ", "ANALYZE"} and not allowed_resources:
        return True, f"Default read policy for internal resource '{target}'"
        
    return False, f"Permission not found for {action_key} on {target}"

def evaluate_zero_trust_policy(
    agent: Dict[str, Any],
    action: str,
    target: str,
    payload: str,
    stored_policies: List[Dict[str, Any]],
    declared_intent: Optional[str] = None
) -> Dict[str, Any]:
    """Evaluates agent action against Zero-Trust policies, agent permissions, and intent constraints."""
    action_u = action.upper()
    target_l = target.lower()
    agent_status = agent.get("status", "ACTIVE")
    permissions = json.loads(agent.get("permissions", "{}")) if isinstance(agent.get("permissions"), str) else agent.get("permissions", {})
    
    reasons = []
    decision = "ALLOW"
    base_risk = 10
    
    # Rule 1: Agent lifecycle and kill-switch check
    if agent_status != "ACTIVE":
        return {
            "decision": "BLOCK",
            "risk_score": 100,
            "reasons": [f"Agent is currently {agent_status}. All operations are blocked."],
            "authorized": False,
            "rule_matched": "AGENT_LIFECYCLE_KILL_SWITCH"
        }
        
    # Rule 2: Fine-grained permission verification
    perm_ok, perm_reason = check_agent_permissions(permissions, action_u, target)
    if not perm_ok:
        base_risk += 45
        reasons.append(perm_reason)
        decision = "BLOCK"
    else:
        reasons.append(perm_reason)

    # Rule 3: Intent-Aware Consistency Validation
    if declared_intent:
        intent_lower = declared_intent.lower()
        # Verify if action aligns with declared intent
        if action_u in {"DELETE", "DROP"} and "delete" not in intent_lower and "clean" not in intent_lower:
            base_risk += 35
            reasons.append(f"Intent discrepancy: Action '{action_u}' does not match declared intent '{declared_intent}'")
            decision = "ASK_HUMAN"
        elif action_u == "EXPORT" and "export" not in intent_lower and "report" not in intent_lower:
            base_risk += 30
            reasons.append(f"Intent discrepancy: External export requested under general task '{declared_intent}'")
            decision = "ASK_HUMAN"

    # Rule 4: Match stored database policies (ordered by priority)
    for p in stored_policies:
        if not p.get("enabled", 1):
            continue
        p_action = p.get("action", "").upper()
        p_target = p.get("target_pattern", "")
        p_effect = p.get("effect", "BLOCK").upper()
        p_threshold = p.get("risk_threshold", 70)
        
        if (p_action == "*" or p_action == action_u) and match_target(p_target, target):
            reasons.append(f"Policy '{p.get('name')}' triggered: rule match for {action_u} on {target}")
            if p_effect == "BLOCK":
                decision = "BLOCK"
                base_risk = max(base_risk, p_threshold)
                break
            elif p_effect == "ASK_HUMAN" and decision != "BLOCK":
                decision = "ASK_HUMAN"
                base_risk = max(base_risk, p_threshold)

    # Rule 5: Destination sensitivity heuristics
    if any(untrusted in target_l for untrusted in ["external", "public", "dropzone", "attacker", "pastebin", "webhook"]):
        base_risk += 30
        reasons.append(f"Untrusted egress destination detected: {target}")
        if action_u in {"EXPORT", "SEND", "TRANSFER"}:
            if decision != "BLOCK":
                decision = "ASK_HUMAN"

    risk_score = min(100, max(0, base_risk))
    
    # Default to deny/approval if risk is elevated
    if risk_score >= 80 and decision != "BLOCK":
        decision = "BLOCK"
        reasons.append("Risk score threshold (>=80) exceeded: Action blocked by policy")
    elif risk_score >= 55 and decision == "ALLOW":
        decision = "ASK_HUMAN"
        reasons.append("Moderate-to-high risk (>=55): Requires human operator review")

    return {
        "decision": decision,
        "risk_score": risk_score,
        "reasons": reasons,
        "authorized": decision == "ALLOW"
    }

def detect_permission_drift(current_permissions: Dict[str, List[str]], baseline_permissions: Dict[str, List[str]]) -> Dict[str, Any]:
    """Compares current agent permissions with approved baselines to detect privilege drift."""
    added_privileges = {}
    removed_privileges = {}
    has_drift = False
    critical_actions = {"write", "delete", "export", "execute"}
    drift_severity = "LOW"
    
    all_keys = set(current_permissions.keys()).union(set(baseline_permissions.keys()))
    
    for key in all_keys:
        curr = set(current_permissions.get(key, []))
        base = set(baseline_permissions.get(key, []))
        
        added = curr - base
        removed = base - curr
        
        if added:
            has_drift = True
            added_privileges[key] = list(added)
            if key in critical_actions:
                drift_severity = "HIGH"
        if removed:
            has_drift = True
            removed_privileges[key] = list(removed)

    return {
        "has_drift": has_drift,
        "drift_severity": drift_severity,
        "added_privileges": added_privileges,
        "removed_privileges": removed_privileges,
        "summary": "Permissions match approved baseline" if not has_drift else f"Detected privilege changes across {len(added_privileges)} category(s)"
    }

def validate_policy_as_code_yaml(yaml_content: str) -> Dict[str, Any]:
    """Validates policy-as-code schema and detects syntax or security configuration errors."""
    try:
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            return {"valid": False, "error": "Root of policy document must be an object"}
        if "version" not in data:
            return {"valid": False, "error": "Missing required field 'version'"}
        if "rules" not in data or not isinstance(data["rules"], list):
            return {"valid": False, "error": "Missing or invalid 'rules' list"}
            
        validated_rules = []
        for i, rule in enumerate(data["rules"]):
            for req in ["id", "action", "target", "effect"]:
                if req not in rule:
                    return {"valid": False, "error": f"Rule at index {i} missing required property '{req}'"}
            effect = rule["effect"].upper()
            if effect not in {"ALLOW", "BLOCK", "ASK_HUMAN", "QUARANTINE"}:
                return {"valid": False, "error": f"Invalid effect '{effect}' in rule {rule.get('id')}"}
            validated_rules.append(rule)
            
        return {
            "valid": True,
            "version": data.get("version"),
            "rule_count": len(validated_rules),
            "parsed_rules": validated_rules
        }
    except Exception as e:
        return {"valid": False, "error": f"YAML syntax error: {str(e)}"}
