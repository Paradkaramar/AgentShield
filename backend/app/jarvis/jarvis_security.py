import re
import uuid
import json
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from fastapi import HTTPException, status
from ..engines.prompt_injection import inspect_prompt
from ..engines.dlp import redact_sensitive_string
from ..core.audit import record_audit_entry

# High-risk / sensitive actions that REQUIRE explicit user confirmation before execution
SENSITIVE_ACTIONS = {
    "KILL_SWITCH": {
        "risk_level": "CRITICAL",
        "description": "Trigger Emergency Kill Switch & quarantine an AI agent",
        "requires_roles": ["admin", "security_analyst", "operator"]
    },
    "REVOKE_CREDENTIALS": {
        "risk_level": "CRITICAL",
        "description": "Revoke active credentials and rotate tool tokens",
        "requires_roles": ["admin"]
    },
    "SUSPEND_AGENT": {
        "risk_level": "HIGH",
        "description": "Suspend an active agent from processing tasks",
        "requires_roles": ["admin", "security_analyst", "operator"]
    },
    "REACTIVATE_AGENT": {
        "risk_level": "HIGH",
        "description": "Reactivate a suspended or quarantined agent",
        "requires_roles": ["admin", "security_analyst"]
    },
    "APPROVE_REQUEST": {
        "risk_level": "HIGH",
        "description": "Human-in-the-loop manual approval of a blocked or pending tool execution",
        "requires_roles": ["admin", "security_analyst", "operator"]
    },
    "REJECT_REQUEST": {
        "risk_level": "MEDIUM",
        "description": "Reject a pending tool execution request",
        "requires_roles": ["admin", "security_analyst", "operator"]
    }
}

# Forbidden operations that can NEVER be executed under any circumstances
FORBIDDEN_OPERATIONS = [
    r"drop\s+table",
    r"delete\s+from\s+audit_log",
    r"rm\s+-rf",
    r"format\s+[c-z]:",
    r"shutdown",
    r"exec\s*\(",
    r"eval\s*\(",
    r"system\s*\(",
    r"os\.system",
    r"subprocess",
    r"__import__",
    r"bypass\s+zero[\s_-]*trust",
    r"disable\s+guardrails",
    r"turn\s+off\s+security"
]

def check_message_for_prompt_injection(message: str) -> Dict[str, Any]:
    """Inspects prompt for injection/jailbreak attempts targeted at the JARVIS assistant."""
    # 1. Check heuristics engine
    inspection = inspect_prompt(message)
    if inspection.get("is_injection"):
        return {
            "is_threat": True,
            "confidence": inspection.get("confidence", 0.9),
            "reasons": [s.get("rule", "Prompt injection signature") for s in inspection.get("signals", [])],
            "recommendation": inspection.get("recommendation", "BLOCK")
        }

    # 2. Check forbidden operational command signatures
    msg_lower = message.lower()
    for pattern in FORBIDDEN_OPERATIONS:
        if re.search(pattern, msg_lower):
            return {
                "is_threat": True,
                "confidence": 0.98,
                "reasons": [f"Forbidden administrative override or shell injection signature: '{pattern}'"],
                "recommendation": "BLOCK"
            }

    return {"is_threat": False, "confidence": 0.0, "reasons": [], "recommendation": "ALLOW"}

def verify_tool_authorization(
    tool_name: str,
    user: Dict[str, Any],
    tool_metadata: Dict[str, Any]
) -> Tuple[bool, Optional[str]]:
    """Checks if the user has appropriate role for the requested tool."""
    user_role = user.get("role", "operator")
    # Admin has access to all tools
    if user_role == "admin":
        return True, None

    required_roles = tool_metadata.get("allowed_roles", ["admin", "security_analyst", "operator", "auditor"])
    if user_role not in required_roles:
        return False, f"Role '{user_role}' is not authorized to execute tool '{tool_name}'. Required: {', '.join(required_roles)}"

    return True, None

def check_requires_confirmation(action_type: str) -> Optional[Dict[str, Any]]:
    """Returns sensitive action spec if confirmation is required before execution."""
    return SENSITIVE_ACTIONS.get(action_type.upper())

def sanitize_assistant_output(text: str) -> str:
    """Redacts any leaked credentials or raw secret keys from JARVIS output."""
    return redact_sensitive_string(text)

def log_jarvis_action(
    db: sqlite3.Connection,
    actor: str,
    action: str,
    resource: str,
    details: Dict[str, Any]
) -> str:
    """Records a cryptographically chained audit log entry for every JARVIS action."""
    return record_audit_entry(
        db=db,
        actor=f"JARVIS:{actor}",
        action=action,
        resource=resource,
        details=details
    )
