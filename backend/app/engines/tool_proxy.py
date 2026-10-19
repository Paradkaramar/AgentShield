import time
import fnmatch
from typing import Dict, Any, List, Optional
from ..core.config import SECRET_VAULT
from .dlp import redact_sensitive_string

def check_destination_allowlist(target: str, allowed_patterns: List[str]) -> bool:
    if not allowed_patterns:
        return True
    for pat in allowed_patterns:
        if pat == "*" or fnmatch.fnmatch(target.lower(), pat.lower()):
            return True
    return False

def execute_proxy_tool_call(
    agent_id: str,
    tool_id: str,
    action: str,
    target: str,
    payload: str,
    allowed_destinations: List[str],
    policy_authorized: bool,
    requires_vault_secret: Optional[str] = None
) -> Dict[str, Any]:
    """Routes tool execution through the secure proxy gateway with credential injection and DLP scrubbing."""
    start_time = time.time()
    
    # 1. Fail closed if not policy-authorized
    if not policy_authorized:
        return {
            "status": "BLOCKED",
            "error": "Tool Proxy Gateway rejected invocation: Unauthorized by Zero-Trust policy",
            "latency_ms": int((time.time() - start_time) * 1000),
            "result": None,
            "egress_allowed": False
        }
        
    # 2. Destination Allowlist Enforcement
    if not check_destination_allowlist(target, allowed_destinations):
        return {
            "status": "BLOCKED",
            "error": f"Tool Proxy Gateway: Target '{target}' is not in allowed destinations list {allowed_destinations}",
            "latency_ms": int((time.time() - start_time) * 1000),
            "result": None,
            "egress_allowed": False
        }
        
    # 3. Secure Credential Injection from Enclave Vault (No credentials returned to frontend)
    injected_auth = None
    if requires_vault_secret and requires_vault_secret in SECRET_VAULT:
        injected_auth = "[VAULT_MANAGED_CREDENTIAL_INJECTED_AT_EGRESS]"
        
    # 4. Simulated safe deterministic tool execution
    latency_ms = max(5, int((time.time() - start_time) * 1000) + 12)
    
    # Sanitize payload
    sanitized_payload = redact_sensitive_string(payload)
    
    response_data = {
        "tool_id": tool_id,
        "action": action,
        "target": target,
        "executed_at": time.time(),
        "proxy_headers": {
            "X-AgentShield-Proxy": "1.0",
            "X-Agent-ID": agent_id,
            "Authorization": injected_auth or "Bearer [INTERNAL-CONTROL-PLANE-TOKEN]"
        },
        "output_summary": f"Simulated proxy execution of '{action}' on '{target}' completed successfully.",
        "sanitized_request_preview": sanitized_payload[:120]
    }
    
    return {
        "status": "SUCCESS",
        "latency_ms": latency_ms,
        "result": response_data,
        "egress_allowed": True
    }
