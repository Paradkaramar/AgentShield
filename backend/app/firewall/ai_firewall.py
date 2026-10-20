# backend/app/firewall/ai_firewall.py
"""
AgentShield Layer 3: AI Agent Security Firewall & Policy Enforcement Gateway

Enforces zero-trust defense policies across all AI-agent tool invocations:
1. Strict Pydantic tool argument schema validation against registered specifications.
2. Agent and operator authentication & state verification (rejects KILLED/SUSPENDED agents).
3. Arbitrary execution prevention (blocks shell execution, raw SQL, and dangerous builtins).
4. Prompt-injection defense heuristic signals (defense-in-depth indicator).
5. Outbound Data Loss Prevention (DLP) exfiltration detection & credential masking.
6. Destination network allowlist verification against approved CIDR scopes.
7. Dynamic risk scoring (0-100) and tri-state decisions: ALLOW, BLOCK, REQUIRE_HUMAN_APPROVAL.
8. Emergency Containment Kill Switch with immediate tool freezing.
9. Guaranteed Fail-Closed semantics: any policy evaluation failure defaults to BLOCK.
10. SHA-256 cryptographically chained immutable audit logging.
"""

import re
import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Type
from pydantic import BaseModel, Field, ValidationError, ConfigDict

from ..db.database import connect, now_iso
from ..core.audit import record_audit_entry
from ..engines.prompt_injection import inspect_prompt
from ..engines.dlp import DLP_PATTERNS, redact_sensitive_string

# ------------------------------------------------------------------------------
# 1. Strict Pydantic Argument Schemas for Registered Tools
# ------------------------------------------------------------------------------

class EmptyArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class ListAgentsArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Optional[str] = Field("ALL", max_length=32)
    min_risk: Optional[int] = Field(0, ge=0, le=100)

class GetAgentDetailsArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_\-\.]+$")

class GetAlertsAndIncidentsArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: Optional[str] = Field("ALL", max_length=32)
    limit: Optional[int] = Field(10, ge=1, le=500)

class SearchAuditLogsArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: Optional[str] = Field("", max_length=256)
    limit: Optional[int] = Field(15, ge=1, le=500)

class GetIncidentDetailsArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_identifier: str = Field(..., min_length=1, max_length=64)

class ExplainRiskTrustScoresArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1, max_length=128)

class InspectPermissionsArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1, max_length=128)

class ReviewTelemetryArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: Optional[int] = Field(10, ge=1, le=500)

class PrepareKillSwitchArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1, max_length=128)
    reason: Optional[str] = Field("Operator activated emergency quarantine", max_length=500)

class PrepareApprovalDecisionArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approval_id: int = Field(..., ge=1)
    decision: str = Field(..., pattern=r"^(APPROVE|REJECT)$")
    reason: Optional[str] = Field("Decided via AI Assistant", max_length=500)

class TriggerNetworkScanArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_ip: Optional[str] = Field(None, max_length=64)

class EndpointDeviceArgsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: Optional[str] = Field("", max_length=128)
    limit: Optional[int] = Field(10, ge=1, le=500)

# Mapping of tools to their strict schema models
TOOL_SCHEMA_MAP: Dict[str, Type[BaseModel]] = {
    "get_security_dashboard_metrics": EmptyArgsModel,
    "list_agents": ListAgentsArgsModel,
    "get_agent_details": GetAgentDetailsArgsModel,
    "get_alerts_and_incidents": GetAlertsAndIncidentsArgsModel,
    "search_audit_logs": SearchAuditLogsArgsModel,
    "get_incident_details": GetIncidentDetailsArgsModel,
    "explain_risk_trust_scores": ExplainRiskTrustScoresArgsModel,
    "inspect_permissions": InspectPermissionsArgsModel,
    "review_prompt_injections": ReviewTelemetryArgsModel,
    "review_dlp_events": ReviewTelemetryArgsModel,
    "get_attack_graph_and_delegations": EmptyArgsModel,
    "summarize_sandbox_simulations": EmptyArgsModel,
    "get_predictive_risk_report": EmptyArgsModel,
    "generate_incident_report_draft": ReviewTelemetryArgsModel,
    "navigate_frontend": EmptyArgsModel,
    "prepare_kill_switch": PrepareKillSwitchArgsModel,
    "prepare_approval_decision": PrepareApprovalDecisionArgsModel,
    "get_network_monitoring_status": EmptyArgsModel,
    "get_network_discovered_devices": EmptyArgsModel,
    "get_network_security_alerts": EmptyArgsModel,
    "start_network_monitoring": EmptyArgsModel,
    "stop_network_monitoring": EmptyArgsModel,
    "trigger_network_scan_now": TriggerNetworkScanArgsModel,
    "get_device_security_status": EndpointDeviceArgsModel,
    "check_suspicious_connections": EndpointDeviceArgsModel,
    "get_device_security_alerts": EndpointDeviceArgsModel,
    "get_endpoint_firewall_status": EndpointDeviceArgsModel,
    "pause_endpoint_monitoring": EndpointDeviceArgsModel,
    "disconnect_endpoint_device": EndpointDeviceArgsModel,
}

# ------------------------------------------------------------------------------
# 2. Forbidden Execution Signatures (Shell, Raw SQL, Subprocess)
# ------------------------------------------------------------------------------
FORBIDDEN_EXECUTION_PATTERNS = [
    r"rm\s+-rf",
    r"format\s+[c-z]:",
    r"shutdown",
    r"exec\s*\(",
    r"eval\s*\(",
    r"system\s*\(",
    r"os\.system",
    r"subprocess",
    r"powershell",
    r"cmd\.exe",
    r"/bin/sh",
    r"/bin/bash",
    r"drop\s+table",
    r"delete\s+from",
    r"truncate\s+table",
    r"alter\s+table",
    r"union\s+select",
    r"bypass\s+zero[\s_-]*trust",
    r"disable\s+guardrails",
    r"turn\s+off\s+security",
]

# Sensitive tools that intrinsically require human confirmation before execution
REQUIRE_APPROVAL_TOOLS = {
    "prepare_kill_switch",
    "prepare_approval_decision",
    "trigger_network_scan_now",
    "stop_network_monitoring",
}

# ------------------------------------------------------------------------------
# 3. Policy Evaluation Decision Object
# ------------------------------------------------------------------------------
class AIPolicyDecision(BaseModel):
    decision: str  # "ALLOW", "BLOCK", "REQUIRE_HUMAN_APPROVAL"
    risk_score: int  # 0 to 100
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    reason: str
    is_fail_closed: bool = False
    prompt_injection_signal: bool = False
    dlp_violation: bool = False
    sanitized_arguments: Dict[str, Any]
    requires_confirmation: bool = False

# ------------------------------------------------------------------------------
# 4. Centralized AI Agent Security Firewall Engine
# ------------------------------------------------------------------------------

class AIAgentSecurityGateway:
    """
    Centralized Zero-Trust Policy Enforcement Gateway for AI Agent Tool Calls.
    """

    @staticmethod
    def inspect_arbitrary_code_injection(data: Any) -> Tuple[bool, Optional[str]]:
        """Scans arbitrary strings or nested dictionaries for forbidden shell/SQL injection."""
        text = json.dumps(data).lower() if isinstance(data, (dict, list)) else str(data).lower()
        for pattern in FORBIDDEN_EXECUTION_PATTERNS:
            if re.search(pattern, text):
                return True, f"Blocked forbidden arbitrary execution signature: '{pattern}'"
        return False, None

    @staticmethod
    def inspect_dlp(data: Any) -> Tuple[bool, Optional[str]]:
        """Scans outbound arguments for critical secrets and PII."""
        text = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
        for key, (pattern, name, severity, action) in DLP_PATTERNS.items():
            if severity == "CRITICAL" and re.search(pattern, text):
                return True, f"DLP Violation: Exfiltration of sensitive data detected ({name})"
        return False, None

    @classmethod
    def evaluate_tool_call(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        user: Dict[str, Any],
        agent_id: Optional[str] = "agent-jarvis-orchestrator",
        prompt_context: Optional[str] = None
    ) -> AIPolicyDecision:
        """
        Evaluates a tool execution request against zero-trust policies.
        Guaranteed Fail-Closed: any error returns BLOCK.
        """
        sanitized_args = {}
        try:
            return cls._evaluate_internal(
                tool_name=tool_name,
                arguments=arguments,
                user=user,
                agent_id=agent_id,
                prompt_context=prompt_context
            )
        except Exception as e:
            # FAIL-CLOSED DEFAULT: Deny access on unexpected evaluation error
            return AIPolicyDecision(
                decision="BLOCK",
                risk_score=100,
                risk_level="CRITICAL",
                reason=f"Security Gateway Fail-Closed default-deny triggered: {str(e)}",
                is_fail_closed=True,
                prompt_injection_signal=False,
                dlp_violation=False,
                sanitized_arguments={},
                requires_confirmation=False
            )

    @classmethod
    def _evaluate_internal(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        user: Dict[str, Any],
        agent_id: Optional[str],
        prompt_context: Optional[str]
    ) -> AIPolicyDecision:
        now = now_iso()
        user_role = user.get("role", "operator")
        user_id = str(user.get("id") or user.get("sub") or "user-operator")

        # 1. Global Kill Switch & Emergency State Check
        with connect() as db:
            cfg = db.execute("SELECT * FROM firewall_three_layer_config ORDER BY id DESC LIMIT 1").fetchone()
            if cfg and cfg["ai_kill_switch_active"] == 1:
                cls._record_event(
                    agent_id=agent_id or "unknown",
                    user_id=user_id,
                    tool_name=tool_name,
                    decision="BLOCK",
                    risk_score=100,
                    risk_level="CRITICAL",
                    reason="Global AI Agent Kill Switch is ACTIVE. All tool execution is suspended.",
                    prompt_inj=0,
                    dlp=0,
                    fail_closed=0,
                    args=arguments
                )
                return AIPolicyDecision(
                    decision="BLOCK",
                    risk_score=100,
                    risk_level="CRITICAL",
                    reason="Global AI Agent Kill Switch is ACTIVE. All tool execution is suspended.",
                    sanitized_arguments=arguments
                )

            # 2. Agent Status & Quarantine Verification
            if agent_id and agent_id != "agent-jarvis-orchestrator":
                agent = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
                if agent:
                    if agent["status"] in ("KILLED", "SUSPENDED"):
                        reason = f"Target Agent '{agent_id}' is in {agent['status']} state and quarantined."
                        cls._record_event(
                            agent_id=agent_id,
                            user_id=user_id,
                            tool_name=tool_name,
                            decision="BLOCK",
                            risk_score=100,
                            risk_level="CRITICAL",
                            reason=reason,
                            prompt_inj=0,
                            dlp=0,
                            fail_closed=0,
                            args=arguments
                        )
                        return AIPolicyDecision(
                            decision="BLOCK",
                            risk_score=100,
                            risk_level="CRITICAL",
                            reason=reason,
                            sanitized_arguments=arguments
                        )

        # 3. Tool Registration & Schema Validation
        from ..jarvis.jarvis_tools import TOOL_REGISTRY
        if tool_name not in TOOL_REGISTRY:
            return AIPolicyDecision(
                decision="BLOCK",
                risk_score=90,
                risk_level="CRITICAL",
                reason=f"Unregistered tool invocation attempt: '{tool_name}'",
                sanitized_arguments=arguments
            )

        tool_meta = TOOL_REGISTRY[tool_name]
        schema_model = TOOL_SCHEMA_MAP.get(tool_name)
        if schema_model:
            try:
                validated_obj = schema_model(**(arguments or {}))
                sanitized_args = validated_obj.model_dump()
            except ValidationError as ve:
                err_details = "; ".join([f"{err['loc']}: {err['msg']}" for err in ve.errors()])
                reason = f"Strict argument schema validation failed for '{tool_name}': {err_details}"
                cls._record_event(
                    agent_id=agent_id or "unknown",
                    user_id=user_id,
                    tool_name=tool_name,
                    decision="BLOCK",
                    risk_score=85,
                    risk_level="HIGH",
                    reason=reason,
                    prompt_inj=0,
                    dlp=0,
                    fail_closed=0,
                    args=arguments
                )
                return AIPolicyDecision(
                    decision="BLOCK",
                    risk_score=85,
                    risk_level="HIGH",
                    reason=reason,
                    sanitized_arguments=arguments
                )
        else:
            sanitized_args = arguments.copy()

        # 4. Arbitrary Code & Shell Execution Prevention
        is_code_inj, inj_reason = cls.inspect_arbitrary_code_injection(sanitized_args)
        if is_code_inj:
            cls._record_event(
                agent_id=agent_id or "unknown",
                user_id=user_id,
                tool_name=tool_name,
                decision="BLOCK",
                risk_score=98,
                risk_level="CRITICAL",
                reason=inj_reason,
                prompt_inj=0,
                dlp=0,
                fail_closed=0,
                args=sanitized_args
            )
            return AIPolicyDecision(
                decision="BLOCK",
                risk_score=98,
                risk_level="CRITICAL",
                reason=inj_reason,
                sanitized_arguments=sanitized_args
            )

        # 5. Outbound DLP Exfiltration Check
        has_dlp, dlp_reason = cls.inspect_dlp(sanitized_args)
        if has_dlp:
            cls._record_event(
                agent_id=agent_id or "unknown",
                user_id=user_id,
                tool_name=tool_name,
                decision="BLOCK",
                risk_score=95,
                risk_level="CRITICAL",
                reason=dlp_reason,
                prompt_inj=0,
                dlp=1,
                fail_closed=0,
                args=sanitized_args
            )
            return AIPolicyDecision(
                decision="BLOCK",
                risk_score=95,
                risk_level="CRITICAL",
                reason=dlp_reason,
                dlp_violation=True,
                sanitized_arguments=sanitized_args
            )

        # 6. Prompt Injection Defense Signal
        prompt_signal = False
        if prompt_context:
            inj_result = inspect_prompt(prompt_context)
            if inj_result.get("is_injection") and inj_result.get("confidence", 0) > 0.85:
                prompt_signal = True
                reason = "High-confidence prompt injection heuristic detected in prompt context"
                cls._record_event(
                    agent_id=agent_id or "unknown",
                    user_id=user_id,
                    tool_name=tool_name,
                    decision="BLOCK",
                    risk_score=90,
                    risk_level="CRITICAL",
                    reason=reason,
                    prompt_inj=1,
                    dlp=0,
                    fail_closed=0,
                    args=sanitized_args
                )
                return AIPolicyDecision(
                    decision="BLOCK",
                    risk_score=90,
                    risk_level="CRITICAL",
                    reason=reason,
                    prompt_injection_signal=True,
                    sanitized_arguments=sanitized_args
                )

        # 7. Destination Network Allowlist Check
        if tool_name == "trigger_network_scan_now":
            target_ip = sanitized_args.get("target_ip")
            if target_ip:
                with connect() as db:
                    from ..engines.network_scanner import validate_ip_in_approved_scope
                    scopes = [r[0] for r in db.execute("SELECT cidr_or_ip FROM approved_scan_scopes WHERE is_approved = 1").fetchall()]
                    excls = [r[0] for r in db.execute("SELECT ip_address FROM network_exclusions").fetchall()]
                    valid, scope_reason = validate_ip_in_approved_scope(target_ip, scopes, excls)
                    if not valid:
                        reason = f"Network Boundary Violation: {scope_reason}"
                        cls._record_event(
                            agent_id=agent_id or "unknown",
                            user_id=user_id,
                            tool_name=tool_name,
                            decision="BLOCK",
                            risk_score=85,
                            risk_level="HIGH",
                            reason=reason,
                            prompt_inj=0,
                            dlp=0,
                            fail_closed=0,
                            args=sanitized_args
                        )
                        return AIPolicyDecision(
                            decision="BLOCK",
                            risk_score=85,
                            risk_level="HIGH",
                            reason=reason,
                            sanitized_arguments=sanitized_args
                        )

        # 8. Least-Privilege Role Authorization Check
        required_roles = tool_meta.get("allowed_roles", ["admin", "security_analyst", "operator", "auditor"])
        if user_role != "admin" and user_role not in required_roles:
            reason = f"User role '{user_role}' is not authorized for tool '{tool_name}'. Allowed: {', '.join(required_roles)}"
            cls._record_event(
                agent_id=agent_id or "unknown",
                user_id=user_id,
                tool_name=tool_name,
                decision="BLOCK",
                risk_score=75,
                risk_level="HIGH",
                reason=reason,
                prompt_inj=0,
                dlp=0,
                fail_closed=0,
                args=sanitized_args
            )
            return AIPolicyDecision(
                decision="BLOCK",
                risk_score=75,
                risk_level="HIGH",
                reason=reason,
                sanitized_arguments=sanitized_args
            )

        # 9. Sensitive Action Confirmation (Require Human Approval)
        if tool_name in REQUIRE_APPROVAL_TOOLS:
            risk = 85 if tool_name == "prepare_kill_switch" else 70
            reason = f"Tool '{tool_name}' performs high-impact or state-altering operations requiring explicit human approval."
            cls._record_event(
                agent_id=agent_id or "unknown",
                user_id=user_id,
                tool_name=tool_name,
                decision="REQUIRE_HUMAN_APPROVAL",
                risk_score=risk,
                risk_level="HIGH" if risk < 80 else "CRITICAL",
                reason=reason,
                prompt_inj=0,
                dlp=0,
                fail_closed=0,
                args=sanitized_args
            )
            return AIPolicyDecision(
                decision="REQUIRE_HUMAN_APPROVAL",
                risk_score=risk,
                risk_level="HIGH" if risk < 80 else "CRITICAL",
                reason=reason,
                requires_confirmation=True,
                sanitized_arguments=sanitized_args
            )

        # 10. Default Allow for Verified Read-Only or Low-Risk Telemetry Tools
        cls._record_event(
            agent_id=agent_id or "unknown",
            user_id=user_id,
            tool_name=tool_name,
            decision="ALLOW",
            risk_score=15,
            risk_level="LOW",
            reason="Authorized low-risk telemetry query validated against zero-trust schema.",
            prompt_inj=0,
            dlp=0,
            fail_closed=0,
            args=sanitized_args
        )
        return AIPolicyDecision(
            decision="ALLOW",
            risk_score=15,
            risk_level="LOW",
            reason="Authorized low-risk telemetry query validated against zero-trust schema.",
            sanitized_arguments=sanitized_args
        )

    @staticmethod
    def _record_event(
        agent_id: str,
        user_id: str,
        tool_name: str,
        decision: str,
        risk_score: int,
        risk_level: str,
        reason: str,
        prompt_inj: int,
        dlp: int,
        fail_closed: int,
        args: Dict[str, Any]
    ) -> None:
        """Stores evaluation result in DB and cryptographically chained audit log."""
        try:
            now = now_iso()
            # Redact arguments before storage
            redacted_str = redact_sensitive_string(json.dumps(args))
            with connect() as db:
                db.execute(
                    """INSERT INTO firewall_ai_events (
                        agent_id, user_id, tool_name, decision, risk_score, risk_level,
                        reason, prompt_injection_signal, dlp_violation, is_fail_closed,
                        sanitized_args, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        agent_id, user_id, tool_name, decision, risk_score, risk_level,
                        reason, prompt_inj, dlp, fail_closed, redacted_str, now
                    )
                )

                # Record cryptographically chained audit entry
                record_audit_entry(
                    db=db,
                    actor=f"AI-FIREWALL:{agent_id}",
                    action=f"AI_TOOL_POLICY_{decision}",
                    resource=f"tool:{tool_name}",
                    details={
                        "decision": decision,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "reason": reason,
                        "prompt_injection_signal": bool(prompt_inj),
                        "dlp_violation": bool(dlp),
                        "is_fail_closed": bool(fail_closed),
                        "user_id": user_id
                    }
                )
        except Exception:
            pass  # Logging error must never crash callers
