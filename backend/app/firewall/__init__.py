# backend/app/firewall/__init__.py
"""
AgentShield Three-Layer Defensive Security Firewall Architecture

Layer 1: Network Firewall (Host & Network Boundary Protection via nftables/UFW generators & OS probe)
Layer 2: Application Firewall (ASGI WAF Middleware + OWASP CRS rules + ModSecurity proxy config)
Layer 3: AI Agent Security Firewall (Zero-Trust Policy Enforcement Gateway for Agent Tool Execution)
"""

from .network_firewall import (
    detect_host_firewall_capabilities,
    validate_management_access,
    generate_nftables_ruleset,
    generate_ufw_commands,
    generate_firewall_rollback_script,
    preview_network_firewall_configuration
)

from .app_firewall import (
    AppFirewallMiddleware,
    WAFRateLimiter,
    inspect_text_for_attacks,
    redact_sensitive_waf_payload
)

from .ai_firewall import (
    AIAgentSecurityGateway,
    AIPolicyDecision,
    TOOL_SCHEMA_MAP
)

__all__ = [
    # Layer 1
    "detect_host_firewall_capabilities",
    "validate_management_access",
    "generate_nftables_ruleset",
    "generate_ufw_commands",
    "generate_firewall_rollback_script",
    "preview_network_firewall_configuration",
    # Layer 2
    "AppFirewallMiddleware",
    "WAFRateLimiter",
    "inspect_text_for_attacks",
    "redact_sensitive_waf_payload",
    # Layer 3
    "AIAgentSecurityGateway",
    "AIPolicyDecision",
    "TOOL_SCHEMA_MAP"
]
