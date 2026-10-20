# backend/app/firewall/network_firewall.py
"""Layer 1: Network Firewall Engine (Linux nftables & UFW Integration)
Provides explicit inbound/outbound ruleset generation, SSH lockout prevention,
PostgreSQL access restrictions, syntax validation, rollback script generation,
and OS capability detection.
"""

import ipaddress
import json
import logging
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("agentshield.network_firewall")

class SSHLockoutRiskWarning(Exception):
    """Raised when proposed firewall rules would sever active administrative SSH access."""
    pass

class FirewallValidationError(Exception):
    """Raised when firewall ruleset configuration fails syntax or semantic validation."""
    pass


def detect_host_firewall_capabilities() -> Dict[str, Any]:
    """Inspects operating system, environment, and firewall utilities.
    Reports real enforcement capability honestly without false claims.
    """
    system_os = platform.system().lower()
    is_linux = system_os == "linux"
    
    nft_binary = shutil.which("nft")
    ufw_binary = shutil.which("ufw")
    iptables_binary = shutil.which("iptables")
    
    is_root = False
    if is_linux and hasattr(os, "geteuid"):
        is_root = os.geteuid() == 0

    can_enforce = is_linux and (is_root or os.environ.get("AGENTSHIELD_FW_SUDO") == "1") and (bool(nft_binary) or bool(ufw_binary))

    status_label = "ACTIVE" if can_enforce else "CONFIGURED_PREVIEW"
    limitations = []
    
    if not is_linux:
        limitations.append(f"Host OS is {platform.system()} (development workstation). Native packet filtering requires Linux netfilter/nftables kernel support.")
    if is_linux and not is_root:
        limitations.append("Process lacks root/CAP_NET_ADMIN privileges required to inspect or mutate netfilter tables directly.")
    if is_linux and not nft_binary and not ufw_binary:
        limitations.append("Neither 'nft' nor 'ufw' binaries were discovered in system PATH.")

    return {
        "os": platform.system(),
        "platform": platform.system(),
        "release": platform.release(),
        "is_linux": is_linux,
        "is_root_or_admin": is_root,
        "nft_available": bool(nft_binary),
        "ufw_available": bool(ufw_binary),
        "iptables_available": bool(iptables_binary),
        "real_enforcement_capable": can_enforce,
        "operational_status": status_label,
        "environment_type": "Docker / Container" if os.path.exists("/.dockerenv") else ("Linux Server" if is_linux else "Workstation Development Host"),
        "limitations": limitations,
        "details": "; ".join(limitations) if limitations else "Enforcement operational"
    }


def validate_management_access(
    management_cidrs: List[str],
    ssh_port: int,
    current_client_ip: Optional[str] = None,
    raise_on_error: bool = False
) -> Tuple[bool, str]:
    """Strictly validates management access to prevent catastrophic administrative lockout.
    Ensures SSH port is valid and current client IP / subnet is covered.
    Returns (is_valid, message).
    """
    if not (1 <= ssh_port <= 65535):
        err = f"Invalid SSH port: {ssh_port}. Must be between 1 and 65535."
        if raise_on_error:
            raise FirewallValidationError(err)
        return False, err

    if not management_cidrs:
        err = "CRITICAL LOCKOUT RISK: No management IPs/subnets configured! Applying this ruleset would completely lock out administrative access."
        if raise_on_error:
            raise SSHLockoutRiskWarning(err)
        return False, err

    parsed_networks = []
    for cidr in management_cidrs:
        try:
            parsed_networks.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
        except ValueError:
            err = f"Invalid management CIDR format: '{cidr}'"
            if raise_on_error:
                raise FirewallValidationError(err)
            return False, err

    # Check against current operator's IP if provided
    if current_client_ip and current_client_ip not in {"127.0.0.1", "localhost", "::1"}:
        try:
            client_addr = ipaddress.ip_address(current_client_ip)
            is_covered = any(client_addr in net for net in parsed_networks)
            if not is_covered:
                err = (
                    f"CRITICAL LOCKOUT HAZARD: Operator's current IP ({current_client_ip}) is NOT in the proposed management CIDR allowlist! "
                    "Applying these rules would immediately terminate your administrative connection."
                )
                if raise_on_error:
                    raise SSHLockoutRiskWarning(err)
                return False, err
        except ValueError:
            pass

    return True, "Management access validated successfully: SSH lockout prevented."


def generate_nftables_ruleset(
    management_cidrs: Optional[List[str]] = None,
    ssh_port: int = 22,
    app_ports: Optional[List[int]] = None,
    postgres_port: int = 5432,
    postgres_allowed_subnets: Optional[List[str]] = None,
    log_dropped: bool = True,
    management_ips: Optional[List[str]] = None
) -> str:
    """Generates an atomic, robust, zero-trust nftables.conf ruleset.
    Enforces default-drop inbound policy, stateful connection tracking,
    PostgreSQL network isolation, and explicit management allowlists.
    """
    cidrs = management_cidrs or management_ips or ["127.0.0.1/32"]
    app_ports = app_ports or [80, 443, 8000, 5173]
    postgres_allowed_subnets = postgres_allowed_subnets or ["127.0.0.1/32", "172.20.0.0/16"]

    # Validate SSH safety
    validate_management_access(cidrs, ssh_port, raise_on_error=True)

    mgmt_elements = ", ".join(cidrs)
    app_port_elements = ", ".join(str(p) for p in app_ports)
    pg_subnet_elements = ", ".join(postgres_allowed_subnets)

    ruleset = f"""#!/usr/sbin/nft -f
# AgentShield Enterprise Zero-Trust Host Firewall
# Generated on: {datetime.now(timezone.utc).isoformat()}
# Policy: Default DROP Inbound, Default DROP Forward, Stateful Outbound

flush ruleset

table inet agentshield {{
    # Named Sets for Dynamic Allowlisting & High-Performance Kernel Lookups
    set management_subnets {{
        type ipv4_addr
        flags interval
        elements = {{ {mgmt_elements} }}
    }}

    set postgres_allowed_sources {{
        type ipv4_addr
        flags interval
        elements = {{ {pg_subnet_elements} }}
    }}

    set web_app_ports {{
        type inet_service
        elements = {{ {app_port_elements} }}
    }}

    chain inbound {{
        type filter hook input priority 0; policy drop;

        # 1. Accept all loopback traffic
        iif "lo" accept comment "Allow loopback interface"

        # 2. Accept established and related connection states
        ct state established,related accept comment "Allow established/related connections"

        # 3. Drop invalid connection packets early
        ct state invalid drop comment "Drop invalid packet states"

        # 4. Restrict Administrative SSH (Lockout Protected)
        tcp dport {ssh_port} ip saddr @management_subnets ct state new accept comment "Allow SSH from approved management enclaves only"

        # 5. Allow Frontend & Web API Ingress
        tcp dport @web_app_ports ct state new accept comment "Allow AgentShield web app and API reverse proxy traffic"

        # 6. PostgreSQL Enclave Protection (NEVER Public)
        tcp dport {postgres_port} ip saddr @postgres_allowed_sources ct state new accept comment "Allow PostgreSQL strictly from internal application subnet"
        tcp dport {postgres_port} drop comment "Block unauthorized PostgreSQL access attempts"

        # 7. ICMP Ping Rate Limited
        ip protocol icmp icmp type echo-request limit rate 5/second accept comment "Rate-limited ICMP ping"

        # 8. Log and Drop all other unauthorized traffic
        {"log prefix \"[AgentShield-NET-DROP] \" flags all counter drop comment \"Log and drop unauthorized inbound packets\"" if log_dropped else "counter drop"}
    }}

    chain forward {{
        type filter hook forward priority 0; policy drop;
        comment "Default drop all forwarded routed traffic unless explicitly bridged"
    }}

    chain outbound {{
        type filter hook output priority 0; policy accept;

        # Stateful outbound tracking
        ct state established,related accept comment "Allow established outgoing connections"
        
        # Outbound DNS (TCP/UDP 53)
        udp dport 53 accept comment "Outbound DNS resolution"
        tcp dport 53 accept comment "Outbound DNS resolution"

        # Outbound NTP time sync
        udp dport 123 accept comment "Outbound NTP network time sync"

        # Outbound HTTPS for authorized external AI model APIs
        tcp dport {{ 80, 443 }} accept comment "Outbound HTTP/HTTPS for authorized external APIs"
    }}
}}
"""
    return ruleset


def generate_ufw_commands(
    management_cidrs: Optional[List[str]] = None,
    ssh_port: int = 22,
    app_ports: Optional[List[int]] = None,
    postgres_port: int = 5432,
    postgres_allowed_subnets: Optional[List[str]] = None,
    management_ips: Optional[List[str]] = None
) -> List[str]:
    """Generates an explicit sequence of UFW commands adhering to zero-trust principles."""
    cidrs = management_cidrs or management_ips or ["127.0.0.1/32"]
    app_ports = app_ports or [80, 443, 8000, 5173]
    postgres_allowed_subnets = postgres_allowed_subnets or ["127.0.0.1", "172.20.0.0/16"]

    validate_management_access(cidrs, ssh_port, raise_on_error=True)

    cmds = [
        "# Reset UFW to safe default-deny baseline",
        "ufw --force reset",
        "ufw default deny incoming",
        "ufw default allow outgoing",
        "",
        "# 1. Allow Loopback interface",
        "ufw allow in on lo to any",
        "",
        "# 2. Management Access (SSH Lockout Protected)",
    ]

    for cidr in cidrs:
        cmds.append(f"ufw allow from {cidr} to any port {ssh_port} proto tcp comment 'AgentShield Admin SSH'")

    cmds.append("")
    cmds.append("# 3. Application Web & API Ingress")
    for port in app_ports:
        cmds.append(f"ufw allow {port}/tcp comment 'AgentShield App Port {port}'")

    cmds.append("")
    cmds.append("# 4. PostgreSQL Isolated Access (Restricted to internal app subnets)")
    for subnet in postgres_allowed_subnets:
        cmds.append(f"ufw allow from {subnet} to any port {postgres_port} proto tcp comment 'PostgreSQL internal access'")
    cmds.append(f"ufw deny {postgres_port}/tcp comment 'Block public access to PostgreSQL'")

    cmds.append("")
    cmds.append("# 5. Enable logging & activate")
    cmds.append("ufw logging on")
    cmds.append("ufw --force enable")

    return cmds


def generate_firewall_rollback_script(firewall_type: str = "nftables") -> str:
    """Generates an immediate safety rollback bash script for emergency recovery."""
    if firewall_type == "ufw":
        return """#!/usr/bin/env bash
# AgentShield UFW Emergency Rollback Script
set -euo pipefail

echo "[AgentShield] Rolling back UFW firewall..."
ufw --force reset
ufw default allow incoming
ufw default allow outgoing
ufw --force disable
echo "[AgentShield] UFW disabled. All host ports reverted to default open access."
"""
    else:
        return """#!/usr/bin/env bash
# AgentShield nftables Emergency Rollback Script
set -euo pipefail

echo "[AgentShield] Rolling back nftables ruleset to baseline open state..."
nft flush ruleset
cat << 'EOF' | nft -f -
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
echo "[AgentShield] nftables flushed to default-accept state. Recovery complete."
"""


def preview_network_firewall_configuration(
    config_dict: Optional[Dict[str, Any]] = None,
    management_ips: Optional[List[str]] = None,
    postgres_allowed_subnets: Optional[List[str]] = None,
    app_ports: Optional[List[int]] = None,
    ssh_port: int = 22,
    firewall_type: str = "nftables"
) -> Dict[str, Any]:
    """Compiles and previews complete proposed network firewall ruleset,
    performing safety audits on SSH lockout and PostgreSQL exposure.
    """
    if config_dict:
        fw_type = config_dict.get("net_firewall_type", firewall_type)
        mgmt_raw = config_dict.get("net_management_ips")
        mgmt_ips = json.loads(mgmt_raw) if isinstance(mgmt_raw, str) else (mgmt_raw or ["127.0.0.1/32"])
        ssh_port = int(config_dict.get("net_ssh_port", ssh_port))
        app_raw = config_dict.get("net_app_ports")
        app_ports = json.loads(app_raw) if isinstance(app_raw, str) else (app_raw or [80, 443, 8000, 5173])
        pg_port = int(config_dict.get("net_postgres_port", 5432))
        pg_raw = config_dict.get("net_postgres_allowed_subnets")
        pg_subnets = json.loads(pg_raw) if isinstance(pg_raw, str) else (pg_raw or ["127.0.0.1/32", "172.20.0.0/16"])
    else:
        fw_type = firewall_type
        mgmt_ips = management_ips or ["127.0.0.1/32"]
        pg_port = 5432
        pg_subnets = postgres_allowed_subnets or ["127.0.0.1/32", "172.20.0.0/16"]
        app_ports = app_ports or [80, 443, 8000, 5173]

    # Perform safety lockout audit
    lockout_safe, lockout_msg = validate_management_access(mgmt_ips, ssh_port, raise_on_error=False)

    # Check postgres public exposure
    pg_exposed_publicly = any(sub in {"0.0.0.0/0", "::/0", "*"} for sub in pg_subnets)

    # Generate ruleset preview
    nft_ruleset = generate_nftables_ruleset(mgmt_ips, ssh_port, app_ports, pg_port, pg_subnets)
    ufw_cmds = generate_ufw_commands(mgmt_ips, ssh_port, app_ports, pg_port, pg_subnets)
    ufw_text = "\n".join(ufw_cmds)
    rollback_script = generate_firewall_rollback_script(fw_type)
    capabilities = detect_host_firewall_capabilities()

    return {
        "firewall_type": fw_type,
        "status": "CONFIGURED_PREVIEW" if not capabilities["real_enforcement_capable"] else "ACTIVE",
        "host_platform": capabilities.get("platform", "Unknown"),
        "real_enforcement_capable": capabilities["real_enforcement_capable"],
        "nftables_conf": nft_ruleset,
        "ufw_script": ufw_text,
        "rollback_script": rollback_script,
        "ruleset_preview": nft_ruleset if fw_type == "nftables" else ufw_text,
        "safety_checks": {
            "operator_lockout_safe": lockout_safe,
            "postgres_public_exposure_blocked": not pg_exposed_publicly,
            "ssh_port": ssh_port,
            "management_cidrs_count": len(mgmt_ips),
            "message": lockout_msg
        },
        "ssh_lockout_safe": lockout_safe,
        "lockout_warning": lockout_msg if not lockout_safe else None,
        "postgres_isolated": not pg_exposed_publicly,
        "postgres_allowed_subnets": pg_subnets,
        "management_cidrs": mgmt_ips,
        "host_capabilities": capabilities,
        "telemetry_type": "PREVIEW_STAGED_RULES" if not capabilities["real_enforcement_capable"] else "ACTIVE_KERNEL_FILTER"
    }
