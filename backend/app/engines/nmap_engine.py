# backend/app/engines/nmap_engine.py
"""Nmap Integration & Authorized Network Discovery Engine.
Provides safe, scoped network discovery using Nmap CLI if installed, with automatic
fallback to AgentShield's native asynchronous socket probe engine.
Enforces strict target authorization, RFC 1918 / loopback boundaries, and safe discovery profiles.
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set

from .network_scanner import COMMON_PORT_SERVICES, HIGH_RISK_PORTS

logger = logging.getLogger("agentshield.nmap_engine")

# Standard Windows installation paths for Nmap
NMAP_STANDARD_PATHS = [
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Nmap\nmap.exe"
]

# Supported safe discovery profiles with documented bounded arguments
SAFE_SCAN_PROFILES = {
    "ping_sweep": {
        "name": "Host Discovery (Ping Sweep)",
        "description": "Fast ICMP/ARP ping scan to determine live reachable hosts without port probing.",
        "nmap_args": ["-sn", "-T3", "--max-retries", "1", "--host-timeout", "10s"],
        "ports": []
    },
    "quick_ports": {
        "name": "Quick Port Discovery",
        "description": "Scans the top standard enterprise service ports with non-intrusive TCP connection checks.",
        "nmap_args": ["-F", "-T3", "--max-retries", "1", "--host-timeout", "20s"],
        "ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8000, 8080, 8443]
    },
    "service_discovery": {
        "name": "Service & Version Detection",
        "description": "Probes open ports to identify listening daemon banners, versions, and application protocols.",
        "nmap_args": ["-sV", "--version-light", "-F", "-T3", "--max-retries", "1", "--host-timeout", "30s"],
        "ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8000, 8080, 8443]
    }
}


def find_nmap_executable() -> Optional[str]:
    """Finds nmap.exe in system PATH or standard Windows directories."""
    which_path = shutil.which("nmap")
    if which_path and os.path.exists(which_path):
        return which_path
    for p in NMAP_STANDARD_PATHS:
        if os.path.exists(p):
            return p
    return None


def get_nmap_version(nmap_path: str) -> Optional[str]:
    """Executes nmap --version to retrieve version string."""
    try:
        proc = subprocess.run(
            [nmap_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False
        )
        if proc.returncode == 0 and proc.stdout:
            first_line = proc.stdout.splitlines()[0]
            return first_line.strip()
    except Exception:
        pass
    return None


def validate_target_scope(
    target_str: str,
    user_confirmed: bool,
    allow_public: bool = False
) -> Tuple[bool, Optional[str], List[str]]:
    """Strictly validates target IP or CIDR against Zero-Trust network security boundaries.
    - Rejects missing user confirmation.
    - Prohibits public internet scanning unless explicitly permitted by policy.
    - Prevents shell metacharacters and malformed IP specs.
    Returns: (is_valid, error_message, expanded_sample_ips)
    """
    if not user_confirmed:
        return False, "Target authorization unverified: You must confirm authorization to scan this target.", []

    cleaned = (target_str or "").strip()
    if not cleaned:
        return False, "Target specification cannot be empty.", []

    # Prohibit dangerous shell metacharacters
    if any(c in cleaned for c in ";|&`$<>\"\n\r\t\\ "):
        return False, "Target contains illegal characters.", []

    try:
        # Check if single IP or CIDR
        if "/" in cleaned:
            network = ipaddress.ip_network(cleaned, strict=False)
            if network.version != 4:
                return False, "Only IPv4 addresses and subnets are supported.", []

            # Enforce max subnet size (/24 max = 256 hosts) to prevent denial of service
            if network.prefixlen < 24:
                return False, f"Subnet /{network.prefixlen} is too large. Max permitted scope is /24 (256 hosts).", []

            is_safe_enclave = network.is_private or network.is_loopback
            if not is_safe_enclave and not allow_public:
                return False, f"Public internet scanning blocked: '{cleaned}' is not an authorized private (RFC 1918) or loopback scope.", []

            # Sample first 20 target IPs for reporting
            target_ips = [str(ip) for ip in list(network.hosts())[:20]]
            return True, None, target_ips
        else:
            ip_obj = ipaddress.ip_address(cleaned)
            if ip_obj.version != 4:
                return False, "Only IPv4 addresses are supported.", []

            is_safe_enclave = ip_obj.is_private or ip_obj.is_loopback
            if not is_safe_enclave and not allow_public:
                return False, f"Public internet scanning blocked: Target IP '{cleaned}' is an external public address.", []

            return True, None, [str(ip_obj)]

    except ValueError:
        # Check if valid hostname like 'localhost'
        if cleaned.lower() in ("localhost", "127.0.0.1"):
            return True, None, ["127.0.0.1"]
        return False, f"Invalid IP address or CIDR format: '{cleaned}'. Examples: '127.0.0.1', '192.168.1.15', '192.168.1.0/24'.", []


class NetworkDiscoveryEngine:
    """Executes authorized discovery scans using Nmap or native socket engine fallback."""

    def get_tool_status(self) -> Dict[str, Any]:
        """Returns live installation and environment status for Nmap."""
        nmap_path = find_nmap_executable()
        version_str = get_nmap_version(nmap_path) if nmap_path else None

        return {
            "nmap_installed": nmap_path is not None,
            "nmap_path": nmap_path,
            "nmap_version": version_str,
            "supported_profiles": list(SAFE_SCAN_PROFILES.keys()),
            "native_engine_ready": True
        }

    async def execute_scan(
        self,
        target: str,
        profile: str = "quick_ports",
        user_confirmed: bool = False,
        triggered_by: str = "admin"
    ) -> Dict[str, Any]:
        """Executes a bounded, safe discovery scan against an authorized target."""
        # 1. Scope & Authorization Validation
        valid, err_msg, sample_ips = validate_target_scope(target, user_confirmed)
        if not valid:
            return {
                "status": "BLOCKED",
                "error": err_msg,
                "target": target,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        selected_profile = SAFE_SCAN_PROFILES.get(profile, SAFE_SCAN_PROFILES["quick_ports"])
        nmap_path = find_nmap_executable()

        started_at = datetime.now(timezone.utc).isoformat()
        start_mono = time.monotonic()

        # If Nmap is installed, use Nmap CLI with XML output parsing
        if nmap_path:
            return await self._execute_nmap_scan(
                nmap_path=nmap_path,
                target=target,
                profile_name=profile,
                profile_def=selected_profile,
                triggered_by=triggered_by,
                started_at=started_at,
                start_mono=start_mono
            )
        else:
            # Fallback to native asynchronous socket scanner
            return await self._execute_native_socket_scan(
                target=target,
                profile_name=profile,
                profile_def=selected_profile,
                triggered_by=triggered_by,
                started_at=started_at,
                start_mono=start_mono
            )

    async def _execute_nmap_scan(
        self,
        nmap_path: str,
        target: str,
        profile_name: str,
        profile_def: Dict[str, Any],
        triggered_by: str,
        started_at: str,
        start_mono: float
    ) -> Dict[str, Any]:
        """Runs Nmap via subprocess with XML output (-oX -) and strict timeouts."""
        cmd = [nmap_path, "-oX", "-"] + profile_def["nmap_args"] + [target]
        timeout_sec = 40.0

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {
                "status": "TIMEOUT",
                "error": f"Nmap scan exceeded maximum allowable execution time ({timeout_sec}s). Scan terminated.",
                "target": target,
                "profile": profile_name,
                "tool_used": "nmap",
                "hosts": [],
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "error": f"Failed to execute Nmap process: {str(e)}",
                "target": target,
                "profile": profile_name,
                "tool_used": "nmap",
                "hosts": [],
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }

        elapsed_ms = round((time.monotonic() - start_mono) * 1000, 2)
        xml_text = stdout.decode("utf-8", errors="ignore")
        hosts = self._parse_nmap_xml(xml_text)

        # Generate risk flags
        risk_findings = self._extract_risk_findings(hosts)

        return {
            "status": "COMPLETED",
            "tool_used": "nmap",
            "nmap_installed": True,
            "target": target,
            "profile": profile_name,
            "profile_name": profile_def["name"],
            "hosts_scanned": len(hosts) or (1 if "/" not in target else 254),
            "hosts_up": len(hosts),
            "hosts": hosts,
            "risk_findings": risk_findings,
            "scan_duration_ms": elapsed_ms,
            "triggered_by": triggered_by,
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat()
        }

    def _parse_nmap_xml(self, xml_text: str) -> List[Dict[str, Any]]:
        """Parses Nmap XML output (-oX -) into structured host and service objects."""
        hosts = []
        if not xml_text.strip():
            return hosts

        try:
            root = ET.fromstring(xml_text)
            for host_elem in root.findall("host"):
                # Check status
                status_elem = host_elem.find("status")
                if status_elem is not None and status_elem.get("state") != "up":
                    continue

                # IP Address
                addr_elem = host_elem.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    continue
                ip_str = addr_elem.get("addr")

                # Hostnames
                hostnames = []
                hn_elem = host_elem.find("hostnames")
                if hn_elem is not None:
                    for h in hn_elem.findall("hostname"):
                        hostnames.append(h.get("name"))
                hostname = hostnames[0] if hostnames else None

                # Open Ports & Services
                ports = []
                ports_elem = host_elem.find("ports")
                if ports_elem is not None:
                    for p in ports_elem.findall("port"):
                        state_elem = p.find("state")
                        if state_elem is None or state_elem.get("state") != "open":
                            continue

                        port_id = int(p.get("portid"))
                        proto = p.get("protocol", "tcp")

                        srv_elem = p.find("service")
                        service_name = srv_elem.get("name", "unknown") if srv_elem is not None else COMMON_PORT_SERVICES.get(port_id, "unknown")
                        product = srv_elem.get("product", "") if srv_elem is not None else ""
                        version = srv_elem.get("version", "") if srv_elem is not None else ""
                        banner = f"{product} {version}".strip() or service_name

                        ports.append({
                            "port": port_id,
                            "protocol": proto,
                            "state": "OPEN",
                            "service_name": service_name,
                            "banner": banner
                        })

                hosts.append({
                    "ip_address": ip_str,
                    "hostname": hostname,
                    "status": "UP",
                    "open_ports": ports,
                    "open_port_count": len(ports)
                })
        except Exception as e:
            logger.warning(f"Error parsing Nmap XML: {e}")

        return hosts

    async def _execute_native_socket_scan(
        self,
        target: str,
        profile_name: str,
        profile_def: Dict[str, Any],
        triggered_by: str,
        started_at: str,
        start_mono: float
    ) -> Dict[str, Any]:
        """Fallback asynchronous TCP socket scanner with multi-port concurrency and banner grabs."""
        target_ports = profile_def["ports"] or [80, 443, 8000, 22, 21, 3389]
        target_ips = []

        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            target_ips = [str(ip) for ip in list(net.hosts())[:32]]  # bounded to 32 hosts for fallback
        else:
            target_ips = [target]

        hosts = []
        for ip in target_ips:
            open_ports = []
            is_host_up = False

            # Probe each port asynchronously with 0.8s timeout
            for port in target_ports:
                port_result = await self._probe_single_socket_port(ip, port)
                if port_result:
                    is_host_up = True
                    open_ports.append(port_result)

            # Try reverse DNS resolution
            hostname = None
            if is_host_up:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass

                hosts.append({
                    "ip_address": ip,
                    "hostname": hostname,
                    "status": "UP",
                    "open_ports": open_ports,
                    "open_port_count": len(open_ports)
                })

        elapsed_ms = round((time.monotonic() - start_mono) * 1000, 2)
        risk_findings = self._extract_risk_findings(hosts)

        return {
            "status": "COMPLETED",
            "tool_used": "native_socket_engine",
            "nmap_installed": False,
            "target": target,
            "profile": profile_name,
            "profile_name": profile_def["name"],
            "hosts_scanned": len(target_ips),
            "hosts_up": len(hosts),
            "hosts": hosts,
            "risk_findings": risk_findings,
            "scan_duration_ms": elapsed_ms,
            "triggered_by": triggered_by,
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "notice": "Scan executed using AgentShield Native Async Socket Engine (Nmap is not installed on this system)."
        }

    async def _probe_single_socket_port(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Asynchronously probes a single TCP port and grabs banner if possible."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=0.8
            )
            banner = COMMON_PORT_SERVICES.get(port, "unknown")
            try:
                # Send HTTP HEAD or newline to entice banner
                if port in (80, 8080, 8000):
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                else:
                    writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(128), timeout=0.5)
                if data:
                    raw_banner = data.decode("utf-8", errors="ignore").strip().splitlines()[0]
                    banner = raw_banner[:60] if raw_banner else banner
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            return {
                "port": port,
                "protocol": "tcp",
                "state": "OPEN",
                "service_name": COMMON_PORT_SERVICES.get(port, "unknown"),
                "banner": banner
            }
        except Exception:
            return None

    def _extract_risk_findings(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generates risk alerts for high-risk ports, exposed databases, or cleartext protocols."""
        findings = []
        for h in hosts:
            ip = h.get("ip_address", "")
            for p in h.get("open_ports", []):
                port = p.get("port")
                if port in HIGH_RISK_PORTS:
                    sev, desc = HIGH_RISK_PORTS[port]
                    findings.append({
                        "severity": sev,
                        "ip_address": ip,
                        "port": port,
                        "service": p.get("service_name"),
                        "description": desc
                    })
        return findings


# Global singleton instance
network_discovery_engine = NetworkDiscoveryEngine()


if __name__ == "__main__":
    import sys

    print("==================================================")
    print(" AgentShield - Network Discovery & Nmap Engine")
    print("==================================================")

    # 1. Tool Status
    status = network_discovery_engine.get_tool_status()
    print(f"[*] Nmap installed: {status['nmap_installed']}")
    if status["nmap_installed"]:
        print(f"[*] Nmap path:      {status['nmap_path']}")
        print(f"[*] Nmap version:   {status['nmap_version']}")
    else:
        print("[*] Engine mode:    Native Asynchronous Socket Fallback (Zero-Dependency)")
    print(f"[*] Profiles:       {', '.join(status['supported_profiles'])}")
    print("--------------------------------------------------")

    # 2. Target specification
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    profile = sys.argv[2] if len(sys.argv) > 2 else "quick_ports"
    print(f"[*] Target Scope:   {target}")
    print(f"[*] Scan Profile:   {profile}")
    print(f"[*] Authorization:  Verified (CLI Operator)")
    print("[*] Initiating scan...")

    # 3. Execute Scan
    result = asyncio.run(network_discovery_engine.execute_scan(
        target=target,
        profile=profile,
        user_confirmed=True,
        triggered_by="cli_operator"
    ))

    print("--------------------------------------------------")
    print(f"[+] Scan Status:    {result.get('status')}")
    print(f"[+] Tool Used:      {result.get('tool_used')}")
    print(f"[+] Duration:       {result.get('scan_duration_ms')} ms")
    print(f"[+] Hosts Up:       {result.get('hosts_up')} / {result.get('hosts_scanned')}")

    for host in result.get("hosts", []):
        print(f"\n[HOST] IP: {host.get('ip_address')} | Hostname: {host.get('hostname') or 'N/A'}")
        ports = host.get("open_ports", [])
        if ports:
            print(f"  Discovered {len(ports)} open port(s):")
            for p in ports:
                print(f"    - Port {p.get('port')}/{p.get('protocol')} [{p.get('state')}]: {p.get('service_name')} (Banner: {p.get('banner')})")
        else:
            print("  No open ports discovered in target profile.")

    findings = result.get("risk_findings", [])
    if findings:
        print(f"\n[!] Risk Findings ({len(findings)}):")
        for f in findings:
            print(f"    [{f.get('severity')}] Port {f.get('port')}: {f.get('description')}")
    else:
        print("\n[+] No high-risk security anomalies detected.")
    print("==================================================")

