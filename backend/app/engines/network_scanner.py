# backend/app/engines/network_scanner.py
"""Continuous Network Monitoring & Authorized Scope Scanner Engine
Strictly validates approved IP ranges, enforces exclusions, executes non-disruptive
asynchronous TCP/socket sweeps, and compares findings against the security baseline.
"""

import asyncio
import ipaddress
import json
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple

COMMON_PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB / Active Directory",
    1433: "MS SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis In-Memory Store",
    8000: "HTTP / Alternate API",
    8080: "HTTP Proxy / Alternate Web",
    8443: "HTTPS Alternate",
    9090: "Prometheus Metrics",
    27017: "MongoDB"
}

HIGH_RISK_PORTS = {
    21: ("CRITICAL", "Unencrypted FTP file transfer service exposed"),
    23: ("CRITICAL", "Legacy cleartext Telnet management interface exposed"),
    445: ("HIGH", "Direct SMB file sharing / NetBIOS exposed to network"),
    3389: ("HIGH", "Remote Desktop Protocol (RDP) endpoint reachable"),
    6379: ("HIGH", "Redis in-memory database exposed without perimeter isolation"),
    27017: ("HIGH", "MongoDB NoSQL database port directly accessible")
}

class ScopeViolationError(Exception):
    """Raised when an operation targets an IP address outside authorized CIDR scope."""
    pass

class ExclusionViolationError(Exception):
    """Raised when an operation targets an explicitly excluded sensitive asset."""
    pass

class EmergencyStopTriggered(Exception):
    """Raised when an in-flight scan is aborted by the global emergency kill switch."""
    pass


def validate_ip_in_approved_scope(
    ip_str: str,
    approved_cidrs: List[str],
    excluded_ips: List[str]
) -> Tuple[bool, Optional[str]]:
    """Strictly checks whether a target IP is authorized within approved CIDRs and not excluded.
    Returns: (is_valid, rejection_reason)
    """
    try:
        target_ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'"

    # 1. Check exclusions first
    for exc in excluded_ips:
        try:
            if target_ip == ipaddress.ip_address(exc.strip()):
                return False, f"IP {ip_str} is explicitly listed in administrator exclusions"
        except ValueError:
            continue

    # 2. Check if inside ANY approved CIDR
    if not approved_cidrs:
        return False, "No approved scan scopes configured. Continuous discovery is locked down."

    matched_scope = False
    for cidr in approved_cidrs:
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
            if target_ip in network:
                matched_scope = True
                break
        except ValueError:
            continue

    if not matched_scope:
        return False, f"Target IP {ip_str} falls outside all authorized administrator CIDR ranges."

    return True, None


def expand_scope_to_target_ips(
    approved_cidrs: List[str],
    excluded_ips: List[str],
    max_hosts_per_scope: int = 254
) -> List[str]:
    """Expands configured CIDR scopes into a safe, bounded list of target IP addresses,
    filtering out exclusions, broadcast, and network identifier addresses.
    """
    valid_ips: List[str] = []
    excluded_set: Set[str] = {exc.strip() for exc in excluded_ips}

    for cidr in approved_cidrs:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            if net.num_addresses == 1:
                ip = str(net.network_address)
                if ip not in excluded_set and ip not in valid_ips:
                    valid_ips.append(ip)
            else:
                # Use net.hosts() to skip network address and broadcast
                count = 0
                for host in net.hosts():
                    ip = str(host)
                    if ip not in excluded_set and ip not in valid_ips:
                        valid_ips.append(ip)
                        count += 1
                        if count >= max_hosts_per_scope:
                            break
        except ValueError:
            continue

    return valid_ips


async def safe_tcp_port_probe(
    ip: str,
    port: int,
    timeout_seconds: float = 1.0
) -> Optional[Dict[str, Any]]:
    """Executes a safe, non-disruptive TCP connect probe to determine if port is open,
    measures connection latency, and attempts a non-intrusive banner preview.
    """
    start_time = time.perf_counter()
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout_seconds)
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        banner = ""
        service_name = COMMON_PORT_SERVICES.get(port, f"TCP/{port}")

        # Non-intrusive banner peek
        try:
            if port in {80, 8000, 8080}:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                await writer.drain()
            elif port in {21, 22, 25, 110}:
                # Servers typically speak first on connect
                pass
            
            # Read first chunk with tight 300ms timeout
            banner_bytes = await asyncio.wait_for(reader.read(256), timeout=0.3)
            if banner_bytes:
                banner = banner_bytes.decode("utf-8", errors="replace").strip().split("\r\n")[0][:120]
        except Exception:
            banner = ""

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        return {
            "port": port,
            "protocol": "tcp",
            "service_name": service_name,
            "banner": banner,
            "latency_ms": latency_ms,
            "state": "OPEN"
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def probe_host(
    ip: str,
    target_ports: List[int],
    timeout_seconds: float = 1.0,
    semaphore: Optional[asyncio.Semaphore] = None,
    emergency_stop_check: Optional[callable] = None
) -> Dict[str, Any]:
    """Scans configured target ports for an individual host with concurrency bounds and emergency stop checks."""
    if emergency_stop_check and emergency_stop_check():
        raise EmergencyStopTriggered("Scan cancelled: Global emergency stop engaged")

    hostname = f"host-{ip.replace('.', '-')}.internal"

    open_ports: List[Dict[str, Any]] = []
    host_latency = 999.0

    async def _probe_single(p: int):
        if emergency_stop_check and emergency_stop_check():
            raise EmergencyStopTriggered("Scan cancelled: Global emergency stop engaged")

        if semaphore:
            async with semaphore:
                return await safe_tcp_port_probe(ip, p, timeout_seconds=timeout_seconds)
        else:
            return await safe_tcp_port_probe(ip, p, timeout_seconds=timeout_seconds)

    tasks = [_probe_single(p) for p in target_ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, Exception):
            if isinstance(res, EmergencyStopTriggered):
                raise res
            continue
        if res and isinstance(res, dict) and res.get("state") == "OPEN":
            open_ports.append(res)
            if res.get("latency_ms", 999.0) < host_latency:
                host_latency = res["latency_ms"]

    is_reachable = len(open_ports) > 0
    if is_reachable:
        try:
            dns_res = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyaddr, ip),
                timeout=0.2
            )
            hostname = dns_res[0]
        except Exception:
            pass

    return {
        "ip_address": ip,
        "hostname": hostname,
        "status": "REACHABLE" if is_reachable else "OFFLINE",
        "open_ports": open_ports,
        "latency_ms": host_latency if is_reachable else None
    }


def compare_with_baseline(
    scan_results: List[Dict[str, Any]],
    baseline_assets: Dict[str, Dict[str, Any]],
    baseline_services: Dict[str, Set[int]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
    """Compares current scan observations against stored baseline.
    Generates security alerts, calculates detected changes, and strictly separates
    observed facts from suspected threats.
    
    Returns: (alerts, asset_updates, total_changes_count)
    """
    alerts: List[Dict[str, Any]] = []
    asset_updates: List[Dict[str, Any]] = []
    changes_count = 0

    for host_data in scan_results:
        ip = host_data["ip_address"]
        is_reachable = host_data["status"] == "REACHABLE"
        open_ports = host_data["open_ports"]
        current_port_numbers = {p["port"] for p in open_ports}

        known_asset = baseline_assets.get(ip)
        is_in_baseline = bool(known_asset and known_asset.get("in_baseline"))

        if is_reachable:
            # 1. New Host Discovery
            if not known_asset:
                changes_count += 1
                alerts.append({
                    "alert_type": "NEW_HOST_DISCOVERED",
                    "severity": "MEDIUM",
                    "title": f"Newly Discovered Unbaselined Host: {ip}",
                    "observed_fact": f"Host {ip} responded to TCP sweep with {len(open_ports)} open port(s) [Ports: {sorted(list(current_port_numbers))}].",
                    "suspected_threat": "Unregistered host detected inside approved network segment. Possible rogue agent node, shadow asset, or lateral pivot point.",
                    "target_ip": ip,
                    "target_port": open_ports[0]["port"] if open_ports else None,
                    "evidence_json": {
                        "ip": ip,
                        "hostname": host_data.get("hostname"),
                        "open_ports": [p["port"] for p in open_ports],
                        "latency_ms": host_data.get("latency_ms")
                    }
                })

            # 2. Unexpected Port Checks
            expected_ports = baseline_services.get(ip, set())
            for port_info in open_ports:
                p_num = port_info["port"]
                svc_name = port_info["service_name"]

                if p_num not in expected_ports:
                    changes_count += 1
                    risk_info = HIGH_RISK_PORTS.get(p_num)
                    severity = risk_info[0] if risk_info else "HIGH"
                    threat_desc = risk_info[1] if risk_info else f"Unexpected service {svc_name} on port {p_num} not present in approved security baseline."

                    alerts.append({
                        "alert_type": "UNEXPECTED_OPEN_PORT",
                        "severity": severity,
                        "title": f"Unexpected Open Port: {p_num}/{port_info['protocol']} ({svc_name}) on {ip}",
                        "observed_fact": f"Observed TCP port {p_num} ({svc_name}) open on host {ip} with latency {port_info.get('latency_ms')}ms. Banner: '{port_info.get('banner') or 'N/A'}'.",
                        "suspected_threat": f"Unapproved open port may violate least-privilege perimeter policy. {threat_desc}",
                        "target_ip": ip,
                        "target_port": p_num,
                        "evidence_json": {
                            "ip": ip,
                            "port": p_num,
                            "service": svc_name,
                            "banner": port_info.get("banner"),
                            "baseline_ports": sorted(list(expected_ports))
                        }
                    })

            asset_updates.append({
                "ip_address": ip,
                "hostname": host_data.get("hostname"),
                "status": "REACHABLE",
                "in_baseline": 1 if is_in_baseline else 0,
                "latency_ms": host_data.get("latency_ms"),
                "open_ports": open_ports
            })

        else:
            # Host not reachable
            if known_asset and is_in_baseline:
                changes_count += 1
                alerts.append({
                    "alert_type": "HOST_OFFLINE",
                    "severity": "LOW",
                    "title": f"Baselined Asset Unreachable: {ip}",
                    "observed_fact": f"Baselined host {ip} ({known_asset.get('hostname')}) did not respond to any port probes during current scan cycle.",
                    "suspected_threat": "Potential outage, network partition, or unannounced asset decommission.",
                    "target_ip": ip,
                    "target_port": None,
                    "evidence_json": {
                        "ip": ip,
                        "last_seen": known_asset.get("last_seen"),
                        "baseline_status": "WAS_REACHABLE"
                    }
                })

            asset_updates.append({
                "ip_address": ip,
                "hostname": host_data.get("hostname"),
                "status": "OFFLINE",
                "in_baseline": 1 if is_in_baseline else 0,
                "latency_ms": None,
                "open_ports": []
            })

    return alerts, asset_updates, changes_count
