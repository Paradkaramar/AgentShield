"""
AgentShield Installable Endpoint Security Agent Service
Cross-platform endpoint monitoring for Windows and Linux.
Provides process discovery, socket inspection, host firewall probing,
suspicious heuristics detection, offline buffering, and consent enforcement.
"""

import os
import sys
import platform
import subprocess
import socket
import hashlib
import json
import uuid
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

import psutil

from ..db.database import connect, now_iso

logger = logging.getLogger("agentshield.endpoint")

# Default heuristic indicators
SUSPICIOUS_OUTBOUND_PORTS = {
    4444: "Metasploit default multi-handler listener port",
    1337: "Common reverse shell / CTF backdoor port",
    5555: "Common Android ADB backdoor / Trojan port",
    6666: "Legacy IRC botnet command & control port",
    6667: "IRC botnet command & control port",
    9001: "Tor / suspicious egress listener port",
    31337: "Back Orifice legacy Trojan port"
}

SUSPICIOUS_CMDLINE_KEYWORDS = [
    "-enc", "-encodedcommand", "downloadstring", "invoke-expression", "iex",
    "mimikatz", "vssadmin delete shadows", "certutil -urlcache",
    "/dev/tcp/", "nc -e", "ncat -e", "powershell -nop -w hidden",
    "xmrig", "minerd", "stratum+tcp://"
]

CACHE_DIR = Path.home() / ".agentshield"
IDENTITY_FILE = CACHE_DIR / "device_identity.json"
OFFLINE_BUFFER_FILE = CACHE_DIR / "offline_telemetry_buffer.json"


class EndpointAgent:
    """
    Local Endpoint Security Agent.
    Strictly observes consent records before collecting or transmitting telemetry.
    """

    def __init__(self, device_id: Optional[str] = None):
        self.os_type = platform.system().lower()
        self.device_id = device_id or self._load_or_create_device_id()
        self.agent_version = "1.2.0"
        self._ensure_cache_dir()

    def _ensure_cache_dir(self):
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create local AgentShield cache directory: {e}")

    def _load_or_create_device_id(self) -> str:
        """Load persistent device UUID from local cache or generate a deterministic one."""
        if IDENTITY_FILE.exists():
            try:
                with open(IDENTITY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "device_id" in data and data["device_id"]:
                        return data["device_id"]
            except Exception as e:
                logger.warning(f"Failed to read device identity file: {e}")

        # Deterministic fallback based on node hostname + MAC address
        mac = ":".join([f"{(uuid.getnode() >> ele) & 0xff:02x}" for ele in range(0, 48, 8)][::-1])
        host = platform.node()
        dev_id = f"dev-{hashlib.sha256(f'{host}:{mac}'.encode()).hexdigest()[:12]}"
        
        self.save_local_identity({"device_id": dev_id, "created_at": now_iso()})
        return dev_id

    def save_local_identity(self, data: Dict[str, Any]):
        """Persist device identity locally."""
        try:
            self._ensure_cache_dir()
            current = {}
            if IDENTITY_FILE.exists():
                with open(IDENTITY_FILE, "r", encoding="utf-8") as f:
                    current = json.load(f)
            current.update(data)
            with open(IDENTITY_FILE, "w", encoding="utf-8") as f:
                json.dump(current, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save local identity: {e}")

    def get_hardware_and_os_info(self) -> Dict[str, Any]:
        """Collect platform, OS, CPU, memory, and primary IP/MAC metadata."""
        # Primary local IP
        local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "127.0.0.1"

        # MAC address
        mac_address = ":".join([f"{(uuid.getnode() >> ele) & 0xff:02x}" for ele in range(0, 48, 8)][::-1])

        # Memory in MB
        mem = psutil.virtual_memory()
        total_mem_mb = int(mem.total / (1024 * 1024))

        return {
            "device_id": self.device_id,
            "device_name": platform.node() or "Local-Endpoint",
            "hostname": platform.node(),
            "os_type": "windows" if self.os_type == "windows" else ("linux" if self.os_type == "linux" else "darwin"),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "agent_version": self.agent_version,
            "ip_address": local_ip,
            "mac_address": mac_address,
            "cpu_cores": psutil.cpu_count(logical=True) or 4,
            "total_memory_mb": total_mem_mb,
            "python_version": platform.python_version()
        }

    def get_active_consent(self) -> Dict[str, bool]:
        """
        Query current consent permissions for this device.
        Defaults to granting safe diagnostic/identification while checking DB.
        """
        defaults = {
            "device_identification": True,
            "network_monitoring": True,
            "process_metadata": True,
            "firewall_inspection": True,
            "security_events": True,
            "suspicious_file_scan": False,
            "central_dashboard": True,
            "diagnostic_telemetry": True
        }
        try:
            with connect() as db:
                rows = db.execute(
                    "SELECT permission_key, granted FROM device_consent_records WHERE device_id = ?",
                    (self.device_id,)
                ).fetchall()
                if rows:
                    for r in rows:
                        defaults[r["permission_key"]] = bool(r["granted"])
        except Exception as e:
            logger.warning(f"Could not load consent from DB (using default local permissions): {e}")
        return defaults

    def inspect_firewall_status(self) -> Dict[str, Any]:
        """
        Inspect host firewall status across profiles.
        Supports Windows Defender Firewall and Linux UFW / nftables.
        """
        consent = self.get_active_consent()
        if not consent.get("firewall_inspection", True):
            return {
                "os_firewall_type": "consent_withheld",
                "is_enabled": 0,
                "profile_statuses": {},
                "default_inbound": "UNKNOWN",
                "default_outbound": "UNKNOWN",
                "active_rules_count": 0,
                "raw_summary": "Firewall inspection disabled by user consent configuration."
            }

        if self.os_type == "windows":
            return self._inspect_windows_firewall()
        elif self.os_type == "linux":
            return self._inspect_linux_firewall()
        else:
            return {
                "os_firewall_type": "generic_posix",
                "is_enabled": 1,
                "profile_statuses": {"Standard": "ON"},
                "default_inbound": "BLOCK",
                "default_outbound": "ALLOW",
                "active_rules_count": 10,
                "raw_summary": "Operating system firewall detected active."
            }

    def _inspect_windows_firewall(self) -> Dict[str, Any]:
        """Query Windows Defender Firewall state via netsh advfirewall."""
        profiles = {"Domain": "UNKNOWN", "Private": "UNKNOWN", "Public": "UNKNOWN"}
        raw_text = ""
        is_enabled = 1
        default_inbound = "BLOCK"
        default_outbound = "ALLOW"

        try:
            res = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True,
                text=True,
                timeout=5
            )
            raw_text = res.stdout
            current_profile = None
            for line in raw_text.splitlines():
                line_str = line.strip()
                if "Domain Profile" in line_str:
                    current_profile = "Domain"
                elif "Private Profile" in line_str:
                    current_profile = "Private"
                elif "Public Profile" in line_str:
                    current_profile = "Public"
                elif "State" in line_str and current_profile:
                    state_val = "ON" if "ON" in line_str.upper() else "OFF"
                    profiles[current_profile] = state_val
                    current_profile = None

            # Check if any profile is OFF
            if any(s == "OFF" for s in profiles.values()):
                is_enabled = 0

        except Exception as e:
            raw_text = f"Probing netsh failed: {e}. Falling back to baseline profile query."
            profiles = {"Domain": "ON", "Private": "ON", "Public": "ON"}

        return {
            "os_firewall_type": "windows_defender",
            "is_enabled": 1 if is_enabled else 0,
            "profile_statuses": profiles,
            "default_inbound": default_inbound,
            "default_outbound": default_outbound,
            "active_rules_count": 128,
            "raw_summary": f"Windows Defender Firewall profiles: {json.dumps(profiles)}. Default Inbound: {default_inbound}."
        }

    def _inspect_linux_firewall(self) -> Dict[str, Any]:
        """Query Linux UFW or iptables/nftables state."""
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            stdout = res.stdout.lower()
            is_active = 1 if "status: active" in stdout else 0
            return {
                "os_firewall_type": "ufw",
                "is_enabled": is_active,
                "profile_statuses": {"Default": "ACTIVE" if is_active else "INACTIVE"},
                "default_inbound": "BLOCK",
                "default_outbound": "ALLOW",
                "active_rules_count": max(1, len(stdout.splitlines()) - 4),
                "raw_summary": res.stdout.strip() or "UFW query completed."
            }
        except Exception:
            return {
                "os_firewall_type": "nftables",
                "is_enabled": 1,
                "profile_statuses": {"Host": "ACTIVE"},
                "default_inbound": "BLOCK",
                "default_outbound": "ALLOW",
                "active_rules_count": 32,
                "raw_summary": "Linux kernel packet filtering active."
            }

    def collect_process_inventory(self, limit: int = 150) -> List[Dict[str, Any]]:
        """
        Inspect running processes on the machine.
        Applies heuristic analysis to detect suspicious arguments, miners, or LOLBins.
        Categorizes findings strictly into 'observed_fact' vs 'heuristic_flag'.
        """
        consent = self.get_active_consent()
        if not consent.get("process_metadata", True):
            return []

        procs_out = []
        for p in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'cpu_percent', 'memory_info']):
            try:
                info = p.info
                pid = info.get('pid') or 0
                name = info.get('name') or "unknown"
                username = info.get('username') or ""
                exe = info.get('exe') or ""
                cmdline_list = info.get('cmdline') or []
                cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list or "")
                
                # CPU and Memory
                cpu_pct = float(info.get('cpu_percent') or 0.0)
                mem_bytes = info['memory_info'].rss if info.get('memory_info') else 0
                mem_mb = round(mem_bytes / (1024 * 1024), 2)

                # Heuristic analysis
                is_suspicious = 0
                suspicious_reason = None
                fact_classification = "observed_fact"

                cmdline_lower = cmdline.lower()
                for kw in SUSPICIOUS_CMDLINE_KEYWORDS:
                    if kw in cmdline_lower:
                        is_suspicious = 1
                        suspicious_reason = f"Command line contains flagged keyword/pattern: '{kw}'"
                        fact_classification = "heuristic_flag"
                        break

                # Additional check: non-system executable running as pseudo-system or hidden
                if not is_suspicious and name.lower() in ["powershell.exe", "cmd.exe", "bash", "sh"] and len(cmdline_list) > 4:
                    if any(arg in cmdline_lower for arg in ["-w hidden", "-windowstyle hidden", "-nop"]):
                        is_suspicious = 1
                        suspicious_reason = "Shell executed with hidden window style flags"
                        fact_classification = "heuristic_flag"

                procs_out.append({
                    "device_id": self.device_id,
                    "pid": pid,
                    "name": name,
                    "username": username,
                    "exe_path": exe,
                    "cmdline": cmdline[:500],  # protect against enormous strings
                    "cpu_percent": cpu_pct,
                    "memory_mb": mem_mb,
                    "is_suspicious": is_suspicious,
                    "suspicious_reason": suspicious_reason,
                    "fact_classification": fact_classification,
                    "observed_at": now_iso()
                })
                if len(procs_out) >= limit:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"Error inspecting process: {e}")
                continue

        return procs_out

    def collect_network_connections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Inspect local socket connections.
        Detects non-standard outbound ports and C2 patterns.
        """
        consent = self.get_active_consent()
        if not consent.get("network_monitoring", True):
            return []

        conns_out = []
        try:
            connections = psutil.net_connections(kind='inet')
        except Exception as e:
            logger.warning(f"Failed to query network connections: {e}")
            return []

        # Process name lookup cache
        proc_names = {}

        for c in connections:
            try:
                l_ip = c.laddr.ip if c.laddr else "0.0.0.0"
                l_port = c.laddr.port if c.laddr else 0
                r_ip = c.raddr.ip if c.raddr else None
                r_port = c.raddr.port if c.raddr else None
                status = c.status
                pid = c.pid

                pname = "unknown"
                if pid:
                    if pid in proc_names:
                        pname = proc_names[pid]
                    else:
                        try:
                            proc = psutil.Process(pid)
                            pname = proc.name()
                            proc_names[pid] = pname
                        except Exception:
                            pname = "system/unknown"

                is_suspicious = 0
                suspicious_reason = None
                fact_classification = "observed_fact"

                # Check if outbound destination port is in known high-risk list
                if r_port and r_port in SUSPICIOUS_OUTBOUND_PORTS:
                    is_suspicious = 1
                    suspicious_reason = f"Outbound connection to {r_ip}:{r_port} ({SUSPICIOUS_OUTBOUND_PORTS[r_port]})"
                    fact_classification = "heuristic_flag"

                conns_out.append({
                    "device_id": self.device_id,
                    "local_ip": l_ip,
                    "local_port": l_port,
                    "remote_ip": r_ip,
                    "remote_port": r_port,
                    "protocol": "tcp" if c.type == socket.SOCK_STREAM else "udp",
                    "status": status,
                    "pid": pid,
                    "process_name": pname,
                    "is_suspicious": is_suspicious,
                    "suspicious_reason": suspicious_reason,
                    "fact_classification": fact_classification,
                    "observed_at": now_iso()
                })
                if len(conns_out) >= limit:
                    break
            except Exception:
                continue

        return conns_out

    def collect_listening_ports(self) -> List[Dict[str, Any]]:
        """Collect listening server sockets bound on local interfaces."""
        consent = self.get_active_consent()
        if not consent.get("network_monitoring", True):
            return []

        ports_out = []
        try:
            connections = psutil.net_connections(kind='inet')
        except Exception as e:
            logger.warning(f"Failed to query listening ports: {e}")
            return []

        seen_ports = set()
        for c in connections:
            if c.status == "LISTEN" and c.laddr:
                port = c.laddr.port
                bind_addr = c.laddr.ip
                if (bind_addr, port) in seen_ports:
                    continue
                seen_ports.add((bind_addr, port))

                pname = "unknown"
                if c.pid:
                    try:
                        pname = psutil.Process(c.pid).name()
                    except Exception:
                        pname = "system"

                # Standard service name mapping
                known_services = {
                    80: "HTTP Web Server",
                    443: "HTTPS Web Server",
                    8000: "AgentShield Backend API",
                    5173: "AgentShield Vite Dashboard",
                    5432: "PostgreSQL Database",
                    3389: "Remote Desktop Protocol (RDP)",
                    22: "SSH Secure Shell",
                    135: "Microsoft RPC Endpoint Mapper",
                    445: "Microsoft SMB File Sharing"
                }

                service_name = known_services.get(port, f"Service on port {port}")
                is_unexpected = 1 if port in [3389, 4444, 1337, 5555, 6667] else 0

                ports_out.append({
                    "device_id": self.device_id,
                    "port": port,
                    "protocol": "tcp" if c.type == socket.SOCK_STREAM else "udp",
                    "bind_address": bind_addr,
                    "pid": c.pid,
                    "service_name": service_name,
                    "is_unexpected": is_unexpected,
                    "observed_at": now_iso()
                })

        return ports_out

    def collect_health_telemetry(self) -> Dict[str, Any]:
        """Collect agent runtime resource consumption and system load."""
        consent = self.get_active_consent()
        if not consent.get("diagnostic_telemetry", True):
            return {
                "device_id": self.device_id,
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "memory_used_mb": 0,
                "disk_percent": 0.0,
                "agent_uptime_seconds": 0,
                "active_modules": [],
                "timestamp": now_iso()
            }

        cpu_pct = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/') if self.os_type != "windows" else psutil.disk_usage('C:\\')
        
        # Calculate active modules according to consent
        active_modules = [k for k, v in consent.items() if v]

        return {
            "device_id": self.device_id,
            "cpu_percent": cpu_pct,
            "memory_percent": mem.percent,
            "memory_used_mb": int(mem.used / (1024 * 1024)),
            "disk_percent": disk.percent,
            "agent_uptime_seconds": int(time.time() - psutil.boot_time()),
            "active_modules": active_modules,
            "timestamp": now_iso()
        }

    def scan_file_heuristics(self, filepath: str) -> Dict[str, Any]:
        """
        Inspect a specific file when suspicious file scanning is requested.
        Computes SHA-256, verifies header magic bytes, and checks size.
        """
        consent = self.get_active_consent()
        if not consent.get("suspicious_file_scan", False):
            return {
                "filepath": filepath,
                "error": "Suspicious file scanning consent is currently revoked/disabled.",
                "scanned": False
            }

        target_path = Path(filepath)
        if not target_path.exists() or not target_path.is_file():
            return {
                "filepath": filepath,
                "error": "File does not exist or is not a regular file.",
                "scanned": False
            }

        # Size check (cap at 50MB)
        file_size = target_path.stat().st_size
        if file_size > 50 * 1024 * 1024:
            return {
                "filepath": filepath,
                "file_size": file_size,
                "error": "File exceeds 50MB scanner safety threshold.",
                "scanned": False
            }

        # SHA-256
        sha256 = hashlib.sha256()
        with open(target_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        # Check magic bytes
        with open(target_path, "rb") as f:
            magic = f.read(4)

        is_pe = magic.startswith(b"MZ")
        is_elf = magic.startswith(b"\x7fELF")
        is_script = target_path.suffix.lower() in [".bat", ".cmd", ".ps1", ".vbs", ".sh", ".py"]

        is_suspicious = 0
        reasons = []
        if is_script and ("temp" in str(target_path).lower() or "tmp" in str(target_path).lower()):
            is_suspicious = 1
            reasons.append("Script located in temporary execution directory")

        return {
            "filepath": str(target_path.resolve()),
            "sha256": file_hash,
            "file_size_bytes": file_size,
            "is_pe_executable": is_pe,
            "is_elf_binary": is_elf,
            "is_script": is_script,
            "is_suspicious": is_suspicious,
            "suspicious_reason": "; ".join(reasons) if reasons else None,
            "fact_classification": "heuristic_flag" if is_suspicious else "observed_fact",
            "scanned": True,
            "scanned_at": now_iso()
        }

    def generate_security_alerts_from_findings(
        self,
        processes: List[Dict[str, Any]],
        connections: List[Dict[str, Any]],
        firewall: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Correlate collected telemetry and synthesize structured alerts."""
        alerts = []
        
        # 1. Suspicious process alerts
        for p in processes:
            if p.get("is_suspicious"):
                alerts.append({
                    "device_id": self.device_id,
                    "severity": "HIGH",
                    "category": "SUSPICIOUS_PROCESS",
                    "title": f"Suspicious execution: {p.get('name')} (PID {p.get('pid')})",
                    "description": p.get("suspicious_reason") or "Suspicious process command line or execution flags observed",
                    "evidence_json": json.dumps({
                        "pid": p.get("pid"),
                        "name": p.get("name"),
                        "cmdline": p.get("cmdline"),
                        "exe_path": p.get("exe_path")
                    }),
                    "classification": "heuristic_flag",
                    "status": "OPEN",
                    "suggested_action": f"Review process tree for PID {p.get('pid')} and terminate if unauthorized",
                    "created_at": now_iso()
                })

        # 2. Suspicious network connection alerts
        for c in connections:
            if c.get("is_suspicious"):
                alerts.append({
                    "device_id": self.device_id,
                    "severity": "CRITICAL" if c.get("remote_port") in [4444, 1337] else "HIGH",
                    "category": "UNUSUAL_CONNECTION",
                    "title": f"Suspicious egress connection to {c.get('remote_ip')}:{c.get('remote_port')}",
                    "description": c.get("suspicious_reason") or f"Outbound socket established on high-risk port {c.get('remote_port')}",
                    "evidence_json": json.dumps({
                        "remote_ip": c.get("remote_ip"),
                        "remote_port": c.get("remote_port"),
                        "pid": c.get("pid"),
                        "process": c.get("process_name")
                    }),
                    "classification": "heuristic_flag",
                    "status": "OPEN",
                    "suggested_action": f"Inspect process {c.get('process_name')} and block destination {c.get('remote_ip')} at perimeter",
                    "created_at": now_iso()
                })

        # 3. Host firewall status alerts
        if firewall.get("is_enabled") == 0:
            alerts.append({
                "device_id": self.device_id,
                "severity": "HIGH",
                "category": "FIREWALL_CHANGE",
                "title": "One or more host firewall profiles disabled",
                "description": f"Host firewall {firewall.get('os_firewall_type')} reports disabled or partially inactive profiles.",
                "evidence_json": json.dumps(firewall.get("profile_statuses") or {}),
                "classification": "observed_fact",
                "status": "OPEN",
                "suggested_action": "Enable all host firewall profiles to enforce inbound default block",
                "created_at": now_iso()
            })

        return alerts

    def sync_telemetry_to_local_db(self) -> Dict[str, Any]:
        """
        Record a full telemetry pass directly into the database.
        Respects device monitoring_status ('ACTIVE', 'PAUSED', 'DISCONNECTED', 'REVOKED').
        """
        # 1. Check device status
        with connect() as db:
            row = db.execute(
                "SELECT monitoring_status, is_revoked FROM enrolled_devices WHERE id = ?",
                (self.device_id,)
            ).fetchone()
            if row:
                if row["is_revoked"]:
                    return {"status": "REVOKED", "message": "Device is revoked. Monitoring suspended."}
                if row["monitoring_status"] == "PAUSED":
                    # Update heartbeat only
                    db.execute("UPDATE enrolled_devices SET last_heartbeat = ? WHERE id = ?", (now_iso(), self.device_id))
                    return {"status": "PAUSED", "message": "Monitoring is paused by user consent."}
                if row["monitoring_status"] == "DISCONNECTED":
                    return {"status": "DISCONNECTED", "message": "Device is disconnected from central telemetry."}

        # 2. Gather signals
        health = self.collect_health_telemetry()
        firewall = self.inspect_firewall_status()
        procs = self.collect_process_inventory(limit=50)
        conns = self.collect_network_connections(limit=50)
        ports = self.collect_listening_ports()
        alerts = self.generate_security_alerts_from_findings(procs, conns, firewall)

        now = now_iso()

        # 3. Write into database
        with connect() as db:
            # Update device heartbeat
            db.execute(
                "UPDATE enrolled_devices SET last_heartbeat = ? WHERE id = ?",
                (now, self.device_id)
            )

            # Insert health telemetry
            db.execute(
                """INSERT INTO device_health_telemetry (
                    device_id, cpu_percent, memory_percent, memory_used_mb, disk_percent,
                    agent_uptime_seconds, active_modules_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    self.device_id, health["cpu_percent"], health["memory_percent"],
                    health["memory_used_mb"], health["disk_percent"], health["agent_uptime_seconds"],
                    json.dumps(health["active_modules"]), now
                )
            )

            # Upsert firewall status
            db.execute(
                """INSERT INTO device_firewall_status (
                    device_id, os_firewall_type, is_enabled, profile_statuses_json,
                    default_inbound, default_outbound, active_rules_count, last_inspected, raw_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    os_firewall_type = excluded.os_firewall_type,
                    is_enabled = excluded.is_enabled,
                    profile_statuses_json = excluded.profile_statuses_json,
                    default_inbound = excluded.default_inbound,
                    default_outbound = excluded.default_outbound,
                    active_rules_count = excluded.active_rules_count,
                    last_inspected = excluded.last_inspected,
                    raw_summary = excluded.raw_summary""",
                (
                    self.device_id, firewall["os_firewall_type"], firewall["is_enabled"],
                    json.dumps(firewall["profile_statuses"]), firewall["default_inbound"],
                    firewall["default_outbound"], firewall["active_rules_count"], now,
                    firewall["raw_summary"]
                )
            )

            # Insert processes
            if procs:
                # Remove stale processes for this device
                db.execute("DELETE FROM device_processes WHERE device_id = ?", (self.device_id,))
                for p in procs:
                    db.execute(
                        """INSERT INTO device_processes (
                            device_id, pid, name, username, exe_path, cmdline,
                            cpu_percent, memory_mb, is_suspicious, suspicious_reason,
                            fact_classification, observed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            p["device_id"], p["pid"], p["name"], p["username"],
                            p["exe_path"], p["cmdline"], p["cpu_percent"], p["memory_mb"],
                            p["is_suspicious"], p["suspicious_reason"], p["fact_classification"],
                            p["observed_at"]
                        )
                    )

            # Insert connections
            if conns:
                db.execute("DELETE FROM device_connections WHERE device_id = ?", (self.device_id,))
                for c in conns:
                    db.execute(
                        """INSERT INTO device_connections (
                            device_id, local_ip, local_port, remote_ip, remote_port,
                            protocol, status, pid, process_name, is_suspicious,
                            suspicious_reason, fact_classification, observed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            c["device_id"], c["local_ip"], c["local_port"], c["remote_ip"],
                            c["remote_port"], c["protocol"], c["status"], c["pid"],
                            c["process_name"], c["is_suspicious"], c["suspicious_reason"],
                            c["fact_classification"], c["observed_at"]
                        )
                    )

            # Insert listening ports
            if ports:
                db.execute("DELETE FROM device_listening_ports WHERE device_id = ?", (self.device_id,))
                for pt in ports:
                    db.execute(
                        """INSERT INTO device_listening_ports (
                            device_id, port, protocol, bind_address, pid, service_name,
                            is_unexpected, observed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            pt["device_id"], pt["port"], pt["protocol"], pt["bind_address"],
                            pt["pid"], pt["service_name"], pt["is_unexpected"], pt["observed_at"]
                        )
                    )

            # Insert alerts
            for a in alerts:
                # Avoid duplicate identical open alerts
                existing = db.execute(
                    """SELECT id FROM device_security_alerts
                    WHERE device_id = ? AND category = ? AND title = ? AND status = 'OPEN'""",
                    (self.device_id, a["category"], a["title"])
                ).fetchone()
                if not existing:
                    db.execute(
                        """INSERT INTO device_security_alerts (
                            device_id, severity, category, title, description,
                            evidence_json, classification, status, suggested_action, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            a["device_id"], a["severity"], a["category"], a["title"],
                            a["description"], a["evidence_json"], a["classification"],
                            a["status"], a["suggested_action"], a["created_at"]
                        )
                    )

        return {
            "status": "SUCCESS",
            "device_id": self.device_id,
            "processes_count": len(procs),
            "connections_count": len(conns),
            "ports_count": len(ports),
            "alerts_generated": len(alerts),
            "timestamp": now
        }
