# backend/app/engines/traffic_engine.py
"""Traffic Monitoring & Wireshark/TShark Control Engine.
Provides safe, authorized live packet captures, TShark CLI interface management,
interface enumeration, strict BPF capture filter validation, and integration with
the offline PCAP parser.
"""

import asyncio
import os
import re
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from ..core.config import BASE_DIR
from .pcap_parser import parse_pcap_file, PCAPAnalysisResult

CAPTURES_DIR = BASE_DIR / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)

# Standard Windows installation paths for Wireshark / TShark
TSHARK_STANDARD_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    r"C:\Wireshark\tshark.exe"
]

# Strict BPF capture filter validation regex (alphanumeric, spaces, safe operators)
SAFE_BPF_TOKEN_REGEX = re.compile(r"^[a-zA-Z0-9\s\.\:\-\_\(\)]+$")
DISALLOWED_BPF_CHARS = set(";|&`$<>\"\n\r\t\\")


def find_tshark_executable() -> Optional[str]:
    """Finds the tshark executable in system PATH or standard Windows directories."""
    which_path = shutil.which("tshark")
    if which_path and os.path.exists(which_path):
        return which_path
    for p in TSHARK_STANDARD_PATHS:
        if os.path.exists(p):
            return p
    return None


def get_tshark_version(tshark_path: str) -> Optional[str]:
    """Executes tshark -v to retrieve version information."""
    try:
        proc = subprocess.run(
            [tshark_path, "-v"],
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


def get_available_capture_interfaces() -> List[Dict[str, Any]]:
    """Lists available network interfaces for live capture.
    If TShark is installed, queries 'tshark -D'. Otherwise, enumerates host IP adapters.
    """
    interfaces = []
    tshark_path = find_tshark_executable()

    if tshark_path:
        try:
            proc = subprocess.run(
                [tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False
            )
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # Format: "1. \Device\NPF_{...} (Ethernet)" or "1. eth0"
                    match = re.match(r"^(\d+)\.\s+(.+)$", line)
                    if match:
                        num, desc = match.groups()
                        interfaces.append({
                            "index": int(num),
                            "id": num,
                            "name": desc,
                            "is_tshark_interface": True
                        })
                if interfaces:
                    return interfaces
        except Exception:
            pass

    # Fallback to local host interfaces
    try:
        hostname = socket.gethostname()
        local_ips = socket.gethostbyname_ex(hostname)[2]
    except Exception:
        local_ips = ["127.0.0.1"]

    interfaces.append({
        "index": 1,
        "id": "loopback",
        "name": "Loopback Pseudo-Interface (127.0.0.1)",
        "is_tshark_interface": False
    })
    idx = 2
    for ip in local_ips:
        if ip != "127.0.0.1":
            interfaces.append({
                "index": idx,
                "id": f"adapter-{idx}",
                "name": f"Local Network Adapter ({ip})",
                "is_tshark_interface": False
            })
            idx += 1

    return interfaces


def validate_bpf_filter(bpf_filter: str) -> Tuple[bool, Optional[str]]:
    """Strictly validates a Berkeley Packet Filter (BPF) string to prevent command injection."""
    cleaned = (bpf_filter or "").strip()
    if not cleaned:
        return True, None

    # Length guard
    if len(cleaned) > 150:
        return False, "Capture filter exceeds maximum allowed length (150 characters)."

    # Reject dangerous shell characters
    for ch in DISALLOWED_BPF_CHARS:
        if ch in cleaned:
            return False, f"Prohibited character '{ch}' detected in capture filter."

    if not SAFE_BPF_TOKEN_REGEX.match(cleaned):
        return False, "Capture filter contains disallowed characters or formatting."

    # Allowlist standard BPF keywords
    allowed_keywords = {
        "tcp", "udp", "icmp", "ip", "ip6", "arp", "port", "host", "net", "src", "dst",
        "and", "or", "not", "less", "greater", "broadcast", "multicast", "proto"
    }
    tokens = re.findall(r"[a-zA-Z0-9]+", cleaned.lower())
    for token in tokens:
        if token.isdigit():
            # Port or subnet number
            val = int(token)
            if val > 65535 and not (len(token) <= 3):  # allow reasonable IP octets
                return False, f"Numerical filter value out of range: {token}"
            continue
        if token not in allowed_keywords and not re.match(r"^[0-9a-fA-F\.\:]+$", token):
            return False, f"Unrecognized keyword or token in capture filter: '{token}'"

    return True, None


class ActiveCaptureSession:
    def __init__(
        self,
        session_id: str,
        interface: str,
        bpf_filter: str,
        max_duration_seconds: int,
        max_packets: int,
        filepath: str,
        process: Optional[asyncio.subprocess.Process] = None
    ):
        self.session_id = session_id
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.max_duration_seconds = max_duration_seconds
        self.max_packets = max_packets
        self.filepath = filepath
        self.process = process
        self.status = "RUNNING"
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.completed_at: Optional[str] = None
        self.error_message: Optional[str] = None
        self.packet_count: int = 0
        self.file_size_bytes: int = 0


class TrafficMonitorService:
    def __init__(self):
        self._active_sessions: Dict[str, ActiveCaptureSession] = {}
        self._lock = asyncio.Lock()

    def get_tool_status(self) -> Dict[str, Any]:
        """Returns live installation and environment status for TShark and Wireshark."""
        tshark_path = find_tshark_executable()
        version_str = get_tshark_version(tshark_path) if tshark_path else None
        interfaces = get_available_capture_interfaces()
        sample_path = CAPTURES_DIR / "sample_network_traffic.pcap"

        return {
            "tshark_installed": tshark_path is not None,
            "tshark_path": tshark_path,
            "tshark_version": version_str,
            "interfaces": interfaces,
            "captures_dir": str(CAPTURES_DIR),
            "sample_pcap_available": sample_path.exists(),
            "sample_pcap_path": str(sample_path) if sample_path.exists() else None,
            "offline_parser_ready": True
        }

    async def start_live_capture(
        self,
        interface: str,
        bpf_filter: str = "",
        duration_seconds: int = 15,
        max_packets: int = 200,
        triggered_by: str = "admin"
    ) -> Dict[str, Any]:
        """Starts an authorized, bounded live packet capture using TShark CLI.
        Enforces maximum duration (up to 60s), packet count (up to 1000), and safe storage.
        """
        async with self._lock:
            # 1. Limit concurrent live captures to 1
            running = [s for s in self._active_sessions.values() if s.status == "RUNNING"]
            if running:
                return {
                    "status": "BLOCKED",
                    "error": "A packet capture session is already in progress. Stop it before starting another."
                }

            # 2. Check TShark presence
            tshark_path = find_tshark_executable()
            if not tshark_path:
                return {
                    "status": "UNAVAILABLE",
                    "error": "TShark (Wireshark CLI) is not installed on this system. Live traffic capture requires Wireshark/Npcap. Offline PCAP analysis remains fully functional.",
                    "installation_help": "Download and install Wireshark with Npcap from https://www.wireshark.org/download.html"
                }

            # 3. Validate BPF filter
            is_valid, bpf_err = validate_bpf_filter(bpf_filter)
            if not is_valid:
                return {
                    "status": "INVALID_FILTER",
                    "error": f"Invalid BPF capture filter: {bpf_err}"
                }

            # 4. Bound parameters strictly
            duration = max(5, min(duration_seconds, 60))
            packets = max(10, min(max_packets, 1000))

            session_id = f"cap-{uuid.uuid4().hex[:8]}"
            filename = f"capture_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{session_id}.pcapng"
            filepath = str(CAPTURES_DIR / filename)

            # Build command list (never shell=True)
            # tshark -i <interface> -a duration:<sec> -c <count> -w <filepath> [-f <bpf>]
            cmd = [
                tshark_path,
                "-i", interface,
                "-a", f"duration:{duration}",
                "-c", str(packets),
                "-w", filepath,
                "-q"
            ]
            if bpf_filter.strip():
                cmd.extend(["-f", bpf_filter.strip()])

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            except Exception as e:
                return {
                    "status": "ERROR",
                    "error": f"Failed to spawn TShark subprocess: {str(e)}"
                }

            session = ActiveCaptureSession(
                session_id=session_id,
                interface=interface,
                bpf_filter=bpf_filter.strip(),
                max_duration_seconds=duration,
                max_packets=packets,
                filepath=filepath,
                process=proc
            )
            self._active_sessions[session_id] = session

            # Start background monitor for session completion
            asyncio.create_task(self._monitor_capture(session))

            return {
                "status": "RUNNING",
                "session_id": session_id,
                "interface": interface,
                "bpf_filter": bpf_filter.strip() or "All Traffic",
                "duration_limit_seconds": duration,
                "packet_limit": packets,
                "filename": filename,
                "message": f"Authorized live packet capture started on interface {interface}."
            }

    async def _monitor_capture(self, session: ActiveCaptureSession):
        """Monitors the capture subprocess until timeout or termination, then updates stats."""
        try:
            stdout, stderr = await asyncio.wait_for(
                session.process.communicate(),
                timeout=session.max_duration_seconds + 5.0
            )
            session.completed_at = datetime.now(timezone.utc).isoformat()
            session.status = "COMPLETED"
        except asyncio.TimeoutError:
            try:
                session.process.terminate()
                await session.process.wait()
            except Exception:
                pass
            session.completed_at = datetime.now(timezone.utc).isoformat()
            session.status = "COMPLETED"
        except Exception as e:
            session.status = "ERROR"
            session.error_message = str(e)
            session.completed_at = datetime.now(timezone.utc).isoformat()

        # Update file metrics
        if os.path.exists(session.filepath):
            session.file_size_bytes = os.path.getsize(session.filepath)
            try:
                parsed = parse_pcap_file(session.filepath)
                session.packet_count = parsed.total_packets
            except Exception:
                pass

    async def stop_live_capture(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Stops an ongoing capture session cleanly."""
        async with self._lock:
            target_session = None
            if session_id:
                target_session = self._active_sessions.get(session_id)
            else:
                for s in self._active_sessions.values():
                    if s.status == "RUNNING":
                        target_session = s
                        break

            if not target_session or target_session.status != "RUNNING":
                return {"status": "NOT_RUNNING", "message": "No active capture session found to stop."}

            if target_session.process:
                try:
                    target_session.process.terminate()
                    await asyncio.wait_for(target_session.process.wait(), timeout=3.0)
                except Exception:
                    try:
                        target_session.process.kill()
                    except Exception:
                        pass

            target_session.status = "STOPPED"
            target_session.completed_at = datetime.now(timezone.utc).isoformat()

            # Inspect resulting file
            analysis = None
            if os.path.exists(target_session.filepath):
                target_session.file_size_bytes = os.path.getsize(target_session.filepath)
                try:
                    res = parse_pcap_file(target_session.filepath)
                    target_session.packet_count = res.total_packets
                    analysis = res.to_dict()
                except Exception as e:
                    target_session.error_message = f"Parse error: {str(e)}"

            return {
                "status": "STOPPED",
                "session_id": target_session.session_id,
                "packet_count": target_session.packet_count,
                "file_size_bytes": target_session.file_size_bytes,
                "filepath": target_session.filepath,
                "analysis": analysis,
                "message": "Live traffic capture terminated successfully."
            }

    def get_capture_status(self) -> Dict[str, Any]:
        """Returns the status of the current or most recent capture session."""
        active = None
        recent = []
        for s in reversed(list(self._active_sessions.values())):
            item = {
                "session_id": s.session_id,
                "interface": s.interface,
                "bpf_filter": s.bpf_filter,
                "status": s.status,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "packet_count": s.packet_count,
                "file_size_bytes": s.file_size_bytes,
                "filename": os.path.basename(s.filepath),
                "error": s.error_message
            }
            if s.status == "RUNNING" and active is None:
                active = item
            else:
                recent.append(item)

        return {
            "active_capture": active,
            "recent_captures": recent[:10]
        }


# Global singleton instance
traffic_monitor_service = TrafficMonitorService()
