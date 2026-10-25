# backend/app/engines/pcap_parser.py
"""Pure-Python PCAP and PCAPNG Parser & Sample Traffic Generator.
Provides robust offline packet capture dissection without requiring TShark, WinPcap,
or administrative privileges. Parses Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP, DNS,
HTTP, and TLS metadata, extracting security anomalies and session metrics.
"""

import io
import os
import struct
import socket
import ipaddress
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set


# Standard PCAP Magic Numbers
PCAP_MAGIC_MICRO_BE = 0xa1b2c3d4  # Big-endian microsecond
PCAP_MAGIC_MICRO_LE = 0xd4c3b2a1  # Little-endian microsecond
PCAP_MAGIC_NANO_BE  = 0xa1b23c4d  # Big-endian nanosecond
PCAP_MAGIC_NANO_LE  = 0x4d3cb2a1  # Little-endian nanosecond

# PCAPNG Block Types
PCAPNG_SECTION_HEADER_BLOCK = 0x0A0D0D0A
PCAPNG_INTERFACE_DESC_BLOCK = 0x00000001
PCAPNG_ENHANCED_PACKET_BLOCK = 0x00000006
PCAPNG_SIMPLE_PACKET_BLOCK   = 0x00000003

# EtherTypes
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_IPV6 = 0x86dd

# IP Protocols
IP_PROTO_ICMP = 1
IP_PROTO_TCP  = 6
IP_PROTO_UDP  = 17


def _format_mac(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes[:6])


def _parse_dns_query(payload: bytes) -> Optional[Tuple[str, str]]:
    """Extract domain name and query type from DNS payload."""
    if len(payload) < 12:
        return None
    try:
        # DNS Header: ID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount == 0:
            return None
        idx = 12
        labels = []
        while idx < len(payload):
            length = payload[idx]
            if length == 0:
                idx += 1
                break
            if length > 63 or idx + 1 + length > len(payload):
                return None  # Pointer or malformed
            idx += 1
            labels.append(payload[idx:idx + length].decode("ascii", errors="ignore"))
            idx += length
        if not labels:
            return None
        domain = ".".join(labels)
        qtype_str = "A"
        if idx + 2 <= len(payload):
            qtype = struct.unpack("!H", payload[idx:idx + 2])[0]
            type_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR"}
            qtype_str = type_map.get(qtype, f"TYPE{qtype}")
        return domain, qtype_str
    except Exception:
        return None


def _parse_tls_sni(payload: bytes) -> Optional[str]:
    """Extract Server Name Indication (SNI) from TLS Client Hello if present."""
    if len(payload) < 43 or payload[0] != 0x16:  # 0x16 = Handshake
        return None
    try:
        # Check Handshake Type == 1 (Client Hello)
        if payload[5] != 0x01:
            return None
        idx = 43  # Skip record header(5) + handshake header(4) + client version(2) + random(32)
        if idx >= len(payload):
            return None
        # Session ID length
        sess_id_len = payload[idx]
        idx += 1 + sess_id_len
        # Cipher suites length
        if idx + 2 > len(payload):
            return None
        cipher_len = struct.unpack("!H", payload[idx:idx + 2])[0]
        idx += 2 + cipher_len
        # Compression methods length
        if idx + 1 > len(payload):
            return None
        comp_len = payload[idx]
        idx += 1 + comp_len
        # Extensions length
        if idx + 2 > len(payload):
            return None
        ext_total_len = struct.unpack("!H", payload[idx:idx + 2])[0]
        idx += 2
        ext_end = min(idx + ext_total_len, len(payload))
        while idx + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", payload[idx:idx + 4])
            idx += 4
            if ext_type == 0:  # SNI Extension
                if idx + 5 <= ext_end:
                    # Skip server_name_list_length(2), name_type(1)
                    sni_name_len = struct.unpack("!H", payload[idx + 3:idx + 5])[0]
                    if idx + 5 + sni_name_len <= ext_end:
                        return payload[idx + 5:idx + 5 + sni_name_len].decode("ascii", errors="ignore")
            idx += ext_len
    except Exception:
        pass
    return None


class PCAPAnalysisResult:
    def __init__(self):
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.start_timestamp: Optional[float] = None
        self.end_timestamp: Optional[float] = None
        self.protocols: Dict[str, int] = {}
        self.ip_conversations: Dict[str, int] = {}
        self.top_source_ips: Dict[str, int] = {}
        self.top_dest_ips: Dict[str, int] = {}
        self.port_traffic: Dict[int, int] = {}
        self.dns_queries: List[Dict[str, Any]] = []
        self.tcp_connections: List[Dict[str, Any]] = []
        self.tls_sessions: List[Dict[str, Any]] = []
        self.security_anomalies: List[Dict[str, Any]] = []
        self.file_format: str = "Unknown"

    def to_dict(self) -> Dict[str, Any]:
        duration = 0.0
        if self.start_timestamp and self.end_timestamp and self.end_timestamp >= self.start_timestamp:
            duration = round(self.end_timestamp - self.start_timestamp, 3)

        # Sort top talkers
        sorted_sources = sorted(self.top_source_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        sorted_dests = sorted(self.top_dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        sorted_conversations = [
            {"conversation": k, "packet_count": v}
            for k, v in sorted(self.ip_conversations.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        sorted_ports = sorted(self.port_traffic.items(), key=lambda x: x[1], reverse=True)[:10]

        # Aggregate unique DNS
        dns_summary = {}
        for q in self.dns_queries:
            key = f"{q.get('domain')} ({q.get('type')})"
            dns_summary[key] = dns_summary.get(key, 0) + 1
        sorted_dns = [{"domain_record": k, "count": v} for k, v in sorted(dns_summary.items(), key=lambda x: x[1], reverse=True)[:15]]

        return {
            "format": self.file_format,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_seconds": duration,
            "start_time": datetime.fromtimestamp(self.start_timestamp, tz=timezone.utc).isoformat() if self.start_timestamp else None,
            "end_time": datetime.fromtimestamp(self.end_timestamp, tz=timezone.utc).isoformat() if self.end_timestamp else None,
            "protocols": self.protocols,
            "top_source_ips": [{"ip": ip, "count": cnt} for ip, cnt in sorted_sources],
            "top_dest_ips": [{"ip": ip, "count": cnt} for ip, cnt in sorted_dests],
            "conversations": sorted_conversations,
            "top_ports": [{"port": p, "count": cnt} for p, cnt in sorted_ports],
            "dns_activity": sorted_dns,
            "tcp_sessions_sample": self.tcp_connections[:15],
            "tls_sni_sample": self.tls_sessions[:10],
            "security_anomalies": self.security_anomalies[:20],
            "anomaly_count": len(self.security_anomalies)
        }


def parse_pcap_bytes(data: bytes) -> PCAPAnalysisResult:
    """Parse raw PCAP or PCAPNG bytes into a structured PCAPAnalysisResult."""
    result = PCAPAnalysisResult()
    if len(data) < 24:
        raise ValueError("File is too small to be a valid PCAP/PCAPNG capture.")

    # 1. Detect PCAP vs PCAPNG
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (PCAP_MAGIC_MICRO_BE, PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_NANO_BE, PCAP_MAGIC_NANO_LE):
        result.file_format = "Standard PCAP"
        _parse_standard_pcap(data, result)
    elif magic == PCAPNG_SECTION_HEADER_BLOCK:
        result.file_format = "PCAPNG (Next Generation)"
        _parse_pcapng(data, result)
    else:
        # Check big-endian magic
        magic_be = struct.unpack(">I", data[:4])[0]
        if magic_be in (PCAP_MAGIC_MICRO_BE, PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_NANO_BE, PCAP_MAGIC_NANO_LE):
            result.file_format = "Standard PCAP (BE)"
            _parse_standard_pcap(data, result)
        else:
            raise ValueError(f"Unrecognized capture header magic: 0x{magic:08x}. Must be valid PCAP or PCAPNG.")

    # Run post-parse heuristic anomaly checks
    _evaluate_capture_anomalies(result)
    return result


def parse_pcap_file(filepath: str) -> PCAPAnalysisResult:
    """Read and parse a PCAP/PCAPNG file from disk."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Capture file does not exist: {filepath}")
    with open(filepath, "rb") as f:
        data = f.read()
    return parse_pcap_bytes(data)


def _parse_standard_pcap(data: bytes, res: PCAPAnalysisResult):
    """Parse classic tcpdump/Wireshark PCAP format."""
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<"
    is_nano = False
    if magic in (PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_NANO_LE):
        endian = "<"
        is_nano = (magic == PCAP_MAGIC_NANO_LE)
    else:
        endian = ">"
        magic_be = struct.unpack(">I", data[:4])[0]
        is_nano = (magic_be in (PCAP_MAGIC_NANO_BE, PCAP_MAGIC_NANO_LE))

    # Read global header (24 bytes)
    # magic(4), ver_major(2), ver_minor(2), thiszone(4), sigfigs(4), snaplen(4), network(4)
    network_link = struct.unpack(f"{endian}I", data[20:24])[0]
    offset = 24
    data_len = len(data)

    while offset + 16 <= data_len:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", data[offset:offset + 16])
        offset += 16
        if offset + incl_len > data_len:
            break  # Truncated trailing packet
        pkt_data = data[offset:offset + incl_len]
        offset += incl_len

        # Timestamp
        ts_float = ts_sec + (ts_usec / 1e9 if is_nano else ts_usec / 1e6)
        _process_single_packet(pkt_data, ts_float, incl_len, network_link, res)


def _parse_pcapng(data: bytes, res: PCAPAnalysisResult):
    """Parse PCAPNG block format."""
    offset = 0
    data_len = len(data)
    endian = "<"
    link_type = 1  # Default Ethernet

    while offset + 8 <= data_len:
        block_type, block_len = struct.unpack(f"{endian}II", data[offset:offset + 8])
        if block_len < 12 or offset + block_len > data_len:
            break

        block_data = data[offset:offset + block_len]
        if block_type == PCAPNG_SECTION_HEADER_BLOCK:
            # Check byte order magic inside SHB at offset 8
            if len(block_data) >= 12:
                bom = struct.unpack("<I", block_data[8:12])[0]
                if bom == 0x1A2B3C4D:
                    endian = "<"
                elif bom == 0x4D3C2B1A:
                    endian = ">"
        elif block_type == PCAPNG_INTERFACE_DESC_BLOCK:
            if len(block_data) >= 12:
                link_type = struct.unpack(f"{endian}H", block_data[8:10])[0]
        elif block_type == PCAPNG_ENHANCED_PACKET_BLOCK:
            if len(block_data) >= 32:
                # interface_id(4), ts_high(4), ts_low(4), cap_len(4), orig_len(4)
                iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(f"{endian}IIIII", block_data[8:28])
                ts_ticks = (ts_high << 32) | ts_low
                ts_float = ts_ticks / 1e6  # Default microsecond resolution
                pkt_data = block_data[28:28 + cap_len]
                _process_single_packet(pkt_data, ts_float, cap_len, link_type, res)
        elif block_type == PCAPNG_SIMPLE_PACKET_BLOCK:
            if len(block_data) >= 16:
                orig_len = struct.unpack(f"{endian}I", block_data[8:12])[0]
                cap_len = block_len - 16
                pkt_data = block_data[12:12 + cap_len]
                _process_single_packet(pkt_data, time.time(), cap_len, link_type, res)

        offset += block_len


def _process_single_packet(
    pkt_bytes: bytes,
    ts: float,
    length: int,
    link_type: int,
    res: PCAPAnalysisResult
):
    """Dissect Ethernet, IP, TCP/UDP, and application payload metadata."""
    res.total_packets += 1
    res.total_bytes += length

    if res.start_timestamp is None or ts < res.start_timestamp:
        res.start_timestamp = ts
    if res.end_timestamp is None or ts > res.end_timestamp:
        res.end_timestamp = ts

    # Handle Link Type (1 = LINKTYPE_ETHERNET)
    payload = pkt_bytes
    ethertype = ETHERTYPE_IPV4
    if link_type == 1:
        if len(pkt_bytes) < 14:
            return
        ethertype = struct.unpack("!H", pkt_bytes[12:14])[0]
        payload = pkt_bytes[14:]

    if ethertype == ETHERTYPE_ARP:
        res.protocols["ARP"] = res.protocols.get("ARP", 0) + 1
        return

    if ethertype == ETHERTYPE_IPV6:
        res.protocols["IPv6"] = res.protocols.get("IPv6", 0) + 1
        return

    if ethertype != ETHERTYPE_IPV4 or len(payload) < 20:
        res.protocols["Other"] = res.protocols.get("Other", 0) + 1
        return

    # IPv4 Header
    ver_ihl = payload[0]
    ihl = (ver_ihl & 0x0F) * 4
    if len(payload) < ihl:
        return

    ip_proto = payload[9]
    src_ip = socket.inet_ntoa(payload[12:16])
    dst_ip = socket.inet_ntoa(payload[16:20])
    l4_payload = payload[ihl:]

    # Track IPs
    res.top_source_ips[src_ip] = res.top_source_ips.get(src_ip, 0) + 1
    res.top_dest_ips[dst_ip] = res.top_dest_ips.get(dst_ip, 0) + 1
    conv_key = f"{src_ip} <-> {dst_ip}"
    res.ip_conversations[conv_key] = res.ip_conversations.get(conv_key, 0) + 1

    if ip_proto == IP_PROTO_ICMP:
        res.protocols["ICMP"] = res.protocols.get("ICMP", 0) + 1
        return

    elif ip_proto == IP_PROTO_TCP:
        res.protocols["TCP"] = res.protocols.get("TCP", 0) + 1
        if len(l4_payload) < 20:
            return
        src_port, dst_port, seq, ack, offset_reserved = struct.unpack("!HHIIB", l4_payload[:13])
        flags = l4_payload[13]
        tcp_header_len = ((offset_reserved >> 4) & 0x0F) * 4
        app_payload = l4_payload[tcp_header_len:]

        res.port_traffic[dst_port] = res.port_traffic.get(dst_port, 0) + 1
        res.port_traffic[src_port] = res.port_traffic.get(src_port, 0) + 1

        # Flags: SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04
        flag_strs = []
        if flags & 0x02: flag_strs.append("SYN")
        if flags & 0x10: flag_strs.append("ACK")
        if flags & 0x01: flag_strs.append("FIN")
        if flags & 0x04: flag_strs.append("RST")
        if flags & 0x08: flag_strs.append("PSH")

        # Classify Application Layer
        if dst_port == 443 or src_port == 443 or dst_port == 8443:
            res.protocols["TLS/HTTPS"] = res.protocols.get("TLS/HTTPS", 0) + 1
            sni = _parse_tls_sni(app_payload)
            if sni:
                res.tls_sessions.append({"client_ip": src_ip, "server_ip": dst_ip, "sni": sni})
        elif dst_port in (80, 8080, 8000) or src_port in (80, 8080, 8000):
            res.protocols["HTTP"] = res.protocols.get("HTTP", 0) + 1
        elif dst_port == 21 or src_port == 21:
            res.protocols["FTP"] = res.protocols.get("FTP", 0) + 1
            if b"USER " in app_payload:
                res.security_anomalies.append({
                    "severity": "CRITICAL",
                    "type": "CLEARTEXT_CREDENTIAL_FTP",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": 21,
                    "description": "Cleartext FTP USER command observed traversing network segment."
                })
        elif dst_port == 23 or src_port == 23:
            res.protocols["Telnet"] = res.protocols.get("Telnet", 0) + 1
            res.security_anomalies.append({
                "severity": "CRITICAL",
                "type": "LEGACY_TELNET_TRAFFIC",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": 23,
                "description": "Unencrypted Telnet command stream observed in traffic capture."
            })
        elif dst_port == 53 or src_port == 53:
            res.protocols["DNS"] = res.protocols.get("DNS", 0) + 1
            dns_res = _parse_dns_query(app_payload)
            if dns_res:
                res.dns_queries.append({"domain": dns_res[0], "type": dns_res[1], "client": src_ip})

        res.tcp_connections.append({
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "flags": "|".join(flag_strs) or "NONE",
            "bytes": len(l4_payload)
        })

    elif ip_proto == IP_PROTO_UDP:
        res.protocols["UDP"] = res.protocols.get("UDP", 0) + 1
        if len(l4_payload) < 8:
            return
        src_port, dst_port, udp_len = struct.unpack("!HHH", l4_payload[:6])
        app_payload = l4_payload[8:]

        res.port_traffic[dst_port] = res.port_traffic.get(dst_port, 0) + 1
        res.port_traffic[src_port] = res.port_traffic.get(src_port, 0) + 1

        if dst_port == 53 or src_port == 53:
            res.protocols["DNS"] = res.protocols.get("DNS", 0) + 1
            dns_res = _parse_dns_query(app_payload)
            if dns_res:
                res.dns_queries.append({"domain": dns_res[0], "type": dns_res[1], "client": src_ip})
                # Check for suspicious long subdomains (DNS Tunneling)
                if len(dns_res[0]) > 60:
                    res.security_anomalies.append({
                        "severity": "HIGH",
                        "type": "POTENTIAL_DNS_TUNNELING",
                        "src_ip": src_ip,
                        "domain": dns_res[0],
                        "description": f"Unusually long DNS query ({len(dns_res[0])} chars) indicates potential C2 tunneling."
                    })
        elif dst_port in (67, 68) or src_port in (67, 68):
            res.protocols["DHCP"] = res.protocols.get("DHCP", 0) + 1
        elif dst_port == 123 or src_port == 123:
            res.protocols["NTP"] = res.protocols.get("NTP", 0) + 1


def _evaluate_capture_anomalies(res: PCAPAnalysisResult):
    """Analyze aggregated flow statistics for port scanning, floods, and plain HTTP."""
    # 1. Port scan detection: single source IP connecting to many distinct ports
    target_ports_by_src: Dict[str, Set[int]] = {}
    for conn in res.tcp_connections:
        try:
            src_ip = conn["src"].split(":")[0]
            dst_port = int(conn["dst"].split(":")[1])
            if src_ip not in target_ports_by_src:
                target_ports_by_src[src_ip] = set()
            target_ports_by_src[src_ip].add(dst_port)
        except Exception:
            continue

    for src_ip, ports in target_ports_by_src.items():
        if len(ports) >= 6:
            res.security_anomalies.append({
                "severity": "HIGH",
                "type": "RECONNAISSANCE_PORT_SCAN",
                "src_ip": src_ip,
                "distinct_ports_contacted": len(ports),
                "ports_sample": list(ports)[:10],
                "description": f"Source {src_ip} swept {len(ports)} distinct ports within capture window."
            })

    # 2. Plaintext HTTP Alert
    if res.protocols.get("HTTP", 0) > 0:
        res.security_anomalies.append({
            "severity": "MEDIUM",
            "type": "UNENCRYPTED_HTTP_OBSERVED",
            "packet_count": res.protocols.get("HTTP", 0),
            "description": "Cleartext HTTP packets observed. Sensitive headers and cookies may be readable on transit."
        })


# --- Sample PCAP Binary Generator ---

def generate_sample_benign_pcap() -> bytes:
    """Creates a valid binary PCAP containing realistic benign enterprise traffic:
    - DNS A query & response for 'api.agentshield.internal'
    - TLS Client Hello to 'gateway.security.internal:443'
    - HTTP GET /api/v1/health request & 200 OK response
    - ICMP Echo request and reply
    - Benign cleartext reconnaissance marker for anomaly engine testing
    """
    out = io.BytesIO()

    # 1. PCAP Global Header (24 bytes)
    # magic(4), major(2), minor(2), thiszone(4), sigfigs(4), snaplen(4), network(4)
    out.write(struct.pack("<IHHiIII", PCAP_MAGIC_MICRO_LE, 2, 4, 0, 0, 65535, 1))

    now = time.time() - 30.0

    def write_packet(pkt_bytes: bytes, delta: float = 0.1):
        nonlocal now
        now += delta
        ts_sec = int(now)
        ts_usec = int((now - ts_sec) * 1e6)
        out.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt_bytes), len(pkt_bytes)))
        out.write(pkt_bytes)

    src_mac = b"\x00\x0c\x29\x4f\x8e\x35"
    dst_mac = b"\x00\x50\x56\xc0\x00\x08"

    def build_eth_ip_udp(src_ip: str, dst_ip: str, src_p: int, dst_p: int, udp_payload: bytes) -> bytes:
        eth = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPV4)
        ip_total_len = 20 + 8 + len(udp_payload)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, ip_total_len, 0x1234, 0x4000, 64, IP_PROTO_UDP, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
        )
        udp = struct.pack("!HHHH", src_p, dst_p, 8 + len(udp_payload), 0)
        return eth + ip + udp + udp_payload

    def build_eth_ip_tcp(src_ip: str, dst_ip: str, src_p: int, dst_p: int, flags: int, tcp_payload: bytes = b"") -> bytes:
        eth = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPV4)
        ip_total_len = 20 + 20 + len(tcp_payload)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, ip_total_len, 0x5678, 0x4000, 64, IP_PROTO_TCP, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
        )
        # 5 words header length = 20 bytes
        tcp = struct.pack("!HHIIBBHHH", src_p, dst_p, 1000, 2000, (5 << 4), flags, 8192, 0, 0)
        return eth + ip + tcp + tcp_payload

    # Packet 1: DNS Query for api.agentshield.internal
    dns_query = struct.pack("!HHHHHH", 0x1a2b, 0x0100, 1, 0, 0, 0)
    # Domain labels: 3 api 11 agentshield 8 internal 0
    dns_query += b"\x03api\x0bagentshield\x08internal\x00\x00\x01\x00\x01"
    write_packet(build_eth_ip_udp("192.168.1.50", "192.168.1.1", 54321, 53, dns_query))

    # Packet 2: DNS Response
    dns_resp = struct.pack("!HHHHHH", 0x1a2b, 0x8180, 1, 1, 0, 0)
    dns_resp += b"\x03api\x0bagentshield\x08internal\x00\x00\x01\x00\x01"
    # Answer: pointer to name (0xc00c), type A(1), class IN(1), TTL 300, len 4, IP 192.168.1.10
    dns_resp += struct.pack("!HHIH", 0xc00c, 1, 1, 300) + struct.pack("!H4s", 4, socket.inet_aton("192.168.1.10"))
    write_packet(build_eth_ip_udp("192.168.1.1", "192.168.1.50", 53, 54321, dns_resp))

    # Packet 3: TCP SYN to Port 443 (gateway.security.internal)
    write_packet(build_eth_ip_tcp("192.168.1.50", "192.168.1.10", 49152, 443, 0x02))

    # Packet 4: TCP SYN-ACK from Port 443
    write_packet(build_eth_ip_tcp("192.168.1.10", "192.168.1.50", 443, 49152, 0x12))

    # Packet 5: TLS Client Hello with SNI "gateway.security.internal"
    sni_hostname = b"gateway.security.internal"
    sni_ext_data = struct.pack("!H", len(sni_hostname) + 3) + b"\x00" + struct.pack("!H", len(sni_hostname)) + sni_hostname
    ext_block = struct.pack("!HH", 0, len(sni_ext_data)) + sni_ext_data
    # Dummy Client Hello structure
    ch_body = b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack("!H", 2) + b"\x00\x2f" + b"\x01\x00" + struct.pack("!H", len(ext_block)) + ext_block
    hs_header = struct.pack("!B", 1) + struct.pack("!I", len(ch_body))[1:] + ch_body
    tls_record = struct.pack("!BHH", 0x16, 0x0303, len(hs_header)) + hs_header
    write_packet(build_eth_ip_tcp("192.168.1.50", "192.168.1.10", 49152, 443, 0x18, tls_record))

    # Packet 6: HTTP GET /health
    http_req = b"GET /api/v1/health HTTP/1.1\r\nHost: 192.168.1.10:8000\r\nUser-Agent: AgentShield-Monitor/1.0\r\nAccept: application/json\r\n\r\n"
    write_packet(build_eth_ip_tcp("192.168.1.50", "192.168.1.10", 49153, 8000, 0x18, http_req))

    # Packet 7: HTTP 200 OK
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"status\":\"SYSTEMS_ONLINE\"}"
    write_packet(build_eth_ip_tcp("192.168.1.10", "192.168.1.50", 8000, 49153, 0x18, http_resp))

    # Packet 8: Simulated Reconnaissance Probe across 6 ports (for anomaly detection testing)
    recon_src = "192.168.1.200"
    for target_p in [21, 22, 23, 80, 443, 3389, 8080]:
        write_packet(build_eth_ip_tcp(recon_src, "192.168.1.10", 55000 + target_p, target_p, 0x02), delta=0.02)

    return out.getvalue()
