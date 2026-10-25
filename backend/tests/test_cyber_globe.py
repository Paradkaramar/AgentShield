# backend/tests/test_cyber_globe.py
"""Automated Test Suite for AgentShield 3D Cyber Network Globe & Targeted Scanner.
Validates:
1. Live vs Demo telemetry mode separation
2. Strict Private LAN non-geolocation boundary (RFC 1918 / loopback never placed on Earth coordinates)
3. Verified Public IP geolocation and confidence tagging
4. Target scanning scope validation and user authorization enforcement
5. Device details and factual AI explanation without hallucinations
6. Wireshark/TShark traffic streaming telemetry
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import init_db
from app.core.auth import create_access_token
from app.engines.geolocation import get_ip_geolocation, is_private_or_local_ip
from app.engines.nmap_engine import validate_target_scope

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def auth_headers(role: str = "admin") -> dict:
    token = create_access_token({"sub": "admin", "role": role})
    return {"Authorization": f"Bearer {token}"}


def test_private_ip_never_geolocated():
    """Ensures private addresses (RFC 1918, loopback, CGNAT) are never geolocated to real Earth coordinates."""
    private_samples = [
        "127.0.0.1",
        "192.168.1.1",
        "192.168.0.254",
        "10.0.0.15",
        "10.254.1.1",
        "172.16.0.1",
        "172.31.255.254",
        "169.254.1.1"
    ]
    for ip in private_samples:
        assert is_private_or_local_ip(ip) is True
        geo = get_ip_geolocation(ip)
        assert geo["is_private"] is True
        assert geo["geolocated"] is False
        assert geo["latitude"] is None
        assert geo["longitude"] is None
        assert geo["location_confidence"] == "PRIVATE_LAN_ENCLAVE"
        assert "Virtual Topology" in geo["display_location"]


def test_public_ip_geolocated():
    """Ensures public IPs have approximate coordinates and explicit confidence ratings."""
    public_samples = ["8.8.8.8", "1.1.1.1", "52.95.245.1", "35.200.0.1"]
    for ip in public_samples:
        assert is_private_or_local_ip(ip) is False
        geo = get_ip_geolocation(ip)
        assert geo["is_private"] is False
        assert geo["geolocated"] is True
        assert isinstance(geo["latitude"], float)
        assert isinstance(geo["longitude"], float)
        assert -90.0 <= geo["latitude"] <= 90.0
        assert -180.0 <= geo["longitude"] <= 180.0
        assert geo["location_confidence"] in ("VERIFIED_PUBLIC_IP", "APPROXIMATE_REGIONAL")


def test_globe_telemetry_live():
    """Tests GET /api/globe/telemetry in live mode."""
    res = client.get("/api/globe/telemetry?mode=live", headers=auth_headers())
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["mode"] == "live"
    assert data["is_demo_mode"] is False
    assert "summary" in data
    assert "globe_nodes" in data
    assert "virtual_lan_nodes" in data
    assert "connection_arcs" in data


def test_globe_telemetry_demo():
    """Tests GET /api/globe/telemetry in demo mode clearly distinguishing simulation."""
    res = client.get("/api/globe/telemetry?mode=demo", headers=auth_headers())
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["mode"] == "demo"
    assert data["is_demo_mode"] is True
    assert "DEMO SIMULATION ACTIVE" in data["simulation_banner"]
    assert len(data["globe_nodes"]) >= 3
    assert len(data["connection_arcs"]) >= 2
    # Verify simulated attack node is present with distinct alert color
    attack_node = next((n for n in data["globe_nodes"] if n["indicator"] == "ALERT_CRITICAL"), None)
    assert attack_node is not None
    assert attack_node["marker_color"] == "#ef4444"


def test_scan_authorization_enforced():
    """Tests that scan execution is blocked if user_confirmed is False."""
    payload = {
        "target": "127.0.0.1",
        "profile": "quick_ports",
        "user_confirmed": False
    }
    res = client.post("/api/globe/scan/start", json=payload, headers=auth_headers())
    assert res.status_code == 400
    assert "Target authorization unverified" in res.json()["detail"]


def test_scan_scope_boundaries():
    """Validates boundary validation against dangerous shell characters and oversized CIDRs."""
    # Shell injection attempt
    valid, err, _ = validate_target_scope("127.0.0.1; rm -rf /", user_confirmed=True)
    assert valid is False
    assert "illegal characters" in err

    # Oversized subnet (> /24)
    valid, err, _ = validate_target_scope("192.168.0.0/16", user_confirmed=True)
    assert valid is False
    assert "too large" in err

    # Valid /24 subnet
    valid, err, ips = validate_target_scope("192.168.1.0/24", user_confirmed=True)
    assert valid is True
    assert err is None
    assert len(ips) > 0


def test_device_details_endpoint():
    """Tests GET /api/globe/device/{ip} returns real facts and geolocation metadata."""
    res = client.get("/api/globe/device/127.0.0.1", headers=auth_headers())
    assert res.status_code == 200
    dev = res.json()["device"]
    assert dev["ip_address"] == "127.0.0.1"
    assert dev["is_private"] is True
    assert dev["geolocation"]["geolocated"] is False
    assert "observed_ports" in dev
    assert "relevant_findings" in dev


def test_ai_explain_device_facts_only():
    """Tests POST /api/globe/ai-explain delivers deterministic, factual reasoning without hallucinations."""
    res = client.post("/api/globe/ai-explain", json={"ip_address": "127.0.0.1"}, headers=auth_headers())
    assert res.status_code == 200
    data = res.json()
    assert "analyst_verdict" in data
    assert "risk_score" in data
    assert "evidence_chain" in data
    assert "verified_evidence_statement" in data
    assert "No synthetic ports" in data["verified_evidence_statement"]


def test_traffic_stream_endpoint():
    """Tests GET /api/globe/traffic/stream returns real packet structures."""
    res = client.get("/api/globe/traffic/stream", headers=auth_headers())
    assert res.status_code == 200
    data = res.json()
    assert "packets" in data
    assert "metrics" in data
    assert "tcp_stream_rate" in data["metrics"]
    assert len(data["packets"]) > 0
    pkt = data["packets"][0]
    assert "src" in pkt
    assert "dst" in pkt
    assert "protocol" in pkt
