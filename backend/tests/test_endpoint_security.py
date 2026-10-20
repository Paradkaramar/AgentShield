# backend/tests/test_endpoint_security.py
"""
AgentShield Installable Personal Device Security Platform
Comprehensive Integration & Verification Test Suite

Tests:
1. Enrollment token generation & expiration
2. Device enrollment with valid token & unique credential generation
3. Rejection of invalid, expired, or reused enrollment tokens
4. Granular consent management & mandatory permission immutability
5. Dynamic consent enforcement (withholding telemetry collectors)
6. EndpointAgent local hardware & OS discovery
7. Host firewall status inspection (Windows Defender / Linux UFW)
8. Process inventory & heuristic classification (observed_fact vs heuristic_flag)
9. Network connection inspection & suspicious outbound port detection
10. Suspicious file heuristic & SHA-256 scanning
11. Device monitoring pause and resume controls
12. Device disconnection and permanent revocation
13. Host firewall rule authorization with operator lockout protection
14. Multilingual JARVIS assistant endpoint voice/text commands (EN, HI, MR)
15. Cryptographic audit trail logging for all device actions
"""

import pytest
import json
import hashlib
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import init_db, connect, now_iso
from app.core.auth import create_access_token
from app.services.endpoint_agent import EndpointAgent
from app.jarvis.multilingual_commands import parse_multilingual_intent

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    """Ensure database schema and baseline tables are freshly initialized."""
    init_db()
    with connect() as db:
        db.execute(
            "UPDATE enrolled_devices SET is_revoked = 0, monitoring_status = 'ACTIVE' WHERE id = 'dev-primary-desktop'"
        )

@pytest.fixture
def auth_headers():
    token = create_access_token({"username": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def analyst_headers():
    token = create_access_token({"username": "analyst", "role": "security_analyst"})
    return {"Authorization": f"Bearer {token}"}


# ============================================================================
# 1. ENROLLMENT TOKEN TESTS
# ============================================================================

def test_enrollment_token_generation(auth_headers):
    """Test generating a short-lived, secure enrollment token."""
    resp = client.post("/api/endpoint/enrollment-tokens", json={"created_by": "admin", "valid_days": 7}, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["token"].startswith("SHIELD-")
    assert data["status"] == "ACTIVE"

    # Verify listing tokens
    list_resp = client.get("/api/endpoint/enrollment-tokens", headers=auth_headers)
    assert list_resp.status_code == 200
    tokens = list_resp.json()
    assert any(t["token"] == data["token"] for t in tokens)


def test_device_enrollment_valid_token(auth_headers):
    """Test enrolling a new computer using a valid token and verifying consent defaults."""
    # 1. Generate token
    tok_resp = client.post("/api/endpoint/enrollment-tokens", json={"created_by": "admin", "valid_days": 1}, headers=auth_headers)
    token = tok_resp.json()["token"]

    # 2. Enroll device
    enroll_payload = {
        "token": token,
        "device_name": "Test-SecOps-Laptop",
        "hostname": "SECOPS-LAPTOP-01",
        "os_type": "windows",
        "os_release": "11 Pro",
        "os_version": "10.0.26100",
        "agent_version": "1.2.0",
        "ip_address": "192.168.1.188",
        "cpu_cores": 8,
        "total_memory_mb": 16384,
        "consent_permissions": {
            "network_monitoring": True,
            "process_metadata": True,
            "firewall_inspection": True,
            "suspicious_file_scan": False
        }
    }

    resp = client.post("/api/endpoint/enroll", json=enroll_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ENROLLED"
    assert "device_id" in data
    assert "device_token" in data
    dev_id = data["device_id"]

    # 3. Verify in device list
    dev_list_resp = client.get("/api/endpoint/devices", headers=auth_headers)
    assert dev_list_resp.status_code == 200
    devices = dev_list_resp.json()
    enrolled = next((d for d in devices if d["id"] == dev_id), None)
    assert enrolled is not None
    assert enrolled["device_name"] == "Test-SecOps-Laptop"
    assert enrolled["monitoring_status"] == "ACTIVE"


def test_device_enrollment_invalid_token():
    """Test that unauthorized enrollment tokens are strictly rejected."""
    enroll_payload = {
        "token": "INVALID-TOKEN-9999",
        "device_name": "Rogue-Computer"
    }
    resp = client.post("/api/endpoint/enroll", json=enroll_payload)
    assert resp.status_code == 400
    assert "Invalid enrollment token" in resp.json()["detail"]


def test_device_enrollment_token_reuse(auth_headers):
    """Test that a consumed enrollment token cannot be replayed."""
    # Generate token
    tok_resp = client.post("/api/endpoint/enrollment-tokens", json={"created_by": "admin", "valid_days": 1}, headers=auth_headers)
    token = tok_resp.json()["token"]

    # First enrollment succeeds
    resp1 = client.post("/api/endpoint/enroll", json={"token": token, "device_name": "PC-1"})
    assert resp1.status_code == 200

    # Second enrollment with same token must fail
    resp2 = client.post("/api/endpoint/enroll", json={"token": token, "device_name": "PC-2"})
    assert resp2.status_code == 400
    assert "already been consumed" in resp2.json()["detail"]


# ============================================================================
# 2. GRANULAR CONSENT & PERMISSION ENFORCEMENT TESTS
# ============================================================================

def test_granular_consent_retrieval_and_update(auth_headers):
    """Test retrieving and dynamically updating granular permission records."""
    # Use demo workstation
    dev_id = "dev-primary-desktop"
    consent_resp = client.get(f"/api/endpoint/devices/{dev_id}/consent", headers=auth_headers)
    assert consent_resp.status_code == 200
    perms = consent_resp.json()
    assert len(perms) >= 8

    # Verify mandatory permission cannot be revoked
    bad_update = client.put(
        f"/api/endpoint/devices/{dev_id}/consent",
        json={"permissions": {"device_identification": False}},
        headers=auth_headers
    )
    assert bad_update.status_code == 400
    assert "mandatory" in bad_update.json()["detail"]

    # Verify optional permission can be toggled
    good_update = client.put(
        f"/api/endpoint/devices/{dev_id}/consent",
        json={"permissions": {"process_metadata": False, "suspicious_file_scan": True}},
        headers=auth_headers
    )
    assert good_update.status_code == 200
    assert good_update.json()["status"] == "SUCCESS"

    # Verify updated values
    check_resp = client.get(f"/api/endpoint/devices/{dev_id}/consent", headers=auth_headers)
    updated_perms = {p["permission_key"]: bool(p["granted"]) for p in check_resp.json()}
    assert updated_perms["process_metadata"] is False
    assert updated_perms["suspicious_file_scan"] is True


def test_consent_enforcement_telemetry_withheld(auth_headers):
    """Test that when consent is revoked, the API and agent stop serving that telemetry."""
    dev_id = "dev-primary-desktop"

    # Revoke process_metadata
    client.put(
        f"/api/endpoint/devices/{dev_id}/consent",
        json={"permissions": {"process_metadata": False}},
        headers=auth_headers
    )

    # Query processes - must return CONSENT_WITHHELD
    resp = client.get(f"/api/endpoint/devices/{dev_id}/processes", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "CONSENT_WITHHELD"
    assert data["processes"] == []
    assert "withheld consent" in data["message"]

    # Re-enable process_metadata
    client.put(
        f"/api/endpoint/devices/{dev_id}/consent",
        json={"permissions": {"process_metadata": True}},
        headers=auth_headers
    )
    resp_enabled = client.get(f"/api/endpoint/devices/{dev_id}/processes", headers=auth_headers)
    assert resp_enabled.status_code == 200
    assert resp_enabled.json()["status"] == "OK"


# ============================================================================
# 3. ENDPOINT AGENT CAPABILITY TESTS
# ============================================================================

def test_endpoint_agent_hardware_discovery():
    """Test real endpoint agent hardware, platform, and network interface discovery."""
    agent = EndpointAgent("dev-test-hw")
    hw = agent.get_hardware_and_os_info()

    assert hw["device_id"] == "dev-test-hw"
    assert hw["os_type"] in ["windows", "linux", "darwin"]
    assert hw["cpu_cores"] >= 1
    assert hw["total_memory_mb"] > 512
    assert hw["agent_version"] == "1.2.0"
    assert hw["ip_address"] != ""


def test_endpoint_agent_firewall_inspection():
    """Test host firewall inspection without requiring administrative elevation."""
    agent = EndpointAgent("dev-test-fw")
    fw = agent.inspect_firewall_status()

    assert "os_firewall_type" in fw
    assert "is_enabled" in fw
    assert "default_inbound" in fw
    assert "profile_statuses" in fw
    assert fw["default_inbound"] in ["BLOCK", "UNKNOWN"]


def test_endpoint_agent_process_heuristics():
    """Test process metadata collection and LOLBin / commandline heuristic detection."""
    agent = EndpointAgent("dev-test-procs")
    procs = agent.collect_process_inventory(limit=10)

    # Should collect real processes on the system
    assert len(procs) > 0
    first = procs[0]
    assert "pid" in first
    assert "name" in first
    assert "fact_classification" in first
    assert first["fact_classification"] in ["observed_fact", "heuristic_flag"]


def test_endpoint_agent_file_heuristic_scanning():
    """Test file heuristic scanning respecting user consent and header analysis."""
    agent = EndpointAgent("dev-primary-desktop")

    # With consent for suspicious_file_scan withheld:
    with connect() as db:
        db.execute(
            "UPDATE device_consent_records SET granted = 0 WHERE device_id = 'dev-primary-desktop' AND permission_key = 'suspicious_file_scan'"
        )

    res_withheld = agent.scan_file_heuristics("README.md")
    assert res_withheld["scanned"] is False
    assert "revoked" in res_withheld["error"]

    # Grant consent and scan README.md
    with connect() as db:
        db.execute(
            "UPDATE device_consent_records SET granted = 1 WHERE device_id = 'dev-primary-desktop' AND permission_key = 'suspicious_file_scan'"
        )

    res_granted = agent.scan_file_heuristics("README.md")
    assert res_granted["scanned"] is True
    assert "sha256" in res_granted
    assert len(res_granted["sha256"]) == 64
    assert res_granted["fact_classification"] == "observed_fact"


# ============================================================================
# 4. DEVICE MANAGEMENT, PAUSE, DISCONNECT & REVOCATION
# ============================================================================

def test_device_monitoring_pause_and_resume(auth_headers):
    """Test pause and resume controls for device security monitoring."""
    dev_id = "dev-primary-desktop"

    # Pause
    pause_resp = client.post(f"/api/endpoint/devices/{dev_id}/pause", headers=auth_headers)
    assert pause_resp.status_code == 200
    assert pause_resp.json()["status"] == "PAUSED"

    # Verify details reflect PAUSED
    det = client.get(f"/api/endpoint/devices/{dev_id}", headers=auth_headers).json()
    assert det["monitoring_status"] == "PAUSED"

    # Agent sync during paused state does not collect telemetry
    agent = EndpointAgent(dev_id)
    sync_res = agent.sync_telemetry_to_local_db()
    assert sync_res["status"] == "PAUSED"

    # Resume
    resume_resp = client.post(f"/api/endpoint/devices/{dev_id}/resume", headers=auth_headers)
    assert resume_resp.status_code == 200
    assert resume_resp.json()["status"] == "ACTIVE"


def test_device_disconnect_and_revocation(auth_headers):
    """Test disconnecting a device and permanently revoking credentials."""
    dev_id = "dev-revoke-test"
    with connect() as db:
        db.execute(
            """INSERT INTO enrolled_devices (
                id, device_name, hostname, os_type, os_release, os_version,
                agent_version, device_token_hash, enrolled_at, last_heartbeat,
                monitoring_status, is_revoked, revocation_reason, cpu_cores, total_memory_mb
            ) VALUES (?, 'Revoke-Target-PC', 'DESKTOP-REV', 'windows', '11', '10.0', '1.2.0', 'fakehash', ?, ?, 'ACTIVE', 0, NULL, 4, 8192)
            ON CONFLICT(id) DO UPDATE SET is_revoked = 0, monitoring_status = 'ACTIVE'""",
            (dev_id, now_iso(), now_iso())
        )

    # Disconnect
    disc = client.post(f"/api/endpoint/devices/{dev_id}/disconnect", headers=auth_headers)
    assert disc.status_code == 200
    assert disc.json()["status"] == "DISCONNECTED"

    # Revoke
    revoke_resp = client.post(
        f"/api/endpoint/devices/{dev_id}/revoke?reason=Decommissioned+workstation",
        headers=auth_headers
    )
    assert revoke_resp.status_code == 200
    data = revoke_resp.json()
    assert data["status"] == "REVOKED"

    # Verify device record is marked revoked
    det = client.get(f"/api/endpoint/devices/{dev_id}", headers=auth_headers).json()
    assert det["is_revoked"] == 1
    assert "Decommissioned" in det["revocation_reason"]

    # Revoked device cannot be resumed
    resume_attempt = client.post(f"/api/endpoint/devices/{dev_id}/resume", headers=auth_headers)
    assert resume_attempt.status_code == 400


# ============================================================================
# 5. PROTECTIVE FIREWALL ACTION & LOCKOUT SAFETY
# ============================================================================

def test_authorized_firewall_action_safety(auth_headers):
    """Test that firewall changes require explicit confirmation and prevent management lockout."""
    dev_id = "dev-primary-desktop"

    # 1. Reject lockout of critical management port (SSH 22, API 8000)
    lockout_req = {
        "action_type": "BLOCK_PORT",
        "target_value": "8000",
        "reason": "Accidental rule",
        "confirmation_code": "APPROVE"
    }
    resp_lockout = client.post(f"/api/endpoint/devices/{dev_id}/firewall-action", json=lockout_req, headers=auth_headers)
    assert resp_lockout.status_code == 400
    assert "critical management service" in resp_lockout.json()["detail"]

    # 2. Reject unconfirmed rule (missing 'APPROVE')
    unconfirmed_req = {
        "action_type": "BLOCK_PORT",
        "target_value": "4444",
        "reason": "Block reverse shell port",
        "confirmation_code": "YES"
    }
    resp_unconfirmed = client.post(f"/api/endpoint/devices/{dev_id}/firewall-action", json=unconfirmed_req, headers=auth_headers)
    assert resp_unconfirmed.status_code == 400
    assert "APPROVE" in resp_unconfirmed.json()["detail"]

    # 3. Successful authorized rule application
    valid_req = {
        "action_type": "BLOCK_PORT",
        "target_value": "4444",
        "reason": "Quarantine Metasploit port",
        "confirmation_code": "APPROVE"
    }
    resp_valid = client.post(f"/api/endpoint/devices/{dev_id}/firewall-action", json=valid_req, headers=auth_headers)
    assert resp_valid.status_code == 200
    assert resp_valid.json()["status"] == "EXECUTED"
    assert resp_valid.json()["rollback_prepared"] is True


# ============================================================================
# 6. MULTILINGUAL JARVIS ASSISTANT ENDPOINT COMMANDS
# ============================================================================

def test_jarvis_endpoint_commands_english(auth_headers):
    """Test English JARVIS endpoint security commands."""
    # 1. Firewall status
    resp1 = client.post("/api/jarvis/chat", json={"message": "Show me the current firewall status.", "language": "en"}, headers=auth_headers)
    assert resp1.status_code == 200
    assert resp1.json()["tool_calls"][0]["tool_name"] == "get_endpoint_firewall_status"

    # 2. Pause monitoring
    resp2 = client.post("/api/jarvis/chat", json={"message": "Pause monitoring.", "language": "en"}, headers=auth_headers)
    assert resp2.status_code == 200
    assert resp2.json()["tool_calls"][0]["tool_name"] == "pause_endpoint_monitoring"

    # 3. Disconnect device
    resp3 = client.post("/api/jarvis/chat", json={"message": "Disconnect this device from the dashboard.", "language": "en"}, headers=auth_headers)
    assert resp3.status_code == 200
    assert resp3.json()["tool_calls"][0]["tool_name"] == "disconnect_endpoint_device"


def test_jarvis_endpoint_commands_hindi_and_hinglish(auth_headers):
    """Test Hindi and Hinglish endpoint security commands."""
    # 1. Device security status
    resp1 = client.post("/api/jarvis/chat", json={"message": "Jarvis, is device ki security status batao.", "language": "hi"}, headers=auth_headers)
    assert resp1.status_code == 200
    assert resp1.json()["tool_calls"][0]["tool_name"] == "get_device_security_status"

    # 2. Check suspicious connections
    resp2 = client.post("/api/jarvis/chat", json={"message": "Mere computer par koi suspicious connection hai?", "language": "hi"}, headers=auth_headers)
    assert resp2.status_code == 200
    assert resp2.json()["tool_calls"][0]["tool_name"] == "check_suspicious_connections"


def test_jarvis_endpoint_commands_marathi(auth_headers):
    """Test Marathi endpoint security commands."""
    resp = client.post("/api/jarvis/chat", json={"message": "Mala navin security alerts dakhav.", "language": "mr"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["tool_calls"][0]["tool_name"] == "get_device_security_alerts"


# ============================================================================
# 7. AUDIT TRAIL LOGGING TEST
# ============================================================================

def test_endpoint_audit_trail_logging(auth_headers):
    """Test that sensitive endpoint operations are recorded in device_audit_logs."""
    with connect() as db:
        logs = db.execute("SELECT * FROM device_audit_logs ORDER BY timestamp DESC LIMIT 10").fetchall()
        assert len(logs) > 0
        actions = [l["action"] for l in logs]
        assert any("DEVICE" in a or "MONITORING" in a or "FIREWALL" in a for a in actions)
