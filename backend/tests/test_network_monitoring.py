# backend/tests/test_network_monitoring.py
"""Automated Test Suite for Continuous Network Monitoring
Validates Scope Enforcement, Exclusions, Authorization/RBAC, Scheduler,
Duplicate Job Prevention, Failure Recovery, Emergency Stop, Baseline Diffing,
and Multilingual JARVIS Commands.
"""

import asyncio
import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import connect, init_db, now_iso
from app.engines.network_scanner import (
    validate_ip_in_approved_scope, expand_scope_to_target_ips,
    compare_with_baseline, safe_tcp_port_probe
)
from app.services.network_monitor import network_monitoring_service
from app.jarvis.multilingual_commands import parse_multilingual_intent
from app.core.auth import create_access_token

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()
    # Ensure network monitoring service state is clean
    network_monitoring_service.reset_emergency_stop(actor="test")
    with connect() as db:
        db.execute("UPDATE network_monitoring_config SET service_enabled = 1, is_paused = 0, emergency_stop = 0")


# --- 1. Scope Enforcement & Exclusions Tests ---

def test_scope_enforcement_approved_cidr():
    approved_cidrs = ["127.0.0.1/32", "192.168.1.0/24"]
    excluded_ips = ["192.168.1.1"]

    # Allowed inside CIDR
    valid, err = validate_ip_in_approved_scope("192.168.1.50", approved_cidrs, excluded_ips)
    assert valid is True
    assert err is None

    # Blocked outside CIDR (Public or other internal)
    valid, err = validate_ip_in_approved_scope("8.8.8.8", approved_cidrs, excluded_ips)
    assert valid is False
    assert "outside all authorized" in err

    valid, err = validate_ip_in_approved_scope("10.0.0.1", approved_cidrs, excluded_ips)
    assert valid is False
    assert "outside all authorized" in err


def test_scope_enforcement_exclusions():
    approved_cidrs = ["192.168.1.0/24"]
    excluded_ips = ["192.168.1.1", "192.168.1.254"]

    # Target is in CIDR but on exclusion list
    valid, err = validate_ip_in_approved_scope("192.168.1.1", approved_cidrs, excluded_ips)
    assert valid is False
    assert "explicitly listed in administrator exclusions" in err

    # Non-excluded target is allowed
    valid, err = validate_ip_in_approved_scope("192.168.1.45", approved_cidrs, excluded_ips)
    assert valid is True


def test_scope_expansion_filters_exclusions():
    approved = ["192.168.1.0/29"] # IPs: .1 to .6
    excluded = ["192.168.1.1", "192.168.1.3"]

    targets = expand_scope_to_target_ips(approved, excluded)
    assert "192.168.1.1" not in targets
    assert "192.168.1.3" not in targets
    assert "192.168.1.2" in targets
    assert "192.168.1.4" in targets


# --- 2. Authorization & RBAC Tests ---

def test_rbac_admin_only_routes():
    # Regular analyst token
    analyst_token = create_access_token({"username": "analyst_bob", "role": "security_analyst"})
    headers = {"Authorization": f"Bearer {analyst_token}"}

    with connect() as db:
        db.execute("DELETE FROM approved_scan_scopes WHERE cidr_or_ip = '10.10.10.0/24'")

    # Analysts cannot add approved CIDRs (Admin only)
    scope_payload = {"name": "Test Subnet", "cidr_or_ip": "10.10.10.0/24"}
    res = client.post("/api/network/scopes", json=scope_payload, headers=headers)
    assert res.status_code == 403

    # Admin can add approved CIDRs
    admin_token = create_access_token({"username": "admin_alice", "role": "admin"})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    res_admin = client.post("/api/network/scopes", json=scope_payload, headers=admin_headers)
    assert res_admin.status_code == 200
    assert "added successfully" in res_admin.json()["message"]


def test_rbac_analyst_can_view_and_acknowledge_alerts():
    analyst_token = create_access_token({"username": "analyst_bob", "role": "security_analyst"})
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # View alerts
    res = client.get("/api/network/alerts", headers=headers)
    assert res.status_code == 200
    alerts = res.json()
    assert isinstance(alerts, list)

    if alerts:
        alt_id = alerts[0]["id"]
        # Analyst can update alert status
        patch_res = client.patch(f"/api/network/alerts/{alt_id}", json={"status": "ACKNOWLEDGED"}, headers=headers)
        assert patch_res.status_code == 200
        assert patch_res.json()["status"] == "SUCCESS"


# --- 3. Duplicate-Job Prevention & Emergency Stop ---

@pytest.mark.anyio
async def test_duplicate_job_prevention():
    # Acquire the scanner lock simulating a long in-flight sweep
    async with network_monitoring_service._scan_lock:
        # Attempt to run a simultaneous scan cycle
        result = await network_monitoring_service.execute_scan_cycle(triggered_by="TEST_DUPLICATE")
        assert result["status"] == "SKIPPED"
        assert "already running" in result["message"] or "already in progress" in result["message"]


def test_global_emergency_stop_lifecycle():
    admin_token = create_access_token({"username": "admin", "role": "admin"})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Trigger Emergency Stop
    stop_res = client.post("/api/network/controls/emergency-stop", json={"reason": "Critical rogue device alert"}, headers=headers)
    assert stop_res.status_code == 200
    assert stop_res.json()["status"] == "EMERGENCY_STOP_ACTIVATED"

    # 2. Verify status reflects Emergency Stop
    status_res = client.get("/api/network/status", headers=headers)
    assert status_res.status_code == 200
    assert status_res.json()["state"] == "EMERGENCY_STOP"
    assert status_res.json()["emergency_stop"] is True

    # 3. Attempting to scan while stopped should be blocked
    scan_res = client.post("/api/network/controls/scan-now", headers=headers)
    assert scan_res.status_code == 400
    assert "emergency stop" in scan_res.json()["detail"].lower()

    # 4. Reset Emergency Stop
    reset_res = client.post("/api/network/controls/reset-emergency-stop", headers=headers)
    assert reset_res.status_code == 200
    assert reset_res.json()["status"] == "EMERGENCY_STOP_RESET"

    # 5. Verify status returns to normal
    status_res_after = client.get("/api/network/status", headers=headers)
    assert status_res_after.json()["emergency_stop"] is False


# --- 4. Baseline Comparison & Security Alert Generation ---

def test_baseline_comparison_generates_facts_and_threats():
    scan_results = [
        {
            "ip_address": "192.168.1.99",
            "hostname": "unbaselined-node.internal",
            "status": "REACHABLE",
            "open_ports": [
                {"port": 6379, "protocol": "tcp", "service_name": "Redis", "banner": "+PONG", "latency_ms": 12.4, "state": "OPEN"}
            ],
            "latency_ms": 12.4
        }
    ]

    baseline_assets = {
        "192.168.1.10": {"ip_address": "192.168.1.10", "in_baseline": 1, "last_seen": now_iso()}
    }
    baseline_services = {
        "192.168.1.10": {443, 22}
    }

    alerts, updates, changes_count = compare_with_baseline(scan_results, baseline_assets, baseline_services)

    assert changes_count >= 1
    alert_types = [a["alert_type"] for a in alerts]
    assert "NEW_HOST_DISCOVERED" in alert_types
    assert "UNEXPECTED_OPEN_PORT" in alert_types

    # Verify strict separation of verified facts and suspected threats
    redis_alert = next(a for a in alerts if a["alert_type"] == "UNEXPECTED_OPEN_PORT")
    assert "Observed TCP port 6379" in redis_alert["observed_fact"]
    assert "Unapproved open port" in redis_alert["suspected_threat"]
    assert redis_alert["severity"] == "HIGH"


# --- 5. Failure Recovery & Safe Probe Execution ---

@pytest.mark.anyio
async def test_safe_probe_handles_unreachable_target():
    # Probing an unassigned or closed loopback port should cleanly return None without raising uncaught exceptions
    result = await safe_tcp_port_probe("127.0.0.1", 59999, timeout_seconds=0.3)
    assert result is None


# --- 6. Multilingual JARVIS Network Monitoring Commands ---

def test_jarvis_multilingual_network_status_commands():
    # English
    t, args, nav, lang = parse_multilingual_intent("Jarvis, show network monitoring status")
    assert t == "get_network_monitoring_status"
    assert nav == "Network Monitoring"

    # Hinglish / Hindi
    t_hi, _, _, lang_hi = parse_multilingual_intent("Jarvis, network monitoring status batao.")
    assert t_hi == "get_network_monitoring_status"

    # Marathi
    t_mr, _, _, lang_mr = parse_multilingual_intent("Jarvis, network monitoring chi sthiti sanga")
    assert t_mr == "get_network_monitoring_status"


def test_jarvis_multilingual_discovered_devices():
    # English
    t, _, _, _ = parse_multilingual_intent("Show newly discovered devices.")
    assert t == "get_network_discovered_devices"

    # Hinglish / Hindi
    t_hi, _, _, _ = parse_multilingual_intent("Naye discovered devices dikhao")
    assert t_hi == "get_network_discovered_devices"

    # Marathi
    t_mr, _, _, _ = parse_multilingual_intent("Navin shodhlele devices dakhav")
    assert t_mr == "get_network_discovered_devices"


def test_jarvis_multilingual_suspicious_activity():
    # English
    t, _, _, _ = parse_multilingual_intent("Show suspicious network activity")
    assert t == "get_network_security_alerts"

    # Marathi user prompt verbatim from requirements
    t_mr, _, _, _ = parse_multilingual_intent("Mala suspicious network activity dakhav.")
    assert t_mr == "get_network_security_alerts"

    # Hindi
    t_hi, _, _, _ = parse_multilingual_intent("Suspicious network activity dikhao")
    assert t_hi == "get_network_security_alerts"


def test_jarvis_multilingual_start_stop_monitoring():
    # Start - English
    t_start, _, _, _ = parse_multilingual_intent("Start monitoring my approved network.")
    assert t_start == "start_network_monitoring"

    # Stop - English
    t_stop, _, _, _ = parse_multilingual_intent("Stop the current monitoring job.")
    assert t_stop == "stop_network_monitoring"

    # Start - Hindi
    t_start_hi, _, _, _ = parse_multilingual_intent("Approved network monitoring shuru karo")
    assert t_start_hi == "start_network_monitoring"

    # Stop - Marathi
    t_stop_mr, _, _, _ = parse_multilingual_intent("Sadhya chaloo asleli monitoring thambva")
    assert t_stop_mr == "stop_network_monitoring"


def test_jarvis_chat_api_network_monitoring_end_to_end():
    # Test end-to-end through the JARVIS chat API
    res = client.post("/api/jarvis/chat", json={
        "message": "Jarvis, network monitoring status batao.",
        "language": "hinglish",
        "is_voice": False
    })
    assert res.status_code == 200
    data = res.json()
    assert "tool_results" in data
    assert len(data["tool_results"]) > 0
    assert data["tool_results"][0]["tool_name"] == "get_network_monitoring_status"
    assert "Network Monitoring Status" in data["message"] or "State" in data["message"] or "network monitoring" in data["speech_text"].lower()
