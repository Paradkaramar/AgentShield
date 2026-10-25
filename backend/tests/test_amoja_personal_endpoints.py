# backend/tests/test_amoja_personal_endpoints.py
"""Comprehensive Test Suite for AMOJA AI Personal Assistant REST Endpoints:
Application Launching & Closing, File Operations, WhatsApp Verification,
Windows System Status, and Settings.
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import init_db
from app.core.auth import create_access_token

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

@pytest.fixture
def auth_headers():
    token = create_access_token({"username": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def operator_headers():
    token = create_access_token({"username": "operator_test", "role": "operator"})
    return {"Authorization": f"Bearer {token}"}


def test_get_approved_apps(auth_headers):
    """Verifies that the whitelist of approved applications is returned."""
    resp = client.get("/api/jarvis/personal/apps", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "apps" in data
    assert "notepad" in data["apps"]
    assert "calculator" in data["apps"]
    assert "paint" in data["apps"]


def test_launch_app_security_rejections(auth_headers):
    """Verifies that arbitrary binary launches and command injection attempts are blocked."""
    # 1. Unapproved application
    resp_unauth = client.post(
        "/api/jarvis/personal/launch-app",
        json={"app_name": "malicious_ransomware.exe"},
        headers=auth_headers
    )
    assert resp_unauth.status_code == 200
    data = resp_unauth.json()
    assert "error" in data
    assert "not in the approved application whitelist" in data["error"]

    # 2. Command injection metacharacters
    resp_inj = client.post(
        "/api/jarvis/personal/launch-app",
        json={"app_name": "notepad; rm -rf /"},
        headers=auth_headers
    )
    assert resp_inj.status_code == 200
    data = resp_inj.json()
    assert "error" in data
    assert "Illegal characters detected" in data["error"]


def test_close_app_safeguards(operator_headers):
    """Verifies safeguards when attempting to close apps."""
    # 1. Explorer closure by non-admin requires elevation
    resp_exp = client.post(
        "/api/jarvis/personal/close-app",
        json={"app_name": "explorer"},
        headers=operator_headers
    )
    assert resp_exp.status_code == 200
    assert "requires administrative privileges" in resp_exp.json()["error"]

    # 2. Unapproved process
    resp_bad = client.post(
        "/api/jarvis/personal/close-app",
        json={"app_name": "unknown_crypto_miner"},
        headers=operator_headers
    )
    assert resp_bad.status_code == 200
    assert "not in the approved application whitelist" in resp_bad.json()["error"]


def test_authorized_files_search_and_traversal_blocking(auth_headers):
    """Verifies file search within scopes and blocking path traversal."""
    resp = client.get(
        "/api/jarvis/personal/files?query=test&scope=workspace",
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "matches" in data
    assert "authorized_scopes" in data

    # Verify traversal query sanitization
    resp_trav = client.get(
        "/api/jarvis/personal/files?query=../../../../etc/passwd",
        headers=auth_headers
    )
    assert resp_trav.status_code == 200
    assert resp_trav.json()["query"] == "passwd"


def test_open_file_unauthorized_path_blocked(auth_headers):
    r"""Verifies that attempting to open system paths (like C:\Windows\System32) is blocked."""
    resp = client.post(
        "/api/jarvis/personal/open-file",
        json={"filepath": r"C:\Windows\System32\cmd.exe"},
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False
    assert "Security violation" in data["error"] or "not authorized" in data["error"]


def test_whatsapp_message_verification_and_confirmation(auth_headers):
    """Verifies recipient phone formatting and required confirmation workflow."""
    resp = client.post(
        "/api/jarvis/personal/whatsapp",
        json={
            "recipient": "9876543210",
            "message": "Security alert: Incident #101 mitigated successfully."
        },
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["requires_confirmation"] is True
    assert data["action_type"] == "SEND_WHATSAPP_MESSAGE"
    assert data["target_id"] == "+919876543210"
    assert "Security alert" in data["impact_explanation"]


def test_whatsapp_attachment_path_traversal_blocked(auth_headers):
    r"""Verifies that unauthorized attachment paths are rejected."""
    resp = client.post(
        "/api/jarvis/personal/whatsapp",
        json={
            "recipient": "+919876543210",
            "message": "Check this file",
            "attachment_path": r"C:\Windows\System32\drivers\etc\hosts"
        },
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False
    assert "not within user-authorized directories" in data["error"]


def test_get_windows_system_status(auth_headers):
    """Verifies retrieval of system telemetry."""
    resp = client.get("/api/jarvis/personal/windows-status", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert "cpu" in data
    assert "memory" in data
    assert "disk" in data
    assert "uptime" in data


def test_windows_settings_validation(auth_headers):
    """Verifies that allowed settings URIs work and invalid ones are rejected."""
    # Allowed
    resp = client.post(
        "/api/jarvis/personal/windows-settings",
        json={"setting_page": "network"},
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "uri" in data or "message" in data or "page" in data

    # Unknown
    resp_bad = client.post(
        "/api/jarvis/personal/windows-settings",
        json={"setting_page": "unauthorized_malicious_setting"},
        headers=auth_headers
    )
    assert resp_bad.status_code == 200
    assert resp_bad.json()["success"] is False
    assert "not recognized" in resp_bad.json()["error"]
