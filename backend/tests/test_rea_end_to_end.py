import io
import json
import sqlite3
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import init_db, connect
from app.core.config import BASE_DIR
from app.engines.rea_engine import (
    check_rea_status,
    analyze_target_with_rea,
    get_authorized_rea_targets,
    validate_rea_target,
    generate_rea_forensic_report,
    generate_amoja_rea_explanation
)
from app.jarvis.multilingual_commands import parse_multilingual_intent
from app.jarvis.jarvis_tools import dispatch_tool, TOOL_REGISTRY

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_authorized_targets_catalog():
    """Verifies that pre-approved harmless targets (including desktop Electron app) are listed."""
    resp = client.get("/api/rea/authorized-targets")
    assert resp.status_code == 200
    targets = resp.json()
    assert isinstance(targets, list)
    assert len(targets) >= 1

    target_ids = [t["id"] for t in targets]
    assert "app_electron_desktop" in target_ids

    desktop_target = next(t for t in targets if t["id"] == "app_electron_desktop")
    assert desktop_target["is_harmless_test_app"] is True
    assert "Electron" in desktop_target["name"] or "Electron" in desktop_target["format"]
    assert desktop_target["recommended_workflow"] == "analyze-javascript-application"
    assert "STATIC_ANALYSIS_ONLY" in desktop_target["safety_posture"]


def test_validate_target_authorized_and_denied():
    """Verifies pre-flight validation against path traversal and unauthorized host directories."""
    # 1. Authorized harmless desktop app
    resp_ok = client.post("/api/rea/validate-target", json={"target_path": "desktop"})
    assert resp_ok.status_code == 200
    data_ok = resp_ok.json()
    assert data_ok["valid"] is True
    assert data_ok["status"] == "AUTHORIZED"
    assert data_ok["recommended_workflow"] == "analyze-javascript-application"
    assert data_ok["permission_granted"] is True

    # Verify audit entry was logged
    with connect() as db:
        audit_entry = db.execute(
            "SELECT * FROM audit_log WHERE action='REA_TARGET_VALIDATED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert audit_entry is not None
        assert "desktop" in audit_entry["details_json"]

    # 2. Unauthorized system directory blocked
    resp_denied = client.post("/api/rea/validate-target", json={"target_path": r"C:\Windows\System32"})
    assert resp_denied.status_code == 200
    data_denied = resp_denied.json()
    assert data_denied["valid"] is False
    assert data_denied["status"] == "DENIED"
    assert data_denied["code"] == "UNAUTHORIZED_BOUNDARY"

    # 3. Non-existent path
    resp_404 = client.post("/api/rea/validate-target", json={"target_path": "non_existent_target_123.bin"})
    assert resp_404.status_code == 200
    data_404 = resp_404.json()
    assert data_404["valid"] is False
    assert data_404["status"] == "NOT_FOUND"


def test_real_electron_app_inspection():
    """
    Submits a real static analysis job on the harmless desktop Electron application
    through REA's verified CLI and checks AST, boundaries, and evidence.
    """
    workspace_root = BASE_DIR.parent
    desktop_dir = workspace_root / "desktop"
    assert desktop_dir.exists(), "Harmless desktop Electron app directory must exist"

    # Analyze with REA
    result = analyze_target_with_rea(desktop_dir, workflow="analyze-javascript-application")
    assert result["success"] is True
    assert result["exit_code"] == 0
    assert result["workflow"] == "analyze-javascript-application"
    assert result["confidence"] == "derived" or result["confidence"] == "observed"

    # Evidence verification: check that REA captured JavaScript / Electron application graph
    findings = result["evidence"].get("normalized_result") or result["evidence"]
    stats = findings.get("statistics") or {}
    summ = findings.get("summary") or {}
    graph = findings.get("graph") or {}

    assert stats.get("parsed_javascript_files", 0) > 0, "REA should have parsed JavaScript files in desktop"
    assert stats.get("visited_ast_nodes", 0) > 0, "REA should have visited AST nodes"
    assert summ.get("ipc", {}).get("operations", 0) > 0, "REA should have detected Electron IPC operations"
    assert len(graph.get("nodes", [])) > 0, "REA should have mapped application graph nodes"

    # Verify documented transparent limitations
    assert len(result["limitations"]) > 0
    assert any("bundle bootstrap code was never executed" in lim or "inert" in lim for lim in result["limitations"])


def test_generate_forensic_report_endpoint():
    """
    Verifies that the /api/rea/generate-report endpoint compiles a formal
    Markdown & JSON forensic investigation dossier and records a chained audit event.
    """
    # Create test investigation
    workspace_root = BASE_DIR.parent
    desktop_dir = workspace_root / "desktop"
    investigation = analyze_target_with_rea(desktop_dir, workflow="analyze-javascript-application")

    resp = client.post(
        "/api/rea/generate-report",
        json={"investigation": investigation}
    )
    assert resp.status_code == 200
    report = resp.json()
    assert "report_id" in report
    assert report["verdict"] == "COMPLETED"
    assert "markdown_report" in report
    assert "structured_data" in report

    md = report["markdown_report"]
    assert "FORENSIC INVESTIGATION REPORT" in md
    assert "Executive Summary" in md
    assert "Cryptographic Integrity" in md
    assert "Observed Forensic Evidence" in md
    assert "Inferred Security Risks" in md
    assert "Documented Limitations" in md
    assert "STRICTLY_DISABLED" in md

    # Check cryptographic audit log
    with connect() as db:
        audit_entry = db.execute(
            "SELECT * FROM audit_log WHERE action='REA_REPORT_GENERATED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert audit_entry is not None
        assert report["report_id"] in audit_entry["resource"]


def test_jarvis_multilingual_rea_intent_routing():
    """
    Verifies that English, Hindi, Marathi, and Hinglish voice/text queries
    route accurately to REA tools without breaking the conversational assistant.
    """
    # 1. English
    tool_en, args_en, nav_en, _ = parse_multilingual_intent("Inspect desktop app with REA")
    assert tool_en == "rea_inspect_target"
    assert args_en["target_path"] == "desktop"
    assert nav_en == "Reverse Engineering"

    # 2. Hindi
    tool_hi, args_hi, nav_hi, _ = parse_multilingual_intent("REA se desktop app inspect karo")
    assert tool_hi == "rea_inspect_target"
    assert args_hi["target_path"] == "desktop"

    # 3. Marathi
    tool_mr, _, nav_mr, _ = parse_multilingual_intent("REA engine chi sthiti sanga")
    assert tool_mr == "rea_get_status"
    assert nav_mr == "Reverse Engineering"

    # 4. Hinglish Report Generation
    tool_rep, args_rep, _, _ = parse_multilingual_intent("Forensic report generate karo")
    assert tool_rep == "rea_generate_report"


def test_jarvis_dispatch_tool_rea_execution():
    """
    Verifies executing REA tools via JARVIS central dispatch_tool:
    - rea_get_status
    - rea_inspect_target on harmless desktop app
    - rea_generate_report
    """
    admin_user = {"username": "soc_lead", "role": "admin"}

    # 1. rea_get_status
    status_res = dispatch_tool("rea_get_status", {}, admin_user)
    assert status_res["status"] == "SUCCESS"
    assert status_res["rea_status"]["installed"] is True

    # 2. rea_inspect_target
    inspect_res = dispatch_tool("rea_inspect_target", {"target_path": "desktop"}, admin_user)
    assert inspect_res["status"] == "SUCCESS"
    assert inspect_res["filename"] == "desktop"
    assert inspect_res["workflow"] == "analyze-javascript-application"
    assert len(inspect_res["observed_facts"]) >= 2
    assert "english_briefing" in inspect_res

    # 3. rea_generate_report
    analysis_id = inspect_res["analysis_id"]
    report_res = dispatch_tool("rea_generate_report", {"analysis_id": analysis_id}, admin_user)
    assert report_res["status"] == "SUCCESS"
    assert "markdown_report" in report_res["report"]


def test_independence_of_connected_capabilities():
    """
    Guarantees that adding REA capabilities does not break or alter:
    - Personal Windows Assistant
    - AgentShield Cybersecurity
    - Live Intelligence
    """
    admin_user = {"username": "admin", "role": "admin"}

    # 1. Personal Windows Assistant remains fully operational
    apps_res = dispatch_tool("launch_approved_application", {"app_name": "calculator"}, admin_user)
    assert apps_res["status"] == "LAUNCHED"

    files_res = dispatch_tool("search_authorized_files", {"query": "readme", "scope": "workspace"}, admin_user)
    assert files_res["status"] == "SUCCESS"

    status_res = dispatch_tool("get_windows_system_status", {}, admin_user)
    assert status_res["status"] in ("HEALTHY", "SUCCESS")
    assert "cpu" in status_res

    # 2. AgentShield Cybersecurity remains fully operational
    metrics_res = dispatch_tool("get_security_dashboard_metrics", {}, admin_user)
    assert "total_agents" in metrics_res
    assert "active_agents" in metrics_res

    audit_res = dispatch_tool("search_audit_logs", {"limit": 5}, admin_user)
    assert audit_res["status"] == "SUCCESS"
    assert len(audit_res["audit_entries"]) >= 1

    # 3. Live Intelligence remains fully operational
    weather_res = dispatch_tool("get_live_weather", {"city": "Mumbai"}, admin_user)
    assert weather_res["status"] == "SUCCESS"
    assert weather_res.get("city") == "Mumbai" or weather_res.get("location") == "Mumbai"
