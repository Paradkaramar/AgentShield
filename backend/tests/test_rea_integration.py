import io
import sqlite3
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import init_db, connect
from app.engines.rea_engine import (
    check_rea_status,
    analyze_target_with_rea,
    generate_amoja_rea_explanation,
    RE_LAB_VAULT_DIR
)

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_rea_status_endpoint():
    """Verifies that the /api/rea/status endpoint returns live REA health and providers."""
    resp = client.get("/api/rea/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["installed"] is True
    assert data["version"] != "NOT_FOUND"
    assert "6.7" in data["version"] or "6." in data["version"]
    assert "node_version" in data
    assert isinstance(data["providers"], list)
    assert data["zero_trust_status"] == "ENFORCING"
    assert "inspect-sqlite-database" in data["supported_workflows"]
    assert "analyze-javascript-application" in data["supported_workflows"]


def test_benign_sqlite_inspection_rea(tmp_path):
    """Creates a benign SQLite test artifact and verifies real REA inspection."""
    test_db = tmp_path / "benign_sample.db"
    conn = sqlite3.connect(test_db)
    conn.execute("CREATE TABLE security_telemetry (id INTEGER PRIMARY KEY, metric_name TEXT, score REAL);")
    conn.execute("INSERT INTO security_telemetry VALUES (1, 'zero_trust_health', 99.4);")
    conn.commit()
    conn.close()

    result = analyze_target_with_rea(test_db, workflow="inspect-sqlite-database")
    assert result["success"] is True
    assert result["workflow"] == "inspect-sqlite-database"
    assert result["filename"] == "benign_sample.db"
    assert len(result["hashes"]["sha256"]) == 64
    assert result["confidence"] == "observed"

    # Evidence verification: check that REA actually parsed the table
    findings = result["evidence"].get("normalized_result") or result["evidence"]
    schema = findings.get("schema", {})
    table_names = [t.get("name") for t in schema.get("tables", [])]
    assert "security_telemetry" in table_names

    # Check limitations are returned
    assert len(result["limitations"]) > 0


def test_rea_upload_and_audit_trail(tmp_path):
    """Tests file upload through the API, verifying database persistence and audit ledger chaining."""
    test_db = tmp_path / "test_vault_artifact.db"
    conn = sqlite3.connect(test_db)
    conn.execute("CREATE TABLE audit_canary (id INTEGER PRIMARY KEY, token TEXT);")
    conn.execute("INSERT INTO audit_canary VALUES (1, 'CANARY_98765');")
    conn.commit()
    conn.close()

    with open(test_db, "rb") as f:
        file_bytes = f.read()

    resp = client.post(
        "/api/rea/upload",
        files={"file": ("test_vault_artifact.db", file_bytes, "application/octet-stream")}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "analysis_id" in data
    assert "amoja_briefing" in data

    # Verify audit entry was written
    with connect() as db:
        audit_entry = db.execute(
            "SELECT * FROM audit_log WHERE action='REA_LAB_ARTIFACT_ANALYZED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert audit_entry is not None
        assert "test_vault_artifact.db" in audit_entry["details_json"]

        # Verify entry in re_lab_analyses
        re_row = db.execute(
            "SELECT * FROM re_lab_analyses WHERE id=?",
            (data["analysis_id"],)
        ).fetchone()
        assert re_row is not None
        assert re_row["filename"] == "test_vault_artifact.db"


def test_path_traversal_and_unauthorized_access():
    r"""Verifies that inspecting unauthorized host paths (e.g. C:\Windows or traversal) is blocked with 403."""
    # Attempting to inspect Windows System directory
    resp = client.post(
        "/api/rea/inspect-path",
        json={"path": r"C:\Windows\System32"}
    )
    assert resp.status_code in [403, 404]

    # Non-existent path
    resp_404 = client.post(
        "/api/rea/inspect-path",
        json={"path": r"E:\AgentShield_Starter_Project\non_existent_fake_path_12345.bin"}
    )
    assert resp_404.status_code == 404


def test_amoja_rea_bilingual_explanation(tmp_path):
    """Verifies that AMOJA AI generates evidence-grounded English and Hinglish explanations."""
    test_db = tmp_path / "amoja_test.db"
    conn = sqlite3.connect(test_db)
    conn.execute("CREATE TABLE agents_catalog (agent_id TEXT PRIMARY KEY, name TEXT);")
    conn.execute("INSERT INTO agents_catalog VALUES ('agent-101', 'FinanceBot');")
    conn.commit()
    conn.close()

    investigation = analyze_target_with_rea(test_db, workflow="inspect-sqlite-database")
    explanation = generate_amoja_rea_explanation(investigation, question="Amoja, is file mein kya mila?", language="hinglish")

    assert "observed_facts" in explanation
    assert len(explanation["observed_facts"]) >= 2
    assert "inferred_risks" in explanation
    assert "limitations" in explanation
    assert "english_briefing" in explanation
    assert "hinglish_briefing" in explanation

    # Verify 3-tier fact separation in text
    assert "Observed Facts" in explanation["english_briefing"]
    assert "Inferred Risks" in explanation["english_briefing"]
    assert "Limitations" in explanation["english_briefing"]

    # Verify custom answer was provided
    assert explanation["custom_answer"] is not None
    assert "AMOJA AI Analyst" in explanation["custom_answer"]


def test_rea_explain_api_endpoint(tmp_path):
    """Verifies interactive Q&A endpoint /api/rea/explain with an existing analysis."""
    test_db = tmp_path / "explain_sample.db"
    conn = sqlite3.connect(test_db)
    conn.execute("CREATE TABLE memory_bank (id INT, value TEXT);")
    conn.commit()
    conn.close()

    with open(test_db, "rb") as f:
        file_bytes = f.read()

    upload_resp = client.post(
        "/api/rea/upload",
        files={"file": ("explain_sample.db", file_bytes, "application/octet-stream")}
    )
    analysis_id = upload_resp.json()["analysis_id"]

    # Query AMOJA in English
    q_resp = client.post(
        "/api/rea/explain",
        json={
            "analysis_id": analysis_id,
            "question": "Explain the database structure found by REA.",
            "language": "en"
        }
    )
    assert q_resp.status_code == 200
    q_data = q_resp.json()
    assert "observed_facts" in q_data
    assert "english_briefing" in q_data


def test_rea_history_endpoint():
    """Verifies /api/rea/history endpoint returns recent REA investigations."""
    resp = client.get("/api/rea/history")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_rea_providers_discovered_from_real_cli():
    """Verifies that providers are parsed from live REA analysis_provider_candidates."""
    status = check_rea_status()
    assert status["installed"] is True
    assert isinstance(status["providers"], list)
    assert len(status["providers"]) > 0
    provider_names = [p["name"] for p in status["providers"]]
    # REA 6.7.0 bundles adapters for major disassemblers
    assert any("Ghidra" in name or "Hopper" in name or "IDA" in name for name in provider_names)
    for p in status["providers"]:
        assert "id" in p
        assert "status" in p
        assert p["status"] in ["available", "unavailable", "unknown"]


def test_rea_failure_handling_never_reports_fake_success(tmp_path):
    """Proves that corrupted or incompatible targets fail honestly with success=False."""
    corrupted_file = tmp_path / "corrupted_file.db"
    corrupted_file.write_bytes(b"NOT_A_VALID_SQLITE_DATABASE_HEADER_AT_ALL_XYZ123")

    result = analyze_target_with_rea(corrupted_file, workflow="inspect-sqlite-database")
    # REA fails on invalid SQLite headers with non-zero exit code or error envelope
    assert result["success"] is False
    assert result["exit_code"] != 0 or "error" in result.get("evidence", {}) or "error" in result.get("raw_result", {})
    # Must never fake schema or tables on failure
    findings = result["evidence"].get("normalized_result") or result["evidence"]
    schema = findings.get("schema", {})
    assert len(schema.get("tables", [])) == 0


def test_rea_invalid_workflow_safely_rejected(tmp_path):
    """Proves that unauthorized or unwhitelisted workflows are blocked without execution."""
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"sample bytes")

    result = analyze_target_with_rea(sample_file, workflow="malicious_unwhitelisted_command")
    assert result["success"] is False
    assert result["code"] == "INVALID_WORKFLOW"
    assert "Unsupported or unauthorized REA workflow" in result["error"]


def test_rea_inspect_artifact_real_execution(tmp_path):
    """Proves that inspect-artifact works end-to-end on a script artifact with real REA output."""
    script_file = tmp_path / "telemetry_agent.js"
    script_file.write_text("console.log('Zero Trust Telemetry Agent'); module.exports = { status: 'healthy' };")

    result = analyze_target_with_rea(script_file, workflow="inspect-artifact")
    assert result["success"] is True
    assert result["workflow"] == "inspect-artifact"
    assert result["confidence"] == "observed"
    assert "Artifact Inspection" in result["summary"]

    # Verify actual REA output envelope
    raw = result["raw_result"]
    assert "evidence_id" in raw or "normalized_result" in raw
    normalized = raw.get("normalized_result", {})
    assert "observations" in normalized
    assert len(normalized["observations"]) >= 1

    # Verify AMOJA explanation captures the artifact observations
    briefing = generate_amoja_rea_explanation(result)
    assert any("Artifact format classification" in fact for fact in briefing["observed_facts"])

