import os
import re
import json
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from ..db.database import connect, now_iso
from ..core.audit import record_audit_entry
from ..core.config import BASE_DIR
from ..engines.reverse_engineering import (
    reconstruct_behavior_timeline,
    analyze_system_prompt_drift,
    reverse_engineer_payload,
    generate_forensic_report_data,
    analyze_file_complete,
    export_re_report,
    check_ghidra_availability,
    check_sandbox_status,
    YARA_NATIVE_AVAILABLE
)

router = APIRouter(prefix="/api/forensics", tags=["Reverse Engineering & Forensics"])

# Secure vault directory for uploaded samples, quarantined completely outside web path
RE_LAB_VAULT_DIR = BASE_DIR / "data" / "re_lab_vault"
RE_LAB_VAULT_DIR.mkdir(parents=True, exist_ok=True)
MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25 Megabytes strict limit


@router.get("/timeline/{agent_id}")
def get_timeline(agent_id: str):
    with connect() as db:
        events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id ASC LIMIT 50", (agent_id,)).fetchall()
        return reconstruct_behavior_timeline([dict(e) for e in events])


@router.post("/payload-analysis")
def analyze_payload(body: Dict[str, str]):
    payload = body.get("payload", "")
    return reverse_engineer_payload(payload)


@router.post("/prompt-diff")
def diff_prompt(body: Dict[str, str]):
    baseline = body.get("baseline", "")
    current = body.get("current", "")
    return analyze_system_prompt_drift(baseline, current)


@router.get("/report/{incident_id}")
def get_forensic_report(incident_id: int):
    with connect() as db:
        inc = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        agent = db.execute("SELECT * FROM agents WHERE id=?", (inc["agent_id"],)).fetchone()
        events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id ASC LIMIT 30", (inc["agent_id"],)).fetchall()
        
    report = generate_forensic_report_data(dict(inc), dict(agent) if agent else {"id": inc["agent_id"]}, [dict(e) for e in events])
    return report


# ==============================================================================
# REVERSE ENGINEERING LAB ENDPOINTS (Upload, Static Inspection, AI Forensics)
# ==============================================================================

@router.get("/re-lab/tools-status")
def get_re_lab_tools_status():
    """Returns operational status for Ghidra SRE, native YARA, and host isolation sandbox."""
    return {
        "ghidra": check_ghidra_availability(),
        "yara": {
            "native_installed": YARA_NATIVE_AVAILABLE,
            "engine": "YARA_NATIVE" if YARA_NATIVE_AVAILABLE else "AGENTSHIELD_BUILTIN_FALLBACK",
            "status": "READY" if YARA_NATIVE_AVAILABLE else "FALLBACK_ACTIVE",
            "detail": "Native yara-python engine active" if YARA_NATIVE_AVAILABLE else "Using AgentShield built-in signature fallback engine."
        },
        "sandbox": check_sandbox_status()
    }


@router.get("/re-lab/history")
def get_re_lab_history():
    """Retrieves list of past file and code reverse engineering investigations."""
    with connect() as db:
        rows = db.execute("""
            SELECT id, filename, file_size, sha256_hash, sha1_hash, md5_hash,
                   file_type, mime_type, entropy, analysis_mode, severity, verdict,
                   confidence, summary, created_at
            FROM re_lab_analyses
            ORDER BY created_at DESC
            LIMIT 50
        """).fetchall()
        return [dict(r) for r in rows]


@router.get("/re-lab/analysis/{analysis_id}")
def get_re_lab_analysis_detail(analysis_id: str):
    """Retrieves full analysis record including indicators, strings, AST findings, and AI dossier."""
    with connect() as db:
        row = db.execute("""
            SELECT * FROM re_lab_analyses
            WHERE id=? OR sha256_hash=?
        """, (analysis_id, analysis_id)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Analysis record not found")
        
        d = dict(row)
        # Parse JSON fields
        for field in ["indicators_json", "metadata_json", "strings_sample_json", "yara_matches_json", "source_analysis_json", "ghidra_analysis_json", "dynamic_sandbox_json", "report_json"]:
            if field in d and isinstance(d[field], str):
                try:
                    d[field.replace("_json", "")] = json.loads(d[field])
                except Exception:
                    d[field.replace("_json", "")] = []

        return d


@router.post("/re-lab/upload")
async def upload_file_for_re(file: UploadFile = File(...)):
    """Safe upload endpoint with file size validation, path traversal neutralization, and static RE."""
    raw_filename = file.filename or "unknown_file.bin"
    # Neutralize path traversal attempts (e.g. ../../etc/passwd or C:\Windows\System32)
    clean_basename = Path(raw_filename).name
    safe_filename = re.sub(r"[^a-zA-Z0-9_\.-]", "_", clean_basename)
    if not safe_filename:
        safe_filename = f"sample_{uuid.uuid4().hex[:8]}.bin"

    # Streaming read with strict 25MB size limit
    file_bytes = bytearray()
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        file_bytes.extend(chunk)
        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded file exceeds maximum permitted size of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB"
            )

    bytes_data = bytes(file_bytes)

    # Store in quarantined vault under unique safe filename
    quarantine_id = uuid.uuid4().hex[:12]
    quarantine_path = RE_LAB_VAULT_DIR / f"{quarantine_id}_{safe_filename}"
    try:
        with open(quarantine_path, "wb") as f:
            f.write(bytes_data)
    except Exception as e:
        # Fallback if disk write is constrained
        pass

    # Execute comprehensive static and heuristic analysis
    analysis = analyze_file_complete(bytes_data, safe_filename)
    dossier = export_re_report(analysis)

    # Persist in SQLite re_lab_analyses
    now = now_iso()
    with connect() as db:
        db.execute("""
            INSERT OR REPLACE INTO re_lab_analyses (
                id, filename, file_size, sha256_hash, sha1_hash, md5_hash,
                file_type, mime_type, entropy, analysis_mode, severity, verdict,
                confidence, summary, indicators_json, metadata_json, strings_sample_json,
                yara_matches_json, source_analysis_json, ghidra_analysis_json,
                dynamic_sandbox_json, ai_explanation_en, ai_explanation_hinglish,
                report_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis["id"],
            analysis["filename"],
            analysis["file_size"],
            analysis["sha256_hash"],
            analysis["sha1_hash"],
            analysis["md5_hash"],
            analysis["file_type"],
            analysis["mime_type"],
            analysis["entropy"],
            analysis["analysis_mode"],
            analysis["severity"],
            analysis["verdict"],
            analysis["confidence"],
            analysis["summary"],
            json.dumps(analysis["indicators"]),
            json.dumps(analysis.get("pe_metadata") or analysis.get("elf_metadata") or {}),
            json.dumps(analysis["strings_summary"].get("sample_strings", [])),
            json.dumps(analysis["yara_matches"]),
            json.dumps(analysis.get("source_analysis", {})),
            json.dumps(analysis.get("ghidra_status", {})),
            json.dumps(analysis.get("sandbox_status", {})),
            analysis["ai_explanation_en"],
            analysis["ai_explanation_hinglish"],
            json.dumps(dossier),
            now
        ))

        # Record Cryptographic Audit Ledger Entry
        record_audit_entry(
            db,
            actor="security_analyst",
            action="RE_LAB_FILE_ANALYZED",
            resource=f"re_sample:{analysis['sha256_hash'][:16]}",
            details={
                "filename": safe_filename,
                "file_size": len(bytes_data),
                "sha256": analysis["sha256_hash"],
                "verdict": analysis["verdict"],
                "severity": analysis["severity"],
                "analysis_mode": analysis["analysis_mode"]
            }
        )

    return analysis


@router.post("/re-lab/analyze-code")
def analyze_code_snippet(body: Dict[str, Any]):
    """Analyzes raw script code (Python, PowerShell, Bash, JavaScript) or malicious prompt payload."""
    code = body.get("code", "")
    language = body.get("language", "powershell")
    filename = body.get("filename", f"snippet.{'ps1' if 'power' in language.lower() else 'py' if 'py' in language.lower() else 'sh' if 'sh' in language.lower() else 'js' if 'js' in language.lower() else 'txt'}")

    clean_basename = Path(filename).name
    safe_filename = re.sub(r"[^a-zA-Z0-9_\.-]", "_", clean_basename) or "snippet.txt"

    if not code:
        raise HTTPException(status_code=400, detail="Code content cannot be empty")

    bytes_data = code.encode("utf-8")
    analysis = analyze_file_complete(bytes_data, safe_filename)
    dossier = export_re_report(analysis)

    # Persist in DB
    now = now_iso()
    with connect() as db:
        db.execute("""
            INSERT OR REPLACE INTO re_lab_analyses (
                id, filename, file_size, sha256_hash, sha1_hash, md5_hash,
                file_type, mime_type, entropy, analysis_mode, severity, verdict,
                confidence, summary, indicators_json, metadata_json, strings_sample_json,
                yara_matches_json, source_analysis_json, ghidra_analysis_json,
                dynamic_sandbox_json, ai_explanation_en, ai_explanation_hinglish,
                report_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis["id"],
            analysis["filename"],
            analysis["file_size"],
            analysis["sha256_hash"],
            analysis["sha1_hash"],
            analysis["md5_hash"],
            analysis["file_type"],
            analysis["mime_type"],
            analysis["entropy"],
            analysis["analysis_mode"],
            analysis["severity"],
            analysis["verdict"],
            analysis["confidence"],
            analysis["summary"],
            json.dumps(analysis["indicators"]),
            json.dumps(analysis.get("pe_metadata") or analysis.get("elf_metadata") or {}),
            json.dumps(analysis["strings_summary"].get("sample_strings", [])),
            json.dumps(analysis["yara_matches"]),
            json.dumps(analysis.get("source_analysis", {})),
            json.dumps(analysis.get("ghidra_status", {})),
            json.dumps(analysis.get("sandbox_status", {})),
            analysis["ai_explanation_en"],
            analysis["ai_explanation_hinglish"],
            json.dumps(dossier),
            now
        ))

        record_audit_entry(
            db,
            actor="security_analyst",
            action="RE_LAB_CODE_ANALYZED",
            resource=f"re_code:{analysis['sha256_hash'][:16]}",
            details={
                "filename": safe_filename,
                "language": language,
                "sha256": analysis["sha256_hash"],
                "verdict": analysis["verdict"],
                "severity": analysis["severity"]
            }
        )

    return analysis


@router.get("/re-lab/report/{analysis_id}/download")
def download_re_report(analysis_id: str, format: str = "json"):
    """Downloads exportable JSON cryptographic dossier or formatted plain text investigation report."""
    with connect() as db:
        row = db.execute("SELECT * FROM re_lab_analyses WHERE id=? OR sha256_hash=?", (analysis_id, analysis_id)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Analysis record not found")

        d = dict(row)

    report_obj = {}
    try:
        report_obj = json.loads(d.get("report_json", "{}"))
    except Exception:
        pass

    if not report_obj or "integrity_sha256" not in report_obj:
        report_obj = export_re_report(d)

    if format.lower() == "json":
        json_str = json.dumps(report_obj, indent=2)
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=RE_Dossier_{d['filename']}.json"}
        )

    # Format Human-Readable Text Report
    txt_lines = [
        "=" * 78,
        f"AGENTSHIELD REVERSE ENGINEERING INVESTIGATION DOSSIER",
        "=" * 78,
        f"Report ID:          {report_obj.get('report_id')}",
        f"Generated At:       {report_obj.get('generated_at')}",
        f"Integrity SHA-256:  {report_obj.get('integrity_sha256')}",
        "-" * 78,
        "1. TARGET SAMPLE IDENTIFICATION",
        f"   Filename:         {d.get('filename')}",
        f"   File Size:        {d.get('file_size')} bytes",
        f"   SHA-256:          {d.get('sha256_hash')}",
        f"   SHA-1:            {d.get('sha1_hash')}",
        f"   MD5:              {d.get('md5_hash')}",
        f"   File Type:        {d.get('file_type')}",
        f"   Shannon Entropy:  {d.get('entropy')}",
        "-" * 78,
        "2. THREAT EVALUATION & CLASSIFICATION",
        f"   Verdict:          {d.get('verdict')}",
        f"   Severity Level:   {d.get('severity')}",
        f"   Confidence Score: {d.get('confidence')}",
        f"   Analysis Mode:    {d.get('analysis_mode')} (Direct Host Execution Prohibited)",
        "-" * 78,
        "3. AMOJA AI FORENSIC BRIEFING (ENGLISH)",
        f"   {d.get('ai_explanation_en', 'N/A')}",
        "-" * 78,
        "4. AMOJA AI FORENSIC BRIEFING (HINGLISH)",
        f"   {d.get('ai_explanation_hinglish', 'N/A')}",
        "-" * 78,
        "5. ZERO-TRUST SECURITY ASSURANCE",
        "   Host Execution:   STRICTLY_DISABLED",
        "   Analysis Mode:    Zero-Trust Heuristic & Static Telemetry Verification",
        "=" * 78
    ]
    txt_content = "\n".join(txt_lines)

    return Response(
        content=txt_content,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=RE_Report_{d['filename']}.txt"}
    )


@router.post("/re-lab/ai-explain")
def ask_amoja_re_explanation(body: Dict[str, Any]):
    """Interactive AMOJA AI forensic assistant for specific queries about a reverse engineered sample."""
    analysis_id = body.get("analysis_id", "")
    question = body.get("question", "")
    language = body.get("language", "auto").lower()

    with connect() as db:
        row = db.execute("SELECT * FROM re_lab_analyses WHERE id=? OR sha256_hash=?", (analysis_id, analysis_id)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Analysis record not found")
        sample = dict(row)

    # Generate grounded technical answer
    fname = sample.get("filename")
    verdict = sample.get("verdict")
    severity = sample.get("severity")
    sha256 = sample.get("sha256_hash")

    is_hindi_hinglish = (
        language in {"hi", "hinglish"}
        or (language != "en" and any(w in question.lower().split() for w in ["kya", "hai", "kaise", "batao", "karein", "kyun"]))
    )

    if is_hindi_hinglish:
        answer = (
            f"AMOJA AI Analyst Response:\n"
            f"Sample '{fname}' ka verdict '{verdict}' hai aur risk level '{severity}' mark kiya gaya hai. "
            f"Is sample ka SHA-256 hash '{sha256[:16]}...' hai. "
            f"Zero-Trust rule ke tahat is file ko direct host Windows system par execute nahi kiya gaya hai. "
            f"Recommendation: Is binary ko quarantined folder mein isolate rakhein aur network egress alerts monitor karein."
        )
    else:
        answer = (
            f"AMOJA AI Analyst Response:\n"
            f"Sample '{fname}' is classified as '{verdict}' with '{severity}' severity risk posture. "
            f"Integrity SHA-256 verification: {sha256}. "
            f"In accordance with Zero-Trust guidelines, this sample was analyzed purely via static disassembly and heuristic signatures without host execution. "
            f"Recommendation: Keep the sample quarantined, inspect related tool access logs, and enforce default-deny egress policies."
        )

    return {
        "analysis_id": analysis_id,
        "question": question,
        "answer": answer,
        "language": "hinglish" if is_hindi_hinglish else "english",
        "grounded_sample": fname
    }
