import os
import re
import json
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends

from ..db.database import connect, now_iso
from ..core.audit import record_audit_entry
from ..core.config import BASE_DIR
from ..engines.rea_engine import (
    check_rea_status,
    analyze_target_with_rea,
    generate_amoja_rea_explanation,
    get_authorized_rea_targets,
    validate_rea_target,
    generate_rea_forensic_report,
    RE_LAB_VAULT_DIR,
    MAX_FILE_SIZE_BYTES
)

router = APIRouter(prefix="/api/rea", tags=["REA Reverse Engineering Lab"])

# Permitted root directories for direct path inspection
ALLOWED_INSPECT_ROOTS = [
    RE_LAB_VAULT_DIR.resolve(),
    BASE_DIR.parent.resolve()  # e:\AgentShield_Starter_Project
]


def is_path_authorized(target_path: Path) -> bool:
    r"""
    Enforces authorization boundary: target must resolve to a path within
    the quarantined vault or the active AgentShield project workspace.
    Explicitly forbids inspecting system root directories (e.g. C:\Windows, C:\Users).
    """
    try:
        resolved = target_path.resolve()
        # Ensure it is within at least one allowed root
        for allowed in ALLOWED_INSPECT_ROOTS:
            try:
                resolved.relative_to(allowed)
                return True
            except ValueError:
                continue
        return False
    except Exception:
        return False


@router.get("/status")
def get_rea_lab_status():
    """
    Returns the real-time operational status of REA, including version,
    Node.js runtime, configured providers (Ghidra, Hopper, Cutter, IDA, etc.),
    and supported artifact workflows.
    """
    return check_rea_status()


@router.post("/upload")
async def upload_and_analyze_with_rea(
    file: UploadFile = File(...),
    workflow: Optional[str] = Form(None)
):
    """
    Secure upload endpoint for REA analysis.
    Validates file size (max 25MB), neutralizes path traversal attacks,
    quarantines the file in the vault, and executes static REA inspection.
    """
    raw_filename = file.filename or "artifact.bin"
    # Neutralize path traversal
    clean_basename = Path(raw_filename).name
    safe_filename = re.sub(r"[^a-zA-Z0-9_\.-]", "_", clean_basename)
    if not safe_filename:
        safe_filename = f"artifact_{uuid.uuid4().hex[:8]}.bin"

    # Streaming read enforcing max file size
    file_bytes = bytearray()
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        file_bytes.extend(chunk)
        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded artifact exceeds maximum permitted size of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB"
            )

    bytes_data = bytes(file_bytes)
    quarantine_id = uuid.uuid4().hex[:12]
    quarantine_path = RE_LAB_VAULT_DIR / f"rea_{quarantine_id}_{safe_filename}"

    with open(quarantine_path, "wb") as f:
        f.write(bytes_data)

    # Execute REA analysis
    investigation = analyze_target_with_rea(quarantine_path, workflow=workflow)

    # Generate AMOJA AI briefing
    amoja_briefing = generate_amoja_rea_explanation(investigation)
    investigation["amoja_briefing"] = amoja_briefing

    # Persist in SQLite re_lab_analyses
    now = now_iso()
    sha256 = investigation["hashes"]["sha256"]
    sha1 = investigation["hashes"]["sha1"]
    md5 = investigation["hashes"]["md5"]

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
            investigation["analysis_id"],
            safe_filename,
            len(bytes_data),
            sha256,
            sha1,
            md5,
            f"REA:{investigation['workflow']}",
            "application/octet-stream",
            0.0,
            f"REA_LAB:{investigation['workflow']}",
            "LOW" if investigation["success"] else "INFO",
            "ANALYZED" if investigation["success"] else "LIMITED",
            0.98 if investigation["success"] else 0.50,
            investigation["summary"],
            json.dumps(investigation.get("limitations", [])),
            json.dumps({"workflow": investigation["workflow"], "confidence": investigation["confidence"]}),
            json.dumps([]),
            json.dumps([]),
            json.dumps(investigation.get("evidence", {})),
            json.dumps({}),
            json.dumps({"mode": "STATIC_ONLY", "host_exec_blocked": True}),
            amoja_briefing["english_briefing"],
            amoja_briefing["hinglish_briefing"],
            json.dumps(investigation),
            now
        ))

        # Record cryptographically chained audit entry
        record_audit_entry(
            db,
            actor="security_analyst",
            action="REA_LAB_ARTIFACT_ANALYZED",
            resource=f"rea_sample:{sha256[:16]}",
            details={
                "analysis_id": investigation["analysis_id"],
                "filename": safe_filename,
                "workflow": investigation["workflow"],
                "file_size": len(bytes_data),
                "sha256": sha256,
                "success": investigation["success"]
            }
        )

    return investigation


@router.post("/inspect-path")
def inspect_path_with_rea(body: Dict[str, Any]):
    """
    Analyzes an authorized workspace artifact or directory path with REA.
    Rejects unauthorized paths outside the AgentShield workspace or quarantine vault.
    """
    raw_path_str = body.get("path", "")
    workflow = body.get("workflow")
    options = body.get("options", {})

    if not raw_path_str:
        raise HTTPException(status_code=400, detail="Target path is required.")

    target_path = Path(raw_path_str)
    if not target_path.exists():
        raise HTTPException(status_code=404, detail=f"Target path does not exist: {raw_path_str}")

    if not is_path_authorized(target_path):
        raise HTTPException(
            status_code=403,
            detail="Access denied. Path is outside authorized workspace or vault boundaries."
        )

    investigation = analyze_target_with_rea(target_path, workflow=workflow, options=options)
    amoja_briefing = generate_amoja_rea_explanation(investigation)
    investigation["amoja_briefing"] = amoja_briefing

    now = now_iso()
    sha256 = investigation["hashes"].get("sha256", "")
    sha1 = investigation["hashes"].get("sha1", "")
    md5 = investigation["hashes"].get("md5", "")

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
            investigation["analysis_id"],
            investigation["filename"],
            investigation["file_size"],
            sha256,
            sha1,
            md5,
            f"REA:{investigation['workflow']}",
            "application/octet-stream",
            0.0,
            f"REA_LAB:{investigation['workflow']}",
            "LOW" if investigation["success"] else "INFO",
            "ANALYZED" if investigation["success"] else "LIMITED",
            0.98 if investigation["success"] else 0.50,
            investigation["summary"],
            json.dumps(investigation.get("limitations", [])),
            json.dumps({"workflow": investigation["workflow"], "confidence": investigation["confidence"]}),
            json.dumps([]),
            json.dumps([]),
            json.dumps(investigation.get("evidence", {})),
            json.dumps({}),
            json.dumps({"mode": "STATIC_ONLY", "host_exec_blocked": True}),
            amoja_briefing["english_briefing"],
            amoja_briefing["hinglish_briefing"],
            json.dumps(investigation),
            now
        ))

        record_audit_entry(
            db,
            actor="security_analyst",
            action="REA_LAB_PATH_INSPECTED",
            resource=f"rea_path:{investigation['filename']}",
            details={
                "analysis_id": investigation["analysis_id"],
                "target_path": str(target_path),
                "workflow": investigation["workflow"],
                "success": investigation["success"]
            }
        )

    return investigation


@router.post("/explain")
def ask_amoja_rea_explanation(body: Dict[str, Any]):
    """
    Interactive AMOJA AI forensic assistant for explaining REA analysis results,
    evidence, and limitations in English or Hinglish.
    """
    analysis_id = body.get("analysis_id", "")
    question = body.get("question", "")
    language = body.get("language", "en").lower()

    if not analysis_id:
        raise HTTPException(status_code=400, detail="analysis_id is required.")

    with connect() as db:
        row = db.execute(
            "SELECT * FROM re_lab_analyses WHERE id=? OR sha256_hash=?",
            (analysis_id, analysis_id)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Investigation record not found.")

        record = dict(row)

    # Reconstruct investigation envelope from DB
    report_data = {}
    try:
        report_data = json.loads(record.get("report_json", "{}"))
    except Exception:
        pass

    investigation = {
        "analysis_id": record["id"],
        "filename": record["filename"],
        "workflow": report_data.get("workflow", record.get("file_type", "").replace("REA:", "")),
        "file_size": record["file_size"],
        "hashes": {
            "sha256": record["sha256_hash"],
            "sha1": record["sha1_hash"],
            "md5": record["md5_hash"]
        },
        "success": (record["verdict"] == "ANALYZED"),
        "limitations": json.loads(record.get("indicators_json", "[]")),
        "raw_result": json.loads(record.get("source_analysis_json", "{}"))
    }

    return generate_amoja_rea_explanation(investigation, question=question, language=language)


@router.get("/history")
def get_rea_history():
    """
    Retrieves history of REA Reverse Engineering Lab investigations.
    """
    with connect() as db:
        rows = db.execute("""
            SELECT id, filename, file_size, sha256_hash, file_type, severity, verdict,
                   confidence, summary, created_at
            FROM re_lab_analyses
            WHERE analysis_mode LIKE 'REA%'
            ORDER BY created_at DESC
            LIMIT 50
        """).fetchall()
        return [dict(r) for r in rows]


@router.get("/authorized-targets")
def list_authorized_rea_targets():
    """
    Returns pre-authorized targets for REA inspection, including the harmless
    AgentShield Desktop (Electron application), frontend AST, and database snapshots.
    """
    return get_authorized_rea_targets()


@router.post("/validate-target")
def validate_target_for_rea(body: Dict[str, Any]):
    """
    Pre-validates an inspection target before running REA.
    Verifies path authorization, safe boundary checks, and auto-detects suitable workflows.
    Records a validation audit record.
    """
    target_path = body.get("target_path", "")
    val = validate_rea_target(target_path)

    with connect() as db:
        record_audit_entry(
            db,
            actor="security_analyst",
            action="REA_TARGET_VALIDATED",
            resource=f"target:{val.get('filename', 'unresolved')}",
            details={
                "target_path": target_path,
                "status": val.get("status"),
                "valid": val.get("valid"),
                "recommended_workflow": val.get("recommended_workflow")
            }
        )

    return val


@router.post("/generate-report")
def generate_forensic_report_endpoint(body: Dict[str, Any]):
    """
    Generates an official, evidence-based Forensic Investigation Dossier
    for an analyzed sample or path using REA and AMOJA AI.
    Outputs structured Markdown and raw telemetry.
    """
    analysis_id = body.get("analysis_id", "")
    investigation_payload = body.get("investigation")

    investigation = None
    if investigation_payload and isinstance(investigation_payload, dict):
        investigation = investigation_payload
    elif analysis_id:
        with connect() as db:
            row = db.execute(
                "SELECT * FROM re_lab_analyses WHERE id=? OR sha256_hash=?",
                (analysis_id, analysis_id)
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Investigation record not found.")
            record = dict(row)
            try:
                report_data = json.loads(record.get("report_json", "{}"))
            except Exception:
                report_data = {}

            investigation = {
                "analysis_id": record["id"],
                "filename": record["filename"],
                "workflow": report_data.get("workflow", record.get("file_type", "").replace("REA:", "")),
                "file_size": record["file_size"],
                "hashes": {
                    "sha256": record["sha256_hash"],
                    "sha1": record["sha1_hash"],
                    "md5": record["md5_hash"]
                },
                "success": (record["verdict"] == "ANALYZED"),
                "limitations": json.loads(record.get("indicators_json", "[]")),
                "raw_result": json.loads(record.get("source_analysis_json", "{}")),
                "summary": record.get("summary", "")
            }
    else:
        raise HTTPException(status_code=400, detail="analysis_id or investigation payload required.")

    report = generate_rea_forensic_report(investigation)

    # Record report generation in audit ledger
    with connect() as db:
        record_audit_entry(
            db,
            actor="security_analyst",
            action="REA_REPORT_GENERATED",
            resource=f"report:{report['report_id']}",
            details={
                "report_id": report["report_id"],
                "analysis_id": report["analysis_id"],
                "filename": report["filename"],
                "sha256": report["sha256"]
            }
        )

    return report

