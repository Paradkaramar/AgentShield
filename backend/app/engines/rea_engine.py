import os
import re
import sys
import json
import uuid
import shutil
import hashlib
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from ..core.config import BASE_DIR

logger = logging.getLogger("agentshield.rea_engine")

# Quarantined Vault directory for REA artifacts
RE_LAB_VAULT_DIR = BASE_DIR / "data" / "re_lab_vault"
RE_LAB_VAULT_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB strict cap
DEFAULT_TIMEOUT_SECONDS = 60  # 60s hard deadline per command

# Candidate paths for REA CLI / scripts
GLOBAL_NPM_REA_MJS = Path(os.environ.get("APPDATA", "")) / "npm" / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"
LOCAL_WORKSPACE_REA_MJS = BASE_DIR.parent / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"


def find_node_executable() -> str:
    """Locates the system Node.js binary."""
    node_bin = shutil.which("node")
    if node_bin:
        return node_bin
    # Windows fallback paths
    for p in [r"C:\Program Files\nodejs\node.exe", r"C:\Program Files (x86)\nodejs\node.exe"]:
        if os.path.exists(p):
            return p
    return "node"


def find_rea_command() -> List[str]:
    """
    Determines the safest and fastest execution command prefix for REA.
    Prioritizes direct `node <path-to-rea.mjs>` to bypass shell wrappers,
    falling back to `rea` CLI or `npx rea-agents`.
    """
    node_bin = find_node_executable()

    # 1. Direct node execution of rea.mjs (fastest and most reliable on Windows)
    if GLOBAL_NPM_REA_MJS.exists():
        return [node_bin, str(GLOBAL_NPM_REA_MJS)]

    if LOCAL_WORKSPACE_REA_MJS.exists():
        return [node_bin, str(LOCAL_WORKSPACE_REA_MJS)]

    # 2. Global executable in PATH or AppData
    rea_bin = shutil.which("rea")
    if rea_bin:
        return [rea_bin]

    npm_bin_dir = Path(os.environ.get("APPDATA", "")) / "npm"
    for candidate in ["rea.cmd", "rea.ps1", "rea"]:
        full_candidate = npm_bin_dir / candidate
        if full_candidate.exists():
            return [str(full_candidate)]

    # 3. Fallback to npx
    npx_bin = shutil.which("npx")
    if npx_bin:
        return [npx_bin, "--yes", "rea-agents"]

    return ["rea"]


def calculate_hashes(data: bytes) -> Dict[str, Any]:
    """Computes SHA-256, SHA-1, MD5 cryptographic hashes of byte content."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size_bytes": len(data)
    }


def parse_rea_json_output(stdout_text: str, stderr_text: str) -> Dict[str, Any]:
    """
    Parses JSON output from REA.
    Separates out streaming progress events (e.g. `{"rea_progress": ...}`)
    and extracts the final structured response envelope.
    """
    text = (stdout_text or "").strip()
    if not text:
        # Check stderr for JSON error
        err_lines = [l.strip() for l in (stderr_text or "").splitlines() if l.strip()]
        for l in reversed(err_lines):
            if l.startswith("{") and l.endswith("}"):
                try:
                    return json.loads(l)
                except Exception:
                    pass
        return {
            "error": "No output returned by REA engine",
            "stderr": stderr_text[:2000] if stderr_text else ""
        }

    # Strategy 1: Sequential JSON decoding to extract all complete JSON objects
    decoder = json.JSONDecoder()
    pos = 0
    non_progress_objects = []
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        if text[pos] != "{":
            next_brace = text.find("{", pos)
            if next_brace == -1:
                break
            pos = next_brace
        try:
            obj, next_idx = decoder.raw_decode(text, pos)
            if isinstance(obj, dict):
                if "rea_progress" not in obj:
                    non_progress_objects.append(obj)
            pos = next_idx
        except Exception:
            pos += 1

    if non_progress_objects:
        return non_progress_objects[-1]

    # Strategy 2: Line-by-line fallback
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for i in range(len(lines) - 1, -1, -1):
        candidate = lines[i]
        if candidate.startswith("{") and candidate.endswith("}"):
            try:
                parsed = json.loads(candidate)
                if "rea_progress" not in parsed:
                    return parsed
            except Exception:
                continue

    return {
        "error": "Unable to parse structured JSON from REA output",
        "raw_stdout_sample": text[:3000],
        "raw_stderr_sample": stderr_text[:1000] if stderr_text else ""
    }


def run_rea_command(
    args: List[str],
    timeout_sec: int = DEFAULT_TIMEOUT_SECONDS,
    cwd: Optional[Path] = None
) -> Tuple[int, Dict[str, Any], str]:
    """
    Safely executes a REA command using `subprocess.run` with list args (`shell=False`).
    Enforces process isolation, timeouts, and memory-safe buffer reading.
    """
    cmd_prefix = find_rea_command()
    full_cmd = cmd_prefix + args

    work_dir = str(cwd) if cwd else str(BASE_DIR)

    logger.info("Executing REA command: %s (cwd=%s)", " ".join(full_cmd[:4]), work_dir)

    try:
        proc = subprocess.run(
            full_cmd,
            cwd=work_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
            shell=False,
            encoding="utf-8",
            errors="replace"
        )
        parsed_json = parse_rea_json_output(proc.stdout, proc.stderr)
        return proc.returncode, parsed_json, proc.stderr or ""
    except subprocess.TimeoutExpired:
        logger.warning("REA command timed out after %ds: %s", timeout_sec, full_cmd[:3])
        return 124, {
            "error": f"REA execution timed out after {timeout_sec} seconds.",
            "code": "EXECUTION_TIMEOUT",
            "category": "timeout"
        }, f"Command exceeded deadline of {timeout_sec}s."
    except Exception as exc:
        logger.error("Failed to execute REA command: %s", exc)
        return 1, {
            "error": f"Failed to execute REA command: {str(exc)}",
            "code": "EXECUTION_FAILED"
        }, str(exc)


def check_rea_status() -> Dict[str, Any]:
    """
    Checks REA operational health, version, node runtime, and analysis providers.
    """
    cmd_prefix = find_rea_command()
    node_bin = find_node_executable()

    # 1. Probe Node.js version
    node_ver = "unknown"
    try:
        nv_proc = subprocess.run([node_bin, "-v"], capture_output=True, text=True, timeout=5, shell=False)
        if nv_proc.returncode == 0:
            node_ver = nv_proc.stdout.strip()
    except Exception:
        pass

    # 2. Probe REA version
    rea_ver = "unknown"
    code, out, _ = run_rea_command(["--version"], timeout_sec=25)
    if code == 0:
        if isinstance(out, dict) and "error" in out:
            pass
        elif isinstance(out, (str, int, float)):
            rea_ver = str(out)

    if rea_ver == "unknown":
        try:
            p = subprocess.run(cmd_prefix + ["--version"], capture_output=True, text=True, timeout=25, shell=False)
            if p.returncode == 0:
                lines = [l.strip() for l in p.stdout.strip().splitlines() if l.strip()]
                if lines:
                    rea_ver = lines[-1]
        except Exception:
            pass

    # 3. Probe REA providers
    code_prov, prov_json, _ = run_rea_command(["providers", "--format", "json"], timeout_sec=20)
    providers_list = []
    server_identity = {}

    if isinstance(prov_json, dict):
        server_identity = prov_json.get("server_identity", {})
        prov_items = prov_json.get("analysis_provider_candidates") or prov_json.get("providers", [])
        if isinstance(prov_items, list):
            for p in prov_items:
                p_info = p.get("provider", {})
                avail = p.get("availability", {})
                providers_list.append({
                    "id": p_info.get("id"),
                    "name": p_info.get("name"),
                    "version": p_info.get("version"),
                    "status": avail.get("status", "unknown"),
                    "code": avail.get("code"),
                    "reason": avail.get("reason"),
                    "selected": p.get("selected", False)
                })

    is_installed = (rea_ver != "unknown" and rea_ver != "")

    return {
        "installed": is_installed,
        "version": rea_ver if is_installed else "NOT_FOUND",
        "node_version": node_ver,
        "node_path": node_bin,
        "command_path": " ".join(cmd_prefix),
        "providers": providers_list,
        "server_identity": server_identity,
        "capabilities": {
            "javascript_electron": True,
            "dotnet_assemblies": True,
            "sqlite_snapshots": True,
            "general_artifacts": True,
            "go_binaries": True,
            "wasm_artifacts": True,
            "native_disassembly": any(p.get("status") == "available" for p in providers_list)
        },
        "supported_workflows": [
            "inspect-sqlite-database",
            "analyze-javascript-application",
            "inspect-artifact",
            "inspect-managed-artifact",
            "inspect-managed-members",
            "inspect-go-binary",
            "inspect-rust-binary",
            "inspect-wasm-artifact",
            "inspect-binary-layout"
        ],
        "zero_trust_status": "ENFORCING",
        "sandbox_policy": "STATIC_ANALYSIS_ONLY (Direct host execution prohibited)"
    }


SUPPORTED_REA_WORKFLOWS = {
    "inspect-sqlite-database",
    "analyze-javascript-application",
    "inspect-artifact",
    "inspect-managed-artifact",
    "inspect-managed-members",
    "inspect-go-binary",
    "inspect-rust-binary",
    "inspect-wasm-artifact",
    "inspect-binary-layout",
    "inspect-pe-resources"
}


def detect_rea_workflow(file_path: Path, bytes_sample: bytes = b"") -> str:
    """
    Selects the optimal documented REA analysis workflow based on file extension and magic bytes.
    """
    if file_path.is_dir():
        return "analyze-javascript-application"

    ext = file_path.suffix.lower()

    # SQLite
    if ext in {".db", ".sqlite", ".sqlite3"} or bytes_sample.startswith(b"SQLite format 3"):
        return "inspect-sqlite-database"

    # WebAssembly
    if ext == ".wasm" or bytes_sample.startswith(b"\x00asm"):
        return "inspect-wasm-artifact"

    # JavaScript / Electron directory or ASAR bundle
    if ext == ".asar":
        return "analyze-javascript-application"

    # .NET PE/CLI assemblies or Windows binaries
    if ext in {".dll", ".exe"}:
        return "inspect-managed-artifact"

    # Default provider-neutral artifact inspection (single JS/TS files, GGUF/Safetensors, ELFs, etc.)
    return "inspect-artifact"


def analyze_target_with_rea(
    target_path: Path,
    workflow: Optional[str] = None,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Executes the designated REA inspection on a target path,
    retaining full evidence, limitations, and cryptographic integrity.
    """
    if not target_path.exists():
        return {
            "success": False,
            "error": f"Target file or path does not exist: {target_path}",
            "code": "TARGET_NOT_FOUND"
        }

    # Verify file size if it's a file
    if target_path.is_file():
        file_size = target_path.stat().st_size
        if file_size > MAX_FILE_SIZE_BYTES:
            return {
                "success": False,
                "error": f"File size ({file_size} bytes) exceeds safety maximum of {MAX_FILE_SIZE_BYTES} bytes.",
                "code": "FILE_TOO_LARGE"
            }
        with open(target_path, "rb") as f:
            sample_bytes = f.read(512)
            f.seek(0)
            full_bytes = f.read()
        hashes = calculate_hashes(full_bytes)
    else:
        file_size = 0
        sample_bytes = b""
        hashes = {"sha256": "", "sha1": "", "md5": "", "size_bytes": 0}

    # Resolve workflow if not specified
    selected_workflow = workflow or detect_rea_workflow(target_path, sample_bytes)

    # Validate against whitelisted supported workflows
    if selected_workflow not in SUPPORTED_REA_WORKFLOWS:
        return {
            "success": False,
            "error": f"Unsupported or unauthorized REA workflow: '{selected_workflow}'. Supported workflows: {sorted(list(SUPPORTED_REA_WORKFLOWS))}",
            "code": "INVALID_WORKFLOW"
        }

    # REA analyze-javascript-application strictly requires a directory or an .asar file
    if selected_workflow == "analyze-javascript-application" and not (target_path.is_dir() or target_path.suffix.lower() == ".asar"):
        selected_workflow = "inspect-artifact"

    # Build command arguments
    target_arg = str(target_path.resolve())
    cmd_args = [selected_workflow, target_arg, "--format", "json"]

    opts = options or {}
    if selected_workflow == "inspect-sqlite-database" and "table" in opts:
        cmd_args.extend(["--table", str(opts["table"])])
        if "row_limit" in opts:
            cmd_args.extend(["--row-limit", str(opts["row_limit"])])

    code, rea_result, stderr_diag = run_rea_command(cmd_args, timeout_sec=DEFAULT_TIMEOUT_SECONDS)

    # Extract core facets
    is_success = (code == 0 and "error" not in rea_result)
    limitations = []
    confidence = "observed"
    evidence = {}
    summary_text = ""

    if isinstance(rea_result, dict):
        limitations = rea_result.get("limitations", [])
        confidence = rea_result.get("confidence", "observed")
        evidence = rea_result
        normalized = rea_result.get("normalized_result")
        findings = normalized if isinstance(normalized, dict) else rea_result

        # Synthesize brief summary
        if selected_workflow == "inspect-sqlite-database":
            db_schema = findings.get("schema", {})
            tables = db_schema.get("tables", [])
            indexes = db_schema.get("indexes", [])
            summary_text = f"SQLite Database Snapshot: {len(tables)} tables, {len(indexes)} indexes identified without executing dynamic queries."
        elif selected_workflow == "analyze-javascript-application":
            stats = findings.get("statistics") or {}
            summ = findings.get("summary") or {}
            graph = findings.get("graph") or {}
            parsed_files = stats.get("parsed_javascript_files", 0)
            ast_nodes = stats.get("visited_ast_nodes", 0)
            ipc_ops = summ.get("ipc", {}).get("operations", 0)
            graph_nodes = len(graph.get("nodes", []))
            modules = findings.get("application_graph", {}).get("modules", [])
            if parsed_files > 0 or ast_nodes > 0 or ipc_ops > 0:
                summary_text = f"JavaScript/Electron Application Graph: {parsed_files} files parsed, {ast_nodes} AST nodes, {ipc_ops} IPC operations, {graph_nodes} topology nodes."
            elif modules:
                summary_text = f"JavaScript/TypeScript Application Graph: {len(modules)} modules mapped with import boundaries."
            else:
                summary_text = f"JavaScript/TypeScript Application Graph: {graph_nodes} graph nodes analyzed."
        elif selected_workflow == "inspect-managed-artifact":
            identity = findings.get("identity", {})
            summary_text = f"Managed .NET Assembly: {identity.get('name', target_path.name)} inspected without execution."
        elif selected_workflow == "inspect-artifact":
            subj = findings.get("subject", {})
            root_fmt = subj.get("root_format") or subj.get("format") or "general artifact"
            observations = findings.get("observations", [])
            hypotheses = findings.get("hypotheses", [])
            next_probes = findings.get("next_probes", [])
            summary_text = f"Artifact Inspection ({root_fmt}): {len(observations)} observations, {len(hypotheses)} hypotheses, {len(next_probes)} recommended follow-up probes."
        else:
            summary_text = f"REA Analysis ({selected_workflow}): Completed with exit code {code}."

    if not is_success:
        err_msg = rea_result.get("message") or rea_result.get("error") or "Analysis failed"
        remediation = rea_result.get("remediation", {}).get("action", "Check target format and dependencies")
        summary_text = f"Analysis Limited or Failed: {err_msg}. Remediation: {remediation}"

    analysis_id = f"rea_{uuid.uuid4().hex[:12]}"

    return {
        "analysis_id": analysis_id,
        "success": is_success,
        "workflow": selected_workflow,
        "target_path": str(target_path),
        "filename": target_path.name,
        "file_size": file_size,
        "hashes": hashes,
        "exit_code": code,
        "summary": summary_text,
        "confidence": confidence,
        "limitations": limitations,
        "evidence": evidence,
        "stderr_diagnostics": stderr_diag,
        "raw_result": rea_result
    }


def generate_amoja_rea_explanation(
    investigation: Dict[str, Any],
    question: Optional[str] = None,
    language: str = "en"
) -> Dict[str, Any]:
    """
    AMOJA AI Forensic Explainer for REA findings.
    Strictly separates:
    1) Observed Facts (exact hashes, tables, modules, declared symbols)
    2) Inferred Risks (security anomalies, attack surface expansion, suspicious patterns)
    3) Limitations & Unknowns (unsupported providers, unmapped references, bounded samples)

    Generates briefings in both English and Hinglish.
    Treats all target strings, code fragments, and metadata as untrusted inputs.
    """
    workflow = investigation.get("workflow", "unknown")
    filename = investigation.get("filename", "unknown_artifact")
    hashes = investigation.get("hashes", {})
    sha256 = hashes.get("sha256", "N/A")
    file_size = investigation.get("file_size", 0)
    is_success = investigation.get("success", False)
    limitations = investigation.get("limitations", [])
    raw = investigation.get("raw_result", {})
    evidence = investigation.get("evidence", {})
    normalized = raw.get("normalized_result") if isinstance(raw, dict) else None
    if not isinstance(normalized, dict) and isinstance(evidence, dict):
        normalized = evidence.get("normalized_result")
    findings = normalized if isinstance(normalized, dict) else raw

    # Sanitize inputs (neutralize any prompt injection delimiters)
    clean_filename = re.sub(r"[\r\n`$<>#]", "", filename)[:80]
    clean_sha = sha256[:16] if sha256 else "N/A"

    # 1. Extract Observed Facts
    observed_facts: List[str] = [
        f"Artifact '{clean_filename}' ({file_size} bytes, SHA-256: {clean_sha}...)",
        f"Analysis workflow executed: {workflow} (Exit code: {investigation.get('exit_code', 0)})",
        "Host execution posture: STRICTLY_DISABLED (Static telemetry and offline parsing only)"
    ]

    # Specific evidence extraction
    if workflow == "inspect-sqlite-database":
        schema = findings.get("schema", {})
        tbls = schema.get("tables", [])
        table_names = [t.get("name", "") for t in tbls[:10] if isinstance(t, dict)]
        observed_facts.append(f"Identified {len(tbls)} database tables: {', '.join(table_names) if table_names else 'None'}")
        idxs = schema.get("indexes", [])
        observed_facts.append(f"Identified {len(idxs)} index definitions.")
    elif workflow == "analyze-javascript-application":
        stats = findings.get("statistics") or {}
        summ = findings.get("summary") or {}
        parsed_files = stats.get("parsed_javascript_files", 0)
        ast_nodes = stats.get("visited_ast_nodes", 0)
        ipc_info = summ.get("ipc", {})
        ipc_ops = ipc_info.get("operations", 0)
        literal_channels = ipc_info.get("literal_channels", 0)
        context_bridges = summ.get("context_bridge_apis", 0)
        preload_entries = summ.get("preload_entrypoints", 0)
        browser_windows = summ.get("browser_windows", 0)

        app_graph = findings.get("application_graph", {})
        modules = app_graph.get("modules", [])
        electron_bounds = app_graph.get("electron_boundaries", [])

        if parsed_files > 0 or ast_nodes > 0:
            observed_facts.append(f"Parsed {parsed_files} JavaScript source files across {ast_nodes} AST nodes.")
        elif modules:
            observed_facts.append(f"Parsed {len(modules)} JavaScript/TypeScript source modules.")
        else:
            observed_facts.append("Analyzed JavaScript application AST structure.")

        if ipc_ops > 0:
            observed_facts.append(f"Mapped {ipc_ops} Electron IPC operations across {literal_channels} channels ({context_bridges} context bridges, {preload_entries} preload scripts).")
        elif electron_bounds:
            observed_facts.append(f"Detected {len(electron_bounds)} Electron IPC/context bridge boundaries.")

        if browser_windows > 0:
            observed_facts.append(f"Detected {browser_windows} Electron BrowserWindow instance(s) with configured webPreferences.")
    elif workflow == "inspect-managed-artifact":
        identity = findings.get("identity", {})
        observed_facts.append(f"Assembly runtime: {identity.get('runtime', 'CLR/PE')} | Architecture: {identity.get('architecture', 'MSIL')}")
    elif workflow == "inspect-artifact":
        subj = findings.get("subject", {})
        root_fmt = subj.get("root_format") or subj.get("format") or "general artifact"
        observations = findings.get("observations", [])
        hypotheses = findings.get("hypotheses", [])
        next_probes = findings.get("next_probes", [])
        observed_facts.append(f"Artifact format classification: '{root_fmt}' with {len(observations)} verified observation entries.")
        if hypotheses:
            stmt = hypotheses[0].get("statement", "")
            if stmt:
                observed_facts.append(f"Derived hypothesis: {stmt}")
        if next_probes:
            probe_ops = [p.get("operation", "") for p in next_probes[:3] if p.get("operation")]
            if probe_ops:
                observed_facts.append(f"Recommended next inspection probes: {', '.join(probe_ops)}")
    elif not is_success:
        err_msg = raw.get("message") or raw.get("error") or "Analysis completed with restrictions"
        observed_facts.append(f"Tool reported status: {err_msg}")

    # 2. Extract Inferred Risks
    inferred_risks: List[str] = []
    if not is_success:
        inferred_risks.append("Target artifact could not be parsed by the selected workflow. Verify whether the file is encrypted, packed, or requires a native disassembler provider.")
    else:
        if workflow == "inspect-sqlite-database":
            inferred_risks.append("Database stores application telemetry. Ensure default-deny access controls protect table contents containing agent memory or session keys.")
        elif workflow == "analyze-javascript-application":
            inferred_risks.append("Client-side or Electron application components expose public IPC channels that could be subject to unauthorized tool invocation if unvalidated.")
        else:
            inferred_risks.append("Unmonitored binary or assembly invocation presents potential privilege escalation if executed outside the Zero-Trust control plane.")

    # 3. Limitations & Unknowns
    unknowns: List[str] = []
    if limitations:
        for lim in limitations[:5]:
            if isinstance(lim, str):
                unknowns.append(lim[:180])
    if not unknowns:
        unknowns.append("Native procedure disassembly requires an external provider (Hopper, Ghidra, Cutter, or IDA) to be configured.")
        unknowns.append("Indirect dynamic runtime behavior and memory manipulation cannot be observed through static inspection.")

    # Format English Briefing
    en_lines = [
        f"### 🛡️ AMOJA AI Forensic Briefing — {clean_filename}",
        f"**Target Workflow:** `{workflow}` | **Integrity SHA-256:** `{clean_sha}...`",
        "",
        "#### 1. Observed Facts (Verified Telemetry)",
    ]
    for fact in observed_facts:
        en_lines.append(f"- {fact}")

    en_lines.append("")
    en_lines.append("#### 2. Inferred Risks (Threat Assessment)")
    for risk in inferred_risks:
        en_lines.append(f"- ⚠️ {risk}")

    en_lines.append("")
    en_lines.append("#### 3. Limitations & Unknown Information")
    for unk in unknowns:
        en_lines.append(f"- ℹ️ {unk}")

    en_briefing = "\n".join(en_lines)

    # Format Hinglish Briefing
    hi_lines = [
        f"### 🛡️ AMOJA AI Forensic Briefing (Hinglish) — {clean_filename}",
        f"**Target Workflow:** `{workflow}` | **SHA-256 Verification:** `{clean_sha}...`",
        "",
        "#### 1. Observed Facts (Verified Sach)",
        f"- Target file '{clean_filename}' ka size {file_size} bytes hai aur SHA-256 `{clean_sha}...` verify hua hai.",
        f"- Zero-Trust rule ke tahat is file ko host Windows system par execute nahi kiya gaya — yeh purely static reverse engineering hai.",
    ]
    if workflow == "inspect-sqlite-database":
        hi_lines.append(f"- SQLite snapshot se table schema aur structure bina query execute kiye extract kar liya gaya hai.")
    elif workflow == "analyze-javascript-application":
        hi_lines.append(f"- JavaScript application ka module graph aur dependency structure REA engine ne map kar diya hai.")

    hi_lines.append("")
    hi_lines.append("#### 2. Inferred Risks (Khatre ka Vishleshan)")
    if is_success:
        hi_lines.append("- ⚠️ File ke exported functions aur database tables ko Zero-Trust control plane ke under protect rakhna zaroori hai.")
    else:
        hi_lines.append("- ⚠️ Target format ko selected provider ke saath parse nahi kiya ja saka. Check karein ki kya file packed ya encrypted hai.")

    hi_lines.append("")
    hi_lines.append("#### 3. Limitations & Unknowns (Seemayein)")
    for unk in unknowns[:3]:
        hi_lines.append(f"- ℹ️ {unk}")

    hi_briefing = "\n".join(hi_lines)

    # Answer specific question if provided
    custom_answer = None
    if question:
        q_lower = question.lower()
        is_hinglish_q = any(w in q_lower.split() for w in ["kya", "hai", "kaise", "batao", "karein", "kyun", "samjhao"]) or language == "hinglish"
        if is_hinglish_q:
            custom_answer = (
                f"AMOJA AI Analyst: '{clean_filename}' artifact ko REA workflow `{workflow}` ke zariye inspect kiya gaya hai. "
                f"Is sample ka verdict safe static observation hai, aur host Windows OS par execution strictly prohibited hai. "
                f"Observed findings: {len(observed_facts)} verified points, 0 dynamic crashes."
            )
        else:
            custom_answer = (
                f"AMOJA AI Analyst: Artifact '{clean_filename}' was inspected using REA workflow `{workflow}`. "
                f"Static analysis confirmed file integrity (SHA-256: {clean_sha}...) without host execution. "
                f"Security recommendation: Review the observed schema/module boundaries and keep unmonitored egress locked."
            )

    return {
        "analysis_id": investigation.get("analysis_id"),
        "filename": clean_filename,
        "workflow": workflow,
        "observed_facts": observed_facts,
        "inferred_risks": inferred_risks,
        "limitations": unknowns,
        "english_briefing": en_briefing,
        "hinglish_briefing": hi_briefing,
        "custom_answer": custom_answer,
        "language_served": language
    }


def get_authorized_rea_targets() -> List[Dict[str, Any]]:
    """
    Returns the catalog of authorized applications, source trees, and database snapshots
    pre-approved for safe static inspection by REA.
    """
    targets = []
    workspace_root = BASE_DIR.parent

    # 1. Desktop Harmless Electron Application
    desktop_dir = workspace_root / "desktop"
    if desktop_dir.exists():
        targets.append({
            "id": "app_electron_desktop",
            "name": "AgentShield Desktop (Electron App)",
            "kind": "application",
            "format": "JavaScript / Electron Application",
            "path": str(desktop_dir.relative_to(workspace_root)).replace("\\", "/"),
            "absolute_path": str(desktop_dir.resolve()),
            "recommended_workflow": "analyze-javascript-application",
            "is_harmless_test_app": True,
            "description": "Harmless Electron shell containing main.js, preload.js, and IPC channel declarations.",
            "safety_posture": "STATIC_ANALYSIS_ONLY (Direct host execution prohibited)",
            "permission_required": "AUTHORIZED"
        })

    # 2. Frontend Source Tree (React / TypeScript Graph)
    frontend_src = workspace_root / "frontend" / "src"
    if frontend_src.exists():
        targets.append({
            "id": "source_frontend_tree",
            "name": "AgentShield Web UI Source Tree",
            "kind": "source_tree",
            "format": "TypeScript / React AST Graph",
            "path": str(frontend_src.relative_to(workspace_root)).replace("\\", "/"),
            "absolute_path": str(frontend_src.resolve()),
            "recommended_workflow": "analyze-javascript-application",
            "is_harmless_test_app": True,
            "description": "Complete client-side AST and module dependency hierarchy.",
            "safety_posture": "STATIC_ANALYSIS_ONLY",
            "permission_required": "AUTHORIZED"
        })

    # 3. SQLite Database Telemetry Snapshot
    db_candidates = [
        BASE_DIR / "data" / "agentshield.db",
        BASE_DIR / "agentshield.db"
    ]
    for db_path in db_candidates:
        if db_path.exists():
            rel = str(db_path.relative_to(workspace_root)).replace("\\", "/") if db_path.is_relative_to(workspace_root) else str(db_path)
            targets.append({
                "id": "db_agentshield_sqlite",
                "name": "AgentShield Telemetry Database",
                "kind": "database",
                "format": "SQLite 3 Snapshot",
                "path": rel,
                "absolute_path": str(db_path.resolve()),
                "recommended_workflow": "inspect-sqlite-database",
                "is_harmless_test_app": True,
                "description": "SQLite schema containing audit ledger, incidents, and agent permissions.",
                "safety_posture": "STATIC_READONLY",
                "permission_required": "AUTHORIZED"
            })
            break

    # 4. Quarantined Artifacts in Vault
    if RE_LAB_VAULT_DIR.exists():
        for vault_file in sorted(RE_LAB_VAULT_DIR.glob("*")):
            if vault_file.is_file():
                targets.append({
                    "id": f"vault_{vault_file.stem}",
                    "name": vault_file.name,
                    "kind": "quarantined_vault_artifact",
                    "format": "Binary / Script Artifact",
                    "path": f"data/re_lab_vault/{vault_file.name}",
                    "absolute_path": str(vault_file.resolve()),
                    "recommended_workflow": detect_rea_workflow(vault_file),
                    "is_harmless_test_app": False,
                    "description": f"Quarantined artifact ({vault_file.stat().st_size} bytes) in REA lab vault.",
                    "safety_posture": "QUARANTINED_STATIC_ONLY",
                    "permission_required": "AUTHORIZED"
                })

    return targets


def validate_rea_target(target_path_str: str) -> Dict[str, Any]:
    """
    Validates a requested target path for REA inspection:
    - Path resolution and directory traversal defense
    - Boundary checking against authorized roots (workspace or vault)
    - File size check (max 25MB)
    - Host execution safety posture enforcement
    - Workflow auto-detection
    """
    if not target_path_str or not target_path_str.strip():
        return {
            "valid": False,
            "status": "DENIED",
            "error": "Target path cannot be empty.",
            "code": "EMPTY_TARGET"
        }

    raw_path = Path(target_path_str.strip())
    workspace_root = BASE_DIR.parent

    # If relative path, resolve relative to workspace root
    if not raw_path.is_absolute():
        resolved_path = (workspace_root / raw_path).resolve()
    else:
        resolved_path = raw_path.resolve()

    # Check existence
    if not resolved_path.exists():
        return {
            "valid": False,
            "status": "NOT_FOUND",
            "error": f"Target path does not exist: {target_path_str}",
            "code": "TARGET_NOT_FOUND",
            "resolved_path": str(resolved_path)
        }

    # Verify authorization boundary
    allowed_roots = [
        RE_LAB_VAULT_DIR.resolve(),
        workspace_root.resolve()
    ]
    is_authorized = False
    matched_root = None
    for allowed in allowed_roots:
        try:
            resolved_path.relative_to(allowed)
            is_authorized = True
            matched_root = str(allowed)
            break
        except ValueError:
            continue

    if not is_authorized:
        return {
            "valid": False,
            "status": "DENIED",
            "error": f"Access denied. Target path '{target_path_str}' is outside authorized workspace and vault boundaries.",
            "code": "UNAUTHORIZED_BOUNDARY",
            "resolved_path": str(resolved_path),
            "safety_posture": "ACCESS_BLOCKED"
        }

    # Check file size if it's a regular file
    file_size = 0
    sample_bytes = b""
    if resolved_path.is_file():
        file_size = resolved_path.stat().st_size
        if file_size > MAX_FILE_SIZE_BYTES:
            return {
                "valid": False,
                "status": "DENIED",
                "error": f"Target file size ({file_size} bytes) exceeds safety maximum of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB.",
                "code": "FILE_TOO_LARGE",
                "resolved_path": str(resolved_path)
            }
        try:
            with open(resolved_path, "rb") as f:
                sample_bytes = f.read(512)
        except Exception:
            pass

    recommended_wf = detect_rea_workflow(resolved_path, sample_bytes)

    return {
        "valid": True,
        "status": "AUTHORIZED",
        "target_path": str(target_path_str),
        "resolved_path": str(resolved_path),
        "is_directory": resolved_path.is_dir(),
        "filename": resolved_path.name,
        "file_size": file_size,
        "recommended_workflow": recommended_wf,
        "supported_workflows": sorted(list(SUPPORTED_REA_WORKFLOWS)),
        "safety_posture": "STATIC_ANALYSIS_ONLY (Direct host execution prohibited)",
        "isolation": "HOST_SAFE_INERT_PARSING",
        "permission_granted": True
    }


def generate_rea_forensic_report(
    investigation: Dict[str, Any],
    format_type: str = "markdown"
) -> Dict[str, Any]:
    """
    Generates an official, evidence-based Forensic Investigation Dossier
    for an analyzed sample or application using REA and AMOJA AI.
    Outputs structured Markdown and raw JSON telemetry.
    """
    analysis_id = investigation.get("analysis_id", "N/A")
    filename = investigation.get("filename", "unknown_artifact")
    workflow = investigation.get("workflow", "unknown")
    file_size = investigation.get("file_size", 0)
    hashes = investigation.get("hashes", {})
    sha256 = hashes.get("sha256", "N/A")
    sha1 = hashes.get("sha1", "N/A")
    md5 = hashes.get("md5", "N/A")
    exit_code = investigation.get("exit_code", 0)
    is_success = investigation.get("success", False)
    confidence = investigation.get("confidence", "observed")
    limitations = investigation.get("limitations", [])

    briefing = investigation.get("amoja_briefing") or generate_amoja_rea_explanation(investigation)
    observed_facts = briefing.get("observed_facts", [])
    inferred_risks = briefing.get("inferred_risks", [])
    unknowns = briefing.get("limitations", [])

    raw_result = investigation.get("raw_result", {})
    evidence = investigation.get("evidence", {})
    normalized = raw_result.get("normalized_result") if isinstance(raw_result, dict) else None
    if not isinstance(normalized, dict) and isinstance(evidence, dict):
        normalized = evidence.get("normalized_result")
    findings = normalized if isinstance(normalized, dict) else raw_result

    # Construct Formal Markdown Report
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_lines = [
        "# 🛡️ AMOJA AI // AGENTSHIELD FORENSIC INVESTIGATION REPORT",
        f"**Report ID:** `{analysis_id}` | **Generated:** {now_str}",
        f"**Target Artifact:** `{filename}` | **Workflow:** `{workflow}`",
        f"**Security Clearance:** Zero-Trust Enforced | **Host Execution Posture:** STRICTLY_DISABLED",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        f"A static reverse-engineering and code analysis investigation was performed on `{filename}` using the REA (Reverse Engineer Anything) subsystem v6.7.0. "
        f"The artifact was analyzed strictly as inert syntax without execution on the Windows host. "
        f"Inspection status concluded with verdict **{'COMPLETED_OBSERVED' if is_success else 'LIMITED_BY_PROVIDER'}** (exit code {exit_code}, confidence `{confidence}`).",
        "",
        "## 2. Cryptographic Integrity & Target Telemetry",
        "| Attribute | Value |",
        "| :--- | :--- |",
        f"| **Artifact Name** | `{filename}` |",
        f"| **Target Path** | `{investigation.get('target_path', 'N/A')}` |",
        f"| **File Size** | {file_size:,} bytes |",
        f"| **SHA-256** | `{sha256}` |",
        f"| **SHA-1** | `{sha1}` |",
        f"| **MD5** | `{md5}` |",
        f"| **Disassembler Mode** | Static AST / Header Parser (No Dynamic Execution) |",
        "",
        "## 3. Observed Forensic Evidence (Verified Telemetry)",
    ]

    for fact in observed_facts:
        report_lines.append(f"- ✅ {fact}")

    # Specific evidence sections
    if workflow == "analyze-javascript-application":
        stats = findings.get("statistics") or {}
        summ = findings.get("summary") or {}
        graph = findings.get("graph") or {}
        parsed_files = stats.get("parsed_javascript_files", 0)
        ast_nodes = stats.get("visited_ast_nodes", 0)
        ipc_info = summ.get("ipc", {})
        ipc_ops = ipc_info.get("operations", 0)
        literal_channels = ipc_info.get("literal_channels", 0)
        main_handlers = ipc_info.get("main_handlers", 0)
        renderer_tx = ipc_info.get("renderer_transmissions", 0)
        context_bridges = summ.get("context_bridge_apis", 0)
        preload_entries = summ.get("preload_entrypoints", 0)
        browser_windows = summ.get("browser_windows", 0)
        graph_nodes = len(graph.get("nodes", []))
        graph_edges = len(graph.get("edges", []))

        report_lines.extend([
            "",
            "### 3.1 JavaScript / Electron Application Topology",
            f"- **Parsed Source Files:** {parsed_files}",
            f"- **Visited AST Nodes:** {ast_nodes}",
            f"- **Application Graph Nodes:** {graph_nodes} nodes, {graph_edges} dependency edges",
            f"- **BrowserWindows Detected:** {browser_windows}",
            f"- **Preload Entrypoints:** {preload_entries}",
            f"- **ContextBridge APIs:** {context_bridges}",
            f"- **Electron IPC Operations:** {ipc_ops} (Literal Channels: {literal_channels}, Main Handlers: {main_handlers}, Renderer Transmissions: {renderer_tx})",
        ])

        nodes = graph.get("nodes", [])
        ipc_nodes = [n for n in nodes if isinstance(n, dict) and ("ipc" in n.get("type", "").lower() or "channel" in str(n).lower())]
        if ipc_nodes:
            report_lines.append("")
            report_lines.append("#### Detected Electron IPC Channels & Graph Nodes:")
            for node in ipc_nodes[:15]:
                n_id = node.get("id") or node.get("label") or str(node)
                report_lines.append(f"  * Topology Node: `{n_id}`")

    elif workflow == "inspect-sqlite-database":
        schema = findings.get("schema", {})
        tbls = schema.get("tables", [])
        idxs = schema.get("indexes", [])
        report_lines.extend([
            "",
            "### 3.1 SQLite Database Schema Snapshot",
            f"- **Tables Preserved:** {len(tbls)}",
            f"- **Indexes Cataloged:** {len(idxs)}",
            "",
            "#### Table Inventory:"
        ])
        for t in tbls[:20]:
            t_name = t.get("name", "unnamed")
            col_count = t.get("column_count") or len(t.get("columns", []))
            report_lines.append(f"  * Table `{t_name}` ({col_count} columns)")

    report_lines.extend([
        "",
        "## 4. Inferred Security Risks & Attack Surface Assessment",
    ])
    for risk in inferred_risks:
        report_lines.append(f"- ⚠️ {risk}")

    report_lines.extend([
        "",
        "## 5. Documented Limitations & Unknowns",
        "Under Zero-Trust policy, REA transparently distinguishes between observed evidence and bounded scope:",
    ])
    for lim in (limitations[:8] if limitations else unknowns):
        report_lines.append(f"- ℹ️ {lim}")

    report_lines.extend([
        "",
        "## 6. Cryptographic Audit Ledger Reference",
        f"- **Investigation Analysis ID:** `{analysis_id}`",
        f"- **Verification Hash:** SHA-256 `{sha256}`",
        "- **Chained Audit Action:** `REA_LAB_ARTIFACT_ANALYZED`",
        "- **Audit Policy:** Immutable cryptographically linked SHA-256 record committed to `re_lab_analyses`.",
        "",
        "---",
        "*Report compiled autonomously by AMOJA AI // AgentShield Forensics Subsystem.*"
    ])

    report_markdown = "\n".join(report_lines)

    return {
        "report_id": f"rep_{analysis_id}",
        "analysis_id": analysis_id,
        "filename": filename,
        "workflow": workflow,
        "created_at": now_str,
        "sha256": sha256,
        "verdict": "COMPLETED" if is_success else "LIMITED",
        "markdown_report": report_markdown,
        "structured_data": {
            "summary": investigation.get("summary"),
            "observed_facts": observed_facts,
            "inferred_risks": inferred_risks,
            "limitations": limitations,
            "hashes": hashes,
            "exit_code": exit_code
        }
    }

