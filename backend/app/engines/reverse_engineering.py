import hashlib
import json
import difflib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

def reconstruct_behavior_timeline(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Feature AJ: Reconstructs chronological execution timeline distinguishing observed facts from inferred explanations."""
    timeline = []
    likely_entry_point = None
    
    for i, ev in enumerate(events):
        is_blocked = ev.get("decision") == "BLOCK"
        is_high_risk = ev.get("risk_score", 0) >= 70
        
        entry = {
            "step": i + 1,
            "timestamp": ev.get("created_at"),
            "action": ev.get("action"),
            "target": ev.get("target"),
            "decision": ev.get("decision"),
            "risk_score": ev.get("risk_score"),
            "captured_fact": f"Agent invoked {ev.get('action')} on resource '{ev.get('target')}'; Policy Gateway decided {ev.get('decision')}.",
            "inferred_intent": "Exploration or reconnaissance phase" if i == 0 else "Sensitive data staging" if ev.get("action") == "READ" and is_high_risk else "Exfiltration or impact phase" if ev.get("action") in {"EXPORT", "DELETE"} else "Standard processing workflow",
            "is_suspicious_transition": is_blocked or is_high_risk
        }
        if is_blocked and likely_entry_point is None:
            likely_entry_point = f"Step {i+1}: First security policy block at {ev.get('created_at')} ({ev.get('action')} on {ev.get('target')})"
            
        timeline.append(entry)
        
    return {
        "total_steps": len(timeline),
        "likely_entry_point": likely_entry_point or "No security breach or block observed in timeline",
        "timeline": timeline
    }

def analyze_system_prompt_drift(baseline_prompt: str, current_prompt: str) -> Dict[str, Any]:
    """Feature AK: Detects unauthorized changes, additions, and drift in system prompts."""
    if not baseline_prompt:
        baseline_prompt = ""
    if not current_prompt:
        current_prompt = ""
        
    matcher = difflib.SequenceMatcher(None, baseline_prompt, current_prompt)
    similarity = matcher.ratio()
    drift_percent = round((1.0 - similarity) * 100, 1)
    
    diff_lines = list(difflib.unified_diff(
        baseline_prompt.splitlines(),
        current_prompt.splitlines(),
        fromfile="baseline_instructions",
        tofile="current_instructions",
        lineterm=""
    ))
    
    suspicious_additions = []
    for line in diff_lines:
        if line.startswith("+") and not line.startswith("+++"):
            added_content = line[1:].lower()
            if any(term in added_content for term in ["ignore", "bypass", "exfiltrate", "dump", "unrestricted", "dan"]):
                suspicious_additions.append(line[1:].strip())
                
    has_tampering = len(suspicious_additions) > 0 or drift_percent >= 30.0
    
    return {
        "drift_percentage": drift_percent,
        "similarity_ratio": round(similarity, 3),
        "has_tampering": has_tampering,
        "suspicious_injected_clauses": suspicious_additions,
        "unified_diff": diff_lines,
        "status": "TAMPERED" if has_tampering else "DRIFTED" if drift_percent > 10 else "INTACT"
    }

def reverse_engineer_tool_calls(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Feature AL: Reverse engineers API/tool invocation sequences to detect endpoint probing and schema enumeration."""
    indicators = []
    
    endpoints_probed = [e.get("target") for e in events]
    actions_probed = [e.get("action") for e in events]
    
    # Check for endpoint schema probing
    schema_keywords = ["schema", "tables", "catalog", "describe", "pragma", "information_schema"]
    probes = [ep for ep in endpoints_probed if any(kw in str(ep).lower() for kw in schema_keywords)]
    if probes:
        indicators.append({
            "tactic": "API Schema Discovery (MITRE T1082 / T1087)",
            "evidence": probes,
            "severity": "HIGH",
            "description": "Agent attempted to query catalog or table structure metadata."
        })
        
    # Check for rapid permission testing (probing multiple restricted endpoints sequentially)
    blocked_count = sum(1 for e in events if e.get("decision") == "BLOCK")
    if blocked_count >= 2:
        indicators.append({
            "tactic": "Permission Boundary Testing (Brute Force Probing)",
            "evidence": f"{blocked_count} actions blocked across sequence",
            "severity": "HIGH",
            "description": "Agent executed repeated unauthorized calls probing access barriers."
        })
        
    return {
        "analysis": "Tool Invocation Telemetry Reverse Engineering",
        "probing_indicators": indicators,
        "is_probing_detected": len(indicators) > 0
    }

def reverse_engineer_payload(payload: str) -> Dict[str, Any]:
    """Feature AM: Safe static reverse engineering of malicious prompts and untrusted payloads."""
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    lower = payload.lower()
    
    suspected_objectives = []
    attack_techniques = []
    countermeasures = []
    
    if "ignore" in lower or "disregard" in lower:
        suspected_objectives.append("Guardrail Circumvention / Instruction Override")
        attack_techniques.append("Direct Prompt Injection (CWE-1426)")
        countermeasures.append("Enforce strict input delimiter boundaries and token normalization filters.")
        
    if any(k in lower for k in ["credit", "card", "ssn", "secret", "password", "api_key", "dump"]):
        suspected_objectives.append("Confidential Data Exfiltration / Secret Harvesting")
        attack_techniques.append("Data Scraping & Extraction")
        countermeasures.append("Enable pre-egress DLP scrubbing and block unapproved destination IP/domains.")
        
    if "drop" in lower or "truncate" in lower or "delete" in lower:
        suspected_objectives.append("Data Destruction / Denial of Service")
        attack_techniques.append("SQL / Resource Deletion Injection")
        countermeasures.append("Enforce read-only tool scoping and mandatory human-in-the-loop approval.")
        
    if not suspected_objectives:
        suspected_objectives.append("Standard Operational Data Payload")
        countermeasures.append("Standard Zero-Trust monitoring.")

    return {
        "sha256_hash": payload_hash,
        "length_bytes": len(payload.encode("utf-8")),
        "suspected_objectives": suspected_objectives,
        "attack_techniques": attack_techniques,
        "recommended_defensive_countermeasures": countermeasures,
        "static_safety_verdict": "MALICIOUS" if len(attack_techniques) > 0 else "BENIGN"
    }

def detect_defensive_reverse_engineering(action: str, target: str, payload: str) -> Dict[str, Any]:
    """Feature AO: Detects unauthorized attempts by agents to inspect prompt templates, dump control plane schemas, or reverse engineer security guardrails."""
    combined = f"{action} {target} {payload}".lower()
    
    signatures = [
        ("agentshield", "Control Plane Internal Targeting"),
        ("security.py", "Source Code Inspection Attempt"),
        ("sqlite_master", "Database Metadata Enumeration"),
        ("system_prompt", "Internal Instruction Harvesting"),
        ("reveal_guardrails", "Defense Evasion Probing"),
        ("/docs", "API Schema Enumeration")
    ]
    
    matches = [name for term, name in signatures if term in combined]
    is_detected = len(matches) > 0
    
    return {
        "detected": is_detected,
        "severity": "CRITICAL" if is_detected else "LOW",
        "signatures_triggered": matches,
        "action": "BLOCK" if is_detected else "ALLOW",
        "description": "Agent attempted to probe or reverse-engineer AgentShield's internal security mechanics or prompt architecture" if is_detected else "No reverse-engineering probing detected"
    }

def generate_forensic_report_data(
    incident: Dict[str, Any],
    agent: Dict[str, Any],
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Feature AN: Generates comprehensive forensic dossier for compromised agent incident."""
    now = datetime.now(timezone.utc).isoformat()
    timeline = reconstruct_behavior_timeline(events)
    re_tools = reverse_engineer_tool_calls(events)
    
    report_dict = {
        "report_id": f"FORENSIC-{incident.get('incident_number', '001')}",
        "generated_at": now,
        "incident_summary": {
            "number": incident.get("incident_number"),
            "title": incident.get("title"),
            "severity": incident.get("severity"),
            "status": incident.get("status"),
            "root_cause": incident.get("root_cause")
        },
        "compromised_agent": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "owner": agent.get("owner"),
            "model": agent.get("model"),
            "status": agent.get("status"),
            "risk_score": agent.get("risk_score"),
            "trust_score": agent.get("trust_score")
        },
        "reconstructed_timeline": timeline,
        "tool_call_reverse_engineering": re_tools,
        "conclusions": [
            f"Likely breach origin: {timeline.get('likely_entry_point')}",
            f"Containment status: Agent status is currently {agent.get('status')}",
            "Action recommendation: Keep agent quarantined, rotate any accessed credentials, and review prompt injection rules."
        ]
    }
    
    report_str = json.dumps(report_dict, sort_keys=True)
    report_dict["integrity_sha256"] = hashlib.sha256(report_str.encode("utf-8")).hexdigest()
    return report_dict
