from typing import Dict, Any, List, Optional

def generate_security_explanation(
    action: str,
    target: str,
    decision: str,
    risk_score: int,
    reasons: List[str],
    inspection_signals: Dict[str, Any],
    dlp_findings: Dict[str, Any],
    agent_info: Dict[str, Any]
) -> Dict[str, Any]:
    """Generates an explainable SOC analysis of an event detailing evidence, risk factors, and recommended remediation."""
    evidence_points = []
    
    # 1. Action & Destination Analysis
    if action in {"EXPORT", "DELETE", "SEND", "TRANSFER"}:
        evidence_points.append(f"Action '{action}' is categorized as high-impact and potentially state-altering or egressing data.")
        
    if "external" in target.lower():
        evidence_points.append(f"Destination '{target}' is flagged as an external or untrusted endpoint, presenting data exfiltration risk.")
        
    # 2. Prompt Injection Evidence
    if inspection_signals.get("is_injection"):
        signals = inspection_signals.get("signals", [])
        sig_names = [s.get("rule", "Unknown") for s in signals]
        evidence_points.append(f"Prompt injection detector detected suspicious instructions: {', '.join(sig_names)} (confidence: {inspection_signals.get('confidence', 0.9):.2f}).")
        
    # 3. DLP Evidence
    if dlp_findings.get("has_sensitive_data"):
        violations = dlp_findings.get("violations", [])
        v_names = [v.get("description", "Sensitive Pattern") for v in violations]
        evidence_points.append(f"DLP engine matched sensitive data patterns: {', '.join(v_names)}.")
        
    # 4. Agent Trust Posture
    trust = agent_info.get("trust_score", 90)
    if trust < 70:
        evidence_points.append(f"Agent's continuous trust score is degraded ({trust}/100), reducing tolerance for anomalous actions.")
        
    if not evidence_points:
        evidence_points.append("Action and target are consistent with routine operational permissions.")

    # 5. Remediation Recommendations
    recommendations = []
    if decision == "BLOCK":
        recommendations.append("Maintain block decision. Do not bypass policy gateway.")
        recommendations.append("Investigate upstream prompt sources for prompt-injection attacks.")
        if inspection_signals.get("is_injection"):
            recommendations.append("Consider placing agent into temporary quarantine to prevent secondary lateral movement.")
    elif decision == "ASK_HUMAN":
        recommendations.append("Require a human SecOps operator to inspect the payload before manual approval.")
        recommendations.append("Confirm business requirement for transmitting data to target resource.")
    else:
        recommendations.append("No defensive intervention necessary at this time.")

    confidence_level = "HIGH" if len(evidence_points) > 1 else "MEDIUM"
    
    summary = (
        f"AgentShield Policy Gateway decided to {decision} action '{action}' on target '{target}' "
        f"with calculated risk score of {risk_score}/100. "
        f"Decision driven by: {'; '.join(reasons)}."
    )
    
    return {
        "analyst_verdict": decision,
        "risk_score": risk_score,
        "confidence_level": confidence_level,
        "summary": summary,
        "evidence_chain": evidence_points,
        "contributing_factors": reasons,
        "recommended_defensive_actions": recommendations,
        "uncertainty_label": "Deterministic Policy Engine with Heuristic ML Signals (No Hallucinated LLM Assumptions)"
    }
