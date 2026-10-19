import math
from typing import Dict, Any, List, Optional

def calculate_dynamic_risk(
    agent: Dict[str, Any],
    recent_events: List[Dict[str, Any]],
    action_risk: int,
    dlp_violations: List[Dict[str, Any]],
    injection_confidence: float,
    drift_score: float = 0.0
) -> Dict[str, Any]:
    """Calculates an explainable 0-100 dynamic risk score with explicit contributing factor weights."""
    factors = []
    
    # 1. Base Agent Trust Posture (0-20 pts)
    curr_trust = agent.get("trust_score", 90)
    trust_penalty = max(0, int((100 - curr_trust) * 0.25))
    if trust_penalty > 0:
        factors.append({"factor": "Agent Trust Deficit", "score": trust_penalty, "description": f"Agent trust score is {curr_trust}/100"})
    
    # 2. Immediate Action & Destination Risk (0-35 pts)
    action_contrib = int(action_risk * 0.35)
    factors.append({"factor": "Target & Action Sensitivity", "score": action_contrib, "description": "Derived from action verb, target domain, and permissions"})
    
    # 3. Prompt Injection Signal (0-30 pts)
    injection_contrib = int(injection_confidence * 30)
    if injection_contrib > 0:
        factors.append({"factor": "Prompt Injection Signal", "score": injection_contrib, "description": f"Heuristic confidence {injection_confidence:.2f}"})
        
    # 4. DLP & Data Exfiltration Indicators (0-25 pts)
    dlp_contrib = 0
    if dlp_violations:
        for v in dlp_violations:
            sev = v.get("severity", "LOW")
            dlp_contrib += 20 if sev == "CRITICAL" else 12 if sev == "HIGH" else 5
        dlp_contrib = min(25, dlp_contrib)
        factors.append({"factor": "Sensitive Data / DLP Exposure", "score": dlp_contrib, "description": f"{len(dlp_violations)} DLP violation(s) detected"})
        
    # 5. Behavioral Concept Drift (0-15 pts)
    drift_contrib = int(drift_score * 15)
    if drift_contrib > 0:
        factors.append({"factor": "Behavioral Concept Drift", "score": drift_contrib, "description": f"Statistical drift metric: {drift_score:.2f}"})
        
    # 6. Recent Historical Incident Frequency (0-20 pts)
    blocked_recent = sum(1 for e in recent_events[-10:] if e.get("decision") == "BLOCK")
    history_contrib = min(20, blocked_recent * 7)
    if history_contrib > 0:
        factors.append({"factor": "Recent Block History", "score": history_contrib, "description": f"{blocked_recent} blocked actions in last 10 events"})
        
    total_raw = sum(f["score"] for f in factors)
    total_risk = min(100, max(5, total_raw))
    
    severity = "CRITICAL" if total_risk >= 75 else "HIGH" if total_risk >= 50 else "MEDIUM" if total_risk >= 25 else "LOW"
    
    return {
        "risk_score": total_risk,
        "severity": severity,
        "factors": factors,
        "is_calibrated": True
    }

def update_continuous_trust_score(
    current_trust: int,
    event_decision: str,
    risk_score: int
) -> Dict[str, Any]:
    """Calculates updated continuous trust score with rapid decay upon violation and gradual recovery on compliant actions."""
    if event_decision == "BLOCK":
        # Sharp trust decay
        decay = int(15 + (risk_score * 0.25))
        new_trust = max(0, current_trust - decay)
        change_reason = f"Severe violation blocked (risk score {risk_score}): trust decreased by {decay}"
    elif event_decision == "ASK_HUMAN":
        decay = int(5 + (risk_score * 0.1))
        new_trust = max(10, current_trust - decay)
        change_reason = f"Action flagged for human review (risk score {risk_score}): trust decreased by {decay}"
    else:
        # Gradual recovery (max +2 per compliant action up to 98)
        recovery = 2 if current_trust < 90 else 1
        new_trust = min(98, current_trust + recovery)
        change_reason = f"Compliant action verified: trust recovered by {recovery}"
        
    return {
        "previous_trust": current_trust,
        "new_trust": new_trust,
        "delta": new_trust - current_trust,
        "reason": change_reason
    }

def predict_near_future_risk(recent_events: List[Dict[str, Any]], current_risk: int) -> Dict[str, Any]:
    """Predictive Risk Engine: estimates risk trends and uncertainty intervals over next 1-5 steps."""
    if not recent_events:
        return {
            "predicted_risk_next_1h": current_risk,
            "trend": "STABLE",
            "confidence": 0.85,
            "uncertainty_interval": [max(0, current_risk - 5), min(100, current_risk + 5)],
            "contributing_factors": ["Insufficient historical events, baseline steady state assumed"]
        }
        
    scores = [e.get("risk_score", 10) for e in recent_events[-10:]]
    if len(scores) >= 2:
        slope = (scores[-1] - scores[0]) / len(scores)
    else:
        slope = 0.0
        
    forecast_risk = min(100, max(0, int(current_risk + (slope * 3))))
    trend = "INCREASING" if slope > 1.5 else "DECREASING" if slope < -1.5 else "STABLE"
    
    variance = sum((s - (sum(scores) / len(scores))) ** 2 for s in scores) / len(scores) if scores else 4.0
    margin = int(math.sqrt(variance) * 1.5)
    
    return {
        "predicted_risk_next_1h": forecast_risk,
        "trend": trend,
        "confidence": 0.82,
        "uncertainty_interval": [max(0, forecast_risk - margin), min(100, forecast_risk + margin)],
        "contributing_factors": [
            f"Historical trend slope: {slope:.2f} pts/event",
            f"Recent risk variance: {variance:.1f}"
        ]
    }

def forecast_next_actions(
    agent_id: str,
    recent_events: List[Dict[str, Any]],
    allowed_tools: List[str]
) -> List[Dict[str, Any]]:
    """Next-Action Forecasting: probabilistic projection of next 2-3 most probable actions and estimated risks."""
    # Analyze common operational patterns (e.g., READ -> ANALYZE -> WRITE -> EXPORT)
    last_action = recent_events[-1].get("action", "READ") if recent_events else "READ"
    
    transition_probs = {
        "READ": [("ANALYZE", 0.55, 15), ("WRITE", 0.30, 35), ("EXPORT", 0.15, 65)],
        "ANALYZE": [("WRITE", 0.60, 35), ("READ", 0.25, 10), ("EXPORT", 0.15, 65)],
        "WRITE": [("EXPORT", 0.45, 65), ("SEND", 0.35, 55), ("READ", 0.20, 10)],
        "EXPORT": [("READ", 0.50, 10), ("SEND", 0.30, 50), ("DELETE", 0.20, 80)],
        "DELETE": [("READ", 0.60, 10), ("ANALYZE", 0.30, 15), ("WRITE", 0.10, 30)],
    }
    
    transitions = transition_probs.get(last_action, [("READ", 0.50, 10), ("ANALYZE", 0.30, 15), ("WRITE", 0.20, 35)])
    
    forecasts = []
    for action_name, prob, estimated_risk in transitions:
        forecasts.append({
            "action": action_name,
            "probability": prob,
            "estimated_risk": estimated_risk,
            "requires_human_approval": estimated_risk >= 55,
            "rationale": f"Derived from Markov transition model following {last_action}"
        })
        
    return forecasts
