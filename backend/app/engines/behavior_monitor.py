import json
from typing import Dict, Any, List

def evaluate_behavioral_drift(
    agent_id: str,
    recent_events: List[Dict[str, Any]],
    baseline: Dict[str, Any]
) -> Dict[str, Any]:
    """Evaluates agent execution telemetry against baseline for frequency spikes, destination drift, and volume anomalies."""
    if not recent_events:
        return {
            "drift_score": 0.05,
            "has_anomaly": False,
            "anomaly_signals": [],
            "baseline_version": "v1.0"
        }
        
    allowed_rate = baseline.get("allowed_call_rate", 30)
    typical_tools = json.loads(baseline.get("typical_tools_json", "[]")) if isinstance(baseline.get("typical_tools_json"), str) else baseline.get("typical_tools_json", [])
    approved_dests = json.loads(baseline.get("approved_destinations_json", "[]")) if isinstance(baseline.get("approved_destinations_json"), str) else baseline.get("approved_destinations_json", [])
    avg_payload = baseline.get("avg_payload_size", 512)
    
    anomalies = []
    drift_score = 0.05
    
    # Check 1: Tool invocation frequency in recent window
    event_count = len(recent_events)
    if event_count > allowed_rate:
        drift_score += 0.35
        anomalies.append({
            "type": "Rate Anomaly",
            "detail": f"Event frequency ({event_count} calls) exceeds baseline threshold ({allowed_rate}/window)",
            "severity": "HIGH"
        })
        
    # Check 2: Uncharacteristic Tool Invocation Sequence
    recent_actions = [e.get("action", "") for e in recent_events[-5:]]
    for act in recent_actions:
        if typical_tools and act not in typical_tools and act in {"EXPORT", "DELETE", "EXECUTE"}:
            drift_score += 0.25
            anomalies.append({
                "type": "Sequence Drift",
                "detail": f"Action '{act}' is unusual compared to historical typical tool sequence",
                "severity": "MEDIUM"
            })
            break
            
    # Check 3: Destination Divergence
    recent_dests = [e.get("target", "") for e in recent_events[-5:]]
    for dest in recent_dests:
        if approved_dests and not any(app in dest.lower() for app in approved_dests):
            if "external" in dest.lower() or "http" in dest.lower():
                drift_score += 0.30
                anomalies.append({
                    "type": "Destination Drift",
                    "detail": f"Target '{dest}' deviates from approved baseline destinations",
                    "severity": "HIGH"
                })
                break
                
    drift_score = min(1.0, round(drift_score, 2))
    has_anomaly = len(anomalies) > 0 or drift_score >= 0.50
    
    return {
        "drift_score": drift_score,
        "has_anomaly": has_anomaly,
        "anomaly_signals": anomalies,
        "baseline_version": "v1.0",
        "sample_size": event_count
    }
