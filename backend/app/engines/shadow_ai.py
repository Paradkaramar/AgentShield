import re
from typing import Dict, Any, List

KNOWN_LLM_ENDPOINTS = [
    ("api.openai.com", "OpenAI API Endpoint"),
    ("api.anthropic.com", "Anthropic Claude API Endpoint"),
    ("generativelanguage.googleapis.com", "Google Gemini API Endpoint"),
    ("api.together.xyz", "Together AI Inference"),
    ("api.cohere.ai", "Cohere Platform"),
    ("localhost:11434", "Local Ollama Unmonitored Daemon"),
    ("huggingface.co/api", "HuggingFace Model Hub")
]

def analyze_telemetry_for_shadow_ai(
    network_flows: List[Dict[str, Any]],
    process_list: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Inspects network telemetry and process traces for uninstrumented AI agents and unauthorized LLM beacons."""
    detections = []
    
    # 1. Inspect network flows for known LLM endpoints without AgentShield header
    for flow in network_flows:
        dest = flow.get("destination", "")
        headers = flow.get("headers", {})
        has_shield_token = "X-AgentShield-Proxy" in headers or "X-Agent-ID" in headers
        
        for endpoint, label in KNOWN_LLM_ENDPOINTS:
            if endpoint in dest.lower() and not has_shield_token:
                detections.append({
                    "process_name": flow.get("process", "unknown_process.exe"),
                    "destination_ip_host": dest,
                    "token_signature": flow.get("auth_header_prefix", "Bearer sk-..."),
                    "confidence": 0.94,
                    "evidence": f"Uninstrumented network traffic direct to {label} without control plane headers.",
                    "status": "DETECTED",
                    "remediation": "Deploy AgentShield SDK wrapper or block process outbound egress via firewall."
                })
                break
                
    # 2. Inspect process lists for agentic frameworks running unmonitored
    suspicious_frameworks = [
        ("langchain", "LangChain Python Process"),
        ("autogen", "Microsoft AutoGen Multi-Agent Runner"),
        ("crewai", "CrewAI Autonomous Framework"),
        ("langgraph", "LangGraph Workflow Daemon")
    ]
    for proc in process_list:
        cmdline = proc.get("command_line", "").lower()
        for term, label in suspicious_frameworks:
            if term in cmdline and not proc.get("is_registered"):
                detections.append({
                    "process_name": proc.get("name", "python.exe"),
                    "destination_ip_host": "unspecified-external",
                    "token_signature": f"framework:{term}",
                    "confidence": 0.88,
                    "evidence": f"Unregistered autonomous framework detected: {label} (PID {proc.get('pid', 'N/A')})",
                    "status": "DETECTED",
                    "remediation": "Register agent identity in AgentShield control plane."
                })
                break

    return detections
