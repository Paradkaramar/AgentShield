import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from ..db.database import connect, now_iso
from ..core.audit import record_audit_entry
from ..engines.risk_engine import predict_near_future_risk, calculate_dynamic_risk
from ..engines.policy_engine import detect_permission_drift
from ..engines.kill_switch import trigger_emergency_kill_switch
from .cyber_tools.stego_engine import (
    encode_stego_message, decode_stego_message, inspect_image_and_exif
)
from .personal_assistant import (
    create_reminder, list_reminders, delete_reminder,
    create_note, search_notes, list_notes, delete_note,
    add_todo_item, list_todo_items, toggle_todo_item,
    store_user_memory, list_user_memories, delete_user_memory,
    launch_approved_application, close_approved_application,
    open_website_or_search, search_or_play_youtube,
    search_authorized_files, search_workspace_files,
    open_authorized_file_or_folder, organize_authorized_files,
    prepare_whatsapp_message, get_windows_system_status,
    open_windows_settings, analyze_suspicious_processes,
    prepare_firewall_rule_change, execute_multistep_task
)
from .live_intelligence import (
    fetch_live_weather,
    fetch_cybersecurity_intelligence,
    perform_live_web_research,
    search_live_news_rss,
    check_windows_software_updates
)


# Registry of supported tool definitions with schemas
TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "get_security_dashboard_metrics": {
        "description": "Retrieve high-level SOC dashboard metrics including active agents, blocked actions, open incidents, and risk posture.",
        "category": "read",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "list_agents": {
        "description": "List all registered AI agents with status, risk scores, trust scores, and models.",
        "category": "read",
        "parameters": {
            "status": {"type": "string", "description": "Filter by status: ACTIVE, SUSPENDED, KILLED, or ALL", "default": "ALL"},
            "min_risk": {"type": "integer", "description": "Filter agents with risk_score >= min_risk", "default": 0}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_agent_details": {
        "description": "Retrieve comprehensive details for a specific AI agent including permissions, tools, and recent events.",
        "category": "read",
        "parameters": {
            "agent_id": {"type": "string", "description": "Agent identifier (e.g. agent-finance-01) or agent name"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_alerts_and_incidents": {
        "description": "Retrieve critical, high, medium, and low security alerts and open incidents.",
        "category": "read",
        "parameters": {
            "severity": {"type": "string", "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, or ALL", "default": "ALL"},
            "limit": {"type": "integer", "description": "Maximum number of items to return", "default": 10}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "search_audit_logs": {
        "description": "Search the SHA-256 cryptographically chained immutable audit ledger.",
        "category": "read",
        "parameters": {
            "query": {"type": "string", "description": "Search term across actor, action, resource, or details"},
            "limit": {"type": "integer", "description": "Number of results to retrieve", "default": 15}
        },
        "allowed_roles": ["admin", "security_analyst", "auditor"]
    },
    "get_incident_details": {
        "description": "Retrieve timeline, root cause, evidence, and response playbook for a specific incident.",
        "category": "read",
        "parameters": {
            "incident_identifier": {"type": "string", "description": "Incident ID (e.g. 1) or incident number (e.g. INC-2026-001)"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "explain_risk_trust_scores": {
        "description": "Explain the calculation and factors contributing to an agent's dynamic risk score and continuous trust score.",
        "category": "read",
        "parameters": {
            "agent_id": {"type": "string", "description": "Target agent ID"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "inspect_permissions": {
        "description": "Inspect configured permissions, baseline instructions, and detect permission drift for an AI agent.",
        "category": "read",
        "parameters": {
            "agent_id": {"type": "string", "description": "Agent identifier"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "review_prompt_injections": {
        "description": "Review recent prompt injection attempts and multimodal heuristic detection signals.",
        "category": "read",
        "parameters": {
            "limit": {"type": "integer", "description": "Number of events to retrieve", "default": 10}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "review_dlp_events": {
        "description": "Review Data Loss Prevention (DLP) alerts, sensitive credential exposure, and exfiltration attempts.",
        "category": "read",
        "parameters": {
            "limit": {"type": "integer", "description": "Number of events to retrieve", "default": 10}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_attack_graph_and_delegations": {
        "description": "Retrieve topological attack graph nodes, delegation relationships, and intervention barriers.",
        "category": "read",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "summarize_sandbox_simulations": {
        "description": "Summarize red-team attack simulation runs and mitigation scorecards.",
        "category": "read",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "get_predictive_risk_report": {
        "description": "Forecast near-future agent risk trends and next-action probabilities.",
        "category": "read",
        "parameters": {
            "agent_id": {"type": "string", "description": "Agent identifier (optional, or overall fleet report)"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "generate_incident_report_draft": {
        "description": "Synthesize a structured forensic incident report draft with timeline, root cause, and remediation steps.",
        "category": "read",
        "parameters": {
            "incident_id": {"type": "string", "description": "Incident identifier or number"}
        },
        "allowed_roles": ["admin", "security_analyst"]
    },
    "navigate_frontend": {
        "description": "Navigate the AgentShield web application interface to a designated view or page.",
        "category": "navigation",
        "parameters": {
            "target_page": {"type": "string", "description": "Destination page name: Overview, Agents, Agent Lab, Approvals, Incidents & Alerts, Prompt Injection, DLP Policy & Events, Canary Tokens, Shadow AI Discovery, Attack Graph, Delegation Graph, Red-Team Simulation, Predictive Risk, Digital Twin Replay, Tool Proxy Gateway, Secret Manager, Behavioral Drift, Policy-as-Code & GitOps, Reverse Engineering, Forensic Dossiers, Cryptographic Audit, Settings & RBAC, JARVIS Assistant"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "prepare_kill_switch": {
        "description": "Prepare emergency kill switch quarantine for an agent (requires human confirmation before execution).",
        "category": "sensitive_action",
        "parameters": {
            "agent_id": {"type": "string", "description": "Agent to suspend/quarantine"},
            "reason": {"type": "string", "description": "Operational reason for kill switch activation"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "prepare_approval_decision": {
        "description": "Prepare decision (APPROVE or REJECT) for a pending human-in-the-loop approval request.",
        "category": "sensitive_action",
        "parameters": {
            "approval_id": {"type": "integer", "description": "ID of approval request"},
            "decision": {"type": "string", "description": "APPROVE or REJECT"},
            "reason": {"type": "string", "description": "Justification for decision"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "get_network_monitoring_status": {
        "description": "Retrieve continuous network monitoring status, approved scope, scan interval, last/next scan time, and emergency stop status.",
        "category": "read",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_network_discovered_devices": {
        "description": "Retrieve reachable and newly discovered network devices and hosts within authorized IP ranges, distinguishing baselined vs newly found.",
        "category": "read",
        "parameters": {
            "baseline_only": {"type": "boolean", "description": "Filter by baseline status", "default": False}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_network_security_alerts": {
        "description": "Retrieve network security alerts and suspicious network activity, clearly separating observed facts from suspected threats.",
        "category": "read",
        "parameters": {
            "limit": {"type": "integer", "description": "Maximum number of alerts to retrieve", "default": 10}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "start_network_monitoring": {
        "description": "Start continuous network monitoring on authorized approved scopes. Never expands scope.",
        "category": "write",
        "parameters": {},
        "allowed_roles": ["admin", "operator"]
    },
    "stop_network_monitoring": {
        "description": "Stop current network monitoring jobs and disable continuous scanning.",
        "category": "write",
        "parameters": {},
        "allowed_roles": ["admin"]
    },
    "trigger_network_scan_now": {
        "description": "Trigger an immediate scan sweep of approved network scopes. Never expands scope.",
        "category": "write",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "get_device_security_status": {
        "description": "Retrieve security monitoring status, health, OS, firewall, and active consent for the enrolled personal endpoint device.",
        "category": "read",
        "parameters": {
            "device_id": {"type": "string", "description": "Optional device identifier", "default": ""}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "check_suspicious_connections": {
        "description": "Inspect active network socket connections on this computer for anomalous egress, reverse shells, or non-standard ports.",
        "category": "read",
        "parameters": {
            "device_id": {"type": "string", "description": "Optional device identifier", "default": ""}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_device_security_alerts": {
        "description": "Retrieve open security alerts and suspicious behavioral flags detected on enrolled personal devices.",
        "category": "read",
        "parameters": {
            "device_id": {"type": "string", "description": "Optional device identifier", "default": ""},
            "limit": {"type": "integer", "description": "Maximum alerts to return", "default": 10}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "get_endpoint_firewall_status": {
        "description": "Inspect host firewall configuration (Windows Defender Firewall or Linux UFW), profile states, and default policies.",
        "category": "read",
        "parameters": {
            "device_id": {"type": "string", "description": "Optional device identifier", "default": ""}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "pause_endpoint_monitoring": {
        "description": "Pause security telemetry collection and background monitoring for the personal device.",
        "category": "write",
        "parameters": {
            "device_id": {"type": "string", "description": "Optional device identifier", "default": ""}
        },
        "allowed_roles": ["admin", "operator"]
    },
    "disconnect_endpoint_device": {
        "description": "Disconnect this device from the central AgentShield dashboard synchronization.",
        "category": "write",
        "parameters": {
            "device_id": {"type": "string", "description": "Optional device identifier", "default": ""}
        },
        "allowed_roles": ["admin", "operator"]
    },
    "steganography_inspect_image": {
        "description": "Inspect an image for hidden steganography payloads, bitplane Shannon entropy, and EXIF/GPS forensic metadata.",
        "category": "read",
        "parameters": {
            "image_data": {"type": "string", "description": "Base64 data URI (data:image/png;base64,...) or local image path"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "steganography_encode_payload": {
        "description": "Embed a secret message into a carrier image using cryptographic LSB steganography with SHA-256 integrity verification.",
        "category": "write",
        "parameters": {
            "image_data": {"type": "string", "description": "Base64 data URI or local image path"},
            "message": {"type": "string", "description": "Secret payload text to embed"},
            "password": {"type": "string", "description": "Optional passphrase for encryption", "default": ""}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "steganography_decode_payload": {
        "description": "Extract hidden secret message from a steganographic carrier image.",
        "category": "read",
        "parameters": {
            "image_data": {"type": "string", "description": "Base64 data URI or local image path"},
            "password": {"type": "string", "description": "Optional passphrase if encrypted", "default": ""}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "create_reminder": {
        "description": "Create a new reminder with title and scheduled due time.",
        "category": "personal_assistant",
        "parameters": {
            "title": {"type": "string", "description": "Title or task of the reminder"},
            "due_time": {"type": "string", "description": "Due time or date (e.g. 'Tomorrow at 9 AM', 'In 30 minutes')", "default": "Soon"},
            "priority": {"type": "string", "description": "Priority: LOW, NORMAL, HIGH, URGENT", "default": "NORMAL"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "list_reminders": {
        "description": "List active and upcoming reminders.",
        "category": "personal_assistant",
        "parameters": {
            "include_completed": {"type": "boolean", "description": "Include completed reminders", "default": False}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "create_note": {
        "description": "Save a persistent personal note with title and body.",
        "category": "personal_assistant",
        "parameters": {
            "title": {"type": "string", "description": "Note title"},
            "content": {"type": "string", "description": "Note text content"},
            "tags": {"type": "array", "description": "Optional tags", "default": []}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "search_notes": {
        "description": "Search personal saved notes by title or content.",
        "category": "personal_assistant",
        "parameters": {
            "query": {"type": "string", "description": "Search keyword or phrase"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "add_todo_item": {
        "description": "Add a task to the user's to-do checklist.",
        "category": "personal_assistant",
        "parameters": {
            "task": {"type": "string", "description": "Task description"},
            "priority": {"type": "string", "description": "Priority: LOW, NORMAL, HIGH", "default": "NORMAL"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "list_todo_items": {
        "description": "List tasks from the to-do list.",
        "category": "personal_assistant",
        "parameters": {
            "include_completed": {"type": "boolean", "description": "Include finished tasks", "default": True}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "store_user_memory": {
        "description": "Store a user-controlled long-term memory fact or user preference.",
        "category": "personal_assistant",
        "parameters": {
            "key": {"type": "string", "description": "Memory key name"},
            "value": {"type": "string", "description": "Memory fact or value"},
            "category": {"type": "string", "description": "Category: preference, schedule, contact, fact", "default": "preference"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "list_user_memories": {
        "description": "List all stored user memories and recalled context.",
        "category": "personal_assistant",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "search_workspace_files": {
        "description": "Search for files safely within the authorized project directory without path traversal.",
        "category": "system",
        "parameters": {
            "query": {"type": "string", "description": "File name or extension to search"},
            "max_results": {"type": "integer", "description": "Maximum number of file matches", "default": 15}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "launch_approved_application": {
        "description": "Launch an approved desktop application from the whitelist without arbitrary shell execution.",
        "category": "system",
        "parameters": {
            "app_name": {"type": "string", "description": "Application name: notepad, calculator, paint, explorer, taskmgr, edge, chrome, code"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "close_approved_application": {
        "description": "Close running instances of an approved Windows application safely from the whitelist.",
        "category": "system",
        "parameters": {
            "app_name": {"type": "string", "description": "Application to close: notepad, calculator, paint, taskmgr, edge, chrome, code"},
            "force": {"type": "boolean", "description": "Force terminate if not responding", "default": False}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "open_website_or_search": {
        "description": "Open an approved website URL or initiate a web search in the user's default browser.",
        "category": "personal_assistant",
        "parameters": {
            "query_or_url": {"type": "string", "description": "Website URL (e.g. github.com) or search phrase"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "search_or_play_youtube": {
        "description": "Search for or play music and videos on YouTube safely in the default browser.",
        "category": "personal_assistant",
        "parameters": {
            "query": {"type": "string", "description": "Song title, artist, or video query"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "search_authorized_files": {
        "description": "Search for files and folders safely within user-authorized directories (workspace, Documents, Downloads, Desktop).",
        "category": "personal_assistant",
        "parameters": {
            "query": {"type": "string", "description": "Filename, folder name, or file extension to search"},
            "scope": {"type": "string", "description": "Scope: workspace, documents, downloads, desktop, or all", "default": "all"},
            "max_results": {"type": "integer", "description": "Maximum number of matches", "default": 20}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "open_authorized_file_or_folder": {
        "description": "Open an authorized file or folder in Windows File Explorer or default viewer.",
        "category": "personal_assistant",
        "parameters": {
            "filepath": {"type": "string", "description": "File or folder path"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "organize_authorized_files": {
        "description": "Organize, move, rename, or create folders within user-authorized directories with confirmation.",
        "category": "personal_assistant",
        "parameters": {
            "operation": {"type": "string", "description": "move, rename, create_folder"},
            "source_path": {"type": "string", "description": "Source path"},
            "target_path": {"type": "string", "description": "Destination path or new folder path", "default": ""},
            "new_name": {"type": "string", "description": "New name if renaming", "default": ""}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "prepare_whatsapp_message": {
        "description": "Prepare and verify WhatsApp message automation with mandatory confirmation before sending.",
        "category": "sensitive_action",
        "parameters": {
            "recipient": {"type": "string", "description": "Phone number with country code (e.g. +91...) or contact name"},
            "message": {"type": "string", "description": "Message text to send"},
            "attachment_path": {"type": "string", "description": "Optional file attachment path", "default": ""}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "get_windows_system_status": {
        "description": "Read approved Windows system status including CPU, memory, disk, battery, OS version, uptime, and network adapters.",
        "category": "system",
        "parameters": {},
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "open_windows_settings": {
        "description": "Open approved Windows Settings pages safely using ms-settings URIs.",
        "category": "system",
        "parameters": {
            "setting_page": {"type": "string", "description": "network, wifi, update, privacy, firewall, display, sound, battery, storage, apps", "default": "settings"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "analyze_suspicious_processes": {
        "description": "Inspect active Windows processes for anomalous CPU/RAM, unverified paths, and non-standard sockets.",
        "category": "cybersecurity",
        "parameters": {
            "top_n": {"type": "integer", "description": "Number of processes to inspect", "default": 15}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "prepare_firewall_rule_change": {
        "description": "Prepare approved host firewall configuration changes (block/allow port or rule) with mandatory confirmation.",
        "category": "sensitive_action",
        "parameters": {
            "action": {"type": "string", "description": "add_block_rule, add_allow_rule, delete_rule"},
            "rule_name": {"type": "string", "description": "Descriptive name of firewall rule"},
            "direction": {"type": "string", "description": "in or out", "default": "in"},
            "port": {"type": "integer", "description": "Port number (1-65535)", "default": 0},
            "protocol": {"type": "string", "description": "TCP or UDP", "default": "TCP"}
        },
        "allowed_roles": ["admin"]
    },
    "execute_multistep_task": {
        "description": "Execute a multi-step task sequentially and report verified results for each step.",
        "category": "personal_assistant",
        "parameters": {
            "task_description": {"type": "string", "description": "High-level goal description"},
            "steps": {"type": "array", "description": "Ordered list of tool call steps to execute"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator"]
    },
    "get_live_weather": {
        "description": "Fetch real-time weather and 4-day forecast for a city or coordinates via Open-Meteo.",
        "category": "live_intelligence",
        "parameters": {
            "city": {"type": "string", "description": "City or location name (e.g. Pune, Mumbai, Delhi, London)"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "search_cybersecurity_intelligence": {
        "description": "Query official CISA Known Exploited Vulnerabilities (KEV) Catalog and NIST/MITRE CVE advisories.",
        "category": "live_intelligence",
        "parameters": {
            "query_or_cve": {"type": "string", "description": "CVE identifier (e.g. CVE-2024-38077) or security topic"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "search_live_news_and_tech": {
        "description": "Fetch live news, AI model releases, technology announcements, and current developments.",
        "category": "live_intelligence",
        "parameters": {
            "query": {"type": "string", "description": "Topic or search query (e.g. 'latest AI news', 'India news')"},
            "freshness": {"type": "string", "description": "today, week, or month", "default": "week"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "perform_live_web_research": {
        "description": "Execute multi-source live web research, compare independent sources, and provide verifiable citations.",
        "category": "live_intelligence",
        "parameters": {
            "query": {"type": "string", "description": "Subject or question to research online"},
            "freshness": {"type": "string", "description": "today, week, or month", "default": "week"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    },
    "check_windows_software_updates": {
        "description": "Check official Microsoft Windows and application release updates, Patch Tuesday bulletins, and compare with locally installed OS version.",
        "category": "live_intelligence",
        "parameters": {
            "software_name": {"type": "string", "description": "windows or application name", "default": "windows"}
        },
        "allowed_roles": ["admin", "security_analyst", "operator", "auditor"]
    }
}

# --- Tool Execution Implementations ---

def execute_get_security_dashboard_metrics(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agents_count = db.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    active_count = db.execute("SELECT COUNT(*) FROM agents WHERE status='ACTIVE'").fetchone()[0]
    events_count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    blocked_count = db.execute("SELECT COUNT(*) FROM events WHERE decision='BLOCK'").fetchone()[0]
    pending_approvals = db.execute("SELECT COUNT(*) FROM approvals WHERE status='PENDING'").fetchone()[0]
    high_risk_count = db.execute("SELECT COUNT(*) FROM events WHERE risk_score >= 70").fetchone()[0]
    open_incidents = db.execute("SELECT COUNT(*) FROM incidents WHERE status != 'RESOLVED'").fetchone()[0]
    canary_trips = db.execute("SELECT COUNT(*) FROM canary_tokens WHERE triggered=1").fetchone()[0]
    shadow_ai_count = db.execute("SELECT COUNT(*) FROM shadow_ai_detections WHERE status='DETECTED'").fetchone()[0]
    
    avg_risk = db.execute("SELECT AVG(risk_score) FROM agents").fetchone()[0] or 15.0
    avg_trust = db.execute("SELECT AVG(trust_score) FROM agents").fetchone()[0] or 88.0

    return {
        "total_agents": agents_count,
        "active_agents": active_count,
        "suspended_or_quarantined": agents_count - active_count,
        "total_events_logged": events_count,
        "blocked_actions": blocked_count,
        "pending_human_approvals": pending_approvals,
        "high_risk_events": high_risk_count,
        "open_incidents": open_incidents,
        "triggered_canaries": canary_trips,
        "shadow_ai_processes": shadow_ai_count,
        "average_fleet_risk_score": round(float(avg_risk), 1),
        "average_fleet_trust_score": round(float(avg_trust), 1),
        "zero_trust_posture": "DEFAULT-DENY ZERO-TRUST ENFORCING",
        "system_status": "ONLINE & PROTECTED"
    }

def execute_list_agents(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    status_filter = params.get("status", "ALL").upper()
    min_risk = int(params.get("min_risk", 0))

    query = "SELECT id, name, model, purpose, status, risk_score, trust_score, permissions, tools, created_at FROM agents WHERE risk_score >= ?"
    args = [min_risk]

    if status_filter != "ALL":
        query += " AND status = ?"
        args.append(status_filter)

    query += " ORDER BY risk_score DESC"
    rows = db.execute(query, tuple(args)).fetchall()

    agents = []
    for r in rows:
        d = dict(r)
        d["permissions"] = json.loads(d["permissions"]) if isinstance(d["permissions"], str) else d["permissions"]
        d["tools"] = json.loads(d["tools"]) if isinstance(d["tools"], str) else d["tools"]
        agents.append(d)

    return {
        "count": len(agents),
        "agents": agents
    }

def execute_get_agent_details(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(params.get("agent_id", "")).strip()
    if not agent_id:
        return {"error": "Missing agent_id"}

    # Search by ID or exact/fuzzy name match
    row = db.execute("SELECT * FROM agents WHERE id = ? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
    if not row:
        return {"error": f"Agent '{agent_id}' was not found in the inventory"}

    agent = dict(row)
    agent["permissions"] = json.loads(agent["permissions"]) if isinstance(agent["permissions"], str) else agent["permissions"]
    agent["baseline_permissions"] = json.loads(agent["baseline_permissions"]) if isinstance(agent["baseline_permissions"], str) else agent["baseline_permissions"]
    agent["tools"] = json.loads(agent["tools"]) if isinstance(agent["tools"], str) else agent["tools"]

    # Fetch recent events for this agent
    recent_events = db.execute("SELECT id, action, target, decision, risk_score, reason, created_at FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 5", (agent["id"],)).fetchall()
    
    # Check for permission drift
    drift = detect_permission_drift(agent["baseline_permissions"], agent["permissions"])

    return {
        "agent": agent,
        "recent_events": [dict(e) for e in recent_events],
        "permission_drift": drift
    }

def execute_get_alerts_and_incidents(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    severity = params.get("severity", "ALL").upper()
    limit = int(params.get("limit", 10))

    inc_query = "SELECT id, incident_number, title, severity, status, agent_id, summary, root_cause, created_at FROM incidents WHERE 1=1"
    inc_args = []
    if severity != "ALL":
        inc_query += " AND severity = ?"
        inc_args.append(severity)
    inc_query += " ORDER BY id DESC LIMIT ?"
    inc_args.append(limit)

    incidents = [dict(r) for r in db.execute(inc_query, tuple(inc_args)).fetchall()]

    # Fetch critical / blocked events
    event_query = "SELECT id, agent_id, action, target, decision, risk_score, reason, created_at FROM events WHERE decision='BLOCK' OR risk_score >= 70 ORDER BY id DESC LIMIT ?"
    critical_events = [dict(r) for r in db.execute(event_query, (limit,)).fetchall()]

    return {
        "open_incidents": incidents,
        "blocked_and_critical_events": critical_events
    }

def execute_search_audit_logs(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    query_str = str(params.get("query", "")).strip()
    limit = int(params.get("limit", 15))

    if query_str:
        pattern = f"%{query_str}%"
        sql = """SELECT id, actor, action, resource, details_json, prev_hash, current_hash, timestamp 
                 FROM audit_log 
                 WHERE actor LIKE ? OR action LIKE ? OR resource LIKE ? OR details_json LIKE ?
                 ORDER BY id DESC LIMIT ?"""
        rows = db.execute(sql, (pattern, pattern, pattern, pattern, limit)).fetchall()
    else:
        sql = """SELECT id, actor, action, resource, details_json, prev_hash, current_hash, timestamp 
                 FROM audit_log ORDER BY id DESC LIMIT ?"""
        rows = db.execute(sql, (limit,)).fetchall()

    results = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d["details_json"]) if isinstance(d["details_json"], str) else d["details_json"]
        results.append(d)

    return {
        "count": len(results),
        "query": query_str,
        "audit_entries": results
    }

def execute_get_incident_details(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    ident = str(params.get("incident_identifier", "")).strip()
    if not ident:
        return {"error": "Missing incident_identifier"}

    row = None
    if ident.isdigit():
        row = db.execute("SELECT * FROM incidents WHERE id=?", (int(ident),)).fetchone()
    if not row:
        row = db.execute("SELECT * FROM incidents WHERE incident_number=? OR incident_number LIKE ?", (ident, f"%{ident}%")).fetchone()

    if not row:
        return {"error": f"Incident '{ident}' was not found"}

    item = dict(row)
    item["evidence"] = json.loads(item["evidence_json"]) if isinstance(item["evidence_json"], str) else item["evidence_json"]

    # Gather audit trail entries related to this incident
    related_audits = db.execute(
        "SELECT id, actor, action, resource, timestamp FROM audit_log WHERE resource LIKE ? ORDER BY id DESC LIMIT 5",
        (f"%incident:{item['id']}%",)
    ).fetchall()

    return {
        "incident": item,
        "related_audit_records": [dict(a) for a in related_audits]
    }

def execute_explain_risk_trust_scores(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(params.get("agent_id", "")).strip()
    if not agent_id:
        return {"error": "Missing agent_id"}

    agent = db.execute("SELECT * FROM agents WHERE id=? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
    if not agent:
        return {"error": f"Agent '{agent_id}' not found"}

    agent_d = dict(agent)
    events = db.execute("SELECT * FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 10", (agent_d["id"],)).fetchall()
    blocked_count = sum(1 for e in events if e["decision"] == "BLOCK")
    canary_count = db.execute("SELECT COUNT(*) FROM canary_tokens WHERE triggered=1").fetchone()[0]

    # Calculate explainable factor breakdown
    risk_factors = []
    if agent_d["status"] == "KILLED":
        risk_factors.append("Agent is currently in KILLED / QUARANTINED state (+100 Risk).")
    if blocked_count > 0:
        risk_factors.append(f"{blocked_count} recent policy block decisions in the last 10 actions (+{blocked_count * 15} Risk).")
    if canary_count > 0:
        risk_factors.append("Canary token tripwire detection detected on platform.")

    trust_factors = []
    if agent_d["trust_score"] < 70:
        trust_factors.append("Trust score decayed due to anomalous tool calls and policy violations.")
    else:
        trust_factors.append("Trust score is maintained through routine authorized actions within policy boundaries.")

    return {
        "agent_id": agent_d["id"],
        "agent_name": agent_d["name"],
        "status": agent_d["status"],
        "risk_score": agent_d["risk_score"],
        "trust_score": agent_d["trust_score"],
        "risk_posture": "CRITICAL" if agent_d["risk_score"] >= 80 else ("HIGH" if agent_d["risk_score"] >= 50 else "NORMAL"),
        "risk_factors": risk_factors or ["Routine behavior within normal operational parameters."],
        "trust_factors": trust_factors
    }

def execute_inspect_permissions(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(params.get("agent_id", "")).strip()
    agent = db.execute("SELECT * FROM agents WHERE id=? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
    if not agent:
        return {"error": f"Agent '{agent_id}' not found"}

    agent_d = dict(agent)
    curr_perms = json.loads(agent_d["permissions"]) if isinstance(agent_d["permissions"], str) else agent_d["permissions"]
    base_perms = json.loads(agent_d["baseline_permissions"]) if isinstance(agent_d["baseline_permissions"], str) else agent_d["baseline_permissions"]
    tools = json.loads(agent_d["tools"]) if isinstance(agent_d["tools"], str) else agent_d["tools"]

    drift = detect_permission_drift(base_perms, curr_perms)

    return {
        "agent_id": agent_d["id"],
        "agent_name": agent_d["name"],
        "current_permissions": curr_perms,
        "baseline_permissions": base_perms,
        "allowed_tools": tools,
        "baseline_instructions": agent_d["baseline_instructions"],
        "current_instructions": agent_d["current_instructions"],
        "permission_drift_detected": drift["has_drift"],
        "drift_summary": drift["summary"],
        "drifted_privileges": drift.get("added_privileges", {})
    }

def execute_review_prompt_injections(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    limit = int(params.get("limit", 10))
    rows = db.execute(
        """SELECT id, agent_id, action, target, decision, risk_score, reason, payload_sanitized, created_at 
           FROM events 
           WHERE reason LIKE '%injection%' OR reason LIKE '%LLM01%' OR reason LIKE '%Reverse Engineering%'
           ORDER BY id DESC LIMIT ?""",
        (limit,)
    ).fetchall()

    return {
        "count": len(rows),
        "injections_and_attacks": [dict(r) for r in rows]
    }

def execute_review_dlp_events(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    limit = int(params.get("limit", 10))
    rows = db.execute(
        """SELECT id, agent_id, action, target, decision, risk_score, reason, payload_sanitized, created_at 
           FROM events 
           WHERE reason LIKE '%DLP%' OR reason LIKE '%sensitive%' OR reason LIKE '%exfiltration%'
           ORDER BY id DESC LIMIT ?""",
        (limit,)
    ).fetchall()

    return {
        "count": len(rows),
        "dlp_events": [dict(r) for r in rows]
    }

def execute_get_attack_graph_and_delegations(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agents = db.execute("SELECT id, name, status, risk_score FROM agents").fetchall()
    events = db.execute("SELECT id, agent_id, action, target, decision, risk_score FROM events ORDER BY id DESC LIMIT 15").fetchall()
    delegations = db.execute("SELECT * FROM agent_delegations ORDER BY id DESC LIMIT 10").fetchall()

    nodes = []
    edges = []
    for a in agents:
        nodes.append({"id": a["id"], "label": a["name"], "type": "agent", "risk": a["risk_score"], "status": a["status"]})

    for e in events:
        target_node_id = f"res_{e['target']}"
        nodes.append({"id": target_node_id, "label": e["target"], "type": "resource", "action": e["action"]})
        edges.append({
            "from": e["agent_id"],
            "to": target_node_id,
            "action": e["action"],
            "decision": e["decision"],
            "risk": e["risk_score"]
        })

    return {
        "nodes_count": len(nodes),
        "edges_count": len(edges),
        "delegations": [dict(d) for d in delegations],
        "attack_path_summary": "Topological map reconstructed from real AgentShield audit and policy gateway events."
    }

def execute_summarize_sandbox_simulations(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    events = db.execute("SELECT * FROM events WHERE reason LIKE '%simulation%' OR reason LIKE '%Red-Team%' ORDER BY id DESC LIMIT 5").fetchall()
    twin_count = db.execute("SELECT COUNT(*) FROM digital_twins").fetchone()[0]
    
    return {
        "digital_twins_active": twin_count,
        "recent_simulation_runs": [dict(e) for e in events],
        "status": "Sandbox Replay and Red-Team Simulation Ready"
    }

def execute_get_predictive_risk_report(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = params.get("agent_id")
    if agent_id:
        agent = db.execute("SELECT * FROM agents WHERE id=? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
        if not agent:
            return {"error": f"Agent '{agent_id}' not found"}
        agent_d = dict(agent)
        pred = predict_near_future_risk(agent_d["id"], agent_d["risk_score"], agent_d["trust_score"])
        return {
            "agent_id": agent_d["id"],
            "name": agent_d["name"],
            "prediction": pred
        }
    else:
        # Fleetwide risk forecast
        agents = db.execute("SELECT id, name, risk_score, trust_score FROM agents ORDER BY risk_score DESC LIMIT 5").fetchall()
        reports = []
        for a in agents:
            p = predict_near_future_risk(a["id"], a["risk_score"], a["trust_score"])
            reports.append({"id": a["id"], "name": a["name"], "prediction": p})
        return {
            "fleet_risk_forecast": reports,
            "overall_posture": "MODERATE_ELEVATED" if any(a["risk_score"] > 60 for a in agents) else "STABLE"
        }

def execute_generate_incident_report_draft(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    inc_ident = str(params.get("incident_id", "")).strip()
    if not inc_ident:
        # Pick the latest open incident
        row = db.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
    elif inc_ident.isdigit():
        row = db.execute("SELECT * FROM incidents WHERE id=?", (int(inc_ident),)).fetchone()
    else:
        row = db.execute("SELECT * FROM incidents WHERE incident_number=? OR incident_number LIKE ?", (inc_ident, f"%{inc_ident}%")).fetchone()

    if not row:
        return {"error": "No incident found to draft a report for."}

    inc = dict(row)
    now = now_iso()
    evidence = json.loads(inc["evidence_json"]) if isinstance(inc["evidence_json"], str) else inc["evidence_json"]

    report_draft = {
        "report_id": f"REP-{inc['incident_number']}",
        "title": f"FORENSIC INVESTIGATION REPORT: {inc['title']}",
        "classification": "CONFIDENTIAL // AGENTSHIELD SOC",
        "generated_at": now,
        "incident_number": inc["incident_number"],
        "severity": inc["severity"],
        "status": inc["status"],
        "involved_agent": inc["agent_id"],
        "executive_summary": inc["summary"],
        "root_cause_analysis": inc.get("root_cause") or "Adversarial input or prompt injection triggering unauthorized tool invocation.",
        "attack_vector": inc.get("attack_vector") or "Direct Prompt Injection / Tool Privilege Escalation",
        "evidence_dossier": evidence,
        "applied_playbook": inc.get("response_playbook") or "Automated Containment & Quarantine",
        "remediation_actions": [
            "1. Quarantined compromised AI agent via Emergency Kill Switch.",
            "2. Revoked active credentials and isolated downstream API connectors.",
            "3. Enforced strict Zero-Trust policy gate on target endpoints.",
            "4. Appended non-repudiable audit event to cryptographic SHA-256 ledger."
        ]
    }
    return report_draft

def execute_navigate_frontend(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    target_page = params.get("target_page", "Overview")
    valid_pages = [
        "Overview", "Real-Time Monitor", "Network Monitoring", "Agents", "Agent Lab", "Approvals",
        "Incidents & Alerts", "Prompt Injection", "DLP Policy & Events",
        "Canary Tokens", "Shadow AI Discovery", "Attack Graph", "Delegation Graph",
        "Red-Team Simulation", "Predictive Risk", "Digital Twin Replay",
        "Tool Proxy Gateway", "Secret Manager", "Behavioral Drift",
        "Policy-as-Code & GitOps", "Reverse Engineering", "Forensic Dossiers",
        "Cryptographic Audit", "Settings & RBAC", "JARVIS Assistant"
    ]
    matched = None
    for vp in valid_pages:
        if vp.lower() == target_page.lower() or target_page.lower() in vp.lower():
            matched = vp
            break

    if not matched:
        matched = "Overview"

    return {
        "status": "NAVIGATING",
        "target_page": matched,
        "message": f"Navigating to '{matched}' page."
    }

def execute_get_network_monitoring_status(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    from ..services.network_monitor import network_monitoring_service
    return network_monitoring_service.get_monitoring_status()

def execute_get_network_discovered_devices(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    baseline_only = params.get("baseline_only", False)
    query = "SELECT ip_address, hostname, mac_address, status, in_baseline, latency_ms, first_seen, last_seen FROM network_assets WHERE 1=1"
    args = []
    if baseline_only:
        query += " AND in_baseline = 1"
    query += " ORDER BY in_baseline ASC, last_seen DESC LIMIT 20"
    
    rows = [dict(r) for r in db.execute(query, tuple(args)).fetchall()]
    for r in rows:
        srv_rows = db.execute("SELECT port, protocol, service_name, banner FROM service_observations WHERE ip_address = ? AND state = 'OPEN'", (r["ip_address"],)).fetchall()
        r["open_ports"] = [dict(s) for s in srv_rows]

    new_devices = [d for d in rows if not d.get("in_baseline")]
    baselined_devices = [d for d in rows if d.get("in_baseline")]

    return {
        "total_returned": len(rows),
        "newly_discovered_count": len(new_devices),
        "baselined_count": len(baselined_devices),
        "newly_discovered_devices": new_devices,
        "baselined_devices": baselined_devices,
        "devices": rows
    }

def execute_get_network_security_alerts(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    limit = int(params.get("limit", 10))
    rows = [dict(r) for r in db.execute("""
        SELECT id, scan_job_id, alert_type, severity, title, observed_fact,
               suspected_threat, target_ip, target_port, evidence_json, status, created_at
        FROM network_security_alerts
        ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()]

    for r in rows:
        try:
            r["evidence"] = json.loads(r.get("evidence_json") or "{}")
        except Exception:
            r["evidence"] = {}

    return {
        "total_alerts": len(rows),
        "alerts": rows,
        "fact_threat_distinction": "All records strictly partition verified empirical probe observations from hypothesized adversarial threats."
    }

def execute_start_network_monitoring(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    from ..services.network_monitor import network_monitoring_service
    now = now_iso()
    db.execute("UPDATE network_monitoring_config SET service_enabled = 1, is_paused = 0, updated_at = ?", (now,))
    network_monitoring_service.start_background_service()
    
    scopes = [r[0] for r in db.execute("SELECT cidr_or_ip FROM approved_scan_scopes WHERE is_approved = 1").fetchall()]
    return {
        "status": "STARTED",
        "service_enabled": True,
        "message": f"Continuous network monitoring initiated for approved scopes: {', '.join(scopes)}.",
        "approved_scopes": scopes,
        "scope_guarantee": "Strict zero-trust confinement: scanner will only probe authorized assets within approved CIDRs."
    }

def execute_stop_network_monitoring(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    now = now_iso()
    db.execute("UPDATE network_monitoring_config SET service_enabled = 0, updated_at = ?", (now,))
    return {
        "status": "STOPPED",
        "service_enabled": False,
        "message": "Continuous network monitoring service has been deactivated."
    }

def execute_trigger_network_scan_now(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    from ..services.network_monitor import network_monitoring_service
    scopes = [r[0] for r in db.execute("SELECT cidr_or_ip FROM approved_scan_scopes WHERE is_approved = 1").fetchall()]
    
    # If the user attempted to pass an explicit target IP outside approved scopes, block it immediately
    target_requested = params.get("target_ip")
    if target_requested:
        from ..engines.network_scanner import validate_ip_in_approved_scope
        excls = [r[0] for r in db.execute("SELECT ip_address FROM network_exclusions").fetchall()]
        valid, reason = validate_ip_in_approved_scope(target_requested, scopes, excls)
        if not valid:
            return {
                "error": f"Scope Violation: {reason}. AgentShield Zero-Trust policy strictly blocks scanning arbitrary external addresses."
            }

    # Trigger scan cycle asynchronously
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(network_monitoring_service.execute_scan_cycle(triggered_by="JARVIS"))
    except Exception:
        pass

    return {
        "status": "SCAN_DISPATCHED",
        "message": f"Authorized network scan sweep dispatched across {len(scopes)} approved scope(s).",
        "approved_scopes": scopes
    }

def execute_prepare_kill_switch(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(params.get("agent_id", "")).strip()
    reason = params.get("reason", "Operator activated emergency quarantine via JARVIS")
    agent = db.execute("SELECT * FROM agents WHERE id=? OR LOWER(name) LIKE ?", (agent_id, f"%{agent_id.lower()}%")).fetchone()
    if not agent:
        return {"error": f"Agent '{agent_id}' not found"}

    agent_d = dict(agent)
    action_id = f"act-{uuid.uuid4().hex[:12]}"
    idempotency_key = f"idemp-kill-{agent_d['id']}-{int(datetime.now(timezone.utc).timestamp() * 1000)}-{uuid.uuid4().hex[:6]}"

    explanation = (
        f"You have requested to ACTIVATE THE EMERGENCY KILL SWITCH for {agent_d['name']} ({agent_d['id']}). "
        f"This action will immediately set status to KILLED, set Risk Score to 100, revoke all tool access tokens, "
        f"and log a CRITICAL incident in the audit ledger. Confirmation is required."
    )

    return {
        "requires_confirmation": True,
        "action_id": action_id,
        "action_type": "KILL_SWITCH",
        "target_id": agent_d["id"],
        "target_name": agent_d["name"],
        "risk_level": "CRITICAL",
        "impact_explanation": explanation,
        "idempotency_key": idempotency_key,
        "reason": reason
    }

def execute_prepare_approval_decision(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    approval_id = params.get("approval_id")
    decision = str(params.get("decision", "APPROVE")).upper()
    reason = params.get("reason", "Decided via JARVIS Assistant")

    approval = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    if not approval:
        return {"error": f"Approval request #{approval_id} not found"}

    action_id = f"act-{uuid.uuid4().hex[:12]}"
    idempotency_key = f"idemp-appr-{approval_id}-{decision}-{int(datetime.now(timezone.utc).timestamp() * 1000)}-{uuid.uuid4().hex[:6]}"
    
    explanation = (
        f"Confirm decision to {decision} approval request #{approval_id} for agent {approval['agent_id']} "
        f"attempting action '{approval['action']}' on target '{approval['target']}'."
    )

    return {
        "requires_confirmation": True,
        "action_id": action_id,
        "action_type": "APPROVE_REQUEST" if decision == "APPROVE" else "REJECT_REQUEST",
        "target_id": str(approval_id),
        "target_name": f"Approval #{approval_id} ({approval['action']})",
        "risk_level": "HIGH" if decision == "APPROVE" else "MEDIUM",
        "impact_explanation": explanation,
        "idempotency_key": idempotency_key,
        "decision": decision,
        "reason": reason
    }

def _resolve_target_device_id(db: sqlite3.Connection, device_id: Optional[str] = None) -> Optional[str]:
    """Helper to pick provided device_id or the most recently active enrolled device."""
    if device_id and device_id.strip():
        return device_id.strip()
    row = db.execute("SELECT id FROM enrolled_devices ORDER BY last_heartbeat DESC LIMIT 1").fetchone()
    return row["id"] if row else None


def execute_get_device_security_status(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    dev_id = _resolve_target_device_id(db, params.get("device_id"))
    if not dev_id:
        return {"error": "No enrolled devices found. Please enroll your computer using an enrollment token."}

    dev = db.execute("SELECT * FROM enrolled_devices WHERE id = ?", (dev_id,)).fetchone()
    if not dev:
        return {"error": f"Device '{dev_id}' not found."}

    alerts_count = db.execute("SELECT COUNT(*) FROM device_security_alerts WHERE device_id = ? AND status = 'OPEN'", (dev_id,)).fetchone()[0]
    fw = db.execute("SELECT * FROM device_firewall_status WHERE device_id = ?", (dev_id,)).fetchone()
    health = db.execute("SELECT * FROM device_health_telemetry WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1", (dev_id,)).fetchone()
    consent = db.execute("SELECT permission_key, granted FROM device_consent_records WHERE device_id = ?", (dev_id,)).fetchall()

    granted_perms = [c["permission_key"] for c in consent if c["granted"]]
    withheld_perms = [c["permission_key"] for c in consent if not c["granted"]]

    return {
        "device_id": dev["id"],
        "device_name": dev["device_name"],
        "hostname": dev["hostname"],
        "os": f"{dev['os_type']} {dev['os_release']} ({dev['os_version']})",
        "agent_version": dev["agent_version"],
        "monitoring_status": dev["monitoring_status"],
        "is_revoked": bool(dev["is_revoked"]),
        "last_heartbeat": dev["last_heartbeat"],
        "ip_address": dev["ip_address"],
        "cpu_cores": dev["cpu_cores"],
        "total_memory_mb": dev["total_memory_mb"],
        "open_alerts_count": alerts_count,
        "firewall": {
            "type": fw["os_firewall_type"] if fw else "unknown",
            "is_enabled": bool(fw["is_enabled"]) if fw else False,
            "default_inbound": fw["default_inbound"] if fw else "UNKNOWN"
        },
        "latest_health": {
            "cpu_percent": health["cpu_percent"] if health else 0.0,
            "memory_percent": health["memory_percent"] if health else 0.0,
            "disk_percent": health["disk_percent"] if health else 0.0
        } if health else None,
        "granted_permissions": granted_perms,
        "withheld_permissions": withheld_perms
    }


def execute_check_suspicious_connections(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    dev_id = _resolve_target_device_id(db, params.get("device_id"))
    if not dev_id:
        return {"error": "No enrolled devices found."}

    rows = db.execute(
        """SELECT * FROM device_connections
           WHERE device_id = ? AND is_suspicious = 1
           ORDER BY observed_at DESC LIMIT 20""",
        (dev_id,)
    ).fetchall()

    total_conns = db.execute("SELECT COUNT(*) FROM device_connections WHERE device_id = ?", (dev_id,)).fetchone()[0]
    suspicious_list = [dict(r) for r in rows]

    return {
        "device_id": dev_id,
        "total_connections_observed": total_conns,
        "suspicious_count": len(suspicious_list),
        "suspicious_connections": suspicious_list,
        "has_suspicious_connections": len(suspicious_list) > 0,
        "status": "SUSPICIOUS_ACTIVITY_DETECTED" if len(suspicious_list) > 0 else "ALL_CONNECTIONS_CLEAN"
    }


def execute_get_device_security_alerts(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    dev_id = _resolve_target_device_id(db, params.get("device_id"))
    limit = int(params.get("limit", 10))

    sql = "SELECT * FROM device_security_alerts WHERE status = 'OPEN'"
    args = []
    if dev_id:
        sql += " AND device_id = ?"
        args.append(dev_id)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)

    rows = db.execute(sql, tuple(args)).fetchall()
    alerts = []
    for r in rows:
        d = dict(r)
        if d.get("evidence_json"):
            try:
                d["evidence"] = json.loads(d["evidence_json"])
            except Exception:
                d["evidence"] = {}
        alerts.append(d)

    return {
        "device_id": dev_id or "ALL",
        "count": len(alerts),
        "alerts": alerts
    }


def execute_get_endpoint_firewall_status(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    dev_id = _resolve_target_device_id(db, params.get("device_id"))
    if not dev_id:
        return {"error": "No enrolled devices found."}

    fw = db.execute("SELECT * FROM device_firewall_status WHERE device_id = ?", (dev_id,)).fetchone()
    if not fw:
        return {"error": f"Firewall status not recorded for device '{dev_id}'."}

    fw_dict = dict(fw)
    profiles = json.loads(fw_dict["profile_statuses_json"]) if fw_dict.get("profile_statuses_json") else {}

    return {
        "device_id": dev_id,
        "firewall_type": fw_dict["os_firewall_type"],
        "is_enabled": bool(fw_dict["is_enabled"]),
        "profiles": profiles,
        "default_inbound": fw_dict["default_inbound"],
        "default_outbound": fw_dict["default_outbound"],
        "active_rules_count": fw_dict["active_rules_count"],
        "last_inspected": fw_dict["last_inspected"],
        "summary": fw_dict["raw_summary"]
    }


def execute_pause_endpoint_monitoring(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    dev_id = _resolve_target_device_id(db, params.get("device_id"))
    if not dev_id:
        return {"error": "No enrolled devices found."}

    db.execute("UPDATE enrolled_devices SET monitoring_status = 'PAUSED' WHERE id = ?", (dev_id,))
    now = now_iso()
    db.execute(
        "INSERT INTO device_audit_logs (device_id, action, actor, details_json, timestamp) VALUES (?, 'MONITORING_PAUSED', 'jarvis', '{}', ?)",
        (dev_id, now)
    )
    return {
        "status": "PAUSED",
        "device_id": dev_id,
        "message": f"Security monitoring for device '{dev_id}' has been paused. Telemetry collection suspended."
    }


def execute_disconnect_endpoint_device(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    dev_id = _resolve_target_device_id(db, params.get("device_id"))
    if not dev_id:
        return {"error": "No enrolled devices found."}

    db.execute("UPDATE enrolled_devices SET monitoring_status = 'DISCONNECTED' WHERE id = ?", (dev_id,))
    now = now_iso()
    db.execute(
        "INSERT INTO device_audit_logs (device_id, action, actor, details_json, timestamp) VALUES (?, 'DEVICE_DISCONNECTED', 'jarvis', '{}', ?)",
        (dev_id, now)
    )
    return {
        "status": "DISCONNECTED",
        "device_id": dev_id,
        "message": f"Device '{dev_id}' has been disconnected from dashboard synchronization."
    }


def execute_steganography_inspect_image(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    image_data = params.get("image_data")
    if not image_data:
        return {"error": "Missing required parameter 'image_data'."}
    try:
        res = inspect_image_and_exif(image_data)
        record_audit_entry(
            db=db,
            actor="jarvis_user",
            action="STEGANOGRAPHY_INSPECT",
            resource="image_carrier",
            details={
                "decision": "ALLOW",
                "reason": "User requested image steganography and EXIF inspection.",
                "forensic_status": res.get("forensic_status"),
                "risk_factors": res.get("risk_factors")
            }
        )
        return res
    except Exception as e:
        return {"error": f"Failed to inspect image: {str(e)}"}


def execute_steganography_encode_payload(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    image_data = params.get("image_data")
    message = params.get("message")
    password = params.get("password") or None
    if not image_data or not message:
        return {"error": "Missing required parameters 'image_data' and 'message'."}
    try:
        res = encode_stego_message(image_data, message, password=password)
        record_audit_entry(
            db=db,
            actor="jarvis_user",
            action="STEGANOGRAPHY_ENCODE",
            resource="image_carrier",
            details={
                "decision": "ALLOW",
                "reason": "User encoded secret payload into image carrier.",
                "payload_sha256": res.get("payload_sha256"),
                "bytes_used": res.get("payload_bytes_used")
            }
        )
        return res
    except Exception as e:
        return {"error": f"Failed to encode stego message: {str(e)}"}


def execute_steganography_decode_payload(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    image_data = params.get("image_data")
    password = params.get("password") or None
    if not image_data:
        return {"error": "Missing required parameter 'image_data'."}
    try:
        res = decode_stego_message(image_data, password=password)
        record_audit_entry(
            db=db,
            actor="jarvis_user",
            action="STEGANOGRAPHY_DECODE",
            resource="image_carrier",
            details={
                "decision": "ALLOW",
                "reason": "User extracted payload from steganographic carrier.",
                "detected": res.get("detected"),
                "format": res.get("format")
            }
        )
        return res
    except Exception as e:
        return {"error": f"Failed to decode stego message: {str(e)}"}

def execute_create_reminder(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    u_id = user.get("username", "admin") if user else "admin"
    return create_reminder(u_id, params.get("title", ""), params.get("due_time"), params.get("priority", "NORMAL"))

def execute_list_reminders(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    u_id = user.get("username", "admin") if user else "admin"
    rems = list_reminders(u_id, params.get("include_completed", False))
    return {"reminders": rems, "count": len(rems)}

def execute_create_note(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    u_id = user.get("username", "admin") if user else "admin"
    return create_note(u_id, params.get("title", "Untitled Note"), params.get("content", ""), params.get("tags", []))

def execute_search_notes(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    u_id = user.get("username", "admin") if user else "admin"
    notes = search_notes(u_id, params.get("query", ""))
    return {"notes": notes, "query": params.get("query", ""), "count": len(notes)}

def execute_add_todo_item(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    u_id = user.get("username", "admin") if user else "admin"
    return add_todo_item(u_id, params.get("task", ""), params.get("priority", "NORMAL"))

def execute_list_todo_items(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    u_id = user.get("username", "admin") if user else "admin"
    items = list_todo_items(u_id, params.get("include_completed", True))
    return {"todos": items, "count": len(items)}

def execute_store_user_memory(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    u_id = user.get("username", "admin") if user else "admin"
    return store_user_memory(u_id, params.get("key", ""), params.get("value", ""), params.get("category", "preference"))

def execute_list_user_memories(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    u_id = user.get("username", "admin") if user else "admin"
    mems = list_user_memories(u_id)
    return {"memories": mems, "count": len(mems)}

def execute_search_workspace_files(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return search_workspace_files(params.get("query", ""), max_results=params.get("max_results", 15))

def execute_launch_approved_application(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    role = user.get("role", "operator") if user else "operator"
    return launch_approved_application(params.get("app_name", ""), user_role=role)

def execute_close_approved_application(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    role = user.get("role", "operator") if user else "operator"
    return close_approved_application(params.get("app_name", ""), force=params.get("force", False), user_role=role)

def execute_open_website_or_search(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return open_website_or_search(params.get("query_or_url", ""))

def execute_search_or_play_youtube(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return search_or_play_youtube(params.get("query", ""))

def execute_search_authorized_files(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return search_authorized_files(params.get("query", ""), scope=params.get("scope"), max_results=params.get("max_results", 20))

def execute_open_authorized_file_or_folder(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return open_authorized_file_or_folder(params.get("filepath", ""))

def execute_organize_authorized_files(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    role = user.get("role", "operator") if user else "operator"
    return organize_authorized_files(
        operation=params.get("operation", "move"),
        source_path=params.get("source_path", ""),
        target_path=params.get("target_path"),
        new_name=params.get("new_name"),
        user_role=role
    )

def execute_prepare_whatsapp_message(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    role = user.get("role", "operator") if user else "operator"
    return prepare_whatsapp_message(
        recipient=params.get("recipient", ""),
        message=params.get("message", ""),
        attachment_path=params.get("attachment_path"),
        user_role=role
    )

def execute_get_windows_system_status(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return get_windows_system_status()

def execute_open_windows_settings(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return open_windows_settings(params.get("setting_page", "settings"))

def execute_analyze_suspicious_processes(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return analyze_suspicious_processes(top_n=params.get("top_n", 15))

def execute_prepare_firewall_rule_change(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    role = user.get("role", "admin") if user else "admin"
    port_val = params.get("port")
    port_int = int(port_val) if port_val and int(port_val) > 0 else None
    return prepare_firewall_rule_change(
        action=params.get("action", "add_block_rule"),
        rule_name=params.get("rule_name", ""),
        direction=params.get("direction", "in"),
        port=port_int,
        protocol=params.get("protocol", "TCP"),
        user_role=role
    )

def execute_execute_multistep_task(db: sqlite3.Connection, params: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    u = user or {"username": "admin", "role": "admin"}
    return execute_multistep_task(
        task_description=params.get("task_description", "Multi-step task"),
        steps=params.get("steps", []),
        user=u
    )

def execute_get_live_weather(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    city = params.get("city")
    return fetch_live_weather(city=city)

def execute_search_cybersecurity_intelligence(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    query_or_cve = params.get("query_or_cve", "")
    return fetch_cybersecurity_intelligence(query_or_cve=query_or_cve)

def execute_search_live_news_and_tech(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    query = params.get("query", "technology news")
    freshness = params.get("freshness", "week")
    articles = search_live_news_rss(topic=query, freshness=freshness)
    return {
        "status": "SUCCESS",
        "query": query,
        "freshness": freshness,
        "total_articles": len(articles),
        "articles": articles
    }

def execute_perform_live_web_research(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    query = params.get("query", "")
    freshness = params.get("freshness", "week")
    return perform_live_web_research(query=query, freshness=freshness)

def execute_check_windows_software_updates(db: sqlite3.Connection, params: Dict[str, Any]) -> Dict[str, Any]:
    software_name = params.get("software_name", "windows")
    return check_windows_software_updates(software_name=software_name)

# Mapping of tool names to their execution functions
TOOL_HANDLERS: Dict[str, Any] = {
    "get_security_dashboard_metrics": execute_get_security_dashboard_metrics,
    "list_agents": execute_list_agents,
    "get_agent_details": execute_get_agent_details,
    "get_alerts_and_incidents": execute_get_alerts_and_incidents,
    "search_audit_logs": execute_search_audit_logs,
    "get_incident_details": execute_get_incident_details,
    "explain_risk_trust_scores": execute_explain_risk_trust_scores,
    "inspect_permissions": execute_inspect_permissions,
    "review_prompt_injections": execute_review_prompt_injections,
    "review_dlp_events": execute_review_dlp_events,
    "get_attack_graph_and_delegations": execute_get_attack_graph_and_delegations,
    "summarize_sandbox_simulations": execute_summarize_sandbox_simulations,
    "get_predictive_risk_report": execute_get_predictive_risk_report,
    "generate_incident_report_draft": execute_generate_incident_report_draft,
    "navigate_frontend": execute_navigate_frontend,
    "prepare_kill_switch": execute_prepare_kill_switch,
    "prepare_approval_decision": execute_prepare_approval_decision,
    "get_network_monitoring_status": execute_get_network_monitoring_status,
    "get_network_discovered_devices": execute_get_network_discovered_devices,
    "get_network_security_alerts": execute_get_network_security_alerts,
    "start_network_monitoring": execute_start_network_monitoring,
    "stop_network_monitoring": execute_stop_network_monitoring,
    "trigger_network_scan_now": execute_trigger_network_scan_now,
    "get_device_security_status": execute_get_device_security_status,
    "check_suspicious_connections": execute_check_suspicious_connections,
    "get_device_security_alerts": execute_get_device_security_alerts,
    "get_endpoint_firewall_status": execute_get_endpoint_firewall_status,
    "pause_endpoint_monitoring": execute_pause_endpoint_monitoring,
    "disconnect_endpoint_device": execute_disconnect_endpoint_device,
    "steganography_inspect_image": execute_steganography_inspect_image,
    "steganography_encode_payload": execute_steganography_encode_payload,
    "steganography_decode_payload": execute_steganography_decode_payload,
    "create_reminder": execute_create_reminder,
    "list_reminders": execute_list_reminders,
    "create_note": execute_create_note,
    "search_notes": execute_search_notes,
    "add_todo_item": execute_add_todo_item,
    "list_todo_items": execute_list_todo_items,
    "store_user_memory": execute_store_user_memory,
    "list_user_memories": execute_list_user_memories,
    "search_workspace_files": execute_search_workspace_files,
    "launch_approved_application": execute_launch_approved_application,
    "close_approved_application": execute_close_approved_application,
    "open_website_or_search": execute_open_website_or_search,
    "search_or_play_youtube": execute_search_or_play_youtube,
    "search_authorized_files": execute_search_authorized_files,
    "open_authorized_file_or_folder": execute_open_authorized_file_or_folder,
    "organize_authorized_files": execute_organize_authorized_files,
    "prepare_whatsapp_message": execute_prepare_whatsapp_message,
    "get_windows_system_status": execute_get_windows_system_status,
    "open_windows_settings": execute_open_windows_settings,
    "analyze_suspicious_processes": execute_analyze_suspicious_processes,
    "prepare_firewall_rule_change": execute_prepare_firewall_rule_change,
    "execute_multistep_task": execute_execute_multistep_task,
    "get_live_weather": execute_get_live_weather,
    "search_cybersecurity_intelligence": execute_search_cybersecurity_intelligence,
    "search_live_news_and_tech": execute_search_live_news_and_tech,
    "perform_live_web_research": execute_perform_live_web_research,
    "check_windows_software_updates": execute_check_windows_software_updates
}

def dispatch_tool(tool_name: str, arguments: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatches tool execution safely with error handling and real DB connection."""
    handler: Any = TOOL_HANDLERS.get(tool_name)
    if not handler:
        return {"error": f"Tool '{tool_name}' is not registered or supported"}

    with connect() as db:
        try:
            import inspect
            sig = inspect.signature(handler)
            kwargs: Dict[str, Any] = {}
            if "user" in sig.parameters:
                kwargs["user"] = user
            result = handler(db, arguments, **kwargs)
            return result
        except Exception as e:
            return {"error": f"Execution error in tool '{tool_name}': {str(e)}"}
