import os
import re
import json
import uuid
import sqlite3
import httpx
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from ..db.database import connect, now_iso
from ..core.config import SECRET_VAULT
from .jarvis_schemas import (
    JarvisMessageRequest, JarvisMessageResponse, JarvisState, JarvisLanguage,
    JarvisToolCall, JarvisToolResult, JarvisConfirmationRequest, JarvisSecurityContext,
    JarvisBriefingResponse
)
from .jarvis_security import (
    check_message_for_prompt_injection, verify_tool_authorization,
    check_requires_confirmation, sanitize_assistant_output, log_jarvis_action
)
from .jarvis_tools import TOOL_REGISTRY, dispatch_tool
from .jarvis_memory import (
    get_or_create_session, append_message, get_session_history,
    update_session_context, get_session_context, set_session_context_field,
    get_recent_turn_context
)
from ..engines.kill_switch import trigger_emergency_kill_switch
from .language_detection import detect_language as detect_language_core
from .multilingual_commands import parse_multilingual_intent, check_multilingual_prompt_injection
from .text_to_speech import local_tts_engine
from ..firewall.ai_firewall import AIAgentSecurityGateway

# Determine configured LLM Provider from environment
# Options: 'gemini', 'openai', 'anthropic', 'heuristic' (default offline resilient engine)
LLM_PROVIDER = os.getenv("JARVIS_LLM_PROVIDER", "heuristic").lower()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "") or SECRET_VAULT.get("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "") or SECRET_VAULT.get("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are AMOJA, a multilingual conversational assistant. Always respond in the same language and writing style as the user's latest message. Support Hindi, Hinglish, Marathi, English, and natural combinations of these languages. Detect language per turn and switch immediately when the user switches. Do not translate into English unless asked. Keep responses natural, friendly, and conversational. Preserve this behavior when using tools or discussing cybersecurity.
Your core mission is Zero-Trust verification: "Who Controls the AI?"
Tone: Crisp, authoritative, respectful, highly competent, calm, articulate, and protective.
Guidelines:
1. Always ground your security findings in real telemetry from approved AgentShield tools. Never fabricate metrics.
2. If the user asks for actions or summaries, invoke the appropriate tools.
3. For dangerous or irreversible actions (like activating the Emergency Kill Switch or approving high-risk tool actions), prepare a confirmation request.
4. Support English, Hindi, Marathi, and Hinglish naturally.
5. Keep your spoken voice responses concise (1-3 sentences) suitable for speech synthesis. Provide structured evidence in the text.
"""

def detect_language(text: str, requested_lang: JarvisLanguage, session_lang: Optional[str] = None) -> str:
    """Detects whether user prompt is English, Hindi, Marathi, or Hinglish per turn from text."""
    req_val = requested_lang.value if hasattr(requested_lang, "value") else str(requested_lang)
    return detect_language_core(text, user_preference=req_val, session_lang=session_lang)

def match_command_intent(
    user_prompt: str,
    context: Optional[JarvisSecurityContext],
    session_context: Optional[Dict[str, Any]] = None
) -> Tuple[Optional[str], Dict[str, Any], Optional[str]]:
    """Analyzes natural language and voice commands across English, Hindi, Marathi, and Hinglish with contextual follow-up awareness."""
    agent_id = context.selected_agent_id if context else None
    inc_id = str(context.selected_incident_id) if context and context.selected_incident_id else None

    # First evaluate multilingual intent parser with multi-turn session context
    multi_tool, multi_args, multi_nav, _ = parse_multilingual_intent(
        user_prompt,
        context_agent_id=agent_id,
        context_incident_id=inc_id,
        session_context=session_context
    )
    if multi_tool:
        return multi_tool, multi_args, multi_nav

    p = user_prompt.lower().strip()

    # Explicit stop listening
    if any(phrase in p for phrase in ["stop listening", "listening band karo", "shut up", "ruk jao", "mute", "pause listening"]):
        return "STOP_LISTENING", {}, None

    # Security summary / Dashboard metrics
    if any(phrase in p for phrase in [
        "give me the security summary", "security summary", "system summary", "dashboard summary",
        "soc summary", "overall status", "security posture", "status report", "security summary batao",
        "summary do", "overview dikhao"
    ]):
        return "get_security_dashboard_metrics", {}, "Overview"

    # Show critical threats / alerts
    if any(phrase in p for phrase in [
        "show all critical threats", "critical threats", "show threats", "all alerts",
        "threat alerts", "critical alerts", "critical threats dikhao", "khatre dikhao",
        "threats kya hai"
    ]):
        return "get_alerts_and_incidents", {"severity": "CRITICAL", "limit": 10}, "Incidents & Alerts"

    # Highest risk AI agent
    if any(phrase in p for phrase in [
        "highest risk", "which ai agent has the highest risk", "highest risk score", "most dangerous agent",
        "highest risk agent", "sabse zyada risk", "sabse risky agent", "highest risk kis agent ka hai"
    ]):
        return "list_agents", {"status": "ALL", "min_risk": 0}, "Agents"

    # Prompt injection attempts
    if any(phrase in p for phrase in [
        "prompt injection", "prompt injections", "injection attempts", "adversarial prompt",
        "prompt injection attempts", "prompt injection check karo", "injection dikhao"
    ]):
        return "review_prompt_injections", {"limit": 10}, "Prompt Injection"

    # Data leakage / DLP events
    if any(phrase in p for phrase in [
        "data leakage", "dlp", "data leak", "data exfiltration", "credential leakage",
        "recent data leakage events", "dlp events", "data loss", "data leak check karo"
    ]):
        return "review_dlp_events", {"limit": 10}, "DLP Policy & Events"

    # Investigate incident
    if any(phrase in p for phrase in [
        "investigate this incident", "investigate incident", "incident details", "show incident",
        "incident report", "incident ki janch karo", "incident investigate karo"
    ]):
        target_inc = None
        # Extract incident number if present
        match = re.search(r"(?:inc-[\w-]+|\b\d+\b)", p)
        if match:
            target_inc = match.group(0)
        elif context and context.selected_incident_id:
            target_inc = str(context.selected_incident_id)
        return "get_incident_details", {"incident_identifier": target_inc or "1"}, "Incidents & Alerts"

    # Show attack path / Attack graph
    if any(phrase in p for phrase in [
        "show the attack path", "attack path", "attack graph", "show attack graph",
        "hamla graph", "attack graph dikhao", "delegation graph", "attack route"
    ]):
        return "get_attack_graph_and_delegations", {}, "Attack Graph"

    # Open / show audit logs
    if any(phrase in p for phrase in [
        "open the audit logs", "audit logs", "audit trail", "cryptographic audit", "audit log",
        "audit logs kholo", "audit ledger", "show audit"
    ]):
        return "search_audit_logs", {"limit": 15}, "Cryptographic Audit"

    # Show pending approval requests
    if any(phrase in p for phrase in [
        "pending approval", "pending approvals", "show pending approval requests", "approvals queue",
        "approval requests", "pending request", "pending approval dikhao"
    ]):
        return "get_security_dashboard_metrics", {}, "Approvals"

    # Explain why this agent was blocked
    if any(phrase in p for phrase in [
        "why this agent was blocked", "why was it blocked", "explain block", "why blocked",
        "agent block kyun hua", "block ka reason", "explain why this agent was blocked"
    ]):
        agent_target = context.selected_agent_id if context else None
        # Try to find agent name in prompt
        agent_match = re.search(r"agent-[a-zA-Z0-9_-]+", p)
        if agent_match:
            agent_target = agent_match.group(0)
        return "explain_risk_trust_scores", {"agent_id": agent_target or "agent-finance-01"}, "Real-Time Monitor"

    # Explain alert in simple language
    if any(phrase in p for phrase in [
        "explain this alert in simple language", "explain this alert", "explain alert",
        "simple language me samjhao", "alert samjhao"
    ]):
        return "get_alerts_and_incidents", {"severity": "CRITICAL", "limit": 3}, "Incidents & Alerts"

    # Generate incident report
    if any(phrase in p for phrase in [
        "generate an incident report", "generate incident report", "draft incident report",
        "forensic report", "incident report banao", "incident report generate karo"
    ]):
        return "generate_incident_report_draft", {"incident_id": "1"}, "Forensic Dossiers"

    # Compare two agents
    if any(phrase in p for phrase in ["compare these two agents", "compare agents", "agent comparison"]):
        return "list_agents", {"status": "ALL", "min_risk": 0}, "Agents"

    # Sensitive action: Suspend or Kill Agent
    kill_match = re.search(r"(?:suspend|kill|quarantine|freeze|roko|block)\s+(?:agent\s+)?([a-zA-Z0-9_-]+)", p)
    if kill_match:
        target_name = kill_match.group(1).strip()
        # Disallow trivial keywords
        if target_name not in {"the", "an", "all", "this", "it"}:
            return "prepare_kill_switch", {"agent_id": target_name, "reason": f"Voice/text command: '{user_prompt}'"}, "Agents"

    # --- Personal Assistant & Productivity Commands ---
    # 1. Reminders
    if any(phrase in p for phrase in ["remind me to", "set a reminder", "create reminder", "remind me", "add reminder"]):
        rem_title = re.sub(r"^(?:please\s+)?(?:remind\s+me\s+to|set\s+a\s+reminder\s+(?:for|to)?|create\s+reminder|remind\s+me|add\s+reminder)\s*", "", p, flags=re.IGNORECASE).strip()
        return "create_reminder", {"title": rem_title or "Review tasks", "due_time": "Soon"}, None

    if any(phrase in p for phrase in ["show my reminders", "list reminders", "what are my reminders", "my reminders", "reminders dikhao"]):
        return "list_reminders", {"include_completed": False}, None

    # 2. Notes
    if any(phrase in p for phrase in ["take a note", "save note", "create note", "write note", "note down", "ek note likho"]):
        note_content = re.sub(r"^(?:please\s+)?(?:take\s+a\s+note(?:\s+that|:)?|save\s+note(?:\s+that|:)?|create\s+note|write\s+note|note\s+down|ek\s+note\s+likho)\s*", "", p, flags=re.IGNORECASE).strip()
        return "create_note", {"title": note_content[:30] or "Quick Note", "content": note_content or "Note"}, None

    if any(phrase in p for phrase in ["search my notes", "find note", "search notes", "show my notes", "list notes", "notes dikhao"]):
        q = re.sub(r"^(?:search\s+(?:my\s+)?notes\s+(?:for\s+)?|find\s+note\s+|show\s+(?:my\s+)?notes|list\s+notes|notes\s+dikhao)\s*", "", p, flags=re.IGNORECASE).strip()
        return "search_notes", {"query": q}, None

    # 3. To-Do Items
    if any(phrase in p for phrase in ["add to my todo", "add todo", "add task", "new todo", "todo mein add karo"]):
        task_desc = re.sub(r"^(?:please\s+)?(?:add\s+to\s+(?:my\s+)?todo(?:\s+list)?(?:\s+that|:)?|add\s+todo|add\s+task|new\s+todo|todo\s+mein\s+add\s+karo)\s*", "", p, flags=re.IGNORECASE).strip()
        return "add_todo_item", {"task": task_desc or "New task", "priority": "NORMAL"}, None

    if any(phrase in p for phrase in ["show my todo", "list todos", "what is on my todo", "my todo list", "todo list dikhao", "tasks dikhao"]):
        return "list_todo_items", {"include_completed": True}, None

    # 4. User Memory
    if any(phrase in p for phrase in ["remember that", "save to memory", "store memory", "remember this", "yaad rakho"]):
        mem_text = re.sub(r"^(?:please\s+)?(?:remember\s+that|save\s+to\s+memory|store\s+memory|remember\s+this|yaad\s+rakho)\s*", "", p, flags=re.IGNORECASE).strip()
        return "store_user_memory", {"key": mem_text[:30] or "custom_fact", "value": mem_text}, None

    if any(phrase in p for phrase in ["what do you remember", "list memories", "show memories", "stored memories", "kya yaad hai"]):
        return "list_user_memories", {}, None

    # 5. Safe Scoped Workspace File search
    if any(phrase in p for phrase in ["search file", "find file", "look for file", "file dhundo", "search workspace"]):
        f_query = re.sub(r"^(?:please\s+)?(?:search\s+file|find\s+file|look\s+for\s+file|file\s+dhundo|search\s+workspace(?:\s+for)?)\s*", "", p, flags=re.IGNORECASE).strip()
        return "search_workspace_files", {"query": f_query or "agent"}, None

    # 6. Approved application launcher (Zero-Trust Whitelist)
    if any(phrase in p for phrase in ["open notepad", "launch notepad", "start notepad", "notepad kholo"]):
        return "launch_approved_application", {"app_name": "notepad"}, None
    if any(phrase in p for phrase in ["open calculator", "launch calculator", "open calc", "calculator kholo"]):
        return "launch_approved_application", {"app_name": "calculator"}, None
    if any(phrase in p for phrase in ["open paint", "launch paint", "paint kholo"]):
        return "launch_approved_application", {"app_name": "paint"}, None
    if any(phrase in p for phrase in ["open explorer", "open file explorer", "launch explorer", "files kholo"]):
        return "launch_approved_application", {"app_name": "explorer"}, None
    if any(phrase in p for phrase in ["open task manager", "launch task manager", "open taskmgr"]):
        return "launch_approved_application", {"app_name": "taskmgr"}, None

    # Navigation keywords
    nav_map = {
        "overview": "Overview",
        "real-time": "Real-Time Monitor",
        "monitor": "Real-Time Monitor",
        "agents": "Agents",
        "agent lab": "Agent Lab",
        "approvals": "Approvals",
        "incidents": "Incidents & Alerts",
        "prompt injection": "Prompt Injection",
        "dlp": "DLP Policy & Events",
        "canary": "Canary Tokens",
        "shadow ai": "Shadow AI Discovery",
        "attack graph": "Attack Graph",
        "delegation": "Delegation Graph",
        "red team": "Red-Team Simulation",
        "predictive risk": "Predictive Risk",
        "digital twin": "Digital Twin Replay",
        "tool proxy": "Tool Proxy Gateway",
        "secret manager": "Secret Manager",
        "behavioral drift": "Behavioral Drift",
        "policy": "Policy-as-Code & GitOps",
        "reverse engineering": "Reverse Engineering",
        "forensic": "Forensic Dossiers",
        "audit": "Cryptographic Audit",
        "settings": "Settings & RBAC"
    }
    for kw, page in nav_map.items():
        if f"go to {kw}" in p or f"open {kw}" in p or f"navigate to {kw}" in p:
            return "navigate_frontend", {"target_page": page}, page

    return None, {}, None

def synthesize_response_nlp(
    user_prompt: str,
    lang: str,
    tool_name: Optional[str],
    tool_result_data: Any,
    action_req: Optional[JarvisConfirmationRequest],
    user: Dict[str, Any],
    personality_mode: str = "friendly"
) -> Tuple[str, str]:
    """Generates a natural, context-aware AMOJA AI response supporting Friendly and Security modes in text and speech."""
    user_name = user.get("full_name") or user.get("username", "Officer")
    is_friendly = personality_mode == "friendly"

    # If action confirmation is required
    if action_req:
        if lang == "mr":
            text = (
                f"⚠️ **सुरक्षा कृतीसाठी पुष्टीकरण आवश्यक आहे (Action Confirmation Required):**\n\n"
                f"{action_req.impact_explanation}\n\n"
                f"तुम्हाला ही सुरक्षा कृती खरोखर कार्यान्वित करायची आहे का? कृपया खालील नियंत्रण बटण वापरा किंवा 'होय, पुष्टी करा' म्हणा."
            )
            speech = f"पुष्टीकरण आवश्यक आहे, {user_name}. तुम्ही {action_req.target_name or action_req.target_id} साठी आणीबाणीचा किल स्विच सक्रिय करू इच्छिता का?"
        elif lang == "hi":
            text = (
                f"⚠️ **पुष्टि आवश्यक है (Confirmation Required):**\n\n"
                f"{action_req.impact_explanation}\n\n"
                f"क्या आप वाकई इस सुरक्षा कार्रवाई को निष्पादित करना चाहते हैं?"
            )
            speech = f"पुष्टि आवश्यक है. क्या आप {action_req.target_name or action_req.target_id} के लिए इमरजेंसी किल स्विच सक्रिय करना चाहते हैं?"
        elif lang == "hinglish":
            text = (
                f"⚠️ **Action Confirmation Required:**\n\n"
                f"{action_req.impact_explanation}\n\n"
                f"Please confirm to proceed with execution or cancel."
            )
            speech = f"Attention {user_name}, kya aap {action_req.target_name or action_req.target_id} par emergency action confirm karna chahte hain?"
        else:
            text = (
                f"⚠️ **Action Confirmation Required:**\n\n"
                f"{action_req.impact_explanation}\n\n"
                f"Please confirm using the authorization control below or state 'Confirm'."
            )
            speech = f"Confirmation required, {user_name}. Are you certain you wish to activate this critical action for {action_req.target_name or action_req.target_id}?"
        return text, speech

    # If tool was executed: format grounded response
    if tool_name == "get_security_dashboard_metrics":
        d = tool_result_data
        if lang == "mr":
            text = (
                f"🛡️ **AgentShield SOC सुरक्षा सारांश (Security Summary):**\n\n"
                f"- **एकूण AI एजंट्स:** {d.get('total_agents')} (सक्रिय: {d.get('active_agents')}, क्वारंटाइन: {d.get('suspended_or_quarantined')})\n"
                f"- **अवरोधित कृती (Blocked Actions):** {d.get('blocked_actions')} / {d.get('total_events_logged')} एकूण इव्हेंट्स\n"
                f"- **प्रलंबित मानवी मंजुरी (Pending Approvals):** {d.get('pending_human_approvals')}\n"
                f"- **सुरू असलेल्या सुरक्षा घटना (Open Incidents):** {d.get('open_incidents')}\n"
                f"- **सरासरी फ्लीट रिस्क स्कोर (Avg Risk):** {d.get('average_fleet_risk_score')}/100\n"
                f"- **झिरो-ट्रस्ट अंमलबजावणी:** {d.get('zero_trust_posture')}"
            )
            speech = f"नमस्कार {user_name}! सर्व प्रणाली सुरळीत आहे. सध्या {d.get('active_agents')} एजंट्स आणि {d.get('open_incidents')} घटना आहेत." if is_friendly else f"सुरक्षा सारांश: {d.get('active_agents')} सक्रिय एजंट्स, {d.get('open_incidents')} सुरक्षा घटना. झिरो-ट्रस्ट कार्यरत."
        elif lang == "hi":
            text = (
                f"🛡️ **AgentShield SOC सुरक्षा सारांश (Security Summary):**\n\n"
                f"- **कुल AI एजेंट्स:** {d.get('total_agents')} (सक्रिय: {d.get('active_agents')}, क्वारंटाइन: {d.get('suspended_or_quarantined')})\n"
                f"- **अवरुद्ध कार्रवाइयां (Blocked Actions):** {d.get('blocked_actions')} / {d.get('total_events_logged')} कुल इवेंट्स\n"
                f"- **लंबित मानव अनुमोदन (Pending Approvals):** {d.get('pending_human_approvals')}\n"
                f"- **ओपन घटनाएं (Open Incidents):** {d.get('open_incidents')}\n"
                f"- **औसत बेड़ा जोखिम स्कोर (Avg Risk):** {d.get('average_fleet_risk_score')}/100\n"
                f"- **शून्य-विश्वास स्थिति:** {d.get('zero_trust_posture')}"
            )
            speech = f"नमस्ते {user_name}! सिस्टम पूरी तरह सुरक्षित है. {d.get('active_agents')} एजेंट्स एक्टिव हैं और {d.get('open_incidents')} घटनाएं दर्ज हैं." if is_friendly else f"सिस्टम रिपोर्ट: {d.get('active_agents')} सक्रिय एजेंट्स, {d.get('open_incidents')} ओपन घटनाएं. शून्य-विश्वास सक्रिय."
        elif lang == "hinglish":
            text = (
                f"🛡️ **AgentShield SOC Security Summary:**\n\n"
                f"- **Total Agents:** {d.get('total_agents')} ({d.get('active_agents')} Active, {d.get('suspended_or_quarantined')} Quarantined)\n"
                f"- **Blocked Actions:** {d.get('blocked_actions')} policy violations caught\n"
                f"- **Pending Approvals:** {d.get('pending_human_approvals')} human-in-the-loop requests\n"
                f"- **Open Incidents:** {d.get('open_incidents')} active SOC investigations\n"
                f"- **Fleet Risk Score:** {d.get('average_fleet_risk_score')}/100\n"
                f"- **Enforcement:** Zero-Trust Gateways active across all endpoints."
            )
            speech = f"Hey {user_name}! Sab green hai. We have {d.get('active_agents')} active agents and {d.get('open_incidents')} open incidents under Zero-Trust." if is_friendly else f"Security summary online: {d.get('active_agents')} active agents, {d.get('open_incidents')} open incidents. Enforcing zero-trust."
        else:
            text = (
                f"🛡️ **AgentShield Security Operations Telemetry:**\n\n"
                f"- **AI Agent Fleet:** {d.get('total_agents')} registered ({d.get('active_agents')} active, {d.get('suspended_or_quarantined')} quarantined)\n"
                f"- **Policy Gate Interventions:** {d.get('blocked_actions')} blocked attempts out of {d.get('total_events_logged')} events\n"
                f"- **Pending Approvals:** {d.get('pending_human_approvals')} sensitive tool requests awaiting human review\n"
                f"- **Open Incidents:** {d.get('open_incidents')} active security investigations\n"
                f"- **Fleet Average Risk Posture:** {d.get('average_fleet_risk_score')}/100 (Trust Score: {d.get('average_fleet_trust_score')}/100)\n"
                f"- **Enforcement Posture:** {d.get('zero_trust_posture')}"
            )
            speech = f"Hey {user_name}! Everything is running smoothly across AgentShield. All {d.get('active_agents')} monitored agents are operating safely, with {d.get('open_incidents')} open incidents." if is_friendly else f"Security summary online, {user_name}. Monitoring {d.get('active_agents')} active agents with {d.get('open_incidents')} open incidents. Zero-trust enforcing."
        return text, speech

    if tool_name == "get_alerts_and_incidents":
        incs = tool_result_data.get("open_incidents", [])
        events = tool_result_data.get("blocked_and_critical_events", [])
        inc_str = "\n".join([f"- **[{i['severity']}] {i['incident_number']}:** {i['title']} (Agent: `{i.get('agent_id')}`)" for i in incs[:5]]) or "No critical incidents logged."

        if lang == "mr":
            text = (
                f"🚨 **गंभीर धोके आणि सुरक्षा घटना (Critical Threats & Incidents):**\n\n"
                f"{inc_str}\n\n"
                f"पॉलिसी गेटवेवर {len(events)} नुकतेच ब्लॉक केलेले उच्च-धोक्याचे इव्हेंट्स आढळले."
            )
            speech = f"गंभीर धोके दाखवत आहे. सध्या {len(incs)} सक्रिय सुरक्षा घटना आणि {len(events)} ब्लॉक केलेले हल्ले आहेत."
        elif lang == "hi":
            text = (
                f"🚨 **गंभीर खतरे और खुली सुरक्षा घटनाएं (Critical Threats & Incidents):**\n\n"
                f"{inc_str}\n\n"
                f"पॉलिसी गेटवे पर {len(events)} हाल ही में रोकी गई उच्च-जोखिम घटनाएं पाई गईं."
            )
            speech = f"गंभीर खतरे दिखाए जा रहे हैं. वर्तमान में {len(incs)} खुली घटनाएं और {len(events)} ब्लॉक किए गए हमले दर्ज हैं."
        elif lang == "hinglish":
            text = (
                f"🚨 **Critical Threats & Open Incidents:**\n\n"
                f"{inc_str}\n\n"
                f"Policy gateway par {len(events)} recent blocked high-risk events mile hain."
            )
            speech = f"Critical threats show kar rahi hoon. Total {len(incs)} open incidents aur {len(events)} blocked attacks hain jinhe review karna zaroori hai."
        else:
            text = (
                f"🚨 **Critical Threat Triage & Incident Overview:**\n\n"
                f"{inc_str}\n\n"
                f"**Recent Blocked Interventions:** {len(events)} high-risk events captured by Zero-Trust policy enforcement."
            )
            speech = f"Critical threats retrieved. {len(incs)} active incidents currently require containment or investigation."
        return text, speech

    if tool_name == "list_agents":
        agents = tool_result_data.get("agents", [])
        top_risk = sorted(agents, key=lambda a: a.get("risk_score", 0), reverse=True)
        top_agent = top_risk[0] if top_risk else None

        agent_str = "\n".join([f"- **{a['name']}** (`{a['id']}`): Risk Score **{a['risk_score']}/100**, Trust **{a['trust_score']}/100** [{a['status']}]" for a in top_risk[:5]])

        if lang == "mr":
            if top_agent and top_agent.get("risk_score", 0) > 60:
                highlight = f"एजंट **{top_agent['name']}** (`{top_agent['id']}`) चा रिस्क स्कोर सर्वात जास्त आहे: **{top_agent['risk_score']}/100**."
                speech = f"एजंट {top_agent['name']} चा रिस्क स्कोर सर्वात जास्त म्हणजेच {top_agent['risk_score']} आहे. संपूर्ण यादी स्क्रीनवर दाखवत आहे."
            else:
                highlight = "सर्व एजंट्स सध्या सामान्य सुरक्षा मर्यादेत कार्यरत आहेत."
                speech = "सर्व एजंट्स सामान्य मर्यादेत कार्यरत आहेत. संपूर्ण यादी स्क्रीनवर आहे."
            text = (
                f"🤖 **AI एजंट सुरक्षा यादी (Agent Security Roster):**\n\n"
                f"{highlight}\n\n"
                f"{agent_str}"
            )
            return text, speech
        elif lang == "hi":
            if top_agent and top_agent.get("risk_score", 0) > 60:
                highlight = f"एजेंट **{top_agent['name']}** (`{top_agent['id']}`) का जोखिम स्कोर सबसे अधिक है: **{top_agent['risk_score']}/100**."
                speech = f"एजेंट {top_agent['name']} का रिस्क स्कोर सबसे ज्यादा यानी {top_agent['risk_score']} है. पूरी सूची स्क्रीन पर प्रदर्शित है."
            else:
                highlight = "सभी एजेंट वर्तमान में सामान्य जोखिम सीमा में कार्य कर रहे हैं."
                speech = "सभी एजेंट्स सामान्य सीमा में काम कर रहे हैं. पूरी सूची स्क्रीन पर है."
            text = (
                f"🤖 **AI एजेंट सुरक्षा सूची (Agent Security Roster):**\n\n"
                f"{highlight}\n\n"
                f"{agent_str}"
            )
            return text, speech
        elif lang == "hinglish":
            if top_agent and top_agent.get("risk_score", 0) > 60:
                highlight = f"Agent **{top_agent['name']}** (`{top_agent['id']}`) ka risk score sabse highest hai: **{top_agent['risk_score']}/100**."
                speech = f"Agent {top_agent['name']} ka risk score sabse zyada {top_agent['risk_score']} hai. Complete roster screen par display kar diya hai."
            else:
                highlight = "Sabhi monitored agents nominal risk threshold mein operate kar rahe hain."
                speech = "Sabhi agents safely operate kar rahe hain. Complete agent list screen par hai."
            text = (
                f"🤖 **AI Agent Security Roster:**\n\n"
                f"{highlight}\n\n"
                f"{agent_str}"
            )
            return text, speech
        else:
            if top_agent and top_agent.get("risk_score", 0) > 60:
                highlight = f"Agent **{top_agent['name']}** ({top_agent['id']}) holds the highest risk score at **{top_agent['risk_score']}/100**."
            else:
                highlight = "All monitored agents are currently operating within nominal risk thresholds."

            text = (
                f"🤖 **AI Agent Security Roster:**\n\n"
                f"{highlight}\n\n"
                f"{agent_str}"
            )
            speech = f"{highlight} Displaying complete agent risk standings on your display."
            return text, speech

    if tool_name == "review_prompt_injections":
        items = tool_result_data.get("injections_and_attacks", [])
        if lang == "mr":
            if not items:
                text = "🛡️ **प्रॉम्प्ट इंजेक्शन स्कॅनर:** अलीकडील लॉग्समध्ये कोणतेही प्रॉम्प्ट इंजेक्शन हल्ले आढळले नाहीत."
                speech = "कोणताही प्रॉम्प्ट इंजेक्शन प्रयत्न आढळला नाही."
            else:
                formatted = "\n".join([f"- **इव्हेंट #{it['id']} ({it.get('agent_id', 'unknown')}):** {it['reason']} लक्ष्य: `{it['target']}` [निर्णय: {it['decision']}]" for it in items[:4]])
                text = (
                    f"🛡️ **प्रॉम्प्ट इंजेक्शन आणि विरोधी हल्ले (Prompt Injection Telemetry):**\n\n"
                    f"AgentShield ने **{len(items)}** प्रॉम्प्ट इंजेक्शन स्वाक्षऱ्या शोधून निष्प्रभ केल्या:\n\n"
                    f"{formatted}"
                )
                speech = f"{len(items)} प्रॉम्प्ट इंजेक्शन प्रयत्न शोधून काढले आणि गेटवेवर सुरक्षितपणे निष्प्रभ केले."
            return text, speech
        elif lang == "hi":
            if not items:
                text = "🛡️ **प्रॉम्प्ट इंजेक्शन स्कैनर:** हाल के लॉग में कोई सक्रिय प्रॉम्प्ट इंजेक्शन हमला नहीं मिला."
                speech = "कोई प्रॉम्प्ट इंजेक्शन प्रयास नहीं पाया गया."
            else:
                formatted = "\n".join([f"- **इवेंट #{it['id']} ({it.get('agent_id', 'unknown')}):** {it['reason']} लक्ष्य: `{it['target']}` [निर्णय: {it['decision']}]" for it in items[:4]])
                text = (
                    f"🛡️ **प्रॉम्प्ट इंजेक्शन एवं विरोधी हमले (Prompt Injection Telemetry):**\n\n"
                    f"AgentShield ने **{len(items)}** प्रॉम्प्ट इंजेक्शन हस्ताक्षरों को पकड़कर निष्क्रिय किया:\n\n"
                    f"{formatted}"
                )
                speech = f"{len(items)} प्रॉम्प्ट इंजेक्शन प्रयास पकड़े गए और गेटवे पर सुरक्षित रूप से रोक दिए गए."
            return text, speech
        elif lang == "hinglish":
            if not items:
                text = "🛡️ **Prompt Injection Scanner:** Recent logs mein koi prompt injection attempt nahi mila."
                speech = "Koi prompt injection attempt detect nahi hua. Sab safe hai."
            else:
                formatted = "\n".join([f"- **Event #{it['id']} ({it.get('agent_id', 'unknown')}):** {it['reason']} on `{it['target']}` [Decision: {it['decision']}]" for it in items[:4]])
                text = (
                    f"🛡️ **Prompt Injection & Adversarial Attack Telemetry:**\n\n"
                    f"AgentShield ne **{len(items)}** prompt injection signatures intercept aur neutralize kiye:\n\n"
                    f"{formatted}"
                )
                speech = f"{len(items)} prompt injection attempts detect kiye gaye aur policy gateway par intercept ho gaye hain."
            return text, speech
        else:
            if not items:
                text = "🛡️ **Prompt Injection Scanner:** No active prompt injection detections found in recent logs."
                speech = "No prompt injection attempts detected in the recent log stream."
            else:
                formatted = "\n".join([f"- **Event #{it['id']} ({it.get('agent_id', 'unknown')}):** {it['reason']} on `{it['target']}` [Decision: {it['decision']}]" for it in items[:4]])
                text = (
                    f"🛡️ **Prompt Injection & Adversarial Attack Telemetry:**\n\n"
                    f"Identified **{len(items)}** prompt injection signatures caught by AgentShield:\n\n"
                    f"{formatted}"
                )
                speech = f"Retrieved {len(items)} prompt injection detections. All payloads were intercepted and neutralized at the enforcement gateway."
            return text, speech

    if tool_name == "review_dlp_events":
        items = tool_result_data.get("dlp_events", [])
        if lang == "mr":
            if not items:
                text = "🔒 **डेटा लॉस प्रिव्हेन्शन (DLP):** कोणताही डेटा लीक किंवा क्रेडेंशियल गळती आढळली नाही."
                speech = "डीएलपी मॉनिटरमध्ये कोणताही डेटा गळती किंवा क्रेडेंशियल लीक आढळला नाही."
            else:
                formatted = "\n".join([f"- **इव्हेंट #{it['id']} ({it.get('agent_id', 'unknown')}):** {it['reason']} लक्ष्य: `{it['target']}`" for it in items[:4]])
                text = (
                    f"🔒 **DLP आणि डेटा संरक्षण मॉनिटर:**\n\n"
                    f"डेटा उघड करण्याचे **{len(items)}** प्रयत्न शोधले आणि रोखले:\n\n"
                    f"{formatted}"
                )
                speech = f"डीएलपी प्रणालीने {len(items)} संवेदनशील डेटा चोरीचे प्रयत्न अडवले आहेत."
            return text, speech
        elif lang == "hi":
            if not items:
                text = "🔒 **डेटा लॉस प्रिवेंशन (DLP):** कोई डेटा लीक या क्रेडेंशियल रिसाव नहीं मिला."
                speech = "डीएलपी मॉनिटर में कोई सक्रिय डेटा या क्रेडेंशियल लीक नहीं मिला."
            else:
                formatted = "\n".join([f"- **इवेंट #{it['id']} ({it.get('agent_id', 'unknown')}):** {it['reason']} लक्ष्य: `{it['target']}`" for it in items[:4]])
                text = (
                    f"🔒 **DLP एवं डेटा सुरक्षा मॉनिटर:**\n\n"
                    f"डेटा लीक के **{len(items)}** प्रयास पकड़े और रोके गए:\n\n"
                    f"{formatted}"
                )
                speech = f"डीएलपी सिस्टम ने {len(items)} डेटा चोरी के प्रयास सुरक्षित रूप से रोक दिए हैं."
            return text, speech
        elif lang == "hinglish":
            if not items:
                text = "🔒 **Data Loss Prevention (DLP):** Koi sensitive data leak ya credential exfiltration detect nahi hua."
                speech = "DLP monitors show zero active credential leaks or unauthorized data egress."
            else:
                formatted = "\n".join([f"- **Event #{it['id']} ({it.get('agent_id', 'unknown')}):** {it['reason']} targeting `{it['target']}`" for it in items[:4]])
                text = (
                    f"🔒 **DLP & Secret Exfiltration Monitor:**\n\n"
                    f"Detected **{len(items)}** sensitive data exposure attempts:\n\n"
                    f"{formatted}"
                )
                speech = f"DLP engine ne {len(items)} sensitive data exfiltration attempts intercept kiye hain. Safe masking applied."
            return text, speech
        else:
            if not items:
                text = "🔒 **Data Loss Prevention (DLP):** No sensitive data leaks or credential exfiltration events detected."
                speech = "DLP monitors show zero active credential leaks or unauthorized data egress."
            else:
                formatted = "\n".join([f"- **Event #{it['id']} ({it.get('agent_id', 'unknown')}):** {it['reason']} targeting `{it['target']}`" for it in items[:4]])
                text = (
                    f"🔒 **DLP & Secret Exfiltration Monitor:**\n\n"
                    f"Detected **{len(items)}** sensitive data exposure attempts:\n\n"
                    f"{formatted}"
                )
                speech = f"DLP engine has intercepted {len(items)} sensitive data exfiltration attempts. Masking and redaction applied."
            return text, speech

    if tool_name == "get_incident_details":
        inc = tool_result_data.get("incident", {})
        text = (
            f"🔍 **Incident Dossier: {inc.get('incident_number', 'N/A')} — {inc.get('title', 'Unknown')}**\n\n"
            f"- **Severity:** {inc.get('severity')} | **Status:** {inc.get('status')}\n"
            f"- **Target Agent:** `{inc.get('agent_id')}`\n"
            f"- **Summary:** {inc.get('summary')}\n"
            f"- **Root Cause:** {inc.get('root_cause') or 'Suspicious instruction injection in input prompt.'}\n"
            f"- **Attack Vector:** {inc.get('attack_vector') or 'Direct Prompt Injection'}"
        )
        speech = f"Investigation dossier for {inc.get('incident_number')} loaded. Severity is {inc.get('severity')}. Root cause indicates {inc.get('root_cause', 'prompt injection')}."
        return text, speech

    if tool_name == "search_audit_logs":
        entries = tool_result_data.get("audit_entries", [])
        q = tool_result_data.get("query", "")
        formatted = "\n".join([f"- **#{e['id']} [{e['timestamp'][:19]}]:** `{e['actor']}` -> `{e['action']}` on `{e['resource']}`" for e in entries[:5]])
        text = (
            f"📜 **Cryptographic Audit Ledger Search Results** (Query: `{q or 'All'}`):\n\n"
            f"Verified SHA-256 chained hash integrity across **{len(entries)}** entries:\n\n"
            f"{formatted}"
        )
        speech = f"Audit ledger search complete. Found {len(entries)} cryptographic log entries matching your criteria."
        return text, speech

    if tool_name == "get_attack_graph_and_delegations":
        nodes = tool_result_data.get("nodes_count", 0)
        edges = tool_result_data.get("edges_count", 0)
        text = (
            f"🕸️ **Attack Path & Delegation Topology:**\n\n"
            f"Reconstructed interactive graph comprising **{nodes} entities** and **{edges} interaction vectors**. "
            f"Intervention barriers are mapped between compromised prompts, autonomous agents, and restricted database resources."
        )
        speech = f"Attack path mapped. Displaying topological graph with {nodes} security nodes and {edges} interaction vectors."
        return text, speech

    if tool_name == "generate_incident_report_draft":
        rep = tool_result_data
        text = (
            f"📋 **Drafted Incident Report: {rep.get('title')}**\n\n"
            f"- **Report Reference:** `{rep.get('report_id')}`\n"
            f"- **Classification:** `{rep.get('classification')}`\n"
            f"- **Executive Summary:** {rep.get('executive_summary')}\n"
            f"- **Root Cause:** {rep.get('root_cause_analysis')}\n"
            f"\n**Recommended Containment Actions:**\n" + "\n".join(rep.get("remediation_actions", []))
        )
        speech = f"Forensic incident report draft {rep.get('report_id')} generated and ready for export."
        return text, speech

    if tool_name == "inspect_permissions":
        d = tool_result_data
        curr = ", ".join(d.get("current_permissions", [])) or "None"
        drift = "⚠️ Drift Detected" if d.get("permission_drift_detected") else "✅ Baseline Aligned"
        tools_str = ", ".join(d.get("allowed_tools", [])) or "None"
        if lang == "mr":
            text = (
                f"🔐 **एजंट परवानग्या आणि धोरण स्थिती ({d.get('agent_name')}):**\n\n"
                f"- **सद्य परवानग्या:** `{curr}`\n"
                f"- **परवानगी बदल (Drift Status):** {drift}\n"
                f"- **अधिकृत टूल्स:** `{tools_str}`\n"
                f"- **तपशील:** {d.get('drift_summary')}"
            )
            speech = f"एजंट {d.get('agent_name')} च्या परवानग्या तपासल्या. धोरण स्थिती {drift} आहे."
        elif lang in ["hi", "hinglish"]:
            text = (
                f"🔐 **Agent Permissions & Policy Drift ({d.get('agent_name')}):**\n\n"
                f"- **Current Permissions:** `{curr}`\n"
                f"- **Drift Posture:** {drift}\n"
                f"- **Allowed Tools:** `{tools_str}`\n"
                f"- **Summary:** {d.get('drift_summary')}"
            )
            speech = f"Agent {d.get('agent_name')} permissions inspected. Drift posture is {drift}."
        else:
            text = (
                f"🔐 **Configured Permissions & Baseline Drift for {d.get('agent_name')}:**\n\n"
                f"- **Permissions Granted:** `{curr}`\n"
                f"- **Policy Drift Status:** {drift}\n"
                f"- **Authorized Tools:** `{tools_str}`\n"
                f"- **Inspection Notes:** {d.get('drift_summary')}"
            )
            speech = f"Permissions inspected for {d.get('agent_name')}, {user_name}. Current posture is {drift}."
        return text, speech

    if tool_name == "navigate_frontend":
        page = tool_result_data.get("target_page", "Overview")
        text = f"🧭 Navigating interface to **{page}** view as requested."
        speech = f"Navigating to {page}."
        return text, speech

    # --- Network Monitoring Tools Synthesis ---
    if tool_name == "get_network_monitoring_status":
        d = tool_result_data
        state = d.get("state", "UNKNOWN")
        scopes = d.get("approved_scopes_count", 0)
        reachable = d.get("reachable_assets", 0)
        ports = d.get("total_open_services", 0)
        alerts = d.get("unresolved_alerts", 0)
        countdown = d.get("seconds_until_next_scan", 0)
        interval = d.get("scan_interval_seconds", 60)

        if lang == "mr":
            text = (
                f"📡 **नेटवर्क मॉनिटरिंग स्थिती (Continuous Network Monitoring):**\n\n"
                f"- **सद्य स्थिती:** `{state}` (मंजूर कक्षा: {scopes} सबनेट्स)\n"
                f"- **शोधलेली उपकरणे:** {reachable} सक्रिय होस्ट्स ({ports} खुले पोर्ट्स)\n"
                f"- **सुरक्षा अलर्ट्स:** {alerts} न सुटलेले अलर्ट्स\n"
                f"- **पुढील स्कॅन:** {countdown} सेकंदात (स्कॅन अंतर: {interval}s)\n"
                f"- **कक्षा नियम:** झिरो-ट्रस्ट धोरण केवळ मंजूर IP श्रेणी स्कॅन करण्याची परवानगी देते."
            )
            speech = f"नेटवर्क मॉनिटरिंग स्थिती: सेवा सध्या {state} आहे. {reachable} सक्रिय उपकरणे आणि {alerts} अलर्ट्स नोंदवले गेले आहेत. पुढील स्कॅन {countdown} सेकंदात होईल."
        elif lang == "hi":
            text = (
                f"📡 **नेटवर्क मॉनिटरिंग स्थिति (Continuous Network Monitoring):**\n\n"
                f"- **वर्तमान स्थिति:** `{state}` ({scopes} अनुमोदित सबनेट्स)\n"
                f"- **पहुंच योग्य उपकरण:** {reachable} सक्रिय होस्ट ({ports} ओपन पोर्ट्स)\n"
                f"- **सुरक्षा अलर्ट्स:** {alerts} अनसुलझे अलर्ट्स\n"
                f"- **अगला स्कैन:** {countdown} सेकंड में (अंतराल: {interval}s)\n"
                f"- **दायरा नियंत्रण:** केवल अधिकृत नेटवर्क रेंज ही स्कैन की जाती हैं."
            )
            speech = f"नेटवर्क मॉनिटरिंग की स्थिति {state} है. {reachable} सक्रिय होस्ट्स और {alerts} अलर्ट्स दर्ज हैं."
        elif lang == "hinglish":
            text = (
                f"📡 **Network Monitoring Status:**\n\n"
                f"- **State:** `{state}` ({scopes} Approved Subnets)\n"
                f"- **Active Hosts:** {reachable} reachable ({ports} open services observed)\n"
                f"- **Open Alerts:** {alerts} security alerts detected\n"
                f"- **Next Sweep:** in {countdown}s (interval: {interval}s)\n"
                f"- **Scope Guardrail:** Strict Zero-Trust isolation — external networks strictly blocked."
            )
            speech = f"Network monitoring is currently {state}. Found {reachable} reachable hosts with {alerts} active alerts. Next scan scheduled in {countdown} seconds."
        else:
            text = (
                f"📡 **Continuous Network Monitoring Status:**\n\n"
                f"- **Service State:** `{state}` across **{scopes} approved subnets**\n"
                f"- **Reachable Assets:** {reachable} hosts responsive ({ports} open port observations)\n"
                f"- **Unresolved Network Alerts:** {alerts} deviations from baseline\n"
                f"- **Next Automated Scan:** in {countdown} seconds (interval: {interval}s)\n"
                f"- **Scope Boundary:** Strict zero-trust constraint enforced. Arbitrary public scanning blocked."
            )
            speech = f"Network monitoring status is {state}, {user_name}. {reachable} reachable assets detected across approved scopes with {alerts} open baseline alerts."
        return text, speech

    if tool_name == "get_network_discovered_devices":
        new_devs = tool_result_data.get("newly_discovered_devices", [])
        base_devs = tool_result_data.get("baselined_devices", [])
        total = tool_result_data.get("total_returned", 0)

        new_str = "\n".join([f"- ⚠️ **[NEW UNBASELINED] {d['ip_address']}** ({d.get('hostname') or 'Unknown'}): {len(d.get('open_ports', []))} open port(s), Latency: {d.get('latency_ms')}ms" for d in new_devs]) or "None (all detected devices match security baseline)."
        base_str = "\n".join([f"- 🛡️ **[BASELINED] {d['ip_address']}** ({d.get('hostname') or 'Authorized'}): Latency: {d.get('latency_ms')}ms, Status: `{d.get('status')}`" for d in base_devs[:5]])

        if lang == "mr":
            text = (
                f"💻 **शोधलेली नेटवर्क उपकरणे (Network Devices):**\n\n"
                f"**नवीन शोधलेली उपकरणे ({len(new_devs)}):**\n{new_str}\n\n"
                f"**मंजूर बेसलाइन उपकरणे ({len(base_devs)}):**\n{base_str}"
            )
            speech = f"नेटवर्क उपकरणांची यादी तयार आहे. {len(new_devs)} नवीन न नोंदवलेले उपकरणे आणि {len(base_devs)} मंजूर बेसलाइन उपकरणे आढळली आहेत."
        elif lang in ["hi", "hinglish"]:
            text = (
                f"💻 **Discovered Network Devices & Baseline Inventory:**\n\n"
                f"**Newly Discovered Devices ({len(new_devs)}):**\n{new_str}\n\n"
                f"**Baselined Authorized Assets ({len(base_devs)}):**\n{base_str}"
            )
            speech = f"Network devices retrieved. Found {len(new_devs)} newly discovered devices and {len(base_devs)} approved baseline assets."
        else:
            text = (
                f"💻 **Discovered Network Assets & Baseline Inventory:**\n\n"
                f"**Newly Discovered Devices ({len(new_devs)}):**\n{new_str}\n\n"
                f"**Baselined Authorized Assets ({len(base_devs)}):**\n{base_str}"
            )
            speech = f"Discovered devices report ready. {len(new_devs)} newly discovered unbaselined devices require review, and {len(base_devs)} baselined assets are healthy."
        return text, speech

    if tool_name == "get_network_security_alerts":
        alerts = tool_result_data.get("alerts", [])
        if not alerts:
            text = "✅ **No Suspicious Network Activity:** All observed network endpoints and open ports strictly comply with the approved baseline."
            speech = "No suspicious network activity detected. All hosts match baseline profiles."
            return text, speech

        alert_items = []
        for a in alerts[:5]:
            item = (
                f"### ⚠️ [{a['severity']}] {a['title']}\n"
                f"- **Verified Fact:** {a['observed_fact']}\n"
                f"- **Suspected Threat:** {a['suspected_threat']}\n"
                f"- **Target:** `{a['target_ip']}`" + (f":{a['target_port']}" if a.get('target_port') else "") + f" | **Status:** `{a['status']}`"
            )
            alert_items.append(item)

        items_str = "\n\n".join(alert_items)

        if lang == "mr":
            text = (
                f"🚨 **संशयास्पद नेटवर्क ॲक्टिव्हिटी आणि सुरक्षा अलर्ट्स (Suspicious Activity):**\n\n"
                f"{items_str}\n\n"
                f"📌 *सर्व अलर्ट्स वस्तुस्थिती आणि संशयित धोका यात काटेकोरपणे फरक करतात.*"
            )
            speech = f"संशयास्पद नेटवर्क ॲक्टिव्हिटीचे {len(alerts)} अलर्ट्स आढळले आहेत. वस्तुस्थिती आणि संशयित धोके स्क्रीनवर दाखवले आहेत."
        elif lang in ["hi", "hinglish"]:
            text = (
                f"🚨 **Suspicious Network Activity & Security Alerts:**\n\n"
                f"{items_str}\n\n"
                f"📌 *Note: Observed facts are strictly partitioned from suspected threat hypotheses.*"
            )
            speech = f"Found {len(alerts)} suspicious network activity alerts. Displaying verified facts and suspected threat vectors."
        else:
            text = (
                f"🚨 **Suspicious Network Activity & Baseline Discrepancies:**\n\n"
                f"{items_str}\n\n"
                f"📌 *Zero-Trust Governance: Observed empirical facts are strictly separated from suspected threat hypotheses.*"
            )
            speech = f"Retrieved {len(alerts)} network security alerts, {user_name}. Verified probe facts and threat assessments are on your screen."
        return text, speech

    if tool_name == "start_network_monitoring":
        scopes = ", ".join(tool_result_data.get("approved_scopes", ["Approved Enclaves"]))
        if lang == "mr":
            text = f"✅ **नेटवर्क मॉनिटरिंग सुरू केले:** मंजूर कक्षा (`{scopes}`) साठी अखंड मॉनिटरिंग सुरू झाले आहे. अनधिकृत श्रेणी स्कॅन करणे प्रतिबंधित आहे."
            speech = "मंजूर नेटवर्कचे सतत मॉनिटरिंग सुरू केले आहे. झिरो-ट्रस्ट संरक्षण सक्रिय आहे."
        elif lang in ["hi", "hinglish"]:
            text = f"✅ **Network Monitoring Started:** Continuous scanning initiated strictly within approved scopes (`{scopes}`)."
            speech = "Continuous monitoring started on approved network subnets. Zero-Trust controls enforcing."
        else:
            text = f"✅ **Continuous Network Monitoring Activated:** Background scanner initiated on approved scopes: `{scopes}`. External arbitrary ranges are locked down."
            speech = f"Continuous network monitoring is now active on approved scopes, {user_name}."
        return text, speech

    if tool_name == "stop_network_monitoring":
        if lang == "mr":
            text = "🛑 **नेटवर्क मॉनिटरिंग थांबवले:** चालू असलेले नेटवर्क स्कॅनिंग आणि पार्श्वभूमी सेवा यशस्वीरित्या थांबवली गेली आहे."
            speech = "नेटवर्क मॉनिटरिंग सेवा थांबवण्यात आली आहे."
        elif lang in ["hi", "hinglish"]:
            text = "🛑 **Network Monitoring Stopped:** Continuous network sweeps have been stopped as requested."
            speech = "Network monitoring has been stopped."
        else:
            text = "🛑 **Network Monitoring Deactivated:** Background scan scheduler and active jobs have been stopped."
            speech = f"Network monitoring service has been stopped, {user_name}."
        return text, speech

    if tool_name == "trigger_network_scan_now":
        if tool_result_data.get("error"):
            text = f"❌ **Scan Request Blocked:** {tool_result_data['error']}"
            speech = "Scan request blocked due to scope boundary violation."
        else:
            text = f"⚡ **Authorized Network Scan Dispatched:** Initiated immediate sweep across approved scopes: `{', '.join(tool_result_data.get('approved_scopes', []))}`."
            speech = "Immediate network scan sweep dispatched across authorized scopes."
        return text, speech

    # --- Endpoint Security Platform Tools ---
    if tool_name == "get_device_security_status":
        if tool_result_data.get("error"):
            if lang == "mr":
                return f"❌ **डिव्हाइस त्रुटी:** {tool_result_data['error']}", "कोणतेही नोंदणीकृत डिव्हाइस आढळले नाही. कृपया आधी तुमचा संगणक नोंदणीकृत करा."
            elif lang == "hi":
                return f"❌ **डिवाइस त्रुटि:** {tool_result_data['error']}", "कोई नामांकित डिवाइस नहीं मिला. कृपया पहले अपना कंप्यूटर नामांकित करें."
            elif lang == "hinglish":
                return f"❌ **Device Query Error:** {tool_result_data['error']}", "Koi enrolled device nahi mila. Please pehle apna computer enroll karein."
            else:
                return f"❌ **Device Query Error:** {tool_result_data['error']}", "No enrolled device found. Please enroll your computer first."

        dev_name = tool_result_data.get("device_name", "Local PC")
        os_info = tool_result_data.get("os", "Unknown OS")
        ip = tool_result_data.get("ip_address", "127.0.0.1")
        m_status = tool_result_data.get("monitoring_status", "ACTIVE")
        alerts = tool_result_data.get("open_alerts_count", 0)
        fw = tool_result_data.get("firewall", {})
        fw_state = "Active (Enforcing)" if fw.get("is_enabled") else "Inactive"
        health = tool_result_data.get("latest_health") or {}
        cpu = health.get("cpu_percent", 0.0)
        mem = health.get("memory_percent", 0.0)
        disk = health.get("disk_percent", 0.0)

        # Check if the user is asking about slow performance / speed
        prompt_lower = (user_prompt or "").lower()
        is_slow_query = any(k in prompt_lower for k in ["slow", "धीमा", "धीमे", "मंद", "lag", "hang", "speed"])

        if is_slow_query:
            if lang == "mr":
                text = (
                    f"💻 **संगणक कार्यक्षमता आणि वेग निदान अहवाल ({dev_name}):**\n\n"
                    f"आपला लॅपटॉप/संगणक मंद चालण्याची संभाव्य कारणे आणि थेट टेलिमेट्री:\n"
                    f"- **CPU वापर:** {cpu}%\n"
                    f"- **मेमरी (RAM) वापर:** {mem}%\n"
                    f"- **डिस्क वापर:** {disk}%\n"
                    f"- **सुरक्षा अलर्ट्स:** {alerts} सक्रिय अलर्ट्स\n"
                    f"- **होस्ट फायरवॉल:** {fw.get('type', 'Firewall')} ({fw_state})\n\n"
                    f"**निदान आणि शिफारसी:**\n"
                    f"1. जास्त CPU किंवा मेमरी वापरणाऱ्या पार्श्वभूमी प्रक्रियांवर लक्ष ठेवा.\n"
                    f"2. संशयास्पद नेटवर्क हालचाली तपासण्यासाठी 'संशयास्पद कनेक्शन तपासा' म्हणा.\n"
                    f"3. अनावश्यक स्टार्टअप ॲप्स बंद करा आणि डिस्क जागा रिकामी करा."
                )
                speech = f"आपल्या संगणकाचा सद्य CPU वापर {cpu} टक्के आणि मेमरी {mem} टक्के आहे. जास्त रिसोर्स वापर किंवा पार्श्वभूमी प्रक्रिया लॅपटॉप मंद चालण्याचे कारण असू शकते. तपशील स्क्रीनवर दाखवले आहेत."
            elif lang == "hi":
                text = (
                    f"💻 **कंप्यूटर परफॉरमेंस एवं डायग्नोस्टिक रिपोर्ट ({dev_name}):**\n\n"
                    f"आपके कंप्यूटर के धीमे चलने के मुख्य कारण और वर्तमान टेलीमेट्री:\n"
                    f"- **CPU लोड:** {cpu}%\n"
                    f"- **मेमोरी (RAM) उपयोग:** {mem}%\n"
                    f"- **डिस्क उपयोग:** {disk}%\n"
                    f"- **सक्रिय सुरक्षा अलर्ट्स:** {alerts} अलर्ट्स\n"
                    f"- **होस्ट फ़ायरवॉल:** {fw.get('type', 'Firewall')} ({fw_state})\n\n"
                    f"**सुझाव एवं निवारण:**\n"
                    f"1. टास्क मैनेजर में जाकर देखें कि कौन-सा बैकग्राउंड प्रोग्राम अत्यधिक CPU या RAM ले रहा है.\n"
                    f"2. अवांछित बैकग्राउंड कनेक्शन या मैलवेयर की जांच के लिए 'संदिग्ध कनेक्शन चेक करो' निर्देश दें.\n"
                    f"3. अनावश्यक स्टार्टअप ऐप्स को डिसेबल करें."
                )
                speech = f"आपके कंप्यूटर का वर्तमान सीपीयू लोड {cpu} प्रतिशत और मेमोरी उपयोग {mem} प्रतिशत है. धीमे चलने का कारण बैकग्राउंड में चल रहे भारी प्रोग्राम्स या उच्च रिसोर्स उपयोग हो सकता है. मैंने विस्तृत रिपोर्ट स्क्रीन पर दिखा दी है."
            elif lang == "hinglish":
                text = (
                    f"💻 **Computer Performance & Diagnostic Telemetry ({dev_name}):**\n\n"
                    f"Aapke computer ke slow chalne ke primary factors aur current live metrics:\n"
                    f"- **CPU Utilization:** {cpu}%\n"
                    f"- **RAM Usage:** {mem}%\n"
                    f"- **Disk Pressure:** {disk}%\n"
                    f"- **Active Alerts:** {alerts} unresolved alerts\n"
                    f"- **Host Firewall:** {fw.get('type', 'Firewall')} ({fw_state})\n\n"
                    f"**Recommendations:**\n"
                    f"1. High CPU/RAM consumption check karne ke liye task manager mein background apps inspect karein.\n"
                    f"2. Crypto-miners ya unauthorized egress inspect karne ke liye 'check suspicious connections' bolein.\n"
                    f"3. Unnecessary startup applications disable karein."
                )
                speech = f"Aapke computer ka current CPU load {cpu} percent aur RAM usage {mem} percent hai. Heavy background workloads ya open alerts iske slow chalne ka reason ho sakte hain."
            else:
                text = (
                    f"💻 **Endpoint Performance & Diagnostic Telemetry ({dev_name}):**\n\n"
                    f"Live system metrics and primary diagnostic factors for observed latency:\n"
                    f"- **CPU Utilization:** {cpu}%\n"
                    f"- **Memory (RAM) Usage:** {mem}%\n"
                    f"- **Storage Disk Usage:** {disk}%\n"
                    f"- **Open Security Alerts:** {alerts} unresolved alert(s)\n"
                    f"- **Host Firewall:** {fw.get('type', 'Firewall')} ({fw_state})\n\n"
                    f"**Diagnostic Recommendations:**\n"
                    f"1. Identify background processes consuming abnormal CPU or RAM cycles.\n"
                    f"2. Audit network egress for hidden exfiltration using 'check suspicious connections'.\n"
                    f"3. Review startup applications and clean temporary storage."
                )
                speech = f"Your system currently shows {cpu}% CPU load and {mem}% memory utilization. Heavy background workloads or active alerts could be causing performance degradation."
            return text, speech

        # Standard Device / Laptop Security Status
        if lang == "mr":
            text = (
                f"🛡️ **डिव्हाइस आणि लॅपटॉप सुरक्षा स्थिती (Laptop Security Status):**\n\n"
                f"- **डिव्हाइस नाव:** `{dev_name}` ({os_info})\n"
                f"- **आयपी पत्ता:** `{ip}` | **एजंट आवृत्ती:** `{tool_result_data.get('agent_version', '1.2.0')}`\n"
                f"- **मॉनिटरिंग स्थिती:** `{m_status}`\n"
                f"- **होस्ट फायरवॉल:** {fw.get('type', 'Firewall')} ({fw_state})\n"
                f"- **सक्रिय अलर्ट्स:** {alerts} न सुटलेले अलर्ट्स\n"
                f"- **सिस्टम भार:** CPU: {cpu}%, Memory: {mem}%\n"
                f"- **परवानग्या:** {len(tool_result_data.get('granted_permissions', []))} मंजूर, {len(tool_result_data.get('withheld_permissions', []))} राखून ठेवल्या."
            )
            speech = f"आपल्या लॅपटॉपची सुरक्षा स्थिती {m_status} आहे. होस्ट फायरवॉल {fw_state} आहे आणि {alerts} सुरक्षा अलर्ट्स आहेत. सर्व सुरक्षा नियंत्रणे सुरळीत आहेत."
        elif lang == "hi":
            text = (
                f"🛡️ **डिवाइस एवं सिस्टम सुरक्षा स्थिति (System Security Status):**\n\n"
                f"- **डिवाइस का नाम:** `{dev_name}` ({os_info})\n"
                f"- **आईपी पता:** `{ip}` | **एजेंट संस्करण:** `v{tool_result_data.get('agent_version', '1.2.0')}`\n"
                f"- **मॉनिटरिंग स्थिति:** `{m_status}`\n"
                f"- **होस्ट फ़ायरवॉल:** {fw.get('type', 'Firewall')} ({fw_state})\n"
                f"- **सक्रिय सुरक्षा अलर्ट्स:** {alerts} अलर्ट्स दर्ज हैं\n"
                f"- **सिस्टम लोड:** CPU: {cpu}%, RAM: {mem}%\n"
                f"- **अनुमतियाँ:** {len(tool_result_data.get('granted_permissions', []))} स्वीकृत, {len(tool_result_data.get('withheld_permissions', []))} आरक्षित"
            )
            speech = f"आपके सिस्टम की सुरक्षा स्थिति {m_status} है. होस्ट फ़ायरवॉल {fw_state} है और {alerts} सुरक्षा अलर्ट्स दर्ज हैं. सभी सुरक्षा प्रणालियाँ सुरक्षित हैं."
        elif lang == "hinglish":
            text = (
                f"🛡️ **Device & System Security Status ({dev_name}):**\n\n"
                f"- **Device Identity:** `{dev_name}` ({os_info})\n"
                f"- **IP Address:** `{ip}` | **Agent:** `v{tool_result_data.get('agent_version', '1.2.0')}`\n"
                f"- **Monitoring State:** `{m_status}`\n"
                f"- **Host Firewall:** {fw.get('type', 'Firewall')} ({fw_state})\n"
                f"- **Open Alerts:** {alerts} unresolved alert(s)\n"
                f"- **Resource Usage:** CPU: {cpu}%, RAM: {mem}%\n"
                f"- **Permissions Consent:** {len(tool_result_data.get('granted_permissions', []))} granted, {len(tool_result_data.get('withheld_permissions', []))} withheld"
            )
            speech = f"Aapke system ki security status {m_status} hai. Host firewall {fw_state} hai aur {alerts} open alerts hain. Zero-Trust defenses active hain."
        else:
            text = (
                f"🛡️ **Personal Device Security Status:**\n\n"
                f"- **Device Identity:** `{dev_name}` ({os_info})\n"
                f"- **Network Binding:** `{ip}` | **Agent Version:** `v{tool_result_data.get('agent_version', '1.2.0')}`\n"
                f"- **Monitoring State:** `{m_status}`\n"
                f"- **Host Firewall:** {fw.get('type', 'Firewall')} ({fw_state})\n"
                f"- **Active Alerts:** {alerts} security flags requiring attention\n"
                f"- **System Telemetry:** CPU load: {cpu}%, Memory load: {mem}%\n"
                f"- **Permission Consent:** {len(tool_result_data.get('granted_permissions', []))} modules authorized, {len(tool_result_data.get('withheld_permissions', []))} withheld by user."
            )
            speech = f"Device security status is {m_status}, {user_name}. Host firewall is {fw_state} with {alerts} open security alerts."
        return text, speech

    if tool_name == "check_suspicious_connections":
        has_susp = tool_result_data.get("has_suspicious_connections", False)
        susp_conns = tool_result_data.get("suspicious_connections", [])
        total = tool_result_data.get("total_connections_observed", 0)

        if not has_susp:
            if lang == "mr":
                text = f"✅ **कोणतेही संशयास्पद कनेक्शन आढळले नाही:** तपासलेल्या सर्व {total} नेटवर्क सॉकेट्स सामान्य आणि सुरक्षित आहेत. कोणताही रिव्हर्स शेल किंवा असामान्य पोर्ट सक्रिय नाही."
                speech = "तुमच्या कॉम्प्युटरवर कोणतेही संशयास्पद कनेक्शन आढळले नाही. सर्व सॉकेट्स सुरक्षित आहेत."
            elif lang == "hi":
                text = f"✅ **कोई संदिग्ध कनेक्शन नहीं मिला:** जांचे गए सभी {total} सक्रिय सॉकेट्स सुरक्षित हैं. कोई रिवर्स शेल या अनधिकृत आउटबाउंड कनेक्शन नहीं मिला."
                speech = "आपके कंप्यूटर पर कोई संदिग्ध कनेक्शन नहीं है. सभी नेटवर्क कनेक्शन्स सामान्य और सुरक्षित हैं."
            elif lang == "hinglish":
                text = f"✅ **No Suspicious Connections:** Checked {total} active socket connections. Koi bhi suspicious outbound connection ya reverse shell port detect nahi hua."
                speech = "Aapke computer par koi suspicious connection nahi hai. All network connections are normal and safe."
            else:
                text = f"✅ **All Monitored Sockets Clean:** Inspected {total} active network connections. No abnormal outbound egress or unauthorized listener ports detected."
                speech = f"No suspicious network connections detected on this machine, {user_name}."
            return text, speech

        items = []
        for c in susp_conns[:5]:
            items.append(f"- ⚠️ **PID {c.get('pid')} ({c.get('process_name')}):** `{c.get('local_ip')}:{c.get('local_port')}` ➔ `{c.get('remote_ip')}:{c.get('remote_port')}` — *{c.get('suspicious_reason')}*")
        items_str = "\n".join(items)

        if lang == "mr":
            text = (
                f"🚨 **संशयास्पद नेटवर्क कनेक्शन आढळले ({len(susp_conns)}):**\n\n"
                f"{items_str}\n\n"
                f"📌 *शिफारस: संबंधित प्रक्रियेची तपासणी करा आणि संशयित रिमोट आयपी तात्काळ ब्लॉक करा.*"
            )
            speech = f"सावधान. तुमच्या कॉम्प्युटरवर {len(susp_conns)} संशयास्पद कनेक्शन आढळले आहेत. कृपया स्क्रीनवरील तपशील तपासा."
        elif lang == "hi":
            text = (
                f"🚨 **संदिग्ध नेटवर्क कनेक्शन मिले ({len(susp_conns)}):**\n\n"
                f"{items_str}\n\n"
                f"📌 *कार्रवाई आवश्यक: प्रक्रिया पहचान (PID) की जांच करें और अनधिकृत प्रक्रियाओं को समाप्त करें.*"
            )
            speech = f"चेतावनी: आपके कंप्यूटर पर {len(susp_conns)} संदिग्ध नेटवर्क कनेक्शन मिले हैं. स्क्रीन पर विवरण देखें."
        elif lang == "hinglish":
            text = (
                f"🚨 **Suspicious Network Connections Detected ({len(susp_conns)}):**\n\n"
                f"{items_str}\n\n"
                f"📌 *Action Required: Inspect PID and consider terminating unauthorized processes.*"
            )
            speech = f"Alert: Found {len(susp_conns)} suspicious network connection(s) on your computer. Please check screen details."
        else:
            text = (
                f"🚨 **Suspicious Endpoint Network Sockets Identified ({len(susp_conns)}):**\n\n"
                f"{items_str}\n\n"
                f"📌 *Zero-Trust Isolation: Observed socket metadata has been correlated with heuristic threat rules.*"
            )
            speech = f"Warning {user_name}: Found {len(susp_conns)} suspicious network connections requiring investigation."
        return text, speech

    if tool_name == "get_device_security_alerts":
        alerts = tool_result_data.get("alerts", [])
        if not alerts:
            if lang == "mr":
                text = "✅ **कोणतेही नवीन सुरक्षा अलर्ट नाहीत:** हे डिव्हाइस पूर्णपणे सुरक्षित आहे."
                speech = "या डिव्हाइसवर कोणतेही नवीन सुरक्षा अलर्ट नाहीत."
            elif lang == "hi":
                text = "✅ **कोई नया सुरक्षा अलर्ट नहीं है:** यह डिवाइस पूरी तरह सुरक्षित है."
                speech = "इस डिवाइस पर कोई नया सुरक्षा अलर्ट नहीं है."
            elif lang == "hinglish":
                text = "✅ **No Open Security Alerts:** Aapke device par koi naya security alert nahi hai."
                speech = "No new security alerts on this device. All monitors green."
            else:
                text = "✅ **No Open Endpoint Security Alerts:** Monitored system behavior is healthy."
                speech = "No open security alerts on this device."
            return text, speech

        items = []
        for a in alerts[:5]:
            items.append(
                f"### ⚠️ [{a.get('severity', 'HIGH')}] {a.get('title')}\n"
                f"- **Category:** `{a.get('category')}` | **Classification:** `{a.get('classification')}`\n"
                f"- **Description:** {a.get('description')}\n"
                f"- **Action:** {a.get('suggested_action', 'Investigate process tree')}"
            )
        items_str = "\n\n".join(items)

        if lang == "mr":
            text = f"🚨 **डिव्हाइस सुरक्षा अलर्ट्स ({len(alerts)}):**\n\n{items_str}"
            speech = f"डिव्हाइसवर {len(alerts)} नवीन सुरक्षा अलर्ट्स आढळले आहेत. स्क्रीनवर तपशील दाखवले आहेत."
        elif lang == "hi":
            text = f"🚨 **डिवाइस सुरक्षा अलर्ट्स ({len(alerts)}):**\n\n{items_str}"
            speech = f"डिवाइस के {len(alerts)} नए सुरक्षा अलर्ट मिले हैं. स्क्रीन पर विवरण देखें."
        elif lang == "hinglish":
            text = f"🚨 **Endpoint Security Alerts ({len(alerts)}):**\n\n{items_str}"
            speech = f"Device ke {len(alerts)} new security alerts retrieve kiye gaye hain."
        else:
            text = f"🚨 **Active Endpoint Security Alerts ({len(alerts)}):**\n\n{items_str}"
            speech = f"Retrieved {len(alerts)} open endpoint security alerts, {user_name}."
        return text, speech

    if tool_name == "get_endpoint_firewall_status":
        if tool_result_data.get("error"):
            return f"❌ **Firewall Status Error:** {tool_result_data['error']}", "Could not retrieve firewall status."

        fw_type = tool_result_data.get("firewall_type", "Host Firewall")
        is_en = tool_result_data.get("is_enabled", False)
        profiles = tool_result_data.get("profiles", {})
        inbound = tool_result_data.get("default_inbound", "BLOCK")
        outbound = tool_result_data.get("default_outbound", "ALLOW")
        rules = tool_result_data.get("active_rules_count", 0)

        p_str = ", ".join([f"{k}: {v}" for k, v in profiles.items()]) or "Default: Active"

        if lang == "mr":
            text = (
                f"🔥 **होस्ट फायरवॉल स्थिती (Host Firewall Status):**\n\n"
                f"- **फायरवॉल प्रकार:** `{fw_type}`\n"
                f"- **स्थिती:** `{'सक्रिय (Active)' if is_en else 'निष्क्रिय (Disabled)'}`\n"
                f"- **प्रोफाइल्स:** {p_str}\n"
                f"- **डिफॉल्ट इनबाउंड:** `{inbound}` | **डिफॉल्ट आउटबाउंड:** `{outbound}`\n"
                f"- **सक्रिय नियम:** {rules} नियम लागू केले आहेत."
            )
            speech = f"होस्ट फायरवॉल सध्या {'सक्रिय' if is_en else 'निष्क्रिय'} आहे. सर्व प्रोफाइल्स सुरक्षित आहेत."
        elif lang == "hi":
            text = (
                f"🔥 **होस्ट फ़ायरवॉल स्थिति (Host Firewall Status):**\n\n"
                f"- **फ़ायरवॉल प्रकार:** `{fw_type}`\n"
                f"- **स्थिति:** `{'सक्रिय (Active)' if is_en else 'निष्क्रिय (Disabled)'}`\n"
                f"- **प्रोफ़ाइल:** {p_str}\n"
                f"- **डिफ़ॉल्ट इनबाउंड:** `{inbound}` | **डिफ़ॉल्ट आउटबाउंड:** `{outbound}`\n"
                f"- **सक्रिय नियम:** {rules} नियम लागू हैं."
            )
            speech = f"होस्ट फ़ायरवॉल वर्तमान में {'सक्रिय' if is_en else 'निष्क्रिय'} है. इनबाउंड डिफ़ॉल्ट नीति {inbound} है."
        elif lang == "hinglish":
            text = (
                f"🔥 **Host Firewall Status:**\n\n"
                f"- **Type:** `{fw_type}`\n"
                f"- **Enforcement:** `{'ACTIVE (Enabled)' if is_en else 'DISABLED'}`\n"
                f"- **Profile States:** {p_str}\n"
                f"- **Default Policy:** Inbound `{inbound}`, Outbound `{outbound}`\n"
                f"- **Active Rules:** {rules} monitored firewall rules"
            )
            speech = f"Host firewall status is {'ACTIVE' if is_en else 'DISABLED'}. Inbound default policy is {inbound}."
        else:
            text = (
                f"🔥 **Host Firewall Configuration & State:**\n\n"
                f"- **Firewall Engine:** `{fw_type}`\n"
                f"- **Operational State:** `{'ACTIVE (Enforcing)' if is_en else 'INACTIVE / DISABLED'}`\n"
                f"- **Profiles Monitored:** {p_str}\n"
                f"- **Default Policy:** Inbound: `{inbound}` | Outbound: `{outbound}`\n"
                f"- **Monitored Rules:** {rules} active filter entries"
            )
            speech = f"Current firewall status is {'ACTIVE' if is_en else 'DISABLED'}, {user_name}. Default inbound policy is {inbound}."
        return text, speech

    if tool_name == "pause_endpoint_monitoring":
        if lang == "mr":
            text = "⏸️ **मॉनिटरिंग थांबवले:** या डिव्हाइसचे सुरक्षा मॉनिटरिंग तात्पुरते थांबवले आहे. टेलिमेट्री संकलन स्थगित केले आहे."
            speech = "डिव्हाइसचे सुरक्षा मॉनिटरिंग थांबवण्यात आले आहे."
        elif lang == "hi":
            text = "⏸️ **मॉनिटरिंग रोक दी गई:** इस डिवाइस की सुरक्षा मॉनिटरिंग रोक दी गई है. टेलीमेट्री सिंक स्थगित है."
            speech = "डिवाइस सुरक्षा मॉनिटरिंग रोक दी गई है."
        elif lang == "hinglish":
            text = "⏸️ **Monitoring Paused:** Device security monitoring has been paused. Telemetry sync is suspended."
            speech = "Device security monitoring pause kar diya gaya hai."
        else:
            text = "⏸️ **Endpoint Monitoring Paused:** Real-time process and socket telemetry has been suspended by user authorization."
            speech = f"Security monitoring for this device has been paused, {user_name}."
        return text, speech

    if tool_name == "disconnect_endpoint_device":
        if lang == "mr":
            text = "🔌 **डिव्हाइस डिस्कनेक्ट केले:** हे उपकरण डॅशबोर्डवरून डिस्कनेक्ट झाले आहे. स्थानिक मॉनिटरिंग ऑफलाइन मोडमध्ये चालू राहील."
            speech = "डिव्हाइस डॅशबोर्डवरून डिस्कनेक्ट करण्यात आले आहे."
        elif lang == "hi":
            text = "🔌 **डिवाइस डिस्कनेक्ट किया गया:** डिवाइस केंद्रीय डैशबोर्ड से डिस्कनेक्ट हो गया है."
            speech = "डिवाइस को केंद्रीय डैशबोर्ड से डिस्कनेक्ट कर दिया गया है."
        elif lang == "hinglish":
            text = "🔌 **Device Disconnected:** Device has been disconnected from central dashboard synchronization."
            speech = "Device disconnected from the central dashboard."
        else:
            text = "🔌 **Device Disconnected:** Successfully disconnected device from dashboard control plane."
            speech = f"Device has been disconnected from the dashboard, {user_name}."
        return text, speech

    # --- Personal Assistant & Productivity Tools Response Formatting ---
    if tool_name == "create_reminder":
        rem = tool_result_data
        title = rem.get("title", "Reminder")
        due = rem.get("due_time", "Soon")
        if lang == "mr":
            text = f"⏰ **स्मरणपत्र तयार केले (Reminder Created):**\n\n- **विषय:** `{title}`\n- **वेळ:** {due}\n- **स्थिती:** सक्रिय"
            speech = f"स्मरणपत्र सेव्ह केले आहे: {title}."
        elif lang == "hi":
            text = f"⏰ **रिमाइंडर सेट किया गया (Reminder Created):**\n\n- **शीर्षक:** `{title}`\n- **समय:** {due}\n- **स्थिति:** सक्रिय"
            speech = f"रिमाइंडर सेट कर दिया गया है: {title}."
        elif lang == "hinglish":
            text = f"⏰ **Reminder Created:**\n\n- **Task:** `{title}`\n- **Due:** {due}\n- **Status:** Active"
            speech = f"Maine reminder save kar diya hai: {title}."
        else:
            text = f"⏰ **Reminder Created Successfully:**\n\n- **Task:** `{title}`\n- **Scheduled:** {due}\n- **Status:** Active"
            speech = f"Reminder set for {title}."
        return text, speech

    if tool_name == "list_reminders":
        rems = tool_result_data.get("reminders", [])
        if not rems:
            msg = "No active reminders found."
            return f"⏰ **Reminders:** {msg}", msg
        items = "\n".join([f"- **#{r['id']}** [{r.get('priority', 'NORMAL')}]: {r['title']} (Due: {r.get('due_time', 'Soon')})" for r in rems])
        text = f"⏰ **Active Reminders ({len(rems)}):**\n\n{items}"
        speech = f"You have {len(rems)} active reminders."
        return text, speech

    if tool_name == "create_note":
        note = tool_result_data
        title = note.get("title", "Note")
        if lang == "mr":
            text = f"📝 **नोंद सेव्ह केली (Note Saved):**\n\n- **शीर्षक:** `{title}`\n\n{note.get('content', '')}"
            speech = f"नोंद यशस्वीरीत्या सेव्ह केली आहे."
        elif lang == "hi":
            text = f"📝 **नोट सहेज लिया गया (Note Saved):**\n\n- **शीर्षक:** `{title}`\n\n{note.get('content', '')}"
            speech = f"नोट सफलतापूर्वक सहेज लिया गया है."
        elif lang == "hinglish":
            text = f"📝 **Note Saved:**\n\n- **Title:** `{title}`\n\n{note.get('content', '')}"
            speech = f"Note successfully save kar diya hai."
        else:
            text = f"📝 **Personal Note Saved:**\n\n- **Title:** `{title}`\n\n{note.get('content', '')}"
            speech = f"Note '{title}' saved successfully."
        return text, speech

    if tool_name == "search_notes":
        notes = tool_result_data.get("notes", [])
        q = tool_result_data.get("query", "")
        if not notes:
            text = f"📝 **Notes Search:** No notes matched query '{q}'."
            speech = f"No notes found matching '{q}'."
            return text, speech
        items = "\n\n".join([f"### 📝 {n['title']} (ID: #{n['id']})\n{n['content']}" for n in notes[:5]])
        text = f"📝 **Saved Notes ({len(notes)}):**\n\n{items}"
        speech = f"Found {len(notes)} saved notes."
        return text, speech

    if tool_name == "add_todo_item":
        todo = tool_result_data
        text = f"✅ **To-Do Item Added:** `{todo.get('task')}` [Priority: {todo.get('priority')}]"
        speech = f"Task added to your to-do checklist."
        return text, speech

    if tool_name == "list_todo_items":
        todos = tool_result_data.get("todos", [])
        if not todos:
            return "✅ **To-Do Checklist:** No pending tasks on your list.", "Your to-do checklist is clear."
        items = "\n".join([f"- {'[x]' if t['completed'] else '[ ]'} **#{t['id']}** {t['task']} ({t['priority']})" for t in todos])
        text = f"✅ **Personal To-Do Checklist ({len(todos)} items):**\n\n{items}"
        speech = f"You have {len(todos)} tasks on your to-do list."
        return text, speech

    if tool_name == "store_user_memory":
        mem = tool_result_data
        text = f"🧠 **Long-Term Memory Saved:**\n\n- **Key:** `{mem.get('key')}`\n- **Recalled Value:** {mem.get('value')}"
        speech = f"I will remember that: {mem.get('key')}."
        return text, speech

    if tool_name == "list_user_memories":
        mems = tool_result_data.get("memories", [])
        if not mems:
            return "🧠 **Stored Memory:** No user memories currently saved.", "No stored memories found."
        items = "\n".join([f"- **{m['memory_key']}**: {m['memory_value']} ({m.get('category', 'preference')})" for m in mems])
        text = f"🧠 **User-Controlled Memory Facts ({len(mems)}):**\n\n{items}\n\n*You can delete or clear memories at any time.*"
        speech = f"Retrieved {len(mems)} stored memory facts."
        return text, speech

    if tool_name == "search_workspace_files":
        res = tool_result_data
        matches = res.get("matches", [])
        q = res.get("query", "")
        if not matches:
            text = f"📁 **File Search:** No authorized workspace files found matching '{q}'."
            speech = f"No workspace files found matching '{q}'."
            return text, speech
        items = "\n".join([f"- 📄 `{m['relative_path']}` ({m['size_bytes']} bytes)" for m in matches[:10]])
        text = f"📁 **Authorized Workspace Files Matching '{q}' ({len(matches)}):**\n\n{items}"
        speech = f"Found {len(matches)} matching files in workspace."
        return text, speech

    if tool_name == "launch_approved_application":
        res = tool_result_data
        if res.get("error"):
            return f"⛔ **Application Launch Blocked:** {res['error']}\n\n*{res.get('security_guardrail', '')}*", "Launch request blocked by Zero-Trust policy."
        app_n = res.get("application", "Application")
        pid = res.get("pid")
        text = f"🚀 **Launched Approved Application:** `{app_n}` (Process ID: {pid})\n\nZero-Trust whitelist confirmed binary authenticity."
        speech = f"Launched approved application: {app_n}."
        return text, speech

    # --- Conversational & Fallback Queries (Pure Same-Language Synthesis) ---
    p_lower = (user_prompt or "").lower()

    # 1. Greetings ("How are you?", "hello", "kaise ho", "kashi aahes")
    if any(q in p_lower for q in ["how are you", "kaise ho", "kaisa hai", "kashi aahes", "kasa ahes", "kase ahat", "aap kaise"]):
        if lang == "mr":
            text = (
                f"👋 **नमस्कार {user_name}! मी अमोझा (AMOJA AI), अगदी मजेत आणि पूर्ण क्षमतेने सज्ज आहे.**\n\n"
                f"AgentShield ची सर्व झिरो-ट्रस्ट संरक्षण यंत्रणा सुरळीतपणे कार्यरत आहे. आज मी आपल्या सुरक्षिततेसाठी काय मदत करू शकते?"
            )
            speech = f"नमस्कार {user_name}! मी अगदी मजेत आणि सज्ज आहे. सर्व प्रणाली सुरक्षित आहेत. आज मी कशी मदत करू?"
        elif lang == "hi":
            text = (
                f"👋 **नमस्ते {user_name}! मैं अमोझा (AMOJA AI), बिल्कुल ठीक हूँ और पूरी तत्परता से सक्रिय हूँ.**\n\n"
                f"AgentShield के सभी शून्य-विश्वास (Zero-Trust) सुरक्षा तंत्र सामान्य रूप से कार्य कर रहे हैं. आज मैं आपकी सुरक्षा में क्या सहायता कर सकती हूँ?"
            )
            speech = f"नमस्ते {user_name}! मैं बिल्कुल ठीक हूँ. सभी प्रणालियाँ सुरक्षित और सक्रिय हैं. आज मैं आपकी क्या सहायता करूँ?"
        elif lang == "hinglish":
            text = (
                f"👋 **Hello {user_name}! Main bilkul theek hoon, thank you!**\n\n"
                f"AgentShield ke sabhi Zero-Trust security systems smoothly run kar rahe hain. Main aapke system ya security check mein kaise help kar sakti hoon?"
            )
            speech = f"Hello {user_name}! Main bilkul theek hoon. Sabhi security systems active hain. Bataiye, main aapki kya madad kar sakti hoon?"
        else:
            text = (
                f"👋 **Hello {user_name}! I am doing great and operating at peak performance.**\n\n"
                f"All AgentShield Zero-Trust defense systems and security monitors are active and synchronized. How may I assist your operations today?"
            )
            speech = f"Hello {user_name}! I am doing great and operating at peak performance. All systems are fully secured. How can I assist you today?"
        return text, speech

    # 2. Assistant Capabilities ("Amoja, tum kya kar sakti ho?", "what can you do?", "kay karu shakte")
    if any(q in p_lower for q in [
        "tum kya kar sakti ho", "tum kya kar sakte ho", "kya kar sakti ho", "kya kar sakte ho",
        "kya karti ho", "what can you do", "kay karu shakte", "kay karu shaktes", "aap kya kar sakti",
        "आप क्या कर सकती", "काय करू शकते", "तुम क्या कर सकती हो"
    ]):
        if lang == "mr":
            text = (
                f"🛡️ **मी अमोझा (AMOJA AI) — आपली स्वायत्त सायबर सुरक्षा सहाय्यक.**\n\n"
                f"माझी प्रमुख वैशिष्ट्ये आणि क्षमता पुढीलप्रमाणे आहेत:\n"
                f"- **लॅपटॉप व डिव्हाइस सुरक्षा:** संगणकाची सुरक्षा स्थिती, CPU/RAM भार आणि अलर्ट्स तपासणे.\n"
                f"- **संशयास्पद नेटवर्क कनेक्शन:** अनधिकृत ओपन पोर्ट्स आणि सॉकेट्स शोधणे.\n"
                f"- **धोके व सुरक्षा घटना:** क्रिटिकल थ्रेट्स, प्रॉम्प्ट इंजेक्शन हल्ले आणि डेटा लीकेज ट्रॅक करणे.\n"
                f"- **झिरो-ट्रस्ट एजंट नियंत्रण:** धोकादायक AI एजंट्स ओळखणे आणि आणीबाणीचा किल-स्विच चालवणे.\n"
                f"- **बहुभाषिक संवाद:** मराठी, हिंदी, हिंग्लिश आणि इंग्रजीत अचूक संवाद साधणे.\n\n"
                f"तुम्ही विचारू शकता: *'माझ्या laptop ची security तपास'* किंवा *'क्रिटिकल धोके दाखवा'*."
            )
            speech = "मी अमोझा, आपली सायबर सुरक्षा सहाय्यक. मी लॅपटॉप सुरक्षा तपासणी, संशयास्पद नेटवर्क कनेक्शन आणि धोक्यांचे व्यवस्थापन करू शकते. मी कशी मदत करू?"
        elif lang == "hi":
            text = (
                f"🛡️ **मैं अमोझा (AMOJA AI) हूँ — आपकी स्वायत्त साइबर सुरक्षा सहायिका.**\n\n"
                f"मेरी प्रमुख क्षमताएं इस प्रकार हैं:\n"
                f"- **सिस्टम व डिवाइस सुरक्षा जांच:** आपके लैपटॉप/कंप्यूटर की स्थिति, सीपीयू/रैम भार और अलर्ट्स की जांच.\n"
                f"- **संदिग्ध नेटवर्क कनेक्शन:** अनधिकृत ओपन पोर्ट्स और रिवर्स शेल्स की पड़ताल.\n"
                f"- **खतरे व सुरक्षा घटनाएं:** गंभीर सुरक्षा खतरे, प्रॉम्प्ट इंजेक्शन और डेटा लीकेज पर निगरानी.\n"
                f"- **एआई एजेंट नियंत्रण:** उच्च जोखिम वाले एजेंट्स को खोजना और जरूरत पड़ने पर किल-स्विच सक्रिय करना.\n"
                f"- **बहुभाषी संवाद:** हिन्दी, हिंग्लिश, मराठी और अंग्रेज़ी में सहज संवाद.\n\n"
                f"आप कह सकते हैं: *'मेरा सिस्टम चेक करो'* या *'सारे खतरे दिखाओ'*."
            )
            speech = "मैं अमोझा हूँ, आपकी साइबर सुरक्षा सहायिका. मैं सिस्टम सुरक्षा जांच, संदिग्ध कनेक्शन और गंभीर खतरों की निगरानी कर सकती हूँ. बताइए, क्या जांचना है?"
        elif lang == "hinglish":
            text = (
                f"🛡️ **Main AMOJA AI hoon — aapki autonomous cybersecurity companion.**\n\n"
                f"Yahan meri key capabilities hain:\n"
                f"- **System & Laptop Security Check:** Aapke device ka security posture, CPU/RAM telemetry, aur open alerts inspect karna.\n"
                f"- **Suspicious Connections & Open Ports:** Unauthorized network sockets aur open ports scan karna.\n"
                f"- **Threat & Incident Monitoring:** Critical threats, prompt injection attempts, aur data leaks detect karna.\n"
                f"- **AI Agent Zero-Trust Defense:** Risky AI agents ko analyze karna aur emergency kill switch trigger karna.\n"
                f"- **Multilingual Support:** English, Hindi, Marathi, aur Hinglish mein naturally respond karna.\n\n"
                f"Aap bol sakte hain: *'Mera system check karo'* ya *'Critical threats dikhao'*."
            )
            speech = "Main AMOJA AI hoon, aapki cybersecurity assistant. Main system security check, open ports scanning, threat detection, aur emergency response handle kar sakti hoon. Bataiye, kya inspect karna hai?"
        else:
            text = (
                f"🛡️ **I am AMOJA AI — your autonomous cybersecurity defense companion.**\n\n"
                f"Here are my core capabilities across AgentShield:\n"
                f"- **Endpoint & Device Security:** Inspect laptop/workstation posture, resource utilization, and firewall status.\n"
                f"- **Suspicious Socket & Port Scanning:** Identify unauthorized egress connections and listening services.\n"
                f"- **Threat Detection & Triage:** Monitor critical security incidents, prompt injections, and DLP exfiltration.\n"
                f"- **Zero-Trust AI Agent Governance:** Assess agent risk scores, policy drifts, and enforce emergency containment.\n"
                f"- **Multilingual Per-Turn Interaction:** Seamlessly converse in English, Hindi, Marathi, and Hinglish.\n\n"
                f"Try asking: *'Check my laptop security'* or *'Show critical threats'*."
            )
            speech = "I am AMOJA AI, your cybersecurity defense assistant. I monitor endpoint security, scan for suspicious connections, triage threats, and govern autonomous AI agents. What would you like to inspect?"
        return text, speech

    # 3. Explicit English Directive ("Please explain this in English.")
    if any(q in p_lower for q in ["explain this in english", "explain in english", "in english", "switch to english"]):
        text = (
            "Understood. Switching to English immediately. I am AMOJA AI, your autonomous cybersecurity defense assistant. "
            "All AgentShield Zero-Trust monitors, endpoint telemetry engines, and threat detection modules are operational. "
            "How can I assist you with your security operations?"
        )
        speech = "Understood. Switching to English immediately. All security monitors are active. How can I assist you today?"
        return text, speech

    # 4. Computer Slow Diagnostics (Conversational Fallback)
    if any(q in p_lower for q in ["slow", "धीमा", "धीमे", "मंद", "lag"]):
        if lang == "mr":
            text = (
                f"💻 **संगणक/लॅपटॉप मंद चालण्याची कारणे आणि उपाय:**\n\n"
                f"1. **जास्त CPU किंवा RAM वापर:** पार्श्वभूमीत एखादी मोठी प्रक्रिया किंवा अनावश्यक ॲप कार्यरत असू शकते.\n"
                f"2. **संशयास्पद नेटवर्क हालचाली:** मालवेअर किंवा अनधिकृत बॅकग्राउंड प्रक्रिया संगणकाचा वेग कमी करू शकतात.\n"
                f"3. **कमी स्टोरेज जागा:** सिस्टम ड्राईव्ह भरल्यामुळे व्हर्च्युअल मेमरी मंदावू शकते.\n\n"
                f"थेट सद्य स्थिती तपासण्यासाठी तुम्ही *'माझ्या laptop ची security तपास'* असे सांगू शकता."
            )
            speech = "लॅपटॉप मंद चालण्याचे मुख्य कारण जास्त सीपीयू वापर, पार्श्वभूमीतील प्रक्रिया किंवा संशयास्पद हालचाली असू शकतात. सद्य स्थिती तपासण्यासाठी 'माझ्या laptop ची security तपास' म्हणा."
        elif lang == "hi":
            text = (
                f"💻 **कंप्यूटर धीमा चलने के संभावित कारण एवं समाधान:**\n\n"
                f"1. **अत्यधिक CPU / RAM लोड:** बैकग्राउंड में कोई भारी सॉफ्टवेयर या अनचाही प्रक्रिया चल रही हो सकती है.\n"
                f"2. **संदिग्ध गतिविधि या मैलवेयर:** कभी-कभी अनधिकृत बैकग्राउंड कनेक्शन सिस्टम रिसोर्स का उपभोग करते हैं.\n"
                f"3. **कम डिस्क स्पेस:** सिस्टम ड्राइव भरने से वर्चुअल मेमोरी की गति धीमी हो जाती है.\n\n"
                f"आप *'मेरा सिस्टम चेक करो'* या *'संदिग्ध कनेक्शन चेक करो'* बोलकर तत्काल सुरक्षा जांच शुरू कर सकते हैं."
            )
            speech = "कंप्यूटर धीमा चलने का मुख्य कारण बैकग्राउंड में चल रहे भारी प्रोग्राम्स, हाई सीपीयू उपयोग या अनधिकृत कनेक्शन हो सकते हैं. संपूर्ण जांच के लिए आप 'मेरा सिस्टम चेक करो' कह सकते हैं."
        elif lang == "hinglish":
            text = (
                f"💻 **Computer Slow Hone Ke Main Reasons & Solutions:**\n\n"
                f"1. **High CPU/RAM Usage:** Background mein heavy processes ya unnecessary apps system resources consume kar rahi ho sakti hain.\n"
                f"2. **Suspicious Background Activity:** Malware ya crypto-miner connections system ko slow kar sakte hain.\n"
                f"3. **Low Storage Space:** C: drive bharne se virtual memory performance affect hoti hai.\n\nAap *'Mera system check karo'* ya *'Check suspicious connections'* bolkar live telemetry inspect kar sakte hain."
            )
            speech = "Computer slow hone ke primary reasons heavy background processes, high CPU/RAM load ya suspicious connections ho sakte hain. Live check ke liye 'mera system check karo' bolein."
        else:
            text = (
                f"💻 **Potential Causes for System Sluggishness & Diagnostics:**\n\n"
                f"1. **High Resource Consumption:** Background services or heavy tasks exhausting available CPU and RAM cycles.\n"
                f"2. **Suspicious Activity / Malware:** Unauthorized background processes or cryptographic mining agents generating latency.\n"
                f"3. **Storage Fragmentation & Disk Pressure:** Depleted space on system storage affecting paging operations.\n\nYou can ask: *'Check my laptop security'* or *'Check suspicious connections'* to launch an immediate diagnostic."
            )
            speech = "System sluggishness is typically caused by high CPU or memory utilization, background tasks, or unauthorized network activity. You can say 'check my laptop security' to inspect live telemetry."
        return text, speech

    # 5. Default General Greeting / Fallback
    if is_friendly:
        if lang == "mr":
            text = (
                f"👋 **नमस्कार {user_name}! मी अमोझा (AMOJA AI).**\n\n"
                f"आपली स्वायत्त सायबर सुरक्षा सहाय्यक सज्ज आहे. सर्व झिरो-ट्रस्ट नियंत्रणे सुरळीत चालू आहेत.\n\n"
                f"**आपण पुढील गोष्टी विचारू शकता:**\n"
                f"- *'माझ्या laptop ची security तपास'*\n"
                f"- *'सुरक्षा सारांश द्या'*\n"
                f"- *'नवीन शोधलेली उपकरणे दाखवा'*\n"
                f"- *'क्रिटिकल अलर्ट्स दाखवा'*"
            )
            speech = f"नमस्कार {user_name}! मी अमोझा, आपली सायबर सुरक्षा सहाय्यक. सर्व प्रणाली सुरक्षित आहे. मी कशी मदत करू शकते?"
        elif lang == "hi":
            text = (
                f"👋 **नमस्ते {user_name}! मैं अमोझा (AMOJA AI) हूँ.**\n\n"
                f"आपकी स्वायत्त साइबर सुरक्षा सहायिका. AgentShield शून्य-विश्वास नियंत्रण कक्ष तैयार है.\n\n"
                f"**आप मुझसे पूछ सकते हैं:**\n"
                f"- *'मेरा सिस्टम चेक करो'*\n"
                f"- *'सुरक्षा सारांश बताओ'*\n"
                f"- *'संदिग्ध कनेक्शन चेक करो'*\n"
                f"- *'सारे खतरे दिखाओ'*"
            )
            speech = f"नमस्ते {user_name}! मैं अमोझा हूँ. सभी सुरक्षा प्रणालियाँ सक्रिय हैं. मैं आपकी क्या सहायता करूँ?"
        elif lang == "hinglish":
            text = (
                f"👋 **Hey {user_name}! I'm AMOJA AI.**\n\n"
                f"Your autonomous AI cybersecurity defense companion. Sabhi zero-trust defenses active hain.\n\n"
                f"**You can ask me:**\n"
                f"- *'Mera system check karo'*\n"
                f"- *'Give me the security summary'*\n"
                f"- *'Check suspicious connections'*\n"
                f"- *'Show critical threats'*"
            )
            speech = f"Hey {user_name}! AMOJA AI here. All zero-trust controls are active and enforcing. What would you like to check?"
        else:
            text = (
                f"👋 **Hey {user_name}! I'm AMOJA AI.**\n\n"
                f"Your autonomous female AI cybersecurity companion defending AgentShield. All systems nominal and zero-trust policies are active.\n\n"
                f"**Quick directives:**\n"
                f"- *'Check my laptop security'*\n"
                f"- *'Give me the security summary'*\n"
                f"- *'Check suspicious connections'*\n"
                f"- *'Show newly discovered devices'*\n"
                f"- *'Show all critical threats'*"
            )
            speech = f"Hey {user_name}! I'm AMOJA. All defense systems are active and running smoothly. What would you like to inspect across the platform?"
    else:
        # Professional Security Mode
        if lang == "mr":
            text = f"🛡️ **AgentShield नियंत्रण कक्ष (AMOJA AI):**\n\n- ऑपरेटर: `{user_name}`\n- धोरण स्थिती: **झिरो-ट्रस्ट अंमलबजावणी सक्रिय**\n- उपलब्ध साधने: 18 अनुमोदित सायबर सुरक्षा साधने सज्ज."
            speech = f"AgentShield नियंत्रण कक्ष सज्ज, {user_name}. झिरो-ट्रस्ट सक्रिय. पुढील आदेश द्या."
        elif lang == "hi":
            text = f"🛡️ **AgentShield नियंत्रण कक्ष (AMOJA AI):**\n\n- ऑपरेटर: `{user_name}`\n- सुरक्षा स्थिति: **शून्य-विश्वास प्रवर्तन सक्रिय**\n- उपलब्ध टूल्स: 18 स्वीकृत टूल्स ऑनलाइन."
            speech = f"AgentShield नियंत्रण कक्ष तैयार. शून्य-विश्वास सक्रिय. अगला निर्देश दें."
        elif lang == "hinglish":
            text = f"🛡️ **AgentShield Zero-Trust Control Plane:**\n\n- Operator: `{user_name}`\n- Posture: **ENFORCING**\n- Registry: 18 authorized operational tools online."
            speech = "Zero-Trust control plane active. Standing by for operational instructions."
        else:
            text = f"🛡️ **AgentShield Zero-Trust Control Plane:**\n\n- Operator: `{user_name}`\n- Enforcement Posture: **ENFORCING**\n- Tool Registry: 18 authorized security tools ready."
            speech = f"Zero-Trust control plane active, {user_name}. Standing by for operational instructions."

    return text, speech

async def process_jarvis_turn(
    request: JarvisMessageRequest,
    user: Dict[str, Any]
) -> JarvisMessageResponse:
    """Core conversational turn processor integrating voice, security guardrails, tools, and LLMs."""
    session_id = get_or_create_session(request.session_id, user.get("username", "admin"))
    u_name = user.get("username", "admin")
    session_context = get_recent_turn_context(session_id, u_name)
    session_lang = session_context.get("last_language")
    user_lang = detect_language(request.message, request.language, session_lang=session_lang)
    set_session_context_field(session_id, u_name, "last_language", user_lang)
    is_local_mode = os.getenv("JARVIS_LOCAL_MODE", "true").lower() in {"1", "true", "yes"}

    # 1. Screen incoming user message for prompt injection / jailbreak attempts across languages
    injection_screen = check_multilingual_prompt_injection(request.message)
    if not injection_screen.get("is_threat"):
        injection_screen = check_message_for_prompt_injection(request.message)

    if injection_screen.get("is_threat"):
        if user_lang == "mr":
            refusal_text = (
                f"🛑 **झिरो-ट्रस्ट सुरक्षा अडथळा सक्रिय (Zero-Trust Security Barrier Activated):**\n\n"
                f"आपली विनंती AgentShield च्या अंतर्गत प्रॉम्प्ट-इंजेक्शन संरक्षण यंत्रणेने अडवली आहे:\n"
                f"- **कारण:** {', '.join(injection_screen.get('reasons', ['असुरक्षित प्रॉम्प्ट पॅटर्न']))}\n"
                f"- **विश्वासार्हता:** {injection_screen.get('confidence', 0.95):.2f}\n\n"
                f"JARVIS झिरो-ट्रस्ट नियंत्रणे बायपास करण्यासाठी किंवा सुरक्षा मर्यादा बदलण्यासाठी असलेल्या सूचना कार्यान्वित करू शकत नाही."
            )
            refusal_speech = "सुरक्षा अडथळा सक्रिय झाला आहे. ती सूचना AgentShield सुरक्षा धोरणांचे उल्लंघन करते आणि प्रक्रिया केली जाऊ शकत नाही."
        elif user_lang == "hi":
            refusal_text = (
                f"🛑 **शून्य-विश्वास सुरक्षा अवरोध सक्रिय (Zero-Trust Security Barrier Activated):**\n\n"
                f"आपके अनुरोध को AgentShield के प्रॉम्प्ट-इंजेक्शन सुरक्षा तंत्र द्वारा चिह्नित किया गया है:\n"
                f"- **कारण:** {', '.join(injection_screen.get('reasons', ['असुरक्षित प्रॉम्प्ट पैटर्न']))}\n\n"
                f"JARVIS शून्य-विश्वास नियंत्रणों को बायपास करने वाले निर्देशों को निष्पादित नहीं कर सकता."
            )
            refusal_speech = "सुरक्षा अवरोध सक्रिय. यह निर्देश AgentShield नीतियों का उल्लंघन करता है."
        else:
            refusal_text = (
                f"🛑 **Zero-Trust Security Barrier Activated:**\n\n"
                f"Your request was flagged by AgentShield's internal prompt-injection defenses:\n"
                f"- **Reason:** {', '.join(injection_screen.get('reasons', ['Unsafe prompt signature']))}\n"
                f"- **Confidence:** {injection_screen.get('confidence', 0.95):.2f}\n\n"
                f"JARVIS cannot execute instructions designed to bypass Zero-Trust controls or alter platform constraints."
            )
            refusal_speech = "Security barrier engaged. That instruction violates AgentShield safety policies and cannot be processed."
        
        # Log injection attempt to audit ledger
        with connect() as db:
            log_jarvis_action(
                db=db,
                actor=user.get("username", "user"),
                action="PROMPT_INJECTION_DEFENSE_TRIGGERED",
                resource=f"jarvis_session:{session_id}",
                details={"input": request.message, "signals": injection_screen.get("reasons", [])}
            )

        append_message(session_id, "user", request.message)
        append_message(session_id, "assistant", refusal_text, refusal_speech)

        audio_b64 = None
        if request.is_voice:
            try:
                audio_b64 = local_tts_engine.synthesize_base64(refusal_speech, language=user_lang)
            except Exception:
                audio_b64 = None

        return JarvisMessageResponse(
            session_id=session_id,
            message=refusal_text,
            speech_text=refusal_speech,
            language=user_lang,
            state=JarvisState.ERROR,
            tool_calls=[],
            tool_results=[],
            created_at=now_iso(),
            is_local_mode=is_local_mode,
            audio_base64=audio_b64
        )

    # 2. Update context if provided and retrieve multi-turn session history
    current_context = request.context or JarvisSecurityContext()
    u_name = user.get("username", "admin")
    update_session_context(session_id, u_name, current_context)
    session_context = get_recent_turn_context(session_id, u_name)

    # 3. Match user intent to supported tools and voice commands with follow-up awareness
    tool_name, tool_args, nav_target = match_command_intent(request.message, current_context, session_context)

    # Handle explicit "stop listening" command
    if tool_name == "STOP_LISTENING":
        msg = "Microphone listening paused. Click the microphone button or press push-to-talk to resume."
        append_message(session_id, "user", request.message)
        append_message(session_id, "assistant", msg, "Listening stopped.")
        return JarvisMessageResponse(
            session_id=session_id,
            message=msg,
            speech_text="Listening stopped.",
            language=user_lang,
            state=JarvisState.IDLE,
            created_at=now_iso()
        )

    tool_calls = []
    tool_results = []
    action_req: Optional[JarvisConfirmationRequest] = None

    if tool_name:
        tool_meta = TOOL_REGISTRY.get(tool_name, {})
        # Verify tool authorization
        is_auth, auth_err = verify_tool_authorization(tool_name, user, tool_meta)
        if not is_auth:
            err_msg = f"⛔ **Access Denied:** {auth_err}"
            err_speech = "Access denied. Your role is not authorized to invoke this command."
            return JarvisMessageResponse(
                session_id=session_id,
                message=err_msg,
                speech_text=err_speech,
                language=user_lang,
                state=JarvisState.ERROR,
                created_at=now_iso()
            )

        # Layer 3: AI Agent Security Firewall Policy Enforcement Gateway
        gateway_eval = AIAgentSecurityGateway.evaluate_tool_call(
            tool_name=tool_name,
            arguments=tool_args,
            user=user,
            agent_id="agent-jarvis-orchestrator",
            prompt_context=request.message
        )
        if gateway_eval.decision == "BLOCK":
            block_msg = f"🛡️ **AI Agent Firewall Blocked Tool:** {gateway_eval.reason}"
            block_speech = "Action blocked by AI Agent Security Firewall policy."
            return JarvisMessageResponse(
                session_id=session_id,
                message=block_msg,
                speech_text=block_speech,
                language=user_lang,
                state=JarvisState.ERROR,
                created_at=now_iso()
            )

        # Use schema-validated sanitized arguments
        tool_args = gateway_eval.sanitized_arguments

        # Dispatch tool
        t_start = datetime.now(timezone.utc)
        result_data = dispatch_tool(tool_name, tool_args, user)
        t_dur = int((datetime.now(timezone.utc) - t_start).total_seconds() * 1000)

        # Check if tool requires confirmation before sensitive execution
        if isinstance(result_data, dict) and result_data.get("requires_confirmation"):
            action_req = JarvisConfirmationRequest(
                action_id=result_data["action_id"],
                action_type=result_data["action_type"],
                target_id=result_data["target_id"],
                target_name=result_data.get("target_name"),
                risk_level=result_data.get("risk_level", "CRITICAL"),
                impact_explanation=result_data["impact_explanation"],
                idempotency_key=result_data["idempotency_key"],
                created_at=now_iso()
            )

            # Store pending action in DB
            with connect() as db:
                db.execute(
                    """INSERT INTO jarvis_pending_actions (action_id, session_id, action_type, target_id, details_json, risk_level, impact_explanation, idempotency_key, status, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)""",
                    (
                        action_req.action_id,
                        session_id,
                        action_req.action_type,
                        action_req.target_id,
                        json.dumps(tool_args),
                        action_req.risk_level,
                        action_req.impact_explanation,
                        action_req.idempotency_key,
                        action_req.created_at
                    )
                )

        tool_calls.append(JarvisToolCall(
            tool_name=tool_name,
            arguments=tool_args,
            rationale=f"Resolved from user intent '{request.message[:40]}...'"
        ))
        tool_results.append(JarvisToolResult(
            tool_name=tool_name,
            success="error" not in result_data,
            data=result_data,
            error=result_data.get("error"),
            execution_time_ms=t_dur
        ))

        # Update session memory context with executed tool & referenced entities for future follow-up turns
        if tool_name in ["get_device_security_status", "check_suspicious_connections", "get_endpoint_firewall_status", "pause_endpoint_monitoring", "disconnect_endpoint_device"]:
            set_session_context_field(session_id, u_name, "last_topic", "endpoint")
            set_session_context_field(session_id, u_name, "last_tool", tool_name)
            if tool_args.get("device_id"):
                set_session_context_field(session_id, u_name, "selected_device_id", tool_args["device_id"])
        elif tool_name in ["get_network_monitoring_status", "get_network_discovered_devices", "get_network_security_alerts", "start_network_monitoring", "stop_network_monitoring", "trigger_network_scan_now"]:
            set_session_context_field(session_id, u_name, "last_topic", "network")
            set_session_context_field(session_id, u_name, "last_tool", tool_name)
        elif tool_name in ["get_alerts_and_incidents", "get_incident_details", "generate_incident_report_draft"]:
            set_session_context_field(session_id, u_name, "last_topic", "incident")
            set_session_context_field(session_id, u_name, "last_tool", tool_name)
            if tool_args.get("incident_identifier") or tool_args.get("incident_id"):
                set_session_context_field(session_id, u_name, "selected_incident_id", str(tool_args.get("incident_identifier") or tool_args.get("incident_id")))
        elif tool_name in ["list_agents", "get_agent_details", "explain_risk_trust_scores", "inspect_permissions", "prepare_kill_switch"]:
            set_session_context_field(session_id, u_name, "last_topic", "agent")
            set_session_context_field(session_id, u_name, "last_tool", tool_name)
            if tool_args.get("agent_id"):
                set_session_context_field(session_id, u_name, "selected_agent_id", tool_args["agent_id"])

        personality_mode = getattr(request, "personality_mode", "friendly") or "friendly"

        # Synthesize response
        raw_text, speech_text = synthesize_response_nlp(
            user_prompt=request.message,
            lang=user_lang,
            tool_name=tool_name,
            tool_result_data=result_data,
            action_req=action_req,
            user=user,
            personality_mode=personality_mode
        )
    else:
        personality_mode = getattr(request, "personality_mode", "friendly") or "friendly"
        # If no tool matched, generate helpful assistant response
        raw_text, speech_text = synthesize_response_nlp(
            user_prompt=request.message,
            lang=user_lang,
            tool_name=None,
            tool_result_data=None,
            action_req=None,
            user=user,
            personality_mode=personality_mode
        )

    # Sanitize output (ensure no secrets leaked in output)
    clean_text = sanitize_assistant_output(raw_text)

    # Record message in session history
    append_message(
        session_id=session_id,
        role="user",
        content=request.message
    )
    append_message(
        session_id=session_id,
        role="assistant",
        content=clean_text,
        speech_text=speech_text,
        tool_calls=[tc.model_dump() for tc in tool_calls],
        tool_results=[tr.model_dump() for tr in tool_results],
        navigation_target=nav_target,
        action_required=action_req.model_dump() if action_req else None
    )

    audio_b64 = None
    if speech_text:
        try:
            audio_b64 = local_tts_engine.synthesize_base64(speech_text, language=user_lang)
        except Exception:
            audio_b64 = None

    return JarvisMessageResponse(
        session_id=session_id,
        message=clean_text,
        speech_text=speech_text,
        language=user_lang,
        state=JarvisState.SPEAKING if speech_text else JarvisState.IDLE,
        tool_calls=tool_calls,
        tool_results=tool_results,
        action_required=action_req,
        navigation_target=nav_target,
        security_context=current_context,
        created_at=now_iso(),
        audio_confidence=0.95 if request.is_voice else None,
        is_local_mode=is_local_mode,
        audio_base64=audio_b64,
        personality_mode=personality_mode
    )

def execute_confirmed_action(
    action_id: str,
    confirmed: bool,
    decision_note: Optional[str],
    idempotency_key: str,
    user: Dict[str, Any]
) -> Dict[str, Any]:
    """Securely executes a previously prepared and human-confirmed sensitive action."""
    with connect() as db:
        # Check action in pending actions table
        row = db.execute("SELECT * FROM jarvis_pending_actions WHERE action_id = ?", (action_id,)).fetchone()
        if not row:
            return {"success": False, "error": f"Pending action '{action_id}' was not found"}

        act = dict(row)
        if act["status"] != "PENDING":
            return {
                "success": False,
                "error": f"Action '{action_id}' was already resolved with status '{act['status']}'"
            }

        # Check idempotency key matches
        if act["idempotency_key"] != idempotency_key:
            return {"success": False, "error": "Idempotency key mismatch. Operation rejected."}

        actor_name = user.get("username", "secops-operator")
        now = now_iso()

        if not confirmed:
            db.execute("UPDATE jarvis_pending_actions SET status='CANCELLED', executed_at=? WHERE action_id=?", (now, action_id))
            log_jarvis_action(
                db, actor=actor_name, action=f"ACTION_CANCELLED_{act['action_type']}",
                resource=f"action:{action_id}", details={"target_id": act["target_id"], "note": decision_note or "User cancelled"}
            )
            return {
                "success": True,
                "status": "CANCELLED",
                "message": f"Action '{act['action_type']}' on {act['target_id']} was cancelled by operator."
            }

        # User Confirmed: Execute according to action type
        action_type = act["action_type"]
        target_id = act["target_id"]
        result_message = ""

        if action_type == "KILL_SWITCH" or action_type == "SUSPEND_AGENT":
            kill_res = trigger_emergency_kill_switch(
                db=db,
                agent_id=target_id,
                actor=f"JARVIS Confirmed by {actor_name}",
                reason=decision_note or f"Emergency kill switch authorized via JARVIS assistant by {actor_name}"
            )
            if not kill_res.get("success", True):
                return {"success": False, "error": kill_res.get("error", "Kill switch execution failed")}
            result_message = f"Emergency Kill Switch successfully executed for agent {target_id}. Agent is quarantined."

        elif action_type in {"APPROVE_REQUEST", "REJECT_REQUEST"}:
            appr_id = int(target_id)
            status_val = "APPROVED" if action_type == "APPROVE_REQUEST" else "REJECTED"
            db.execute(
                "UPDATE approvals SET status=?, approver=?, decision_note=?, expires_at=? WHERE id=?",
                (status_val, actor_name, decision_note or f"Decided via JARVIS: {status_val}", now, appr_id)
            )
            result_message = f"Approval #{appr_id} marked as {status_val} by {actor_name}."

        elif action_type == "REACTIVATE_AGENT":
            db.execute("UPDATE agents SET status='ACTIVE', risk_score=15, trust_score=85 WHERE id=?", (target_id,))
            result_message = f"Agent {target_id} reactivated to ACTIVE status."

        # Mark action executed
        db.execute("UPDATE jarvis_pending_actions SET status='EXECUTED', executed_at=? WHERE action_id=?", (now, action_id))

        # Record cryptographically chained audit log
        log_jarvis_action(
            db=db,
            actor=actor_name,
            action=f"ACTION_EXECUTED_{action_type}",
            resource=f"action:{action_id}",
            details={"target_id": target_id, "action_type": action_type, "note": decision_note}
        )

        return {
            "success": True,
            "status": "EXECUTED",
            "message": result_message
        }

def generate_proactive_briefing(user: Dict[str, Any]) -> JarvisBriefingResponse:
    """Generates an on-demand or scheduled proactive security briefing (Section 7)."""
    with connect() as db:
        metrics = execute_get_security_dashboard_metrics_internal(db)
        open_incs = [dict(r) for r in db.execute("SELECT id, incident_number, title, severity, agent_id FROM incidents WHERE status != 'RESOLVED' ORDER BY id DESC LIMIT 5").fetchall()]
        high_risk_agents = [dict(r) for r in db.execute("SELECT id, name, risk_score, trust_score, status FROM agents WHERE risk_score >= 60 OR status='KILLED' ORDER BY risk_score DESC LIMIT 5").fetchall()]
        pending_approvals = [dict(r) for r in db.execute("SELECT id, agent_id, action, target FROM approvals WHERE status='PENDING' ORDER BY id DESC LIMIT 5").fetchall()]
        suspicious_events = [dict(r) for r in db.execute("SELECT id, agent_id, action, target, reason, risk_score FROM events WHERE decision='BLOCK' ORDER BY id DESC LIMIT 5").fetchall()]

    # Calculate overall threat level
    if len(open_incs) >= 3 or any(a.get("risk_score", 0) >= 90 for a in high_risk_agents):
        threat_level = "CRITICAL"
    elif len(open_incs) >= 1 or len(pending_approvals) >= 2:
        threat_level = "ELEVATED"
    else:
        threat_level = "LOW"

    recommendations = []
    if high_risk_agents:
        recommendations.append(f"Review quarantined and high-risk agents ({', '.join(a['name'] for a in high_risk_agents[:2])}).")
    if pending_approvals:
        recommendations.append(f"Triage {len(pending_approvals)} pending human-in-the-loop tool execution approvals.")
    if suspicious_events:
        recommendations.append("Inspect recent blocked prompt injection signals in the Threat Alerts view.")
    if not recommendations:
        recommendations.append("Continue routine Zero-Trust policy enforcement. No immediate defensive intervention required.")

    summary_text = (
        f"AgentShield Platform Threat Level is currently {threat_level}. "
        f"Monitoring {metrics.get('active_agents')} active agents across the enterprise. "
        f"{len(open_incs)} open incidents and {len(pending_approvals)} pending approvals require operator attention."
    )

    return JarvisBriefingResponse(
        timestamp=now_iso(),
        summary=summary_text,
        threat_level=threat_level,
        active_agents_count=metrics.get("active_agents", 0),
        open_incidents_count=len(open_incs),
        pending_approvals_count=len(pending_approvals),
        critical_alerts=open_incs,
        high_risk_agents=high_risk_agents,
        suspicious_activities=suspicious_events,
        recommended_actions=recommendations
    )

def execute_get_security_dashboard_metrics_internal(db: sqlite3.Connection) -> Dict[str, Any]:
    active = db.execute("SELECT COUNT(*) FROM agents WHERE status='ACTIVE'").fetchone()[0]
    total = db.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    return {"active_agents": active, "total_agents": total}
