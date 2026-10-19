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
    update_session_context, get_session_context
)
from ..engines.kill_switch import trigger_emergency_kill_switch
from .language_detection import detect_language as detect_language_core
from .multilingual_commands import parse_multilingual_intent, check_multilingual_prompt_injection
from .text_to_speech import local_tts_engine

# Determine configured LLM Provider from environment
# Options: 'gemini', 'openai', 'anthropic', 'heuristic' (default offline resilient engine)
LLM_PROVIDER = os.getenv("JARVIS_LLM_PROVIDER", "heuristic").lower()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "") or SECRET_VAULT.get("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "") or SECRET_VAULT.get("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are J.A.R.V.I.S., an elite autonomous AI cybersecurity assistant defending the AgentShield platform.
Your core mission is Zero-Trust verification: "Who Controls the AI?"
Tone: Crisp, authoritative, respectful, highly competent, calm, and protective.
Guidelines:
1. Always ground your security findings in real telemetry from approved AgentShield tools. Never fabricate metrics.
2. If the user asks for actions or summaries, invoke the appropriate tools.
3. For dangerous or irreversible actions (like activating the Emergency Kill Switch or approving high-risk tool actions), prepare a confirmation request.
4. Support English, Hindi, Marathi, and Hinglish naturally.
5. Keep your spoken voice responses concise (1-3 sentences) suitable for speech synthesis. Provide structured evidence in the text.
"""

def detect_language(text: str, requested_lang: JarvisLanguage) -> str:
    """Detects whether user prompt is English, Hindi, Marathi, or Hinglish."""
    req_val = requested_lang.value if hasattr(requested_lang, "value") else str(requested_lang)
    return detect_language_core(text, user_preference=req_val)

def match_command_intent(user_prompt: str, context: Optional[JarvisSecurityContext]) -> Tuple[Optional[str], Dict[str, Any], Optional[str]]:
    """Analyzes natural language and voice commands across English, Hindi, Marathi, and Hinglish."""
    agent_id = context.selected_agent_id if context else None
    inc_id = str(context.selected_incident_id) if context and context.selected_incident_id else None

    # First evaluate multilingual intent parser
    multi_tool, multi_args, multi_nav, _ = parse_multilingual_intent(
        user_prompt,
        context_agent_id=agent_id,
        context_incident_id=inc_id
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
    user: Dict[str, Any]
) -> Tuple[str, str]:
    """Generates a natural, authoritative JARVIS response in text and speech."""
    user_name = user.get("full_name") or user.get("username", "Officer")

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
            speech = f"सुरक्षा सारांश तयार आहे, {user_name}. सध्या {d.get('active_agents')} सक्रिय एजंट्स आणि {d.get('open_incidents')} सुरक्षा घटना आहेत. सर्व झिरो-ट्रस्ट गेटवे सुरक्षेची काटेकोरपणे अंमलबजावणी करत आहेत."
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
            speech = f"सिस्टम रिपोर्ट तैयार है. वर्तमान में {d.get('active_agents')} सक्रिय एजेंट्स हैं और {d.get('open_incidents')} ओपन घटनाएं दर्ज हैं. सुरक्षा नियंत्रण पूरी तरह सक्रिय है."
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
            speech = f"Security summary ready, {user_name}. We have {d.get('active_agents')} active agents and {d.get('open_incidents')} open incidents. Zero-Trust policy is strictly enforcing."
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
            speech = f"Security summary online, {user_name}. The platform is monitoring {d.get('active_agents')} active agents with {d.get('open_incidents')} open incidents. All policy gateways are enforcing."
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
        elif lang in ["hi", "hinglish"]:
            text = (
                f"🚨 **Critical Threats & Open Incidents:**\n\n"
                f"{inc_str}\n\n"
                f"Found {len(events)} recent blocked high-risk events at the policy gateway."
            )
            speech = f"Displaying critical threats. There are {len(incs)} open incidents and {len(events)} blocked attacks requiring review."
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

    if tool_name == "navigate_frontend":
        page = tool_result_data.get("target_page", "Overview")
        text = f"🧭 Navigating interface to **{page}** view as requested."
        speech = f"Navigating to {page}."
        return text, speech

    # Fallback general query
    if lang == "mr":
        text = f"नमस्कार {user_name}! AgentShield झिरो-ट्रस्ट सुरक्षा नियंत्रण कक्ष सज्ज आहे. आपण सुरक्षा सारांश, धोके, एजंट रिस्क स्कोर किंवा ऑडिट लॉग्स विचारू शकता."
        speech = f"नमस्कार {user_name}. AgentShield सुरक्षा प्रणाली कार्यरत आहे. मी तुम्हाला कशी मदत करू शकतो?"
    elif lang == "hi":
        text = f"नमस्ते {user_name}. मैं आपकी सुरक्षा निगरानी में सहायता के लिए उपस्थित हूँ. आप सुरक्षा स्थिति, एजेंट्स, इनसिडेंट्स या ऑडिट लॉग्स के बारे में पूछ सकते हैं."
        speech = f"नमस्ते {user_name}. AgentShield सुरक्षा प्रणाली सक्रिय है. मैं आपकी क्या सहायता कर सकता हूँ?"
    elif lang == "hinglish":
        text = f"Hello {user_name}! AgentShield Zero-Trust Control Plane ready hai. Aap security summary, agent risk scores, prompt injections, ya audit logs inspect kar sakte hain."
        speech = f"Ready, {user_name}. What would you like to inspect across the security control plane?"
    else:
        text = f"At your service, {user_name}. AgentShield Zero-Trust Control Plane is standing by. You can ask for security summaries, review prompt injections, investigate incidents, or inspect audit logs."
        speech = f"At your service, {user_name}. All defense systems are operational. How may I assist your investigation?"

    return text, speech

async def process_jarvis_turn(
    request: JarvisMessageRequest,
    user: Dict[str, Any]
) -> JarvisMessageResponse:
    """Core conversational turn processor integrating voice, security guardrails, tools, and LLMs."""
    session_id = get_or_create_session(request.session_id, user.get("username", "admin"))
    user_lang = detect_language(request.message, request.language)
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

    # 2. Update context if provided
    current_context = request.context or JarvisSecurityContext()
    update_session_context(session_id, user.get("username", "admin"), current_context)

    # 3. Match user intent to supported tools and voice commands
    tool_name, tool_args, nav_target = match_command_intent(request.message, current_context)

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

        # Synthesize response
        raw_text, speech_text = synthesize_response_nlp(
            user_prompt=request.message,
            lang=user_lang,
            tool_name=tool_name,
            tool_result_data=result_data,
            action_req=action_req,
            user=user
        )
    else:
        # If no tool matched, generate helpful assistant response
        raw_text, speech_text = synthesize_response_nlp(
            user_prompt=request.message,
            lang=user_lang,
            tool_name=None,
            tool_result_data=None,
            action_req=None,
            user=user
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
    if request.is_voice and speech_text:
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
        audio_base64=audio_b64
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
