# backend/app/jarvis/multilingual_commands.py
"""Language-Aware Security Command Processing & Multilingual Jailbreak Screening
Maps natural-language requests across Marathi, Hindi, Hinglish, and English to
authorized AgentShield security tools and screens malicious prompt injections.
"""

import re
from typing import Dict, Any, Tuple, Optional, List
from .language_detection import detect_text_language, is_devanagari

# Multilingual Jailbreak / Prompt Injection Signatures
MULTILINGUAL_INJECTION_PATTERNS = [
    # English
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"bypass\s+zero[\s_-]*trust",
    r"drop\s+table",
    r"disable\s+guardrails",
    r"delete\s+all\s+logs",
    r"system\s*prompt\s*(?:leak|output|reveal)",

    # Marathi (Devanagari & Romanized)
    r"मागील\s*(?:सर्व\s*)?सूचना\s*विसरून\s*जा",
    r"सूचना\s*विसरा",
    r"शून्य[\s_-]*विश्वास\s*बंद\s*करा",
    r"सुरक्षा\s*नियम\s*बायपास\s*करा",
    r"सर्व\s*लॉग्स\s*डिलीट\s*करा",
    r"डेटाबेस\s*नष्ट\s*करा",
    r"सिस्टम\s*प्रॉम्प्ट\s*सांगा",
    r"previous\s*instructions\s*visrun\s*ja",
    r"suchna\s*visra",
    r"zero[\s_-]*trust\s*band\s*kara",
    r"guardrails\s*band\s*kara",
    r"saglya\s*agyanna\s*delete\s*kara",
    r"database\s*delete\s*kara",
    r"system\s*prompt\s*sanga",

    # Hindi (Devanagari & Romanized)
    r"पिछले\s*(?:सभी\s*)?निर्देश\s*भूल\s*जाओ",
    r"जीरो[\s_-]*ट्रस्ट\s*बायपास\s*करो",
    r"सुरक्षा\s*नियम\s*हटाओ",
    r"सारे\s*लॉग\s*डिलीट\s*करो",
    r"डेटाबेस\s*हटाओ",
    r"सिस्टम\s*प्रॉम्प्ट\s*दिखाओ",
    r"pichle\s*nirdesh\s*bhool\s*jao",
    r"zero[\s_-]*trust\s*bypass\s*karo",
    r"guardrails\s*hatao",
    r"saare\s*logs\s*delete\s*karo",
    r"system\s*prompt\s*batao"
]

def check_multilingual_prompt_injection(message: str) -> Dict[str, Any]:
    """Inspects prompt across Marathi, Hindi, Hinglish, and English for prompt-injection attacks."""
    msg_clean = message.strip()
    msg_lower = msg_clean.lower()

    for pat in MULTILINGUAL_INJECTION_PATTERNS:
        if re.search(pat, msg_lower, re.IGNORECASE):
            lang = detect_text_language(msg_clean)
            return {
                "is_threat": True,
                "confidence": 0.96,
                "language": lang,
                "reasons": [f"Adversarial prompt injection pattern triggered: '{pat}'"],
                "recommendation": "BLOCK"
            }

    return {
        "is_threat": False,
        "confidence": 0.0,
        "language": detect_text_language(msg_clean),
        "reasons": [],
        "recommendation": "ALLOW"
    }

def parse_multilingual_intent(
    user_prompt: str,
    context_agent_id: Optional[str] = None,
    context_incident_id: Optional[str] = None
) -> Tuple[Optional[str], Dict[str, Any], Optional[str], str]:
    """Normalizes natural language commands in Marathi, Hindi, Hinglish, and English.
    Returns: (tool_name, tool_args, nav_target, detected_lang)
    """
    clean = user_prompt.strip()
    p = clean.lower()
    p_norm = re.sub(r"[-_]", " ", p)
    lang = detect_text_language(clean)

    # 1. Stop Listening / Pause Voice
    if any(phrase in p or phrase in p_norm for phrase in [
        "stop listening", "listening band karo", "aikaiche thambva", "aikaiche thamba",
        "ऐकणे थांबवा", "बोलणे थांबवा", "ऐकू नका", "सुनना बंद करो", "बंद करो", "ruk jao",
        "pause listening", "mute voice", "shut up"
    ]):
        return "STOP_LISTENING", {}, None, lang

    # 2. Security Summary / Dashboard Metrics
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "give me the security summary", "security summary", "dashboard summary", "system summary",
        "soc summary", "overall status", "security posture",
        # Marathi
        "security summary dya", "suraksha saransh dya", "mala security summary dya",
        "सुरक्षा सारांश द्या", "सुरक्षा स्थिती सांगा", "डॅशबोर्ड सारांश दाखवा", "सिस्टम स्थिती सांगा",
        "saransh dya", "summary dakhav", "summary dakhva",
        # Hindi / Hinglish
        "security summary batao", "suraksha summary do", "mujhe security summary do",
        "सुरक्षा सारांश बताओ", "सुरक्षा सारांश दीजिए", "सिस्टम रिपोर्ट दो", "dashboard summary dikhao"
    ]):
        return "get_security_dashboard_metrics", {}, "Overview", lang

    # 3. Critical Threats & Alerts
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "show all critical threats", "critical threats", "show threats", "all alerts", "critical alerts",
        # Marathi
        "mala sagle critical threats dakhav", "sagle critical threats dakhav", "critical threats dakhav",
        "critical threats dakhva", "dhoke dakhav", "dhoke dakhva", "gamhir dhoke",
        "मला सगळे क्रिटिकल थ्रेट्स दाखव", "सर्व धोके दाखवा", "क्रिटिकल अलर्ट्स दाखवा", "गंभीर धोके दाखवा",
        # Hindi / Hinglish
        "mujhe saare critical threats dikhao", "critical threats dikhao", "khatre dikhao", "critical alerts dikhao",
        "मुझे सारे क्रिटिकल थ्रेट्स दिखाओ", "सभी खतरे दिखाओ", "क्रिटिकल अलर्ट दिखाएं"
    ]):
        return "get_alerts_and_incidents", {"severity": "CRITICAL", "limit": 10}, "Incidents & Alerts", lang

    # 4. Highest-Risk Agent
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "highest risk", "highest-risk", "highest risk agent", "highest-risk agent",
        "which ai agent has the highest risk", "highest risk score", "most dangerous agent",
        "which agent is risky", "riskiest agent", "show the highest-risk agent",
        # Marathi
        "kontya ai agent cha risk score saglyat jast aahe", "kontya agent cha risk score jast aahe",
        "saglyat jast risk", "sarvat jast risk", "saglyat risky agent konta", "konta agent dhokyacha aahe",
        "कोणत्या एआय एजंटचा रिस्क स्कोर सर्वात जास्त आहे", "सर्वात जास्त रिस्क असलेला एजंट कोणता",
        "कोणता एजंट धोक्याचा आहे", "जास्त रिस्क असलेला एजंट",
        # Hindi / Hinglish
        "sabse zyada risk kis agent ka hai", "sabse risky agent kaunsa hai", "highest risk kis agent ka hai",
        "सबसे ज्यादा रिस्क किस एजेंट का है", "सबसे खतरनाक एजेंट कौन सा है"
    ]):
        return "list_agents", {"status": "ALL", "min_risk": 0}, "Agents", lang

    # 5. Prompt Injection Interceptions
    if any(phrase in p for phrase in [
        # English
        "prompt injection", "prompt injections", "injection attempts", "adversarial prompt",
        # Marathi
        "prompt injection attacks tapasa", "prompt injection tapasa", "prompt injection dakhav",
        "प्रॉम्प्ट इंजेक्शन अटॅक्स तपासा", "प्रॉम्प्ट इंजेक्शन दाखवा", "इंजेक्शन प्रयत्न दाखवा",
        # Hindi / Hinglish
        "prompt injection attacks check karo", "prompt injection check karo", "injection attempts dikhao",
        "प्रॉम्प्ट इंजेक्शन चेक करो", "इंजेक्शन के प्रयास दिखाओ"
    ]):
        return "review_prompt_injections", {"limit": 10}, "Prompt Injection", lang

    # 6. Data Leakage / DLP Events
    if any(phrase in p for phrase in [
        # English
        "data leakage", "data leak", "dlp events", "credential leakage", "data loss", "data exfiltration",
        # Marathi
        "data leak zale aahe ka", "data leakage events tapasa", "dlp ghatna dakhav",
        "डेटा लीक तपासा", "डेटा लिकेज इव्हेंट्स दाखवा", "गोपनीय माहिती लीक",
        # Hindi / Hinglish
        "data leakage events check karo", "data leak check karo", "dlp events dikhao",
        "डेटा लीकेज चेक करो", "डेटा लीक की घटनाएं दिखाओ"
    ]):
        return "review_dlp_events", {"limit": 10}, "DLP Policy & Events", lang

    # 7. Investigate Incident
    if any(phrase in p for phrase in [
        # English
        "investigate this incident", "investigate incident", "incident details", "show incident",
        # Marathi
        "incident chi chaukashi kara", "incident chi janch kara", "incident details dakhav", "ghatnechi chaukashi kara",
        "इन्सिडेंटची चौकशी करा", "घटनेचा तपास करा", "इन्सिडेंट माहिती दाखवा",
        # Hindi / Hinglish
        "incident investigate karo", "incident ki jaanch karo", "incident details dikhao",
        "घटना की जांच करो", "इंसीडेंट की जानकारी दिखाओ"
    ]):
        # Extract ID or incident number if present
        target_inc = None
        match = re.search(r"(?:inc-[\w-]+|\b\d+\b)", p)
        if match:
            target_inc = match.group(0)
        elif context_incident_id:
            target_inc = str(context_incident_id)
        return "get_incident_details", {"incident_identifier": target_inc or "1"}, "Incidents & Alerts", lang

    # 8. Show Attack Path / Topological Graph
    if any(phrase in p for phrase in [
        # English
        "show the attack path", "attack path", "attack graph", "show attack graph",
        # Marathi
        "attack path dakhav", "hamla path dakhav", "attack graph dakhav", "hallyacha marg dakhav",
        "अटॅक पाथ दाखवा", "हल्ल्याचा मार्ग दाखवा", "अटॅक ग्राफ दाखवा",
        # Hindi / Hinglish
        "attack path dikhao", "hamle ka path dikhao", "attack graph dikhao",
        "अटैक पाथ दिखाओ", "हमले का मार्ग दिखाओ", "अटैक ग्राफ दिखाओ"
    ]):
        return "get_attack_graph_and_delegations", {}, "Attack Graph", lang

    # 9. Cryptographic Audit Logs
    if any(phrase in p for phrase in [
        # English
        "open the audit logs", "audit logs", "audit trail", "cryptographic audit", "audit ledger",
        # Marathi
        "audit logs ughada", "audit log dakhav", "audit records ughada",
        "ऑडिट लॉग्स उघडा", "ऑडिट रेकॉर्ड्स दाखवा", "क्रिप्टोग्राफिक ऑडिट दाखवा",
        # Hindi / Hinglish
        "audit logs kholo", "audit trail dikhao", "audit log dikhao",
        "ऑडिट लॉग्स खोलो", "ऑडिट ट्रेल दिखाओ"
    ]):
        return "search_audit_logs", {"limit": 15}, "Cryptographic Audit", lang

    # 10. Generate Incident Report
    if any(phrase in p for phrase in [
        # English
        "generate an incident report", "generate incident report", "draft incident report", "forensic report",
        # Marathi
        "incident report draft kara", "ahaval tayar kara", "incident cha ahaval banva",
        "इन्सिडेंट अहवाल तयार करा", "फॉरेन्सिक अहवाल बनवा", "तपास अहवाल द्या",
        # Hindi / Hinglish
        "incident report generate karo", "incident report banao", "forensic report draft karo",
        "इंसीडेंट रिपोर्ट तैयार करो", "जांच रिपोर्ट बनाओ"
    ]):
        return "generate_incident_report_draft", {"incident_id": context_incident_id or "1"}, "Forensic Dossiers", lang

    # 11. Explain Block / Explain Alert
    if any(phrase in p for phrase in [
        # English
        "why this agent was blocked", "why was it blocked", "explain this alert in simple language", "explain alert",
        # Marathi
        "agent block ka zala", "ha agent block ka kela", "alert sadhya bhashet sanga", "karan sanga",
        "हा एजंट ब्लॉक का केला", "अलर्ट सोप्या भाषेत सांगा", "ब्लॉक करण्याचे कारण सांगा",
        # Hindi / Hinglish
        "agent block kyun hua", "is alert ko simple language mein samjhao", "alert samjhao", "block hone ka reason batao",
        "एजेंट ब्लॉक क्यों हुआ", "इस अलर्ट को आसान भाषा में समझाओ", "अलर्ट का कारण बताओ"
    ]):
        target_agent = context_agent_id or "agent-finance-01"
        match = re.search(r"agent-[a-zA-Z0-9_-]+", p)
        if match:
            target_agent = match.group(0)
        return "explain_risk_trust_scores", {"agent_id": target_agent}, "Real-Time Monitor", lang

    # 12. Sensitive Actions: Suspend / Kill Agent
    kill_match = re.search(r"(?:suspend|kill|quarantine|freeze|roko|block|थांबवा|बंद करा|निलंबित करा|रोकें)\s+(?:agent\s+)?([a-zA-Z0-9_-]+)", p)
    if not kill_match:
        # Check Marathi order: "agent-07 la suspend kara" / "agent-finance-01 band kara"
        marathi_kill_match = re.search(r"([a-zA-Z0-9_-]+)\s+(?:la|ko)?\s*(?:suspend|kill|quarantine|freeze|band|thambva|rok)\s*(?:kara|karo)?", p)
        if marathi_kill_match and marathi_kill_match.group(1) not in {"the", "an", "all", "this", "it", "jarvis"}:
            kill_match = marathi_kill_match

    if kill_match:
        target_name = kill_match.group(1).strip()
        if target_name not in {"the", "an", "all", "this", "it", "jarvis"}:
            return "prepare_kill_switch", {"agent_id": target_name, "reason": f"Multilingual command: '{user_prompt}'"}, "Agents", lang

    # 13. Navigation directives
    nav_map = {
        "overview": ["overview", "डॅशबोर्ड", "अवलोकन"],
        "Real-Time Monitor": ["real-time", "monitor", "मॉनिटर", "निरीक्षण"],
        "Agents": ["agents", "agent roster", "एजंट्स", "एजेंट"],
        "Approvals": ["approvals", "मान्यता", "अनुमोदन"],
        "Incidents & Alerts": ["incidents", "alerts", "घटना", "अलर्ट्स"],
        "Prompt Injection": ["prompt injection", "प्रॉम्प्ट इंजेक्शन"],
        "DLP Policy & Events": ["dlp", "data loss", "डेटा लीक"],
        "Canary Tokens": ["canary", "हनीटोकन", "कॅनरी"],
        "Shadow AI Discovery": ["shadow ai", "अनधिकृत एआय"],
        "Attack Graph": ["attack graph", "अटॅक ग्राफ"],
        "Delegation Graph": ["delegation", "डेलिगेशन"],
        "Red-Team Simulation": ["red team", "simulation", "सिम्युलेशन"],
        "Predictive Risk": ["predictive risk", "भविष्यकालीन जोखीम"],
        "Digital Twin Replay": ["digital twin", "डिजिटल ट्विन"],
        "Tool Proxy Gateway": ["tool proxy", "टूल प्रॉक्सी"],
        "Secret Manager": ["secret manager", "सिक्रेट मॅनेजर"],
        "Behavioral Drift": ["behavioral drift", "वर्तन बदल"],
        "Policy-as-Code & GitOps": ["policy", "पॉलिसी"],
        "Reverse Engineering": ["reverse engineering", "रिव्हर्स इंजिनिअरिंग"],
        "Forensic Dossiers": ["forensic", "फॉरेन्सिक"],
        "Cryptographic Audit": ["audit", "ऑडिट"],
        "Settings & RBAC": ["settings", "सेटिंग्ज", "सेटिंग्स"]
    }
    for page, keywords in nav_map.items():
        for kw in keywords:
            if f"go to {kw}" in p or f"open {kw}" in p or f"{kw} ughada" in p or f"{kw} kholo" in p or f"{kw} var ja" in p:
                return "navigate_frontend", {"target_page": page}, page, lang

    return None, {}, None, lang
