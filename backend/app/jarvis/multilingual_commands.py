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
    context_incident_id: Optional[str] = None,
    session_context: Optional[Dict[str, Any]] = None
) -> Tuple[Optional[str], Dict[str, Any], Optional[str], str]:
    """Normalizes natural language commands in Marathi, Hindi, Hinglish, and English.
    Supports continuous multi-turn dialogue with contextual follow-up resolution.
    Returns: (tool_name, tool_args, nav_target, detected_lang)
    """
    clean = user_prompt.strip()
    p = clean.lower()
    # Strip leading and trailing assistant names (AMOJA / JARVIS / अमोजा / अमोझा / जार्विस)
    p = re.sub(r"^(?:(?:hey|hi|hello|ok|okay)?\s*(?:amoja|amoza|jarvis|अमोजा|अमोझा|जार्विस)\s*[,:\-]?\s*)", "", p)
    p = re.sub(r"(?:\s*[,:\-]?\s*(?:amoja|amoza|jarvis|अमोजा|अमोझा|जार्विस)\s*)$", "", p)
    p_norm = re.sub(r"[-_]", " ", p)
    lang = detect_text_language(clean)

    s_ctx = session_context or {}
    last_topic = s_ctx.get("last_topic", "")
    last_tool = s_ctx.get("last_tool", "")
    active_device = s_ctx.get("selected_device_id", "")
    active_agent = context_agent_id or s_ctx.get("selected_agent_id", "")
    active_inc = str(context_incident_id or s_ctx.get("selected_incident_id", "1"))

    # 1. Stop Listening / Pause Voice / Interruption commands
    if any(phrase in p or phrase in p_norm for phrase in [
        "stop listening", "listening band karo", "aikaiche thambva", "aikaiche thamba",
        "ऐकणे थांबवा", "बोलणे थांबवा", "ऐकू नका", "सुनना बंद करो", "बंद करो", "ruk jao",
        "pause listening", "mute voice", "shut up", "hold on", "wait wait"
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

    # 12. Continuous Network Monitoring: Status
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "network monitoring status", "show network monitoring status", "what is the network monitoring status",
        "network monitoring state", "continuous monitoring status", "network status",
        # Hindi / Hinglish
        "network monitoring status batao", "network monitoring ka status batao", "network monitoring status kya hai",
        "network status batao", "monitoring status batao", "net monitor status",
        "नेटवर्क मॉनिटरिंग का स्टेटस बताओ", "नेटवर्क मॉनिटरिंग स्टेटस बताओ", "नेटवर्क स्टेटस क्या है", "नेटवर्क मॉनिटरिंग की स्थिति बताओ",
        # Marathi
        "network monitoring chi sthiti sanga", "network monitoring status dakhav", "network monitoring status dakhva",
        "network monitoring sthiti sanga", "network status sanga", "network monitoring kay chaloo aahe",
        "नेटवर्क मॉनिटरिंग स्थिती सांगा", "नेटवर्क मॉनिटरिंग स्टेटस दाखवा", "नेटवर्क स्टेटस सांगा", "नेटवर्क मॉनिटरिंग स्टेटस काय आहे"
    ]):
        return "get_network_monitoring_status", {}, "Network Monitoring", lang

    # 13. Network Monitoring: Newly Discovered Devices
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "show newly discovered devices", "newly discovered devices", "discovered devices",
        "show discovered devices", "show newly discovered hosts", "discovered hosts",
        "show new devices", "new network devices", "new hosts on network",
        # Hindi / Hinglish
        "naye discovered devices dikhao", "naye devices dikhao", "naye hosts dikhao",
        "new devices dikhao", "newly discovered devices dikhao", "khoje gaye devices dikhao",
        "नए खोजे गए डिवाइस दिखाओ", "नए डिवाइस दिखाओ", "नए नेटवर्क डिवाइस दिखाओ", "खोजे गए नए होस्ट दिखाओ",
        # Marathi
        "navin shodhlele devices dakhav", "navin devices dakhav", "navin devices dakhva",
        "navin hosts dakhav", "navin shodhleli upkarne dakhav", "navin upkarne dakhva",
        "नवीन शोधलेली उपकरणे दाखवा", "नवीन शोधलेले डिव्हाइसेस दाखवा", "नवीन डिव्हाइसेस दाखवा", "नवीन होस्ट्स दाखवा"
    ]):
        return "get_network_discovered_devices", {"baseline_only": False}, "Network Monitoring", lang

    # 14. Network Monitoring: Suspicious Network Activity / Alerts
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "suspicious network activity", "show suspicious network activity", "network alerts",
        "network security alerts", "suspicious devices", "unusual network activity",
        # Hindi / Hinglish
        "suspicious network activity dikhao", "sandigdh network gatividhi dikhao",
        "network alerts dikhao", "network par suspicious kya hai",
        "संदिग्ध नेटवर्क गतिविधि दिखाओ", "नेटवर्क अलर्ट दिखाओ", "असामान्य नेटवर्क गतिविधि दिखाओ",
        # Marathi
        "mala suspicious network activity dakhav", "suspicious network activity dakhav",
        "shakkaspad network activity dakhav", "shakkaspad network halchali dakhav",
        "network alerts dakhav", "mala network alerts dakhav",
        "मला संशयास्पद नेटवर्क ॲक्टिव्हिटी दाखवा", "संशयास्पद नेटवर्क ॲक्टिव्हिटी दाखवा", "संशयास्पद नेटवर्क हालचाली दाखवा"
    ]):
        return "get_network_security_alerts", {"limit": 10}, "Network Monitoring", lang

    # 15. Network Monitoring: Start Monitoring Approved Network
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "start monitoring my approved network", "start network monitoring", "start monitoring approved network",
        "start approved network monitoring", "start network scan", "start continuous network monitoring",
        # Hindi / Hinglish
        "approved network monitoring shuru karo", "approved network monitoring start karo",
        "network monitoring shuru karo", "network monitoring start karo", "monitoring start karo",
        "नेटवर्क मॉनिटरिंग शुरू करो", "मंजूर नेटवर्क मॉनिटरिंग शुरू करो", "नेटवर्क स्कैन शुरू करो",
        # Marathi
        "majhya approved network chi monitoring suru kara", "approved network monitoring suru kara",
        "network monitoring suru kara", "network monitoring chalu kara", "monitoring suru kara",
        "माझे मंजूर नेटवर्क मॉनिटर करणे सुरू करा", "मंजूर नेटवर्क मॉनिटरिंग सुरू करा", "नेटवर्क मॉनिटरिंग सुरू करा", "नेटवर्क स्कॅन सुरू करा"
    ]):
        return "start_network_monitoring", {}, "Network Monitoring", lang

    # 16. Network Monitoring: Stop Monitoring Job
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "stop the current monitoring job", "stop current monitoring job", "stop the monitoring job",
        "stop network monitoring", "stop network scan", "stop current scan", "cancel current scan",
        # Hindi / Hinglish
        "current monitoring job roko", "network monitoring band karo", "monitoring band karo",
        "current scan roko", "network scan band karo", "scanning roko",
        "वर्तमान मॉनिटरिंग रोकें", "नेटवर्क मॉनिटरिंग बंद करो", "करंट मॉनिटरिंग रोको", "नेटवर्क स्कैन बंद करो",
        # Marathi
        "sadhya chaloo asleli monitoring thambva", "current monitoring job thambva",
        "network monitoring band kara", "monitoring band kara", "sadhya che scan thambva",
        "चालू मॉनिटरिंग थांबवा", "सध्याचे स्कॅन थांबवा", "नेटवर्क मॉनिटरिंग बंद करा", "स्कॅन थांबवा"
    ]):
        return "stop_network_monitoring", {}, "Network Monitoring", lang

    # 17. Sensitive Actions: Suspend / Kill Agent
    kill_match = re.search(r"(?:suspend|kill|quarantine|freeze|roko|block|थांबवा|बंद करा|निलंबित करा|रोकें)\s+(?:agent\s+)?([a-zA-Z0-9_-]+)", p)
    if not kill_match:
        # Check Marathi order: "agent-07 la suspend kara" / "agent-finance-01 band kara"
        marathi_kill_match = re.search(r"([a-zA-Z0-9_-]+)\s+(?:la|ko)?\s*(?:suspend|kill|quarantine|freeze|band|thambva|rok)\s*(?:kara|karo)?", p)
        if marathi_kill_match and marathi_kill_match.group(1) not in {"the", "an", "all", "this", "it", "jarvis", "monitoring", "network", "scan", "job"}:
            kill_match = marathi_kill_match

    if kill_match:
        target_name = kill_match.group(1).strip()
        if target_name not in {"the", "an", "all", "this", "it", "jarvis", "monitoring", "network", "scan", "job", "device"}:
            return "prepare_kill_switch", {"agent_id": target_name, "reason": f"Multilingual command: '{user_prompt}'"}, "Agents", lang

    # 18. Endpoint: Device Security Status
    if any(phrase in p or phrase in p_norm for phrase in [
        # Hindi / Hinglish
        "is device ki security status batao", "device ki security status batao", "device security status",
        "is computer ki security status", "computer security status", "device security status batao",
        "इस डिवाइस की सुरक्षा स्थिति बताओ", "डिवाइस की सुरक्षा स्थिति बताओ", "कंप्यूटर की सुरक्षा स्थिति बताओ",
        # Marathi
        "ya device chi suraksha sthiti sanga", "device chi suraksha sthiti sanga", "majhya computer chi suraksha sthiti sanga",
        "या डिव्हाइसची सुरक्षा स्थिती सांगा", "डिव्हाइसची सुरक्षा स्थिती दाखवा", "संगणकाची सुरक्षा स्थिती सांगा",
        # English
        "device security status", "show device security status", "what is my device security status",
        "is this device secure", "endpoint security status"
    ]):
        return "get_device_security_status", {"device_id": active_device}, "Device Security", lang

    # 19. Endpoint: Check Suspicious Connections / Open Ports (Direct or Follow-up)
    if any(phrase in p or phrase in p_norm for phrase in [
        # Hindi / Hinglish
        "mere computer par koi suspicious connection hai", "koi suspicious connection hai",
        "suspicious connection check karo", "suspicious connections check karo",
        "what about its connections", "what about its open ports", "check its connections",
        "check open ports", "open ports", "its connections", "its open ports", "its ports",
        "check its open ports", "iske ports dikhao", "iske connections check karo", "iske connections",
        "iske open ports", "open ports dikhao", "iske ports",
        "मेरे कंप्यूटर पर कोई संदिग्ध कनेक्शन है", "संदिग्ध कनेक्शन चेक करो",
        "इसके पोर्ट्स दिखाओ", "इसके कनेक्शन्स चेक करो", "इसके ओपन पोर्ट्स दिखाओ", "ओपन पोर्ट्स चेक करो", "इसके पोर्ट्स",
        # Marathi
        "majhya computer var kahi suspicious connection aahe ka", "kahi suspicious connection aahe ka",
        "suspicious connection tapasa", "sanshayaspad connection tapasa",
        "tyache ports tapasa", "yache ports tapasa", "tyache connections dakhav", "yache connections dakhav",
        "tyache ports", "yache ports", "त्याचे पोर्ट्स तपासा", "याचे पोर्ट्स तपासा", "त्याचे ओपन पोर्ट्स", "त्याचे कनेक्शन्स दाखवा",
        "याचे कनेक्शन्स दाखवा", "ओपन पोर्ट्स दाखवा", "पोर्ट्स दाखवा", "ओपन पोर्ट्स",
        "माझ्या संगणकावर काही संशयास्पद कनेक्शन आहे का", "माझ्या कॉम्प्युटरवर काही संशयास्पद कनेक्शन आहे का", "संशयास्पद कनेक्शन तपासा",
        # English
        "are there any suspicious connections", "check suspicious connections", "any suspicious connection on my computer",
        "check for suspicious connections", "show suspicious connections", "active socket connections", "open sockets"
    ]):
        return "check_suspicious_connections", {"device_id": active_device}, "Device Security", lang

    # 20. Endpoint: Security Alerts
    if any(phrase in p or phrase in p_norm for phrase in [
        # Marathi
        "mala navin security alerts dakhav", "navin security alerts dakhav", "navin alerts dakhav",
        "मला नवीन सिक्युरिटी अलर्ट्स दाखव", "नवीन सिक्युरिटी अलर्ट्स दाखवा", "नवीन अलर्ट्स दाखवा",
        # Hindi / Hinglish
        "naye security alerts dikhao", "device ke security alerts dikhao", "mujhe naye security alerts dikhao",
        "नए सुरक्षा अलर्ट दिखाओ", "डिवाइस के सुरक्षा अलर्ट दिखाओ",
        # English
        "show me new security alerts", "show new security alerts", "show device security alerts",
        "show endpoint security alerts", "get device alerts", "mala navin security alerts dakhav"
    ]):
        return "get_device_security_alerts", {"device_id": active_device, "limit": 10}, "Device Security", lang

    # 21. Endpoint: Firewall Status (Direct or Follow-up)
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "show me the current firewall status", "show current firewall status", "current firewall status",
        "show firewall status", "what is the firewall status", "check firewall status",
        "what about its firewall", "its firewall status", "its firewall",
        # Hindi / Hinglish
        "current firewall status dikhao", "firewall status batao", "firewall ka status batao",
        "iska firewall status", "iska firewall", "इसके फायरवॉल की स्थिति", "इसका फायरवॉल स्टेटस",
        "फायरवॉल की स्थिति बताओ", "वर्तमान फायरवॉल स्थिति दिखाओ",
        # Marathi
        "sadhya chi firewall sthiti dakhav", "firewall sthiti sanga", "firewall chi sthiti dakhav",
        "tyachi firewall sthiti", "yachi firewall sthiti", "त्याची फायरवॉल स्थिती", "याची फायरवॉल स्थिती",
        "सध्याची फायरवॉल स्थिती दाखवा", "फायरवॉल स्थिती सांगा"
    ]):
        return "get_endpoint_firewall_status", {"device_id": active_device}, "Device Security", lang

    # 22. Contextual Follow-up: Pause / Stop
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "pause it", "pause monitoring", "pause security monitoring", "pause device monitoring",
        "stop it", "ते थांबवा", "थांबवा", "रोको", "पॉज करो", "रोक दो",
        # Hindi / Hinglish
        "monitoring pause karo", "device monitoring pause karo", "security monitoring pause karo",
        "मॉनिटरिंग पॉज करो", "मॉनिटरिंग रोक दो",
        # Marathi
        "monitoring thambva", "device monitoring thambva", "monitoring pause kara",
        "मॉनिटरिंग थांबवा", "डिव्हाइस मॉनिटरिंग थांबवा"
    ]):
        if last_topic == "network" or "network" in last_tool:
            return "stop_network_monitoring", {}, "Network Monitoring", lang
        return "pause_endpoint_monitoring", {"device_id": active_device}, "Device Security", lang

    # 23. Endpoint: Disconnect Device
    if any(phrase in p or phrase in p_norm for phrase in [
        # English
        "disconnect this device from the dashboard", "disconnect this device", "disconnect device from dashboard",
        # Hindi / Hinglish
        "is device ko dashboard se disconnect karo", "is device ko disconnect karo",
        "इस डिवाइस को डैशबोर्ड से डिस्कनेक्ट करो",
        # Marathi
        "ya device la dashboard varun disconnect kara", "ya device la disconnect kara",
        "या डिव्हाइसला डॅशबोर्डवरून डिस्कनेक्ट करा"
    ]):
        return "disconnect_endpoint_device", {"device_id": active_device}, "Device Security", lang

    # 24. Contextual Follow-up: Network Scan Trigger
    if any(phrase in p or phrase in p_norm for phrase in [
        "trigger a scan now", "trigger scan", "start a scan", "scan now", "run a scan",
        "te suru kara", "scan suru kara", "ते सुरू करा", "स्कॅन सुरू करा", "सुरू करा",
        "ise shuru karo", "scan shuru karo", "स्कैन शुरू करो", "शुरू करो", "स्कैन चलाओ"
    ]):
        if last_topic == "network" or "network" in last_tool:
            return "trigger_network_scan_now", {}, "Network Monitoring", lang

    # 25. Contextual Follow-up: Incident Details / Tell Me More
    if any(phrase in p or phrase in p_norm for phrase in [
        "tell me more about it", "tell me more about that alert", "tell me more about that incident",
        "investigate it", "investigate that alert", "investigate that incident",
        "show more details", "more details about this incident", "more details about that alert",
        "tyachyabaddal sanga", "yachyabaddal sanga", "tyachyabaddal adhik sanga", "yachyabaddal adhik sanga",
        "tyachi chaukashi kara", "yachi janch kara", "adhik mahiti dya",
        "त्याच्याबद्दल अधिक सांगा", "याच्याबद्दल अधिक सांगा", "याबद्दल अधिक सांगा", "त्याबद्दल अधिक सांगा",
        "याच्याबद्दल सांगा", "त्याच्याबद्दल सांगा", "त्याची चौकशी करा", "याची चौकशी करा", "अधिक माहिती द्या",
        "iske bare mein batao", "iske bare mein aur batao", "iski janch karo", "iski jaanch karo",
        "इसके बारे में बताओ", "इसके बारे में और बताओ", "इसके बारे में अधिक बताओ", "इसकी जांच करो"
    ]):
        return "get_incident_details", {"incident_identifier": active_inc}, "Incidents & Alerts", lang

    # 26. Contextual Follow-up: Incident Report Draft
    if any(phrase in p or phrase in p_norm for phrase in [
        "draft a report for it", "generate report for it", "generate incident report for it",
        "tyacha ahaval banva", "ahaval draft kara", "त्याचा अहवाल बनवा", "इन्सिडेंट अहवाल बनवा",
        "iski report banao", "report generate karo", "इसकी रिपोर्ट बनाओ", "रिपोर्ट बनाओ"
    ]):
        return "generate_incident_report_draft", {"incident_id": active_inc}, "Forensic Dossiers", lang

    # 27. Contextual Follow-up: Inspect Agent Permissions
    if any(phrase in p or phrase in p_norm for phrase in [
        "what are its permissions", "show its permissions", "check its permissions", "inspect its permissions",
        "agent permissions", "show permissions", "permissions dakhav", "permission dikhao",
        "tyachya parvangya dakhav", "parvangya tapasa", "त्याच्या परवानग्या दाखवा", "परवानग्या तपासा",
        "iski permission dikhao", "permissions check karo", "इसकी परमिशन दिखाओ", "परमिशन चेक करो"
    ]):
        target = active_agent or "agent-finance-01"
        match = re.search(r"agent-[a-zA-Z0-9_-]+", p)
        if match:
            target = match.group(0)
        return "inspect_permissions", {"agent_id": target}, "Real-Time Monitor", lang

    # 24. Navigation directives
    nav_map = {
        "overview": ["overview", "डॅशबोर्ड", "अवलोकन"],
        "Real-Time Monitor": ["real-time", "monitor", "मॉनिटर", "निरीक्षण"],
        "Network Monitoring": ["network monitoring", "network monitor", "नेटवर्क मॉनिटरिंग", "नेटवर्क"],
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
