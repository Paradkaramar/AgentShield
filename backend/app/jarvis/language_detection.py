# backend/app/jarvis/language_detection.py
"""Multilingual Language Detection Engine for AgentShield JARVIS & AMOJA AI.
Accurately distinguishes Marathi ('mr'), Hindi ('hi'), Hinglish ('hinglish'), and English ('en')
across Devanagari script, Latin/Roman transliteration, hybrid code-switching sentences,
and multi-turn conversational context.
"""

import re
from typing import Dict, Any, Tuple, Optional, Set

# Distinct Marathi Devanagari markers
MARATHI_DEVANAGARI_MARKERS = [
    "ळ",            # U+0933 - Distinct Marathi retroflex Lla
    "माझ्या", "माझे", "माझा", "माझी", "आमच्या", "आमचे", "आमचा", "आमची",
    "त्यांचे", "त्याचा", "त्याची", "त्याचे", "ह्यांचे", "यांचे",
    "ची", "चे", "चा", "च्या", "ला", "ना", "हून", "वरून", "कडे", "मध्ये",
    "आहे", "आहेत",  # is, are
    "नाही", "नाहीत",# not, are not
    "मला", "तुला",  # to me, to you
    "आम्हाला",      # to us
    "दाखव", "दाखवा",# show
    "द्या", "द्यावे", # give
    "कोणत्या", "कोणता", "कोणती", "कोणते", # which
    "सगळे", "सगळ्यात", "सर्व", "सर्वात", "सर्वच", # all, most
    "जास्त", "कमी", # more, less
    "करा", "करावे", "कर", "करू", # do
    "सांगा", "सांग", # tell
    "बघा", "बघ",    # look
    "उघडा", "उघड",  # open
    "तपासा", "तपास", # check
    "झाले", "झाला", "झाली", "झालेले", # happened
    "होते", "होता", "होती", # was/were
    "कसा", "कशी", "कसे", "कशा", # how
    "केव्हा", "कुठे", "कधी", "काय", # when, where, what
    "माहिती", "अहवाल", "धोका", "सुरक्षा", # info, report, danger
    "लॅपटॉप", "संगणक", "उपकरण", # laptop, computer, device
    "होय", "ठीक आहे", # yes, okay
    "विसरून जा", "विसरा" # forget (injection screening)
]

# Distinct Hindi Devanagari markers
HINDI_DEVANAGARI_MARKERS = [
    "मेरा", "मेरी", "मेरे", "हमारा", "हमारी", "हमारे", "आपका", "आपकी", "आपके",
    "उसका", "उसकी", "उसके", "उनका", "उनकी", "उनके",
    "है", "हैं", "हूँ", "हो", # is, are, am, be
    "नहीं", "मत",   # not
    "मुझे", "हमें", "तुम्हें", "आपको", "उसे", "उन्हें", # to me, us, you
    "दिखाओ", "दिखाइए", "देखें", "देखो", # show
    "दीजिए", "दो",  # give
    "कौनसा", "कौनसी", "कौनसे", "किस", "कौन", "किसे", # which, who
    "सारे", "सब", "सबसे", "सभी", # all, most
    "ज्यादा", "कम", # more, less
    "करो", "कीजिए", "करना", "करूँ", "करें", # do
    "सकती", "सकता", "सकते", # can / able to
    "चल", "रहा", "रही", "रहे", # running, moving
    "बताओ", "बताइए", # tell
    "खोलो", "खोलिए", # open
    "जांचो", "जांच", "तलाशो", # inspect
    "हुआ", "हुए", "हुई", # happened
    "था", "थे", "थी", # was/were
    "कैसे", "कैसा", "कैसी", # how
    "कब", "कहाँ", "कहा", "क्यों", "क्यूं", "क्या", # when, where, why, what
    "कंप्यूटर", "धीमा", "धीमे", # computer, slow
    "जानकारी", "रिपोर्ट", "खतरा", "सुरक्षा", # info, report, danger
    "हाँ", "ठीक है", # yes, okay
    "भूल जाओ", "अनदेखा" # forget, ignore (injection screening)
]

# Distinct Marathi Romanized/Transliterated keywords
MARATHI_ROMAN_MARKERS: Set[str] = {
    "mala", "tula", "amhala", "majhya", "majhe", "majha", "majhi",
    "tyanche", "tyache", "tyachi", "yache", "yachi", "dakhav", "dakhva", "dya",
    "kontya", "konta", "konti", "saglyat", "sagle", "sagla", "jast", "kami",
    "aahe", "ahet", "nahi", "nahit", "kara", "karave", "kar", "sanga", "sang",
    "baga", "bagh", "ughada", "ughad", "tapas", "tapasa", "zhale", "zhala", "zhali",
    "hote", "hota", "hoti", "kasa", "kashi", "kase", "kiti", "kahi", "karan",
    "kay", "kadhi", "kuthe", "ahaval", "dhoka", "suraksha", "saransh", "visrun", "visra", "madhe",
    "upkaran", "thambva", "thamba", "ho", "laptopchi", "systemchi", "computerchi", "chi", "cha", "che"
}

# Distinct Hindi Romanized keywords
HINDI_ROMAN_MARKERS: Set[str] = {
    "mera", "meri", "mere", "humara", "humari", "humare", "aapka", "aapki", "aapke",
    "uska", "uski", "uske", "unka", "unki", "unke", "mujhe", "humein", "tum", "tumhara",
    "dikhao", "dikhaiye", "dijiye", "batao", "bataiye", "kholo", "kholiye",
    "kaunsa", "kaunsi", "kaunse", "kis", "kaun", "kya", "kyun", "kyu",
    "saare", "sabse", "sab", "zyada", "hai", "hain", "hoon", "ho", "nahi", "mat",
    "karo", "kijiye", "kar", "sakti", "sakta", "sakte", "chal", "raha", "rahi", "rahe",
    "hua", "huye", "hui", "tha", "thi", "kaise", "kaisa", "kaisi",
    "kitna", "kitni", "kuch", "jaankari", "khatra", "bhool", "andekha", "shuru", "roko",
    "theek", "haan", "dost", "aap", "computer", "slow"
}

# Mixed Hinglish connector markers & phrases
HINGLISH_HYBRID_MARKERS = {
    "check karo", "explain karo", "summary batao", "threats dikhao", "logs kholo",
    "agent ko", "risk score kitna", "suspend karo", "kill switch dabao",
    "investigate karo", "report generate karo", "block kyun hua", "kya kar sakti ho",
    "tum kya", "slow kyun chal", "slow kyu chal", "mera system", "mera computer",
    "kaise ho", "kya chal raha", "kaam kar", "kaise kare", "bata sakti ho", "kya kar sakti"
}

# Mixed Marathi-English (Marathlish) markers & phrases
MARATHLISH_HYBRID_MARKERS = {
    "check kara", "explain kara", "summary dya", "threats dakhav", "threats dakhva",
    "logs ughada", "agent la", "risk score kiti", "suspend kara", "kill switch chalva",
    "investigate kara", "report draft kara", "block ka zala", "risk score saglyat jast",
    "security tapas", "security check kar", "security check kara", "chi security",
    "majhya laptop", "majhya system", "kashi aahes", "kay karu shakte", "laptop chi"
}

# Explicit user language switch patterns
EXPLICIT_ENGLISH_PATTERNS = [
    r"\b(?:reply\s+in|explain\s+in|in|speak\s+in|switch\s+to|use)\s+english\b",
    r"\bplease\s+explain\s+this\s+in\s+english\b",
    r"\benglish\s+please\b",
    r"\bइंग्रजीत\s+(?:सांगा|बोला|द्या|सांग)\b",
    r"\bअंग्रेजी\s+में\s+(?:बोलो|बताओ|बताइए)\b"
]

EXPLICIT_MARATHI_PATTERNS = [
    r"\b(?:reply\s+in|explain\s+in|in|speak\s+in|switch\s+to|use)\s+marathi\b",
    r"\bmarathi\s+madhe\b",
    r"\bmarathit\s+(?:sanga|bola|dya)\b",
    r"\bमराठीत\s+(?:बोला|सांगा|द्या|सांग)\b",
    r"\bमराठी\s+मध्ये\b"
]

EXPLICIT_HINDI_PATTERNS = [
    r"\b(?:reply\s+in|explain\s+in|in|speak\s+in|switch\s+to|use)\s+hindi\b",
    r"\bhindi\s+mein\b",
    r"\bhindi\s+me\s+(?:batao|bolo|dijiye)\b",
    r"\bहिन्दी\s+में\s+(?:बोलो|बताओ|बताइए)\b",
    r"\bहिंदी\s+में\s+(?:बोलो|बताओ|बताइए)\b"
]

def is_devanagari(text: str) -> bool:
    """Returns True if text contains Devanagari script characters (U+0900 to U+097F)."""
    return any("\u0900" <= ch <= "\u097F" for ch in text)

def detect_language(
    text: str,
    user_preference: str = "auto",
    fallback_lang: Optional[str] = "en",
    session_lang: Optional[str] = None
) -> str:
    """Detects whether user prompt is Marathi ('mr'), Hindi ('hi'), Hinglish ('hinglish'), or English ('en').
    Automatically detects language per turn from the actual text/transcript.
    For short or ambiguous messages, uses recent conversation session language.
    """
    clean = (text or "").strip()
    if not clean:
        return session_lang or (user_preference if user_preference not in {"auto", "AUTO"} else (fallback_lang or "en"))

    lower = clean.lower()

    # 1. Explicit user language switch directives override everything
    for pat in EXPLICIT_ENGLISH_PATTERNS:
        if re.search(pat, lower, re.IGNORECASE):
            return "en"
    for pat in EXPLICIT_MARATHI_PATTERNS:
        if re.search(pat, lower, re.IGNORECASE):
            return "mr"
    for pat in EXPLICIT_HINDI_PATTERNS:
        if re.search(pat, lower, re.IGNORECASE):
            return "hi"

    # 1b. If user manually specified a fixed preference (not 'auto'), honor it
    if user_preference and user_preference.lower() not in {"auto", "none", ""}:
        return user_preference.lower()

    # 2. Check for short ambiguous messages that should maintain session context
    words = re.findall(r"\b[a-zA-Z\u0900-\u097F]+\b", lower)
    is_short = len(words) <= 2 or len(clean) <= 12
    neutral_short_terms = {
        "ok", "okay", "haan", "ha", "ho", "theek", "theek hai", "yes", "yep", "sure",
        "thanks", "thank you", "dhanyavaad", "shukriya", "cancel", "stop", "1", "2",
        "proceed", "confirm", "done", "next"
    }
    if is_short and clean.lower() in neutral_short_terms:
        if session_lang in {"mr", "hi", "hinglish", "en"}:
            return session_lang

    # 3. Run core text analysis
    detected = detect_text_language(clean, fallback_lang=None)
    if detected:
        return detected

    # 4. Contextual fallback if available
    if session_lang in {"mr", "hi", "hinglish", "en"}:
        return session_lang

    if user_preference and user_preference not in {"auto", "AUTO"}:
        return user_preference

    return fallback_lang or "en"

def detect_text_language(text: str, fallback_lang: Optional[str] = "en") -> str:
    """Analyzes text characteristics to classify as Marathi, Hindi, Hinglish, or English."""
    if not text or not text.strip():
        return fallback_lang or "en"

    cleaned = text.strip()
    lower_text = cleaned.lower()

    # Explicit directives check
    for pat in EXPLICIT_ENGLISH_PATTERNS:
        if re.search(pat, lower_text, re.IGNORECASE):
            return "en"
    for pat in EXPLICIT_MARATHI_PATTERNS:
        if re.search(pat, lower_text, re.IGNORECASE):
            return "mr"
    for pat in EXPLICIT_HINDI_PATTERNS:
        if re.search(pat, lower_text, re.IGNORECASE):
            return "hi"

    # --- Devanagari Script Analysis ---
    if is_devanagari(cleaned):
        # Distinct letter 'ळ' is an unequivocal Marathi marker
        if "ळ" in cleaned:
            return "mr"

        mr_score = 0
        hi_score = 0

        for marker in MARATHI_DEVANAGARI_MARKERS:
            if marker in cleaned:
                weight = 3 if marker in {"माझ्या", "माझे", "माझा", "माझी", "ची", "तपास", "तपासा", "सांगा", "दाखव"} else 1
                mr_score += len(marker) * weight

        for marker in HINDI_DEVANAGARI_MARKERS:
            if marker in cleaned:
                weight = 3 if marker in {"मेरा", "मेरी", "मेरे", "क्यों", "चल", "रहा", "सकती", "सकता", "हो"} else 1
                hi_score += len(marker) * weight

        if mr_score > hi_score:
            return "mr"
        if hi_score > mr_score:
            return "hi"
        return "mr" if mr_score > 0 else ("hi" if hi_score > 0 else "hi")

    # --- Hybrid Phrase Matching (Indic + English Technical Terms) ---
    for phrase in MARATHLISH_HYBRID_MARKERS:
        if phrase in lower_text:
            return "mr"

    for phrase in HINGLISH_HYBRID_MARKERS:
        if phrase in lower_text:
            return "hinglish"

    # --- Romanized Word Tokenization & Scoring ---
    words = set(re.findall(r"\b[a-z]+\b", lower_text))
    if not words:
        return fallback_lang or "en"

    # Check for pure English phrases before Indic token scoring
    english_common = {
        "hello", "hi", "hey", "how", "are", "you", "what", "can", "do",
        "please", "explain", "this", "in", "is", "the", "for", "with",
        "good", "morning", "afternoon", "evening", "give", "me", "status",
        "show", "system", "security", "threats", "incidents", "alerts"
    }
    english_query_phrases = [
        "how are you", "who are you", "what can you do", "give me the",
        "show me", "please explain", "what is", "is there any"
    ]
    if any(qp in lower_text for qp in english_query_phrases):
        return "en"

    if words.issubset(english_common) and not words.intersection({"mera", "meri", "kya", "tum", "karo", "sakti", "tapas"}):
        return "en"

    mr_matches = words.intersection(MARATHI_ROMAN_MARKERS)
    hi_matches = words.intersection(HINDI_ROMAN_MARKERS)

    # Specific decisive Marathi words
    decisive_mr = {
        "majhya", "majhe", "majha", "majhi", "mala", "dakhav", "dakhva",
        "saglyat", "kontya", "aahe", "ahet", "dya", "ughada", "tapas",
        "tapasa", "sanga", "thambva", "chi", "kay"
    }
    if len(words.intersection(decisive_mr)) >= 1:
        return "mr"

    # Specific decisive Hindi words in Roman script -> Hinglish
    decisive_hi = {
        "mera", "meri", "mere", "mujhe", "dikhao", "sabse", "kaunsa",
        "batao", "kholo", "humein", "tum", "kya", "sakti", "sakta",
        "sakte", "kyun", "kyu", "chal", "raha", "karo", "hai", "hain", "ho"
    }
    if len(words.intersection(decisive_hi)) >= 1:
        return "hinglish"

    if len(mr_matches) > len(hi_matches):
        return "mr"
    if len(hi_matches) > 0:
        return "hinglish"

    # Default to English
    return fallback_lang or "en"

def get_language_display_name(lang_code: str) -> str:
    """Returns human-readable display label for language code."""
    names = {
        "en": "English",
        "hi": "हिन्दी (Hindi)",
        "mr": "मराठी (Marathi)",
        "hinglish": "Hinglish (Hindi + English)",
        "auto": "Auto-Detect"
    }
    return names.get(lang_code, "English")

def get_bcp47_tag(lang_code: str) -> str:
    """Returns standard BCP-47 speech recognition/synthesis tag."""
    tags = {
        "mr": "mr-IN",
        "hi": "hi-IN",
        "hinglish": "en-IN",
        "en": "en-US",
        "auto": "en-US"
    }
    return tags.get(lang_code, "en-US")
