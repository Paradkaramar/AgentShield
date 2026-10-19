# backend/app/jarvis/language_detection.py
"""Multilingual Language Detection Engine for AgentShield JARVIS.
Accurately distinguishes Marathi, Hindi, Hinglish, and English across both
Devanagari script and Latin/Roman transliteration.
"""

import re
from typing import Dict, Any, Tuple, Optional

# Distinct Marathi Devanagari markers
MARATHI_DEVANAGARI_MARKERS = [
    "ळ",            # U+0933 - Distinct Marathi retroflex Lla
    "आहे", "आहेत",  # is, are
    "नाही", "नाहीत",# not, are not
    "मला", "तुला",  # to me, to you
    "आम्हाला",      # to us
    "दाखव", "दाखवा",# show
    "द्या", "द्यावे", # give
    "कोणत्या", "कोणता", "कोणती", # which
    "सगळे", "सगळ्यात", "सर्व", "सर्वात", # all, most
    "जास्त", "कमी", # more, less
    "करा", "करावे", # do
    "सांगा", "सांग", # tell
    "उघडा", "उघड",  # open
    "तपासा", "तपास", # check
    "झाले", "झाला", "झाली", # happened
    "होते", "होता", # was/were
    "कसा", "कशी", "कसे", # how
    "केव्हा", "कुठे", # when, where
    "माहिती", "अहवाल", "धोका", # info, report, danger
    "विसरून जा", "विसरा" # forget (injection screening)
]

# Distinct Hindi Devanagari markers
HINDI_DEVANAGARI_MARKERS = [
    "है", "हैं",    # is, are
    "नहीं", "मत",   # not
    "मुझे", "हमें", # to me, to us
    "दिखाओ", "दिखाइए", # show
    "दीजिए", "दो",  # give
    "कौनसा", "किस", "कौन", # which, who
    "सारे", "सब", "सबसे", # all, most
    "ज्यादा", "कम", # more, less
    "करो", "कीजिए", # do
    "बताओ", "बताइए", # tell
    "खोलो", "खोलिए", # open
    "जांचो", "जांच", # inspect
    "हुआ", "हुए", "हुई", # happened
    "था", "थे", "थी", # was/were
    "कैसे", "कैसा", # how
    "कब", "कहाँ",   # when, where
    "जानकारी", "रिपोर्ट", "खतरा", # info, report, danger
    "भूल जाओ", "अनदेखा" # forget, ignore (injection screening)
]

# Distinct Marathi Romanized/Transliterated keywords
MARATHI_ROMAN_MARKERS = {
    "mala", "tula", "amhala", "tyanche", "tyache", "dakhav", "dakhva", "dya",
    "kontya", "konta", "konti", "saglyat", "sagle", "sagla", "jast", "kami",
    "aahe", "ahet", "nahi", "nahit", "kara", "karave", "sanga", "sang",
    "ughada", "ughad", "tapas", "tapasa", "zhale", "zhala", "zhali",
    "hote", "hota", "kasa", "kashi", "kase", "kiti", "kahi", "karan",
    "ahaval", "dhoka", "suraksha", "saransh", "visrun", "visra", "madhe"
}

# Distinct Hindi Romanized keywords
HINDI_ROMAN_MARKERS = {
    "mujhe", "humein", "uska", "unka", "dikhao", "dikhaiye", "dijiye", "batao",
    "bataiye", "kholo", "kholiye", "kaunsa", "kis", "kaun", "saare", "sabse",
    "zyada", "hai", "hain", "nahi", "mat", "karo", "kijiye", "hua", "huye",
    "tha", "thi", "kaise", "kaisa", "kitna", "kuch", "kyun", "kyu",
    "jaankari", "khatra", "bhool", "andekha"
}

# Mixed Hinglish connector markers
HINGLISH_HYBRID_MARKERS = {
    "check karo", "explain karo", "summary batao", "threats dikhao", "logs kholo",
    "agent ko", "risk score kitna", "suspend karo", "kill switch dabao",
    "investigate karo", "report generate karo", "block kyun hua"
}

# Mixed Marathi-English (Marathlish) markers
MARATHLISH_HYBRID_MARKERS = {
    "check kara", "explain kara", "summary dya", "threats dakhav", "threats dakhva",
    "logs ughada", "agent la", "risk score kiti", "suspend kara", "kill switch chalva",
    "investigate kara", "report draft kara", "block ka zala", "risk score saglyat jast"
}

def is_devanagari(text: str) -> bool:
    """Returns True if text contains Devanagari script characters (U+0900 to U+097F)."""
    return any("\u0900" <= ch <= "\u097F" for ch in text)

def detect_language(text: str, user_preference: str = "auto", fallback_lang: Optional[str] = "en") -> str:
    """Detects whether text is Marathi ('mr'), Hindi ('hi'), Hinglish ('hinglish'), or English ('en'),
    honoring explicit user preferences when set to a specific language.
    """
    if user_preference and user_preference not in {"auto", "AUTO"}:
        return user_preference
    return detect_text_language(text, fallback_lang=fallback_lang)

def detect_text_language(text: str, fallback_lang: Optional[str] = "en") -> str:
    """Detects whether text is Marathi ('mr'), Hindi ('hi'), Hinglish ('hinglish'), or English ('en')."""
    if not text or not text.strip():
        return fallback_lang or "en"

    cleaned = text.strip()
    lower_text = cleaned.lower()

    # 1. Check for explicit language requests from the user
    if any(p in lower_text for p in ["reply in marathi", "in marathi", "मराठीत बोला", "मराठीत सांगा", "मराठीत द्या", "marathit sanga", "marathi madhe"]):
        return "mr"
    if any(p in lower_text for p in ["reply in hindi", "in hindi", "हिन्दी में बोलो", "हिंदी में बताओ", "hindi mein batao", "hindi me bolo"]):
        return "hi"
    if any(p in lower_text for p in ["reply in english", "in english", "इंग्रजीत सांगा", "अंग्रेजी में बोलो"]):
        return "en"

    # 2. Devanagari Script Analysis
    if is_devanagari(cleaned):
        # Distinct letter 'ळ' is an unequivocal Marathi marker in modern Indic languages
        if "ळ" in cleaned:
            return "mr"

        mr_score = 0
        hi_score = 0

        for marker in MARATHI_DEVANAGARI_MARKERS:
            if marker in cleaned:
                mr_score += len(marker)

        for marker in HINDI_DEVANAGARI_MARKERS:
            if marker in cleaned:
                hi_score += len(marker)

        if mr_score > hi_score:
            return "mr"
        if hi_score > mr_score:
            return "hi"
        # If ambiguous Devanagari, default based on markers count or fallback
        return "mr" if mr_score > 0 else ("hi" if hi_score > 0 else "hi")

    # 3. Hybrid English-Indic Phrases Check
    for phrase in MARATHLISH_HYBRID_MARKERS:
        if phrase in lower_text:
            return "mr"

    for phrase in HINGLISH_HYBRID_MARKERS:
        if phrase in lower_text:
            return "hinglish"

    # 4. Romanized Word Tokenization & Scoring
    words = set(re.findall(r"\b[a-z]+\b", lower_text))
    if not words:
        return fallback_lang or "en"

    mr_matches = words.intersection(MARATHI_ROMAN_MARKERS)
    hi_matches = words.intersection(HINDI_ROMAN_MARKERS)

    # Specific Marathi decisive words (e.g. 'mala', 'dakhav', 'saglyat', 'kontya', 'aahe')
    if any(w in mr_matches for w in ["mala", "dakhav", "dakhva", "saglyat", "kontya", "aahe", "ahet", "dya", "ughada", "tapas"]):
        return "mr"

    # Specific Hindi decisive words (e.g. 'mujhe', 'dikhao', 'sabse', 'kaunsa', 'batao', 'kholo')
    if any(w in hi_matches for w in ["mujhe", "dikhao", "sabse", "kaunsa", "batao", "kholo", "humein"]):
        # If words also contain English technical terms, categorize as Hinglish
        tech_words = {"risk", "score", "agent", "critical", "threats", "threat", "prompt", "injection", "audit", "incident", "zero", "trust"}
        if len(words.intersection(tech_words)) >= 1:
            return "hinglish"
        return "hi"

    if len(mr_matches) > len(hi_matches):
        return "mr"
    if len(hi_matches) > 0:
        return "hinglish" if len(words) > len(hi_matches) + 1 else "hi"

    # 5. Default to English
    return "en"

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
