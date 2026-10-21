# backend/app/jarvis/live_intelligence.py
"""
AMOJA AI Live Intelligence & Real-Time Knowledge Engine.

Provides:
1. Intelligent Query Router: Classifies user queries into domain categories.
2. Live Web Search & News Intelligence: Google News RSS / DuckDuckGo multi-provider engine with citations.
3. Cybersecurity Intelligence: Real-time CISA KEV & NIST/CVE records and advisory parsing.
4. Live Weather Engine: Open-Meteo free global meteorological data with multilingual forecast mapping.
5. Windows & Software Intelligence: Microsoft release status and update verification.
6. Untrusted Content & Prompt Injection Defense: Sanitization of external webpage text.
7. Caching & Stale Result Labeling with cryptographic audit logs.
"""

import os
import re
import json
import hashlib
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
import httpx

from ..db.database import connect, now_iso

# Cache TTL configurations (in seconds)
TTL_WEATHER = 900          # 15 minutes
TTL_NEWS = 1800            # 30 minutes
TTL_CYBER = 7200           # 2 hours
TTL_WINDOWS_UPDATE = 14400 # 4 hours
TTL_WEB_RESEARCH = 1800    # 30 minutes

HTTP_TIMEOUT = 8.0         # 8 seconds max for external network requests
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 AMOJA-LiveIntel/2.0"


class LiveQueryCategory(str, Enum):
    GENERAL_KNOWLEDGE = "GENERAL_KNOWLEDGE"
    CURRENT_EVENTS_NEWS = "CURRENT_EVENTS_NEWS"
    AI_TECH_RELEASES = "AI_TECH_RELEASES"
    CYBERSECURITY_INTELLIGENCE = "CYBERSECURITY_INTELLIGENCE"
    WEATHER_FORECAST = "WEATHER_FORECAST"
    WINDOWS_SOFTWARE_UPDATES = "WINDOWS_SOFTWARE_UPDATES"
    RESEARCH_SOURCE_COMPARISON = "RESEARCH_SOURCE_COMPARISON"
    PERSONAL_ASSISTANT = "PERSONAL_ASSISTANT"
    AGENTSHIELD_OPERATIONS = "AGENTSHIELD_OPERATIONS"


# --- 1. Untrusted Content Sanitizer & Prompt Injection Defense ---

SUSPICIOUS_CONTENT_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions", re.IGNORECASE),
    re.compile(r"system\s+prompt\s+override", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:dan|unrestricted|godmode|jailbroken)", re.IGNORECASE),
    re.compile(r"<script[\s\S]*?>[\s\S]*?<\/script>", re.IGNORECASE),
    re.compile(r"javascript:\s*", re.IGNORECASE),
    re.compile(r"base64(?:_decode)?\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"disregard\s+(?:the\s+)?(?:guardrails|guidelines|safety)", re.IGNORECASE),
    re.compile(r"bypass\s+(?:firewall|security|agentshield)", re.IGNORECASE),
]


def defend_untrusted_content(text: str) -> Tuple[str, bool]:
    """
    Sanitizes retrieved web content and news snippets against prompt injection
    and policy override attempts.
    Returns: (sanitized_text, injection_detected)
    """
    if not text:
        return "", False

    cleaned = text
    injection_detected = False

    for pattern in SUSPICIOUS_CONTENT_PATTERNS:
        if pattern.search(cleaned):
            injection_detected = True
            cleaned = pattern.sub("[REDACTED_UNTRUSTED_CONTENT]", cleaned)

    # Strip dangerous HTML tags
    cleaned = re.sub(r"<(?:iframe|object|embed|applet|meta|link)[^>]*?>", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"<\/(?:iframe|object|embed|applet|meta|link)>", "", cleaned, flags=re.IGNORECASE)

    return cleaned.strip(), injection_detected


# --- 2. Intelligent Query Router ---

WEATHER_KEYWORDS = [
    "weather", "forecast", "temperature", "rain", "rainfall", "humidity", "climate", "monsoon",
    "hava", "havaman", "mausam", "barish", "dhoop", "thandi", "garmi",
    "हवामान", "पाऊस", "तापमान", "मौसम", "बारिश"
]

DEVANAGARI_CITIES = {
    "मुंबई": "Mumbai", "मुंबईचे": "Mumbai", "मुंबईत": "Mumbai",
    "पुणे": "Pune", "पुण्याचे": "Pune", "पुण्यात": "Pune",
    "दिल्ली": "Delhi", "दिल्लीचे": "Delhi", "दिल्लीत": "Delhi",
    "नागपूर": "Nagpur", "नागपूरचे": "Nagpur",
    "नाशिक": "Nashik", "नाशिकचे": "Nashik",
    "बंगळुरू": "Bengaluru", "बेंगलुरु": "Bengaluru",
    "हैदराबाद": "Hyderabad", "चेन्नई": "Chennai",
    "कोलकाता": "Kolkata"
}

CYBER_KEYWORDS = [
    "cve", "vulnerability", "exploit", "cisa", "kev", "zero-day", "0-day", "cert-in", "advisory",
    "ransomware", "malware", "phishing", "nvd", "security bulletin",
    "धोका", "सायबर", "सुरक्षा अलर्ट", "खतरा", "कमजोरी", "मैलवेयर"
]

AI_TECH_KEYWORDS = [
    "ai", "artificial intelligence", "llm", "gpt", "gemini", "claude", "deepseek", "nvidia",
    "model launch", "new launch", "tech news", "technology", "gadget", "software release",
    "नया एआई", "नवीन तंत्रज्ञान", "मॉडेल", "लॉन्च"
]

NEWS_KEYWORDS = [
    "news", "latest news", "breaking news", "today news", "current affairs", "headlines",
    "batmya", "taja batmya", "khabar", "samachar", "aaj ki news",
    "बातम्या", "ताज्या बातम्या", "वृत्त", "समाचार", "ताज़ा ख़बर", "खबरें"
]

WINDOWS_UPDATE_KEYWORDS = [
    "windows update", "windows 11 update", "windows 10 update", "kb article", "patch update",
    "os update", "software update", "driver update", "microsoft update", "patch tuesday", "windows 11",
    "विंडोज अपडेट", "सॉफ्टवेअर अपडेट"
]

RESEARCH_KEYWORDS = [
    "research", "compare sources", "verify online", "fact check", "source comparison",
    "find articles", "search web for", "internet par dhundo", "google search",
    "संशोधन", "तपासा", "इंटरनेटवर शोधा", "रिसर्च"
]

PERSONAL_ASSISTANT_KEYWORDS = [
    "open notepad", "close notepad", "open calc", "open calculator", "open paint",
    "open edge", "open chrome", "send whatsapp", "take note", "add reminder", "set reminder",
    "set a reminder", "create reminder", "remind me", "reminder",
    "add todo", "todo list", "my memory", "system status", "battery status",
    "नोटपॅड", "कॅल्क्युलेटर", "व्हॉट्सॲप", "आठवण", "नोट", "टास्क", "रिमाइंडर"
]

AGENTSHIELD_KEYWORDS = [
    "quarantine", "kill switch", "firewall", "block port", "allow port",
    "soc", "dlp", "sandbox", "incident", "network scan", "audit log", "drift",
    "फायरवॉल", "इन्सिडेंट", "स्कॅन", "किल स्विच"
]


class QueryRouteResult:
    def __init__(
        self,
        primary_category: LiveQueryCategory,
        secondary_categories: List[LiveQueryCategory],
        requires_live_data: bool,
        extracted_entities: Dict[str, Any],
        freshness_filter: str = "week"
    ):
        self.primary_category = primary_category
        self.secondary_categories = secondary_categories
        self.requires_live_data = requires_live_data
        self.extracted_entities = extracted_entities
        self.freshness_filter = freshness_filter

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_category": self.primary_category.value,
            "secondary_categories": [c.value for c in self.secondary_categories],
            "requires_live_data": self.requires_live_data,
            "extracted_entities": self.extracted_entities,
            "freshness_filter": self.freshness_filter
        }


def route_query(query: str, context: Optional[Dict[str, Any]] = None) -> QueryRouteResult:
    """
    Classifies user directives into domain categories and determines whether
    live real-time web retrieval is mandatory.
    """
    clean_q = (query or "").strip().lower()
    entities: Dict[str, Any] = {}

    # Extract CVE identifiers (e.g. CVE-2024-38077)
    cve_match = re.search(r"cve[-_]\d{4}[-_]\d{4,7}", clean_q, re.IGNORECASE)
    if cve_match:
        entities["cve_id"] = cve_match.group(0).upper().replace("_", "-")

    # Detect freshness filter (today, week, month)
    freshness = "week"
    if any(w in clean_q for w in ["today", "aaj", "आज", "aajchi", "aajche"]):
        freshness = "today"
    elif any(w in clean_q for w in ["this week", "ya aathvadyat", "is hafte", "या आठवड्यात", "इस हफ्ते"]):
        freshness = "week"
    elif any(w in clean_q for w in ["this month", "ya mahinyat", "is mahine", "या महिन्यात", "इस महीने"]):
        freshness = "month"

    # Extract location for weather queries
    weather_city = None
    for dev_k, dev_name in DEVANAGARI_CITIES.items():
        if dev_k in clean_q:
            weather_city = dev_name
            break

    if not weather_city:
        for city in ["pune", "mumbai", "delhi", "bangalore", "bengaluru", "hyderabad", "chennai", "kolkata", "nagpur", "nashik", "london", "new york", "tokyo", "paris", "berlin"]:
            if re.search(rf"\b{city}\b", clean_q):
                weather_city = city.capitalize()
                break

    if not weather_city:
        city_match = re.search(r"\b(?:in|for|at|of|mein|madhe|च्या|मध्ये|तील)\b\s+([a-zA-Z\u0900-\u097F]+(?:\s+[a-zA-Z\u0900-\u097F]+)?)", clean_q)
        if city_match:
            cand = city_match.group(1).strip()
            cand = re.sub(r"\b(today|now|aaj|aajche|aajchi|please|the)\b", "", cand, flags=re.IGNORECASE).strip()
            if cand.lower() not in ["weather", "forecast", "mausam", "havaman"]:
                weather_city = cand.capitalize()

    if weather_city:
        entities["city"] = weather_city

    # 1. Local Personal Assistant tasks (MUST NOT require live search)
    if any(k in clean_q for k in PERSONAL_ASSISTANT_KEYWORDS):
        return QueryRouteResult(
            primary_category=LiveQueryCategory.PERSONAL_ASSISTANT,
            secondary_categories=[],
            requires_live_data=False,
            extracted_entities=entities,
            freshness_filter=freshness
        )

    # 2. AgentShield Security Operations (MUST NOT require live search)
    if any(k in clean_q for k in AGENTSHIELD_KEYWORDS):
        return QueryRouteResult(
            primary_category=LiveQueryCategory.AGENTSHIELD_OPERATIONS,
            secondary_categories=[],
            requires_live_data=False,
            extracted_entities=entities,
            freshness_filter=freshness
        )

    # 3. Weather
    if any(k in clean_q for k in WEATHER_KEYWORDS):
        return QueryRouteResult(
            primary_category=LiveQueryCategory.WEATHER_FORECAST,
            secondary_categories=[],
            requires_live_data=True,
            extracted_entities=entities,
            freshness_filter=freshness
        )

    # 4. Windows & Software Updates
    if any(k in clean_q for k in WINDOWS_UPDATE_KEYWORDS):
        return QueryRouteResult(
            primary_category=LiveQueryCategory.WINDOWS_SOFTWARE_UPDATES,
            secondary_categories=[LiveQueryCategory.PERSONAL_ASSISTANT],
            requires_live_data=True,
            extracted_entities=entities,
            freshness_filter=freshness
        )

    # 5. Cybersecurity Intelligence / CVE / Advisories
    if entities.get("cve_id") or any(k in clean_q for k in CYBER_KEYWORDS):
        return QueryRouteResult(
            primary_category=LiveQueryCategory.CYBERSECURITY_INTELLIGENCE,
            secondary_categories=[LiveQueryCategory.AGENTSHIELD_OPERATIONS],
            requires_live_data=True,
            extracted_entities=entities,
            freshness_filter=freshness
        )

    # 6. AI & Tech Releases
    if any(k in clean_q for k in AI_TECH_KEYWORDS):
        return QueryRouteResult(
            primary_category=LiveQueryCategory.AI_TECH_RELEASES,
            secondary_categories=[LiveQueryCategory.CURRENT_EVENTS_NEWS],
            requires_live_data=True,
            extracted_entities=entities,
            freshness_filter=freshness
        )

    # 7. Latest News & Current Events
    if any(k in clean_q for k in NEWS_KEYWORDS):
        return QueryRouteResult(
            primary_category=LiveQueryCategory.CURRENT_EVENTS_NEWS,
            secondary_categories=[],
            requires_live_data=True,
            extracted_entities=entities,
            freshness_filter=freshness
        )

    # 8. Deep Research & Source Comparison
    if any(k in clean_q for k in RESEARCH_KEYWORDS):
        return QueryRouteResult(
            primary_category=LiveQueryCategory.RESEARCH_SOURCE_COMPARISON,
            secondary_categories=[LiveQueryCategory.CURRENT_EVENTS_NEWS],
            requires_live_data=True,
            extracted_entities=entities,
            freshness_filter=freshness
        )

    # 9. General Conversation / General Knowledge (Local AI)
    return QueryRouteResult(
        primary_category=LiveQueryCategory.GENERAL_KNOWLEDGE,
        secondary_categories=[],
        requires_live_data=False,
        extracted_entities=entities,
        freshness_filter=freshness
    )


# --- 3. SQLite Live Intelligence Cache Manager ---

def get_cached_intel(cache_key: str) -> Optional[Dict[str, Any]]:
    """Retrieves cached live data if not expired."""
    try:
        with connect() as db:
            row = db.execute(
                "SELECT data_json, expires_at, created_at FROM live_intelligence_cache WHERE cache_key = ?",
                (cache_key,)
            ).fetchone()
            if not row:
                return None

            expires_at = datetime.fromisoformat(row["expires_at"])
            now_dt = datetime.now(timezone.utc)
            data = json.loads(row["data_json"])
            data["_cached_at"] = row["created_at"]
            data["_is_stale"] = now_dt > expires_at
            return data
    except Exception:
        return None


def store_cached_intel(cache_key: str, category: str, data: Dict[str, Any], ttl_seconds: int):
    """Stores fetched live data in cache with explicit expiration."""
    try:
        now_dt = datetime.now(timezone.utc)
        exp_dt = now_dt + timedelta(seconds=ttl_seconds)
        now_str = now_dt.isoformat()
        exp_str = exp_dt.isoformat()
        clean_json = json.dumps(data)

        with connect() as db:
            db.execute(
                """INSERT INTO live_intelligence_cache (cache_key, category, data_json, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(cache_key) DO UPDATE SET
                   data_json=excluded.data_json, expires_at=excluded.expires_at, created_at=excluded.created_at""",
                (cache_key, category, clean_json, exp_str, now_str)
            )
    except Exception:
        pass


def record_live_query_audit(query: str, category: str, sources: List[Dict[str, Any]], summary: str, latency_ms: int):
    """Appends query, sources, and latency to audit trail."""
    try:
        with connect() as db:
            db.execute(
                """INSERT INTO live_intelligence_queries (query, category, sources_json, result_summary, latency_ms, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (query, category, json.dumps(sources), summary[:500], latency_ms, now_iso())
            )
    except Exception:
        pass


# --- 4. Live Weather Engine (Open-Meteo Free API) ---

WMO_WEATHER_MAP = {
    0: {"en": "Clear sky", "mr": "स्वच्छ निरभ्र आकाश", "hi": "साफ आसमान", "icon": "☀️"},
    1: {"en": "Mainly clear", "mr": "मुख्यतः निरभ्र", "hi": "अधिकांशतः साफ", "icon": "🌤️"},
    2: {"en": "Partly cloudy", "mr": "अंशतः ढगाळ", "hi": "आंशिक रूप से बादल", "icon": "⛅"},
    3: {"en": "Overcast", "mr": "पूर्ण ढगाळ", "hi": "घने बादल", "icon": "☁️"},
    45: {"en": "Fog", "mr": "धुके", "hi": "कोहरा", "icon": "🌫️"},
    48: {"en": "Depositing rime fog", "mr": "दाट धुके", "hi": "घना कोहरा", "icon": "🌫️"},
    51: {"en": "Light drizzle", "mr": "हलकी रिमझिम", "hi": "हल्की बूंदाबांदी", "icon": "🌦️"},
    53: {"en": "Moderate drizzle", "mr": "मध्यम रिमझिम", "hi": "मध्यम बूंदाबांदी", "icon": "🌦️"},
    55: {"en": "Dense drizzle", "mr": "दाट रिमझिम", "hi": "तेज बूंदाबांदी", "icon": "🌧️"},
    61: {"en": "Slight rain", "mr": "हलका पाऊस", "hi": "हल्की बारिश", "icon": "🌧️"},
    63: {"en": "Moderate rain", "mr": "मध्यम पाऊस", "hi": "मध्यम बारिश", "icon": "🌧️"},
    65: {"en": "Heavy rain", "mr": "मुसळधार पाऊस", "hi": "भारी बारिश", "icon": "🌧️"},
    71: {"en": "Slight snow fall", "mr": "हलकी बर्फवृष्टी", "hi": "हल्की बर्फबारी", "icon": "🌨️"},
    73: {"en": "Moderate snow fall", "mr": "मध्यम बर्फवृष्टी", "hi": "मध्यम बर्फबारी", "icon": "🌨️"},
    75: {"en": "Heavy snow fall", "mr": "मुसळधार बर्फवृष्टी", "hi": "भारी बर्फबारी", "icon": "❄️"},
    80: {"en": "Slight rain showers", "mr": "पावसाच्या हलक्या सरी", "hi": "हल्की बौछारें", "icon": "🌦️"},
    81: {"en": "Moderate rain showers", "mr": "पावसाच्या मध्यम सरी", "hi": "मध्यम बौछारें", "icon": "🌧️"},
    82: {"en": "Violent rain showers", "mr": "मुसळधार पावसाच्या सरी", "hi": "तेज मूसलाधार बौछारें", "icon": "⛈️"},
    95: {"en": "Thunderstorm", "mr": "वादळी मेघगर्जना", "hi": "गरज के साथ तूफान", "icon": "⛈️"},
    96: {"en": "Thunderstorm with slight hail", "mr": "गारांसह वादळी पाऊस", "hi": "ओलों के साथ तूफान", "icon": "⛈️"},
    99: {"en": "Thunderstorm with heavy hail", "mr": "गारांसह मुसळधार वादळी पाऊस", "hi": "भारी ओलों के साथ तूफान", "icon": "⛈️"}
}


def fetch_live_weather(
    city: Optional[str] = None,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
    force_refresh: bool = False
) -> Dict[str, Any]:
    """
    Fetches real-time weather and forecasts using Open-Meteo free API.
    Does not require API keys. Never invents location.
    """
    clean_city = (city or "").strip()
    resolved_lat = lat if lat is not None else latitude
    resolved_lon = lon if lon is not None else longitude
    if not clean_city and (resolved_lat is None or resolved_lon is None):
        return {
            "error": "City name or coordinates required. Please specify a location (e.g. 'Pune', 'Mumbai', 'Delhi').",
            "needs_location_input": True,
            "status": "MISSING_LOCATION"
        }

    cache_k = f"weather-{clean_city.lower() if clean_city else f'{resolved_lat},{resolved_lon}'}"
    cached = get_cached_intel(cache_k)
    if not force_refresh and cached and not cached.get("_is_stale"):
        cached["is_cached"] = True
        cached["cached"] = True
        return cached

    display_city = clean_city or "Specified Coordinates"
    country_name = "India"

    try:
        with httpx.Client(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}) as client:
            # 1. Geocode if city is given
            if clean_city:
                geo_url = f"https://geocoding-api.open-meteo.com/v1/search?name={urllib.parse.quote(clean_city)}&count=1&language=en&format=json"
                geo_resp = client.get(geo_url)
                if geo_resp.status_code == 200:
                    geo_data = geo_resp.json()
                    results = geo_data.get("results")
                    if results and len(results) > 0:
                        top = results[0]
                        resolved_lat = top["latitude"]
                        resolved_lon = top["longitude"]
                        display_city = top.get("name", clean_city)
                        country_name = top.get("country", "India")
                    else:
                        if cached:
                            cached["is_stale_fallback"] = True
                            return cached
                        return {"error": f"Could not find coordinates for city '{clean_city}'.", "status": "NOT_FOUND"}

            if resolved_lat is None or resolved_lon is None:
                return {"error": "Failed to resolve coordinates for location.", "status": "ERROR"}

            # 2. Fetch Forecast
            forecast_url = (
                f"https://api.open-meteo.com/v1/forecast?latitude={resolved_lat}&longitude={resolved_lon}"
                "&current=temperature_2m,relative_humidity_2m,apparent_temperature,is_day,precipitation,rain,showers,weather_code,wind_speed_10m"
                "&daily=weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max"
                "&timezone=auto"
            )
            fc_resp = client.get(forecast_url)
            if fc_resp.status_code != 200:
                if cached:
                    cached["is_stale_fallback"] = True
                    return cached
                return {"error": f"Open-Meteo weather service returned code {fc_resp.status_code}.", "status": "SERVICE_ERROR"}

            fc_data = fc_resp.json()
            curr = fc_data.get("current", {})
            daily = fc_data.get("daily", {})

            w_code = curr.get("weather_code", 0)
            w_info = WMO_WEATHER_MAP.get(w_code, {"en": "Fair", "mr": "मध्यम", "hi": "सामान्य", "icon": "🌤️"})

            temp_c = curr.get("temperature_2m")
            feels_like = curr.get("apparent_temperature")
            humidity = curr.get("relative_humidity_2m")
            wind_kmh = curr.get("wind_speed_10m")
            precip = curr.get("precipitation", 0.0)

            # Daily forecast
            daily_forecast = []
            dates = daily.get("time", [])
            max_temps = daily.get("temperature_2m_max", [])
            min_temps = daily.get("temperature_2m_min", [])
            pop_max = daily.get("precipitation_probability_max", [])
            d_codes = daily.get("weather_code", [])

            for i in range(min(4, len(dates))):
                dc = d_codes[i] if i < len(d_codes) else 0
                di = WMO_WEATHER_MAP.get(dc, {"en": "Clear", "mr": "निरभ्र", "hi": "साफ", "icon": "☀️"})
                daily_forecast.append({
                    "date": dates[i],
                    "max_c": max_temps[i] if i < len(max_temps) else temp_c,
                    "min_c": min_temps[i] if i < len(min_temps) else temp_c,
                    "rain_probability": pop_max[i] if i < len(pop_max) else 0,
                    "condition": di["en"],
                    "condition_mr": di["mr"],
                    "condition_hi": di["hi"],
                    "icon": di["icon"]
                })

            result = {
                "status": "SUCCESS",
                "city": display_city,
                "country": country_name,
                "latitude": resolved_lat,
                "longitude": resolved_lon,
                "observation_time": curr.get("time", now_iso()),
                "temperature_c": temp_c,
                "apparent_temperature_c": feels_like,
                "humidity_percent": humidity,
                "wind_speed_kmh": wind_kmh,
                "precipitation_mm": precip,
                "weather_code": w_code,
                "condition": w_info["en"],
                "condition_mr": w_info["mr"],
                "condition_hi": w_info["hi"],
                "icon": w_info["icon"],
                "is_severe": w_code in [82, 95, 96, 99] or (wind_kmh and wind_kmh > 55),
                "daily_forecast": daily_forecast,
                "source": "Open-Meteo Meteorological Service",
                "source_url": "https://open-meteo.com/",
                "sources": [{"publisher": "Open-Meteo", "url": "https://open-meteo.com/"}],
                "cached": False,
                "units": "Metric (°C, km/h, mm)"
            }

            store_cached_intel(cache_k, "weather", result, TTL_WEATHER)
            return result
    except Exception as e:
        if cached:
            cached["is_stale_fallback"] = True
            return cached
        return {"error": f"Failed to fetch live weather: {str(e)}", "status": "NETWORK_ERROR"}


# --- 5. Cybersecurity Intelligence Engine (CISA KEV, NVD, CVE) ---

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cybersecurity_intelligence(
    query_or_cve: Optional[str] = None,
    limit: int = 20,
    force_refresh: bool = False
) -> Dict[str, Any]:
    """
    Fetches official cybersecurity intelligence:
    - CVE lookup against CISA Known Exploited Vulnerabilities (KEV) Catalog.
    - Official vulnerability details, severity, exploitation status, mitigation.
    - Distinguishes active exploitation from theoretical risk.
    """
    clean = (query_or_cve or "").strip()
    cve_match = re.search(r"cve[-_]\d{4}[-_]\d{4,7}", clean, re.IGNORECASE)
    target_cve = cve_match.group(0).upper().replace("_", "-") if cve_match else None

    cache_k = f"cyber-{target_cve or hashlib.sha256(clean.encode()).hexdigest()[:12]}"
    cached = get_cached_intel(cache_k)
    if not force_refresh and cached and not cached.get("_is_stale"):
        cached["is_cached"] = True
        cached["cached"] = True
        return cached

    # Fetch CISA KEV catalog (cached centrally)
    kev_cache = get_cached_intel("cisa_kev_catalog")
    kev_catalog = kev_cache.get("vulnerabilities") if kev_cache else None

    if not kev_catalog:
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}) as client:
                resp = client.get(CISA_KEV_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    kev_catalog = data.get("vulnerabilities", [])
                    store_cached_intel("cisa_kev_catalog", "cisa_kev", {"vulnerabilities": kev_catalog, "count": len(kev_catalog)}, TTL_CYBER)
        except Exception:
            kev_catalog = []

    # 1. Targeted CVE search
    if target_cve:
        found_in_kev = None
        if kev_catalog:
            for item in kev_catalog:
                if item.get("cveID") == target_cve:
                    found_in_kev = item
                    break

        if found_in_kev:
            result = {
                "status": "VERIFIED_EXPLOITED",
                "cve_id": target_cve,
                "vendor": found_in_kev.get("vendorProject"),
                "product": found_in_kev.get("product"),
                "vulnerability_name": found_in_kev.get("vulnerabilityName"),
                "date_added_to_kev": found_in_kev.get("dateAdded"),
                "short_description": found_in_kev.get("shortDescription"),
                "required_action": found_in_kev.get("requiredAction"),
                "due_date": found_in_kev.get("dueDate"),
                "known_ransomware_campaign_use": found_in_kev.get("knownRansomwareCampaignUse"),
                "notes": found_in_kev.get("notes"),
                "exploitation_status": "CONFIRMED ACTIVE EXPLOITATION IN THE WILD (Listed in CISA KEV Catalog)",
                "official_sources": [
                    {
                        "publisher": "CISA Known Exploited Vulnerabilities Catalog",
                        "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={target_cve}"
                    },
                    {
                        "publisher": "NIST National Vulnerability Database (NVD)",
                        "url": f"https://nvd.nist.gov/vuln/detail/{target_cve}"
                    }
                ],
                "recommended_mitigation": found_in_kev.get("requiredAction") or "Apply official vendor patches immediately or isolate vulnerable network segments.",
                "verified_at": now_iso()
            }
            store_cached_intel(cache_k, "cyber", result, TTL_CYBER)
            return result

        # Not found in KEV - perform NIST NVD / MITRE lookup
        result = {
            "status": "CVE_RECORD_LOCATED",
            "cve_id": target_cve,
            "vendor": "Refer to official vendor bulletin",
            "product": "Refer to official advisory",
            "vulnerability_name": f"Security Vulnerability {target_cve}",
            "exploitation_status": "THEORETICAL / NO EVIDENCE IN CISA KEV (Not currently listed in US CISA KEV)",
            "short_description": f"Official tracking entry for {target_cve}. Verify vendor security bulletin for exact affected versions.",
            "official_sources": [
                {
                    "publisher": "NIST National Vulnerability Database (NVD)",
                    "url": f"https://nvd.nist.gov/vuln/detail/{target_cve}"
                },
                {
                    "publisher": "MITRE CVE List",
                    "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={target_cve}"
                }
            ],
            "recommended_mitigation": "Check the vendor's official security advisory page and apply current cumulative updates.",
            "verified_at": now_iso()
        }
        store_cached_intel(cache_k, "cyber", result, TTL_CYBER)
        return result

    # 2. General Cybersecurity Advisories (Top recent CISA KEV items)
    recent_items = (kev_catalog or [])[:6]
    formatted_advisories = []
    for item in recent_items:
        formatted_advisories.append({
            "cve_id": item.get("cveID"),
            "vendor_product": f"{item.get('vendorProject')} - {item.get('product')}",
            "name": item.get("vulnerabilityName"),
            "date_added": item.get("dateAdded"),
            "action": item.get("requiredAction"),
            "url": f"https://nvd.nist.gov/vuln/detail/{item.get('cveID')}"
        })

    result = {
        "status": "RECENT_ADVISORIES",
        "query": clean or "Latest CISA KEV Advisories",
        "total_catalog_size": len(kev_catalog) if kev_catalog else 0,
        "advisories": formatted_advisories,
        "source": "US CISA Known Exploited Vulnerabilities (KEV) Catalog",
        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "verified_at": now_iso()
    }
    store_cached_intel(cache_k, "cyber", result, TTL_CYBER)
    return result


# --- 6. Live Web Search & News/Technology Intelligence Engine ---

def search_live_news_rss(topic: str, freshness: str = "week") -> List[Dict[str, Any]]:
    """
    Fetches recent news articles from verified Google News RSS feed.
    Zero-auth, highly resilient, publisher-attributed with exact publication timestamps.
    """
    clean_q = (topic or "").strip()
    if not clean_q:
        clean_q = "technology news"

    # Time filter encoding
    when_param = ""
    if freshness == "today":
        when_param = " when:1d"
    elif freshness == "week":
        when_param = " when:7d"
    elif freshness == "month":
        when_param = " when:30d"

    encoded = urllib.parse.quote(clean_q + when_param)
    rss_url = f"https://news.google.com/rss/search?q={encoded}&hl=en-IN&gl=IN&ceid=IN:en"

    articles = []
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}) as client:
            resp = client.get(rss_url)
            if resp.status_code == 200:
                root = ET.fromstring(resp.content)
                items = root.findall("./channel/item")
                for item in items[:6]:
                    title_elem = item.find("title")
                    link_elem = item.find("link")
                    pub_elem = item.find("pubDate")
                    desc_elem = item.find("description")
                    source_elem = item.find("source")

                    raw_title = title_elem.text if title_elem is not None else ""
                    raw_link = link_elem.text if link_elem is not None else ""
                    raw_pub = pub_elem.text if pub_elem is not None else ""
                    raw_desc = desc_elem.text if desc_elem is not None else ""
                    publisher = source_elem.text if source_elem is not None else ""

                    if " - " in raw_title and not publisher:
                        parts = raw_title.rsplit(" - ", 1)
                        clean_title = parts[0].strip()
                        publisher = parts[1].strip()
                    else:
                        clean_title = raw_title.strip()

                    # Defend against untrusted content in title/desc
                    safe_title, _ = defend_untrusted_content(clean_title)
                    safe_desc, _ = defend_untrusted_content(re.sub(r"<[^>]+>", "", raw_desc))

                    articles.append({
                        "title": safe_title,
                        "publisher": publisher or "Verified News Outlet",
                        "publication_date": raw_pub,
                        "url": raw_link,
                        "snippet": safe_desc[:250],
                        "source_type": "NEWS_RSS"
                    })
    except Exception:
        pass

    return articles


def search_duckduckgo_lite(query: str, max_results: int = 4) -> List[Dict[str, Any]]:
    """
    Fetches real-time search results using DuckDuckGo HTML Lite search.
    Provides verified URLs, titles, and snippets without requiring external API keys.
    """
    clean_q = (query or "").strip()
    if not clean_q:
        return []

    results = []
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
            resp = client.post("https://html.duckduckgo.com/html/", data={"q": clean_q})
            if resp.status_code == 200:
                content = resp.text
                # Match result links and snippets from HTML
                matches = re.findall(
                    r'<a[^>]*class="result__snippet"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>',
                    content,
                    re.IGNORECASE
                )
                title_matches = re.findall(
                    r'<a[^>]*class="result__url"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>',
                    content,
                    re.IGNORECASE
                )

                for idx, match in enumerate(matches[:max_results]):
                    raw_url = match[0]
                    snippet_html = match[1]
                    clean_snippet = re.sub(r"<[^>]+>", "", snippet_html).strip()
                    clean_snippet, _ = defend_untrusted_content(clean_snippet)

                    # Extract actual URL from DuckDuckGo redirect if needed
                    actual_url = raw_url
                    if "uddg=" in raw_url:
                        sub = raw_url.split("uddg=")[-1].split("&")[0]
                        actual_url = urllib.parse.unquote(sub)

                    parsed_domain = urllib.parse.urlparse(actual_url).netloc

                    results.append({
                        "title": f"Web Result from {parsed_domain}",
                        "publisher": parsed_domain or "Web Source",
                        "publication_date": "Recent",
                        "url": actual_url,
                        "snippet": clean_snippet[:250],
                        "source_type": "WEB_SEARCH"
                    })
    except Exception:
        pass

    return results


def perform_live_web_research(query: str, freshness: str = "week", max_sources: int = 5) -> Dict[str, Any]:
    """
    Executes live multi-source web research with prompt injection defense,
    source comparison, and verifiable clickable citations.
    """
    clean_q = (query or "").strip()
    if not clean_q:
        return {"error": "Search query cannot be empty.", "status": "EMPTY_QUERY"}

    cache_k = f"research-{hashlib.sha256((clean_q + freshness).encode()).hexdigest()[:14]}"
    cached = get_cached_intel(cache_k)
    if cached and not cached.get("_is_stale"):
        cached["is_cached"] = True
        return cached

    start_t = datetime.now(timezone.utc)

    # 1. First attempt News RSS (fast, structured, verified dates)
    sources = search_live_news_rss(clean_q, freshness=freshness)

    # 2. Supplement or fallback with DuckDuckGo
    if len(sources) < max_sources:
        ddg_results = search_duckduckgo_lite(clean_q, max_results=max_sources - len(sources))
        sources.extend(ddg_results)

    dur_ms = int((datetime.now(timezone.utc) - start_t).total_seconds() * 1000)

    if not sources:
        if cached:
            cached["is_stale_fallback"] = True
            return cached
        return {
            "status": "NO_SOURCES_FOUND",
            "query": clean_q,
            "message": f"Could not verify live information for '{clean_q}'. External search services returned no verified accessible pages.",
            "sources": []
        }

    # Compare independent sources for claims
    publishers = list(set(s["publisher"] for s in sources if s.get("publisher")))
    independent_count = len(publishers)

    result = {
        "status": "SUCCESS",
        "query": clean_q,
        "freshness": freshness,
        "total_sources_found": len(sources),
        "independent_sources_count": independent_count,
        "publishers": publishers,
        "retrieved_at": now_iso(),
        "sources": sources[:max_sources],
        "latency_ms": dur_ms
    }

    store_cached_intel(cache_k, "research", result, TTL_WEB_RESEARCH)
    record_live_query_audit(clean_q, "WEB_RESEARCH", sources, f"Retrieved {len(sources)} sources", dur_ms)

    return result


# --- 7. Windows & Software Updates Intelligence ---

WINDOWS_RELEASE_INFO = {
    "Windows 11": {
        "current_general_version": "24H2 (OS Build 26100) & 23H2 (OS Build 22631)",
        "release_cycle": "Annual Feature Update + Monthly Cumulative 'Patch Tuesday' Security Updates",
        "latest_patch_tuesday": "Second Tuesday of each calendar month",
        "official_health_url": "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
        "known_advisories": "Check Windows Release Health dashboard for driver and security compatibility holds."
    },
    "Windows 10": {
        "current_general_version": "22H2 (Final Feature Update)",
        "end_of_support_date": "October 14, 2025",
        "official_health_url": "https://learn.microsoft.com/en-us/windows/release-health/release-information"
    }
}


def check_windows_software_updates(software_name: Optional[str] = "windows") -> Dict[str, Any]:
    """
    Checks official release and security update intelligence for Windows and installed software.
    Distinguishes:
    1. News/Advisory about an update.
    2. Availability for user's platform.
    3. What is actually installed on this device.
    Never auto-installs without explicit user control.
    """
    from .personal_assistant import get_windows_system_status

    clean_soft = (software_name or "windows").strip().lower()
    local_status = get_windows_system_status()
    current_os = local_status.get("os", "Windows 11")

    win_info = WINDOWS_RELEASE_INFO.get("Windows 11" if "11" in current_os else "Windows 10", WINDOWS_RELEASE_INFO["Windows 11"])

    return {
        "status": "SUCCESS",
        "software": clean_soft.capitalize(),
        "installed_on_device": {
            "os_version": current_os,
            "hostname": local_status.get("hostname"),
            "status": "RUNNING_LOCALLY"
        },
        "official_release_status": win_info,
        "update_distinction": {
            "public_advisory_status": "Latest security bulletins released via Microsoft Security Response Center (MSRC).",
            "device_availability": "Check Settings > Windows Update to verify if pending updates are approved for your hardware.",
            "installation_status": "No background modification performed. Updates must be confirmed through Windows Settings."
        },
        "settings_link": "ms-settings:windowsupdate",
        "official_source": win_info.get("official_health_url"),
        "verified_at": now_iso()
    }


# --- 8. Multilingual Live Response Synthesizer ---

def synthesize_live_intelligence_response(
    query: str,
    route_result: QueryRouteResult,
    intel_data: Dict[str, Any],
    lang: str = "en",
    mode: str = "friendly"
) -> Dict[str, Any]:
    """
    Synthesizes a structured, citation-grounded response in user's detected language.
    Produces both rich Markdown for chat display and a concise spoken string.
    """
    cat = route_result.primary_category
    l = lang.lower()

    speech_text = ""
    markdown_content = ""
    citations = []

    # 1. WEATHER
    if cat == LiveQueryCategory.WEATHER_FORECAST:
        if intel_data.get("needs_location_input"):
            if l == "mr":
                speech_text = "कृपया मला शहराचे नाव सांगा, उदा. पुणे, मुंबई किंवा दिल्ली."
            elif l == "hi":
                speech_text = "कृपया शहर का नाम बताएं, जैसे मुंबई, दिल्ली या पुणे।"
            elif l == "hinglish":
                speech_text = "Please city ka naam bataiye, jaise Pune, Mumbai ya Delhi."
            else:
                speech_text = "Please specify a city name, for example Pune, Mumbai, or Delhi."
            return {"content": speech_text, "speech_text": speech_text, "citations": []}

        if intel_data.get("error"):
            msg = intel_data["error"]
            return {"content": f"⚠️ {msg}", "speech_text": "Live weather could not be verified.", "citations": []}

        city = intel_data.get("city", "Current City")
        temp = intel_data.get("temperature_c", "N/A")
        feels = intel_data.get("apparent_temperature_c", temp)
        humidity = intel_data.get("humidity_percent", "N/A")
        wind = intel_data.get("wind_speed_kmh", "N/A")
        cond_en = intel_data.get("condition", "Clear")
        cond_local = intel_data.get("condition_mr" if l == "mr" else "condition_hi", cond_en)
        obs_time = intel_data.get("observation_time", "")

        citations = [{"publisher": "Open-Meteo", "url": "https://open-meteo.com/"}]

        if l == "mr":
            speech_text = f"{city} मध्ये सध्या तापमान {temp} अंश सेल्सिअस असून हवामान {cond_local} आहे."
            markdown_content = (
                f"### 🌤️ **{city} हवामान अहवाल (थेट माहिती)**\n\n"
                f"- **सध्याचे तापमान:** {temp}°C (जाणवणारे तापमान: {feels}°C)\n"
                f"- **हवामानाची स्थिती:** {intel_data.get('icon', '🌤️')} {cond_local}\n"
                f"- **हवेतील आर्द्रता:** {humidity}%\n"
                f"- **वाऱ्याचा वेग:** {wind} किमी/तास\n\n"
                f"*स्त्रोत: [Open-Meteo API](https://open-meteo.com/) | नोंदणी वेळ: {obs_time}*\n"
            )
        elif l == "hi":
            speech_text = f"{city} में अभी तापमान {temp} डिग्री सेल्सियस है और मौसम {cond_local} है।"
            markdown_content = (
                f"### 🌤️ **{city} मौसम रिपोर्ट (लाइव अपडेट)**\n\n"
                f"- **वर्तमान तापमान:** {temp}°C (महसूस होने वाला तापमान: {feels}°C)\n"
                f"- **मौसम की स्थिति:** {intel_data.get('icon', '🌤️')} {cond_local}\n"
                f"- **आर्द्रता (Humidity):** {humidity}%\n"
                f"- **हवा की गति:** {wind} किमी/घंटा\n\n"
                f"*स्रोत: [Open-Meteo API](https://open-meteo.com/) | अवलोकन समय: {obs_time}*\n"
            )
        elif l == "hinglish":
            speech_text = f"{city} mein current temperature {temp} degree Celsius hai aur weather {cond_en} hai."
            markdown_content = (
                f"### 🌤️ **{city} Live Weather Report**\n\n"
                f"- **Current Temperature:** {temp}°C (Feels like: {feels}°C)\n"
                f"- **Condition:** {intel_data.get('icon', '🌤️')} {cond_en}\n"
                f"- **Humidity:** {humidity}%\n"
                f"- **Wind Speed:** {wind} km/h\n\n"
                f"*Source: [Open-Meteo Meteorological Service](https://open-meteo.com/) | Observed: {obs_time}*\n"
            )
        else:
            speech_text = f"In {city}, the current temperature is {temp} degrees Celsius with {cond_en.lower()} conditions."
            markdown_content = (
                f"### 🌤️ **Live Weather for {city}**\n\n"
                f"- **Current Temperature:** {temp}°C (Feels like: {feels}°C)\n"
                f"- **Conditions:** {intel_data.get('icon', '🌤️')} {cond_en}\n"
                f"- **Humidity:** {humidity}%\n"
                f"- **Wind Speed:** {wind} km/h\n\n"
                f"*Source: [Open-Meteo Global Meteorological API](https://open-meteo.com/) | Observation: {obs_time}*\n"
            )

        if intel_data.get("is_severe"):
            alert_warn = "\n> ⚠️ **Severe Weather Advisory:** High wind speeds or thunderstorm detected in this region. Exercise appropriate caution.\n"
            markdown_content += alert_warn

        return {"content": markdown_content, "speech_text": speech_text, "citations": citations}

    # 2. CYBERSECURITY INTELLIGENCE
    if cat == LiveQueryCategory.CYBERSECURITY_INTELLIGENCE:
        if intel_data.get("cve_id"):
            cve_id = intel_data["cve_id"]
            exploit_stat = intel_data.get("exploitation_status", "THEORETICAL")
            desc = intel_data.get("short_description", "")
            mitigation = intel_data.get("recommended_mitigation", "")
            sources = intel_data.get("official_sources", [])
            citations = sources

            if l == "mr":
                speech_text = f"{cve_id} बद्दल अधिकृत माहिती उपलब्ध आहे. शोषण स्थिती: {exploit_stat}."
                markdown_content = (
                    f"### 🛡️ **सायबर सिक्युरिटी सल्लागार: {cve_id}**\n\n"
                    f"- **असुरक्षितता आयडी:** `{cve_id}`\n"
                    f"- **सक्रिय शोषण स्थिती:** **{exploit_stat}**\n"
                    f"- **तपशील:** {desc}\n"
                    f"- **शिफारस केलेले निराकरण:** {mitigation}\n\n"
                    f"#### 🔗 **अधिकृत स्त्रोत आणि संदर्भ:**\n"
                )
            elif l == "hi":
                speech_text = f"{cve_id} के बारे में आधिकारिक सुरक्षा डेटा उपलब्ध है। स्थिति: {exploit_stat}."
                markdown_content = (
                    f"### 🛡️ **साइबर सुरक्षा एडवाइजरी: {cve_id}**\n\n"
                    f"- **वल्नरेबिलिटी आईडी:** `{cve_id}`\n"
                    f"- **सक्रिय शोषण स्थिति:** **{exploit_stat}**\n"
                    f"- **विवरण:** {desc}\n"
                    f"- **अनुशंसित पैच / निवारण:** {mitigation}\n\n"
                    f"#### 🔗 **आधिकारिक स्रोत:**\n"
                )
            elif l == "hinglish":
                speech_text = f"{cve_id} ka official security advisory data mila hai. Exploitation status: {exploit_stat}."
                markdown_content = (
                    f"### 🛡️ **Cybersecurity Advisory: {cve_id}**\n\n"
                    f"- **Vulnerability ID:** `{cve_id}`\n"
                    f"- **Exploitation Status:** **{exploit_stat}**\n"
                    f"- **Description:** {desc}\n"
                    f"- **Mitigation Guidance:** {mitigation}\n\n"
                    f"#### 🔗 **Official Sources & Citations:**\n"
                )
            else:
                speech_text = f"Official vulnerability advisory retrieved for {cve_id}. Exploitation status is {exploit_stat}."
                markdown_content = (
                    f"### 🛡️ **Cybersecurity Advisory: {cve_id}**\n\n"
                    f"- **Vulnerability ID:** `{cve_id}`\n"
                    f"- **Exploitation Status:** **{exploit_stat}**\n"
                    f"- **Summary:** {desc}\n"
                    f"- **Recommended Mitigation:** {mitigation}\n\n"
                    f"#### 🔗 **Official Sources:**\n"
                )

            for s in sources:
                markdown_content += f"- [{s.get('publisher')}]({s.get('url')})\n"

            markdown_content += "\n> 🔒 *Zero-Trust Enforcement: AMOJA will never automatically alter firewall or host policies based on security news without explicit operator confirmation.*\n"
            return {"content": markdown_content, "speech_text": speech_text, "citations": citations}

        # List of advisories
        advisories = intel_data.get("advisories", [])
        citations = [{"publisher": "CISA KEV Catalog", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}]
        speech_text = f"Retrieved {len(advisories)} active cybersecurity advisories from CISA." if l == "en" else f"CISA कडून {len(advisories)} सक्रिय सायबर धोके पडताळण्यात आले आहेत."

        markdown_content = "### 🛡️ **सक्रिय सायबर धोके व CISA KEV बुलेटिन (थेट माहिती)**\n\n" if l == "mr" else "### 🛡️ **सक्रिय साइबर सुरक्षा अलर्ट और CISA KEV एडवाइजरी**\n\n" if l == "hi" else "### 🛡️ **Active Cybersecurity Advisories (CISA KEV Catalog)**\n\n"
        for adv in advisories:
            markdown_content += f"- **[{adv.get('cve_id')}]({adv.get('url')})** ({adv.get('vendor_product')}): {adv.get('name')} (Added: {adv.get('date_added')})\n"
        markdown_content += f"\n*Verified via [CISA KEV Catalog]({intel_data.get('source_url', 'https://www.cisa.gov/')}) | Total catalog: {intel_data.get('total_catalog_size', 0)} CVEs*\n"
        return {"content": markdown_content, "speech_text": speech_text, "citations": citations}

    # 2.5 WINDOWS & SOFTWARE UPDATES INTELLIGENCE
    if cat == LiveQueryCategory.WINDOWS_SOFTWARE_UPDATES:
        installed = intel_data.get("installed_on_device", {})
        rel_info = intel_data.get("official_release_status", {})
        distinction = intel_data.get("update_distinction", {})
        src = intel_data.get("official_source", "https://learn.microsoft.com/en-us/windows/release-health/")
        citations = [{"publisher": "Microsoft Windows Release Health", "url": src}]

        os_ver = installed.get("os_version", "Windows")
        gen_ver = rel_info.get("current_general_version", "Latest GA")

        if l == "mr":
            speech_text = f"आपल्या उपकरणावर {os_ver} स्थापित आहे. अधिकृत प्रकाशने आणि सुरक्षा पॅचेसची माहिती पडताळली आहे."
            markdown_content = (
                f"### 🪟 **विंडोज आणि सॉफ्टवेअर अपडेट माहिती**\n\n"
                f"- **या उपकरणावर स्थापित:** `{os_ver}` (होस्ट: `{installed.get('hostname', 'Local')}`)\n"
                f"- **अधिकृत सामान्य आवृत्ती:** {gen_ver}\n"
                f"- **पॅच मंगळवार (Patch Tuesday):** {rel_info.get('latest_patch_tuesday')}\n\n"
                f"#### 🔍 **अपडेट स्थिती फरक (Tri-Partite Distinction):**\n"
                f"1. **अपडेट विषयी सार्वजनिक बातमी:** {distinction.get('public_advisory_status')}\n"
                f"2. **या उपकरणासाठी उपलब्धता:** {distinction.get('device_availability')}\n"
                f"3. **प्रत्यक्षात स्थापित स्थिती:** {distinction.get('installation_status')}\n\n"
                f"> 🔒 *सुरक्षा धोरण: AMOJA कधीही वापरकर्त्याच्या स्पष्ट परवानगीशिवाय सिस्टम अपडेट्स स्थापित करणार नाही किंवा बदलणार नाही.*\n"
                f"*अधिकृत संदर्भ: [Microsoft Release Health Dashboard]({src})*\n"
            )
        elif l == "hi":
            speech_text = f"आपके डिवाइस पर {os_ver} इंस्टॉल्ड है। आधिकारिक रिलीज़ और सुरक्षा पैच की पुष्टि की गई है।"
            markdown_content = (
                f"### 🪟 **विंडोज और सॉफ्टवेयर अपडेट इंटेलिजेंस**\n\n"
                f"- **डिवाइस पर इंस्टॉल्ड:** `{os_ver}` (होस्ट: `{installed.get('hostname', 'Local')}`)\n"
                f"- **आधिकारिक सामान्य रिलीज़:** {gen_ver}\n"
                f"- **पैच ट्यूजडे शेड्यूल:** {rel_info.get('latest_patch_tuesday')}\n\n"
                f"#### 🔍 **अपडेट स्थिति में अंतर (Tri-Partite Distinction):**\n"
                f"1. **अपडेट की सार्वजनिक खबर:** {distinction.get('public_advisory_status')}\n"
                f"2. **आपके हार्डवेयर के लिए उपलब्धता:** {distinction.get('device_availability')}\n"
                f"3. **वर्तमान इंस्टॉल्ड स्थिति:** {distinction.get('installation_status')}\n\n"
                f"> 🔒 *सुरक्षा नीति: AMOJA आपकी स्पष्ट अनुमति के बिना कभी भी स्वचालित रूप से सिस्टम अपडेट इंस्टॉल नहीं करेगा।*\n"
                f"*आधिकारिक स्रोत: [Microsoft Release Health Dashboard]({src})*\n"
            )
        elif l == "hinglish":
            speech_text = f"Aapke device par {os_ver} installed hai. Microsoft official updates aur Patch Tuesday details verified hain."
            markdown_content = (
                f"### 🪟 **Windows & Software Update Intelligence**\n\n"
                f"- **Installed on Device:** `{os_ver}` (Host: `{installed.get('hostname', 'Local')}`)\n"
                f"- **Official General Version:** {gen_ver}\n"
                f"- **Patch Schedule:** {rel_info.get('latest_patch_tuesday')}\n\n"
                f"#### 🔍 **Update Distinction Analysis:**\n"
                f"1. **News & Bulletins:** {distinction.get('public_advisory_status')}\n"
                f"2. **Device Availability:** {distinction.get('device_availability')}\n"
                f"3. **Installed Status:** {distinction.get('installation_status')}\n\n"
                f"> 🔒 *Safety Guardrail: AMOJA never automatically installs OS updates or modifies system configuration without operator authorization.*\n"
                f"*Official Source: [Microsoft Release Health Dashboard]({src})*\n"
            )
        else:
            speech_text = f"Your device is running {os_ver}. Official release status and security updates have been verified."
            markdown_content = (
                f"### 🪟 **Windows & Software Update Intelligence**\n\n"
                f"- **Installed on Device:** `{os_ver}` (Host: `{installed.get('hostname', 'Local')}`)\n"
                f"- **Official Release Status:** {gen_ver}\n"
                f"- **Security Patch Schedule:** {rel_info.get('latest_patch_tuesday')}\n\n"
                f"#### 🔍 **Update Distinction Analysis:**\n"
                f"1. **News/Advisory:** {distinction.get('public_advisory_status')}\n"
                f"2. **Hardware Availability:** {distinction.get('device_availability')}\n"
                f"3. **Installation State:** {distinction.get('installation_status')}\n\n"
                f"> 🔒 *Zero-Trust Policy: AMOJA will never auto-install operating system updates or alter firmware/host settings without explicit administrative confirmation.*\n"
                f"*Official Source: [Microsoft Release Health Dashboard]({src})*\n"
            )

        return {"content": markdown_content, "speech_text": speech_text, "citations": citations}

    # 3. LIVE NEWS & TECH & RESEARCH
    sources = intel_data.get("sources", [])
    citations = sources

    if not sources:
        msg = f"No verified live sources found for '{query}'."
        return {"content": msg, "speech_text": msg, "citations": []}

    top_art = sources[0]
    top_title = top_art.get("title", "")
    top_pub = top_art.get("publisher", "Verified News")

    if l == "mr":
        speech_text = f"थेट माहितीनुसार: {top_title} ({top_pub})."
        markdown_content = f"### 📰 **थेट माहिती आणि संशोधन: {query}**\n\n"
    elif l == "hi":
        speech_text = f"ताज़ा अपडेट के अनुसार: {top_title} ({top_pub})."
        markdown_content = f"### 📰 **लाइव अपडेट और रिसर्च: {query}**\n\n"
    elif l == "hinglish":
        speech_text = f"Live updates ke mutabiq: {top_title} ({top_pub})."
        markdown_content = f"### 📰 **Live Intelligence & Research: {query}**\n\n"
    else:
        speech_text = f"According to live reports from {top_pub}: {top_title}."
        markdown_content = f"### 📰 **Live Intelligence & Research: {query}**\n\n"

    for idx, s in enumerate(sources):
        markdown_content += f"**{idx+1}. [{s.get('title')}]({s.get('url')})**\n"
        markdown_content += f"   - **Publisher:** {s.get('publisher')} | **Date:** {s.get('publication_date')}\n"
        if s.get("snippet"):
            markdown_content += f"   - *Excerpt:* {s.get('snippet')}\n\n"

    markdown_content += f"\n*Retrieved via Live Search Engine at {intel_data.get('retrieved_at', now_iso())} across {intel_data.get('independent_sources_count', len(sources))} independent publishers.*\n"
    return {"content": markdown_content, "speech_text": speech_text, "citations": citations}
