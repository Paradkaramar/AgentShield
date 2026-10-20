# backend/tests/test_multilingual_language_switch.py
"""Comprehensive Test Suite for AMOJA AI Automatic Language Detection
and Same-Language Response System across Hindi, Hinglish, Marathi, and English.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import init_db
from app.core.auth import create_access_token
from app.jarvis.language_detection import detect_language
from app.jarvis.multilingual_commands import parse_multilingual_intent

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

@pytest.fixture
def auth_headers():
    token = create_access_token({"username": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


def test_automatic_language_detection_isolated():
    """Validates per-turn language detection on required test phrases."""
    # 1. English
    assert detect_language("Hello Amoja, how are you?") == "en"
    assert detect_language("Please explain this in English.") == "en"
    assert detect_language("What can you do?") == "en"

    # 2. Hinglish (Hindi written in Roman letters)
    assert detect_language("Amoja, tum kya kar sakti ho?") == "hinglish"
    assert detect_language("Amoja, mera system check karo") == "hinglish"
    assert detect_language("mera computer slow kyu chal raha hai") == "hinglish"

    # 3. Marathi (Devanagari script)
    assert detect_language("माझ्या laptop ची security तपास.") == "mr"
    assert detect_language("माझ्या system ची security check कर.") == "mr"
    assert detect_language("त्याचे पोर्ट्स तपासा") == "mr"

    # 4. Hindi (Devanagari script)
    assert detect_language("मेरा computer slow क्यों चल रहा है?") == "hi"
    assert detect_language("नमस्ते अमोझा, आप क्या कर सकती हैं?") == "hi"
    assert detect_language("मेरा सिस्टम चेक करो") == "hi"


def test_mixed_language_code_switching_intent_mapping():
    """Validates that mixed-language sentences map to authorized tools with detected language."""
    # Marathi + English: "माझ्या laptop ची security तपास."
    tool, args, nav, lang = parse_multilingual_intent("माझ्या laptop ची security तपास.")
    assert tool == "get_device_security_status"
    assert lang == "mr"

    # Marathi + English: "माझ्या system ची security check कर."
    tool, args, nav, lang = parse_multilingual_intent("माझ्या system ची security check कर.")
    assert tool == "get_device_security_status"
    assert lang == "mr"

    # Hinglish: "Amoja, mera system check karo"
    tool, args, nav, lang = parse_multilingual_intent("Amoja, mera system check karo")
    assert tool == "get_device_security_status"
    assert lang == "hinglish"

    # Hindi: "मेरा computer slow क्यों चल रहा है?"
    tool, args, nav, lang = parse_multilingual_intent("मेरा computer slow क्यों चल रहा है?")
    assert tool == "get_device_security_status"
    assert lang == "hi"


def test_required_utterances_same_language_responses(auth_headers):
    """Tests all 5 required prompts verifying actual AI text response, spoken speech text, and audio stream."""
    # Test 1: "Hello Amoja, how are you?" -> en
    r1 = client.post("/api/jarvis/chat", json={
        "message": "Hello Amoja, how are you?",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["language"] == "en"
    assert "doing great" in d1["speech_text"].lower() or "performance" in d1["speech_text"].lower()
    assert d1["audio_base64"] is not None and len(d1["audio_base64"]) > 1000

    # Test 2: "Amoja, tum kya kar sakti ho?" -> hinglish
    r2 = client.post("/api/jarvis/chat", json={
        "message": "Amoja, tum kya kar sakti ho?",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["language"] == "hinglish"
    assert any(w in d2["speech_text"].lower() for w in ["main", "hoon", "aapki", "kar sakti hoon", "bataiye"])
    assert d2["audio_base64"] is not None and len(d2["audio_base64"]) > 1000

    # Test 3: "माझ्या laptop ची security तपास." -> mr
    r3 = client.post("/api/jarvis/chat", json={
        "message": "माझ्या laptop ची security तपास.",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["language"] == "mr"
    assert any(w in d3["speech_text"] for w in ["लॅपटॉपची", "सुरक्षा", "आहे", "नियंत्रणे"])
    assert len(d3["tool_calls"]) > 0
    assert d3["tool_calls"][0]["tool_name"] == "get_device_security_status"
    assert d3["audio_base64"] is not None and len(d3["audio_base64"]) > 1000

    # Test 4: "मेरा computer slow क्यों चल रहा है?" -> hi
    r4 = client.post("/api/jarvis/chat", json={
        "message": "मेरा computer slow क्यों चल रहा है?",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r4.status_code == 200
    d4 = r4.json()
    assert d4["language"] == "hi"
    assert any(w in d4["speech_text"] for w in ["कंप्यूटर", "धीमे", "चलने", "उपयोग", "प्रतिशत", "सीपीयू"])
    assert len(d4["tool_calls"]) > 0
    assert d4["tool_calls"][0]["tool_name"] == "get_device_security_status"
    assert d4["audio_base64"] is not None and len(d4["audio_base64"]) > 1000

    # Test 5: "Please explain this in English." -> en
    r5 = client.post("/api/jarvis/chat", json={
        "message": "Please explain this in English.",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r5.status_code == 200
    d5 = r5.json()
    assert d5["language"] == "en"
    assert "english" in d5["speech_text"].lower()
    assert d5["audio_base64"] is not None and len(d5["audio_base64"]) > 1000


def test_mid_conversation_language_switching_sequence(auth_headers):
    """Tests a conversation that switches from Marathi to Hinglish and then to English within the same session."""
    session_id = "test-session-marathi-hinglish-english"

    # Turn 1: Marathi
    r1 = client.post("/api/jarvis/chat", json={
        "session_id": session_id,
        "message": "माझ्या laptop ची security तपास.",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["language"] == "mr"
    assert any(w in d1["speech_text"] for w in ["लॅपटॉपची", "सुरक्षा", "आहे"])

    # Turn 2: Marathi follow-up
    r2 = client.post("/api/jarvis/chat", json={
        "session_id": session_id,
        "message": "त्याचे पोर्ट्स तपासा",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["language"] == "mr"
    assert any(w in d2["speech_text"] for w in ["सावधान", "कनेक्शन", "आढळले", "स्क्रीनवरील"])

    # Turn 3: Switch to Hinglish
    r3 = client.post("/api/jarvis/chat", json={
        "session_id": session_id,
        "message": "Amoja, tum kya kar sakti ho?",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["language"] == "hinglish"
    assert "kar sakti hoon" in d3["speech_text"].lower() or "bataiye" in d3["speech_text"].lower()

    # Turn 4: Hinglish follow-up
    r4 = client.post("/api/jarvis/chat", json={
        "session_id": session_id,
        "message": "theek hai, critical threats dikhao",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r4.status_code == 200
    d4 = r4.json()
    assert d4["language"] == "hinglish"
    assert any(w in d4["speech_text"].lower() for w in ["critical threats", "show kar rahi", "incidents", "attacks"])

    # Turn 5: Switch to English
    r5 = client.post("/api/jarvis/chat", json={
        "session_id": session_id,
        "message": "Please explain this in English.",
        "language": "auto",
        "is_voice": True
    }, headers=auth_headers)
    assert r5.status_code == 200
    d5 = r5.json()
    assert d5["language"] == "en"
    assert "switching to english" in d5["speech_text"].lower() or "english" in d5["speech_text"].lower()
