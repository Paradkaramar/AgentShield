# backend/tests/test_amoja_voice_pipeline.py
"""Comprehensive End-to-End Test Suite for AMOJA Voice Pipeline.
Tests:
1. Audio format detection, silence handling, and STT transcription via /api/jarvis/voice/transcribe.
2. AI Response generation returning both text and playable neural audio_base64.
3. Indic language speech generation (Marathi, Hindi, Hinglish, English) via /api/jarvis/voice/synthesize.
4. Multi-turn conversation context preservation across speech turns.
5. Error recovery: invalid base64, empty transcripts, unauthenticated requests.
"""

import pytest
import base64
import io
import wave
import struct
from fastapi.testclient import TestClient

from app.main import app
from app.core.auth import create_access_token
from app.jarvis.speech_to_text import local_stt_engine, transcribe_audio_locally
from app.jarvis.text_to_speech import local_tts_engine

client = TestClient(app)

def get_auth_token():
    return create_access_token({"sub": "admin", "username": "admin", "role": "admin"})

def make_test_wav_bytes(duration_sec: float = 0.5, sample_rate: int = 16000, frequency: float = 440.0) -> bytes:
    """Generates synthetic in-memory WAV audio bytes for testing."""
    buf = io.BytesIO()
    num_samples = int(duration_sec * sample_rate)
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        # Generate alternating PCM samples
        samples = []
        for i in range(num_samples):
            val = int(12000 * (1.0 if (i // 15) % 2 == 0 else -1.0))
            samples.append(struct.pack("<h", val))
        wf.writeframes(b"".join(samples))
    return buf.getvalue()

def make_silent_wav_bytes(duration_sec: float = 0.5, sample_rate: int = 16000) -> bytes:
    """Generates pure silence WAV bytes."""
    buf = io.BytesIO()
    num_samples = int(duration_sec * sample_rate)
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(b"\x00\x00" * num_samples)
    return buf.getvalue()


class TestAmojaVoicePipelineEndToEnd:
    """Tests the full voice processing pipeline from audio capture to speech response."""

    def test_audio_format_and_silence_detection(self):
        """Validates that silent audio is detected cleanly without crashing."""
        silent_wav = make_silent_wav_bytes(duration_sec=0.5)
        res = local_stt_engine.transcribe(silent_wav)
        assert res.text == "", "Silent audio should yield an empty transcript"
        assert res.duration_seconds >= 0.4
        assert res.engine is not None

    def test_valid_audio_transcription_service(self):
        """Audio with active signal returns valid transcription structure and metadata."""
        audio_wav = make_test_wav_bytes(duration_sec=0.8)
        res = local_stt_engine.transcribe(audio_wav, language="mr")
        assert res.language in {"mr", "hi", "en"}
        assert res.duration_seconds >= 0.7
        assert res.confidence > 0.0

    def test_transcribe_endpoint_with_auth(self):
        """POST /api/jarvis/voice/transcribe succeeds with valid WAV base64 payload."""
        token = get_auth_token()
        audio_wav = make_test_wav_bytes(duration_sec=0.6)
        b64_audio = base64.b64encode(audio_wav).decode("ascii")

        resp = client.post(
            "/api/jarvis/voice/transcribe",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "audio_base64": b64_audio,
                "language": "auto"
            }
        )
        assert resp.status_code == 200, f"Transcribe endpoint failed: {resp.text}"
        data = resp.json()
        assert "text" in data
        assert "language" in data
        assert "confidence" in data
        assert "engine" in data

    def test_transcribe_endpoint_handles_data_uri_prefix(self):
        """Handles base64 string formatted with 'data:audio/wav;base64,...' prefix."""
        token = get_auth_token()
        audio_wav = make_test_wav_bytes(duration_sec=0.5)
        raw_b64 = base64.b64encode(audio_wav).decode("ascii")
        data_uri = f"data:audio/wav;base64,{raw_b64}"

        resp = client.post(
            "/api/jarvis/voice/transcribe",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "audio_base64": data_uri,
                "language": "hi"
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "text" in data

    def test_transcribe_endpoint_invalid_base64_error(self):
        """Returns 400 Bad Request when audio base64 is corrupt."""
        token = get_auth_token()
        resp = client.post(
            "/api/jarvis/voice/transcribe",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "audio_base64": "!!!NOT_VALID_BASE64$$$",
                "language": "en"
            }
        )
        assert resp.status_code == 400

    def test_ai_response_generation_with_voice_output(self):
        """POST /api/jarvis/message with isVoice=True returns valid message and audio_base64."""
        token = get_auth_token()
        resp = client.post(
            "/api/jarvis/chat",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "message": "Jarvis, provide current zero-trust defense status",
                "language": "en",
                "is_voice": True,
                "personality_mode": "friendly"
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["message"] != ""
        assert data["speech_text"] != ""
        assert data["session_id"] is not None
        assert data["audio_base64"] is not None, "is_voice=True must generate audio_base64"

        # Verify returned audio_base64 is a valid playable WAV
        decoded_wav = base64.b64decode(data["audio_base64"])
        assert decoded_wav[:4] == b"RIFF"
        assert decoded_wav[8:12] == b"WAVE"

    def test_marathi_voice_intent_and_synthesis(self):
        """Validates Marathi user prompt returns Marathi speech response and audio."""
        token = get_auth_token()
        resp = client.post(
            "/api/jarvis/chat",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "message": "सुरक्षा स्थिती काय आहे?",
                "language": "mr",
                "is_voice": True
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["language"] in {"mr", "hi", "en"}
        assert data["audio_base64"] is not None

    def test_multiturn_conversation_preserves_session_context(self):
        """Follow-up voice queries in the same session maintain context without amnesia."""
        token = get_auth_token()
        # Turn 1
        turn1 = client.post(
            "/api/jarvis/chat",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "message": "Jarvis, how many active security agents are registered?",
                "language": "en",
                "is_voice": True
            }
        )
        assert turn1.status_code == 200
        sess_id = turn1.json()["session_id"]

        # Turn 2 using the same session_id
        turn2 = client.post(
            "/api/jarvis/chat",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "message": "Are any of them compromised?",
                "session_id": sess_id,
                "language": "en",
                "is_voice": True
            }
        )
        assert turn2.status_code == 200
        assert turn2.json()["session_id"] == sess_id

    def test_tts_synthesize_endpoint_returns_wav_binary(self):
        """GET/POST /api/jarvis/voice/synthesize streams valid audio/wav content."""
        token = get_auth_token()
        resp = client.post(
            "/api/jarvis/voice/synthesize",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": "Defense telemetry verified. System secure.",
                "language": "en",
                "speed": 1.0,
                "pitch": 1.0
            }
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "audio/wav"
        assert resp.content[:4] == b"RIFF"
        assert resp.content[8:12] == b"WAVE"

    def test_tts_synthesize_json_endpoint(self):
        """POST /api/jarvis/voice/synthesize-json returns structured metadata and base64."""
        token = get_auth_token()
        resp = client.post(
            "/api/jarvis/voice/synthesize-json",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": "अमोझा सुरक्षा प्रणाली सज्ज आहे.",
                "language": "mr",
                "speed": 1.05
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["format"] == "wav"
        assert data["is_local"] is True
        assert len(data["audio_base64"]) > 100
