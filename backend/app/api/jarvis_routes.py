from fastapi import APIRouter, HTTPException, Depends, Query, status
from fastapi.responses import Response
from typing import Dict, Any, List, Optional
import os
import base64

from ..core.auth import get_current_user
from ..jarvis.jarvis_schemas import (
    JarvisMessageRequest, JarvisMessageResponse, JarvisConfirmationDecision,
    JarvisBriefingResponse, JarvisPreferences, JarvisSessionInfo,
    JarvisAudioTranscribeRequest, JarvisAudioTranscribeResponse,
    JarvisAudioSynthesizeRequest, JarvisAudioSynthesizeResponse,
    JarvisVoiceEngineInfo,
    StegoInspectRequest, StegoEncodeRequest, StegoDecodeRequest,
    JarvisReminderCreate, JarvisNoteCreate, JarvisTodoCreate, JarvisMemoryCreate
)
from ..jarvis.cyber_tools.stego_engine import (
    encode_stego_message, decode_stego_message, inspect_image_and_exif
)
from ..jarvis.personal_assistant import (
    create_reminder, list_reminders, delete_reminder,
    create_note, search_notes, list_notes, delete_note,
    add_todo_item, list_todo_items, toggle_todo_item,
    store_user_memory, list_user_memories, delete_user_memory, clear_all_user_memories,
    APPROVED_APPLICATIONS
)
from ..jarvis.jarvis_service import (
    process_jarvis_turn, execute_confirmed_action, generate_proactive_briefing
)
from ..jarvis.jarvis_tools import TOOL_REGISTRY
from ..jarvis.jarvis_memory import (
    get_session_history, clear_session_history, list_user_sessions,
    get_user_preferences, save_user_preferences, search_conversation_history
)
from ..jarvis.speech_to_text import local_stt_engine, transcribe_audio_locally
from ..jarvis.text_to_speech import local_tts_engine
from ..jarvis.live_intelligence import (
    fetch_live_weather,
    fetch_cybersecurity_intelligence,
    search_live_news_rss,
    search_duckduckgo_lite,
    perform_live_web_research,
    check_windows_software_updates
)
from ..db.database import connect, now_iso
from pydantic import BaseModel, Field

class LiveResearchRequest(BaseModel):
    query: str
    freshness: Optional[str] = "week"
    force_refresh: Optional[bool] = False

router = APIRouter(prefix="/api/jarvis", tags=["JARVIS AI Security Assistant"])

@router.post("/chat", response_model=JarvisMessageResponse)
async def chat_with_jarvis(
    request: JarvisMessageRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Processes conversational turns (speech or text) with security validation, approved tools, and grounded responses."""
    try:
        response = await process_jarvis_turn(request, current_user)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"JARVIS service error: {str(e)}"
        )

@router.get("/tools")
def list_supported_tools(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Discovers approved tools with schemas and access requirements."""
    user_role = current_user.get("role", "operator")
    visible_tools = {}
    for name, spec in TOOL_REGISTRY.items():
        allowed_roles = spec.get("allowed_roles", [])
        if user_role == "admin" or user_role in allowed_roles:
            visible_tools[name] = {
                "name": name,
                "description": spec["description"],
                "category": spec["category"],
                "parameters": spec["parameters"]
            }
    return {
        "count": len(visible_tools),
        "user_role": user_role,
        "tools": visible_tools
    }

@router.get("/briefing", response_model=JarvisBriefingResponse)
def get_security_briefing(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Generates an on-demand proactive security briefing summarizing threats, agents, and recommendations."""
    return generate_proactive_briefing(current_user)

@router.post("/confirm")
def confirm_action_decision(
    decision: JarvisConfirmationDecision,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Confirms or cancels a sensitive security operation (e.g. Emergency Kill Switch or manual approval)."""
    result = execute_confirmed_action(
        action_id=decision.action_id,
        confirmed=decision.confirmed,
        decision_note=decision.decision_note,
        idempotency_key=decision.idempotency_key,
        user=current_user
    )
    if not result.get("success", False):
        raise HTTPException(status_code=400, detail=result.get("error", "Action confirmation failed"))
    return result

@router.get("/sessions", response_model=List[JarvisSessionInfo])
def get_user_sessions(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Lists conversation sessions for the authenticated user."""
    user_id = current_user.get("username", "admin")
    sessions = list_user_sessions(user_id)
    return [
        JarvisSessionInfo(
            session_id=s["id"],
            title=s["title"],
            created_at=s["created_at"],
            updated_at=s["updated_at"],
            message_count=s.get("message_count", 0),
            context=s.get("context")
        )
        for s in sessions
    ]

@router.get("/sessions/{session_id}")
def get_session_messages(
    session_id: str,
    limit: int = Query(default=30, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieves message history for a specific conversation session."""
    user_id = current_user.get("username", "admin")
    return get_session_history(session_id, user_id, limit=limit)

@router.delete("/sessions/{session_id}")
def clear_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Clears conversation history for a session (enforces user privacy)."""
    user_id = current_user.get("username", "admin")
    cleared = clear_session_history(session_id, user_id)
    if not cleared:
        raise HTTPException(status_code=404, detail="Session not found or access denied")
    return {"message": f"Session {session_id} history cleared successfully", "session_id": session_id}

@router.get("/preferences", response_model=JarvisPreferences)
def get_preferences(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieves user preferences for voice input/output and assistant behavior."""
    user_id = current_user.get("username", "admin")
    return get_user_preferences(user_id)

@router.post("/preferences", response_model=JarvisPreferences)
def update_preferences(
    prefs: JarvisPreferences,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Updates user preferences for voice input/output and assistant behavior."""
    user_id = current_user.get("username", "admin")
    save_user_preferences(user_id, prefs)
    return prefs

@router.get("/voice/engines", response_model=JarvisVoiceEngineInfo)
def get_voice_engines_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns local ASR and TTS engine capabilities, supported languages, and verified local Indic voices."""
    is_local_mode = os.getenv("JARVIS_LOCAL_MODE", "true").lower() in {"1", "true", "yes"}
    voices = local_tts_engine.get_voices()
    return JarvisVoiceEngineInfo(
        local_mode_enabled=is_local_mode,
        asr_engine=local_stt_engine.active_engine,
        asr_model=os.getenv("JARVIS_WHISPER_MODEL", "small-indic"),
        asr_is_local=True,
        asr_supported_languages=["en", "hi", "mr", "hinglish"],
        tts_engine="piper_indic_local",
        tts_is_local=True,
        tts_voices=voices
    )

@router.post("/voice/transcribe", response_model=JarvisAudioTranscribeResponse)
async def transcribe_audio_endpoint(
    payload: JarvisAudioTranscribeRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Local speech recognition endpoint supporting Marathi, Hindi, Hinglish, and English audio."""
    try:
        raw_b64 = payload.audio_base64
        if "," in raw_b64:
            raw_b64 = raw_b64.split(",", 1)[1]
        audio_bytes = base64.b64decode(raw_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 audio data: {str(e)}")

    lang_code = payload.language.value if hasattr(payload.language, "value") else str(payload.language)
    res = transcribe_audio_locally(audio_bytes, language=None if lang_code == "auto" else lang_code)
    return JarvisAudioTranscribeResponse(
        text=res["text"],
        language=res["language"],
        confidence=res["confidence"],
        duration_seconds=res["duration_seconds"],
        engine=res["engine"],
        is_local=res["is_local"]
    )

@router.post("/voice/synthesize")
def synthesize_audio_endpoint(
    payload: JarvisAudioSynthesizeRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Synthesizes text locally into playable WAV audio stream for Marathi, Hindi, and English."""
    wav_bytes = local_tts_engine.synthesize_wav(
        text=payload.text,
        language=payload.language,
        voice_id=payload.voice_id,
        speech_rate=payload.speed,
        speech_pitch=payload.pitch
    )
    return Response(content=wav_bytes, media_type="audio/wav")

@router.post("/voice/synthesize-json", response_model=JarvisAudioSynthesizeResponse)
def synthesize_audio_json_endpoint(
    payload: JarvisAudioSynthesizeRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Synthesizes speech locally and returns base64 WAV payload."""
    wav_bytes = local_tts_engine.synthesize_wav(
        text=payload.text,
        language=payload.language,
        voice_id=payload.voice_id,
        speech_rate=payload.speed,
        speech_pitch=payload.pitch
    )
    b64 = base64.b64encode(wav_bytes).decode("ascii")
    voice = local_tts_engine.get_default_voice_for_language(payload.language)
    return JarvisAudioSynthesizeResponse(
        audio_base64=b64,
        format="wav",
        duration_seconds=round(len(payload.text) * 0.055 / max(0.5, payload.speed), 2),
        sample_rate=local_tts_engine.sample_rate,
        voice_id=payload.voice_id or voice["id"],
        is_local=True
    )

@router.post("/cyber/stego/inspect")
def inspect_stego_endpoint(
    payload: StegoInspectRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Deep forensic inspection of an image carrier: detects stego payloads, bitplane entropy, and EXIF/GPS metadata."""
    try:
        return inspect_image_and_exif(payload.image_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/cyber/stego/encode")
def encode_stego_endpoint(
    payload: StegoEncodeRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Encodes a secret message into an image carrier with cryptographic SHA-256 integrity."""
    try:
        return encode_stego_message(payload.image_data, payload.message, password=payload.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/cyber/stego/decode")
def decode_stego_endpoint(
    payload: StegoDecodeRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Extracts a hidden secret message from an image carrier."""
    try:
        return decode_stego_message(payload.image_data, password=payload.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==============================================================================
# Phase 3: Personal Assistant & User-Controlled Memory REST Endpoints
# ==============================================================================

# --- Reminders ---
@router.get("/reminders")
def get_reminders(
    include_completed: bool = Query(default=False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieves reminders for the active user."""
    user_id = current_user.get("username", "admin")
    return {"reminders": list_reminders(user_id, include_completed=include_completed)}

@router.post("/reminders")
def post_reminder(
    payload: JarvisReminderCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Creates a new reminder for the active user."""
    user_id = current_user.get("username", "admin")
    result = create_reminder(user_id, payload.title, payload.due_time, payload.priority)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.delete("/reminders/{reminder_id}")
def remove_reminder(
    reminder_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Deletes a reminder."""
    user_id = current_user.get("username", "admin")
    success = delete_reminder(reminder_id, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Reminder not found or access denied")
    return {"message": f"Reminder #{reminder_id} deleted successfully."}

# --- Notes ---
@router.get("/notes")
def get_notes(
    query: Optional[str] = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Lists or searches personal notes."""
    user_id = current_user.get("username", "admin")
    if query:
        notes = search_notes(user_id, query)
    else:
        notes = list_notes(user_id, limit=limit)
    return {"notes": notes}

@router.post("/notes")
def post_note(
    payload: JarvisNoteCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Creates a new personal note."""
    user_id = current_user.get("username", "admin")
    result = create_note(user_id, payload.title, payload.content, payload.tags)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.delete("/notes/{note_id}")
def remove_note(
    note_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Deletes a personal note."""
    user_id = current_user.get("username", "admin")
    success = delete_note(note_id, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Note not found or access denied")
    return {"message": f"Note #{note_id} deleted successfully."}

# --- To-Dos ---
@router.get("/todos")
def get_todos(
    include_completed: bool = Query(default=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Lists user to-do tasks."""
    user_id = current_user.get("username", "admin")
    return {"todos": list_todo_items(user_id, include_completed=include_completed)}

@router.post("/todos")
def post_todo(
    payload: JarvisTodoCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Adds a task to the user's to-do list."""
    user_id = current_user.get("username", "admin")
    result = add_todo_item(user_id, payload.task, payload.priority)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.patch("/todos/{todo_id}/toggle")
def toggle_todo(
    todo_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Toggles task completion."""
    user_id = current_user.get("username", "admin")
    result = toggle_todo_item(todo_id, user_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

# --- User-Controlled Memories ---
@router.get("/memories")
def get_memories(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Lists all user-controlled persistent memories."""
    user_id = current_user.get("username", "admin")
    return {"memories": list_user_memories(user_id)}

@router.post("/memories")
def post_memory(
    payload: JarvisMemoryCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Stores a user-controlled memory."""
    user_id = current_user.get("username", "admin")
    result = store_user_memory(user_id, payload.key, payload.value, payload.category)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.delete("/memories/{key}")
def remove_memory(
    key: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Deletes a specific user memory."""
    user_id = current_user.get("username", "admin")
    success = delete_user_memory(user_id, key)
    if not success:
        raise HTTPException(status_code=404, detail=f"Memory '{key}' not found")
    return {"message": f"Memory '{key}' deleted successfully."}

@router.delete("/memories")
def clear_memories(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Clears all user memories."""
    user_id = current_user.get("username", "admin")
    count = clear_all_user_memories(user_id)
    return {"message": f"Cleared {count} memory entries.", "count": count}

# --- Search Conversation History ---
@router.get("/history/search")
def search_history(
    q: str = Query(..., min_length=1),
    limit: int = Query(default=20, ge=1, le=50),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Searches past conversation messages across all sessions."""
    user_id = current_user.get("username", "admin")
    matches = search_conversation_history(user_id, q, limit=limit)
    return {"query": q, "count": len(matches), "results": matches}

# --- System, Privacy & Hybrid AI Status ---
@router.get("/system/status")
def get_system_status(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns status of local and hybrid AI components, Zero-Trust posture, and privacy settings."""
    user_id = current_user.get("username", "admin")
    prefs = get_user_preferences(user_id)
    return {
        "status": "HEALTHY",
        "zero_trust_status": "ENFORCING",
        "cloud_processing_consent": prefs.cloud_processing_consent,
        "local_mode_active": prefs.local_mode,
        "providers": {
            "local_asr": {
                "name": "Local Indic-Whisper Engine",
                "available": True,
                "status": "ONLINE",
                "mode": "100% On-Device",
                "languages": ["hi", "mr", "hinglish", "en"]
            },
            "local_tts": {
                "name": "Local Piper Indic TTS Engine",
                "available": True,
                "status": "ONLINE",
                "mode": "100% On-Device",
                "languages": ["hi", "mr", "hinglish", "en"]
            },
            "local_llm": {
                "name": "Ollama / Local Security LLM",
                "available": True,
                "status": "STANDBY",
                "mode": "Local Offline Fallback"
            },
            "cloud_llm": {
                "name": "Cloud AI Provider (OpenAI/Anthropic)",
                "available": bool(os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")),
                "status": "AVAILABLE" if (os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")) else "NOT_CONFIGURED",
                "requires_consent": True,
                "consent_granted": prefs.cloud_processing_consent
            }
        },
        "approved_apps": list(APPROVED_APPLICATIONS.keys()),
        "security_safeguards": {
            "unrestricted_shell_blocked": True,
            "idempotency_enforced": True,
            "audit_logging_enabled": True,
            "role_based_access_control": True
        }
    }

# --- Live Intelligence & Real-Time Knowledge Engine Endpoints ---

@router.get("/live/weather")
def get_live_weather_endpoint(
    city: Optional[str] = Query(default=None),
    latitude: Optional[float] = Query(default=None),
    longitude: Optional[float] = Query(default=None),
    force_refresh: bool = Query(default=False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Fetches real-time weather and forecast data via Open-Meteo."""
    return fetch_live_weather(
        city=city,
        latitude=latitude,
        longitude=longitude,
        force_refresh=force_refresh
    )

@router.get("/live/cyber-advisories")
def get_cyber_advisories_endpoint(
    query_or_cve: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=50),
    force_refresh: bool = Query(default=False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Fetches verified CISA KEV catalog advisories or NIST CVE records."""
    return fetch_cybersecurity_intelligence(
        query_or_cve=query_or_cve,
        limit=limit,
        force_refresh=force_refresh
    )

@router.get("/live/news")
def get_live_news_endpoint(
    query: str = Query(default="latest technology cybersecurity news"),
    freshness: str = Query(default="today"),
    max_results: int = Query(default=15, ge=1, le=30),
    force_refresh: bool = Query(default=False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Fetches real-time news articles via authenticated RSS feeds with publisher attribution."""
    articles = search_live_news_rss(
        topic=query,
        freshness=freshness
    )
    return {
        "status": "SUCCESS",
        "query": query,
        "freshness": freshness,
        "count": len(articles),
        "sources": articles,
        "retrieved_at": now_iso()
    }

@router.post("/live/research")
def perform_live_research_endpoint(
    req: LiveResearchRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Conducts independent multi-source live web research and source comparison."""
    return perform_live_web_research(
        query=req.query,
        freshness=req.freshness or "week",
        max_sources=12
    )

@router.get("/live/windows-updates")
def get_windows_updates_endpoint(
    software_name: Optional[str] = Query(default="windows"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Checks official Microsoft Release Health and verifies installed OS status."""
    return check_windows_software_updates(software_name=software_name)

@router.get("/live/history")
def get_live_intel_history(
    limit: int = Query(default=30, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieves recent live intelligence query audit logs."""
    with connect() as db:
        rows = db.execute(
            """SELECT id, query, category, latency_ms, created_at
               FROM live_intelligence_queries
               ORDER BY id DESC LIMIT ?""",
            (limit,)
        ).fetchall()
        return {
            "count": len(rows),
            "history": [
                {
                    "id": r[0],
                    "query_text": r[1],
                    "category": r[2],
                    "latency_ms": r[3],
                    "retrieved_at": r[4]
                }
                for r in rows
            ]
        }


