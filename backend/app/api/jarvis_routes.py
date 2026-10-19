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
    JarvisVoiceEngineInfo
)
from ..jarvis.jarvis_service import (
    process_jarvis_turn, execute_confirmed_action, generate_proactive_briefing
)
from ..jarvis.jarvis_tools import TOOL_REGISTRY
from ..jarvis.jarvis_memory import (
    get_session_history, clear_session_history, list_user_sessions,
    get_user_preferences, save_user_preferences
)
from ..jarvis.speech_to_text import local_stt_engine, transcribe_audio_locally
from ..jarvis.text_to_speech import local_tts_engine

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
