from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
from enum import Enum
from datetime import datetime

class JarvisState(str, Enum):
    IDLE = "IDLE"
    LISTENING = "LISTENING"
    PROCESSING = "PROCESSING"
    SPEAKING = "SPEAKING"
    ERROR = "ERROR"

class JarvisLanguage(str, Enum):
    ENGLISH = "en"
    HINDI = "hi"
    MARATHI = "mr"
    HINGLISH = "hinglish"
    AUTO = "auto"

class JarvisToolCall(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    rationale: Optional[str] = None

class JarvisToolResult(BaseModel):
    tool_name: str
    success: bool
    data: Any
    error: Optional[str] = None
    execution_time_ms: Optional[int] = None

class JarvisSecurityContext(BaseModel):
    selected_agent_id: Optional[str] = None
    selected_incident_id: Optional[Union[str, int]] = None
    selected_alert_id: Optional[Union[str, int]] = None
    current_page: Optional[str] = "Overview"
    zero_trust_status: str = "ENFORCING"
    investigation_notes: Optional[str] = None

class JarvisConfirmationRequest(BaseModel):
    action_id: str
    action_type: str  # e.g. "KILL_SWITCH", "REVOKE_CREDENTIALS", "APPROVE_REQUEST", "SUSPEND_AGENT", "REACTIVATE_AGENT"
    target_id: str
    target_name: Optional[str] = None
    risk_level: str = "CRITICAL"  # CRITICAL, HIGH, MEDIUM
    impact_explanation: str
    idempotency_key: str
    created_at: str
    expires_at: Optional[str] = None

class JarvisConfirmationDecision(BaseModel):
    action_id: str
    confirmed: bool
    decision_note: Optional[str] = None
    idempotency_key: str

class JarvisMessageRequest(BaseModel):
    session_id: Optional[str] = None
    message: str = Field(min_length=1, max_length=4000)
    language: JarvisLanguage = JarvisLanguage.AUTO
    is_voice: bool = False
    context: Optional[JarvisSecurityContext] = None
    personality_mode: Optional[str] = "friendly"

class JarvisMessageResponse(BaseModel):
    session_id: str
    message: str
    speech_text: str
    language: str
    state: JarvisState = JarvisState.IDLE
    tool_calls: List[JarvisToolCall] = Field(default_factory=list)
    tool_results: List[JarvisToolResult] = Field(default_factory=list)
    action_required: Optional[JarvisConfirmationRequest] = None
    navigation_target: Optional[str] = None
    security_context: Optional[JarvisSecurityContext] = None
    created_at: str
    audio_confidence: Optional[float] = None
    is_local_mode: bool = True
    audio_base64: Optional[str] = None
    personality_mode: Optional[str] = "friendly"

class JarvisBriefingResponse(BaseModel):
    timestamp: str
    summary: str
    threat_level: str  # LOW, ELEVATED, HIGH, CRITICAL
    active_agents_count: int
    open_incidents_count: int
    pending_approvals_count: int
    critical_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    high_risk_agents: List[Dict[str, Any]] = Field(default_factory=list)
    suspicious_activities: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)

class JarvisSessionInfo(BaseModel):
    session_id: str
    title: str
    created_at: str
    updated_at: str
    message_count: int
    context: Optional[JarvisSecurityContext] = None

class JarvisChatMessageRecord(BaseModel):
    id: int
    session_id: str
    role: str  # "user", "assistant", "system"
    content: str
    speech_text: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_results: Optional[List[Dict[str, Any]]] = None
    navigation_target: Optional[str] = None
    created_at: str

class JarvisPreferences(BaseModel):
    voice_enabled: bool = True
    default_language: JarvisLanguage = JarvisLanguage.AUTO
    selected_voice: Optional[str] = None
    speech_rate: float = 1.05
    speech_pitch: float = 1.0
    auto_speak_responses: bool = True
    proactive_briefings_enabled: bool = True
    sound_effects_enabled: bool = True
    local_mode: bool = True
    wake_word_enabled: bool = False
    cloud_processing_consent: bool = False
    mic_muted: bool = False
    push_to_talk_mode: bool = False
    personality_mode: str = "friendly"

class JarvisAudioTranscribeRequest(BaseModel):
    audio_base64: str
    audio_format: str = "wav"
    language: JarvisLanguage = JarvisLanguage.AUTO

class JarvisAudioTranscribeResponse(BaseModel):
    text: str
    language: str
    confidence: float
    duration_seconds: float
    engine: str
    is_local: bool
    warning: Optional[str] = None

class JarvisAudioSynthesizeRequest(BaseModel):
    text: str
    language: str = "en"
    voice_id: Optional[str] = None
    speed: float = 1.0
    pitch: float = 1.0

class JarvisAudioSynthesizeResponse(BaseModel):
    audio_base64: str
    format: str = "wav"
    duration_seconds: float
    sample_rate: int
    voice_id: str
    is_local: bool

class JarvisVoiceEngineInfo(BaseModel):
    local_mode_enabled: bool
    asr_engine: str
    asr_model: str
    asr_is_local: bool
    asr_supported_languages: List[str]
    tts_engine: str
    tts_is_local: bool
    tts_voices: List[Dict[str, Any]]
