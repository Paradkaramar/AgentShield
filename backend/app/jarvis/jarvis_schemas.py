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
    ai_mode: Optional[str] = "auto"  # "local" | "online" | "auto"

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
    citations: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    live_intelligence: Optional[Dict[str, Any]] = None
    ai_mode: Optional[str] = "auto"
    model_used: Optional[str] = None
    provider_used: Optional[str] = None

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
    ai_mode: str = "auto"  # "local" | "online" | "auto"
    selected_online_provider: str = "gemini"
    selected_local_model: str = "qwen2.5:3b"

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

# Cyber Tool Schemas (Phase 1 Steganography)
class StegoInspectRequest(BaseModel):
    image_data: str

class StegoEncodeRequest(BaseModel):
    image_data: str
    message: str
    password: Optional[str] = None

class StegoDecodeRequest(BaseModel):
    image_data: str
    password: Optional[str] = None

# Personal Assistant & Memory Schemas
class JarvisReminderCreate(BaseModel):
    title: str
    due_time: Optional[str] = None
    priority: str = "NORMAL"

class JarvisNoteCreate(BaseModel):
    title: str = "Untitled Note"
    content: str
    tags: Optional[List[str]] = None

class JarvisTodoCreate(BaseModel):
    task: str
    priority: str = "NORMAL"

class JarvisMemoryCreate(BaseModel):
    key: str
    value: str
    category: str = "preference"

# ==============================================================================
# Unified AI Router & Local GGUF/Ollama Inference Schemas
# ==============================================================================

class AIChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000, description="User prompt or directive")
    session_id: Optional[str] = Field(default=None, description="Optional conversation session ID")
    mode: Optional[str] = Field(default="auto", description="Dual-model mode: 'local' (only local GGUF), 'online' (only cloud model), 'auto' (task & availability routing)")
    provider: Optional[str] = Field(default="auto", description="Preferred provider: auto, local, gemini, openai, anthropic, heuristic")
    model: Optional[str] = Field(default=None, description="Model identifier override (e.g. qwen2.5:3b, qwen3-4b)")
    system_prompt: Optional[str] = Field(default=None, description="Custom system instruction")
    temperature: Optional[float] = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=1024, ge=1, le=4096)
    language: Optional[str] = Field(default="auto", description="Response language: auto, en, hi, mr, hinglish")
    conversation_history: Optional[List[Dict[str, str]]] = Field(default=None, description="Past turns [{'role': 'user', 'content': '...'}]")

class AIChatResponse(BaseModel):
    response: str
    speech_text: Optional[str] = None
    provider_used: str
    model_used: str
    ai_mode_used: str = "auto"
    is_local: bool
    fallback_occurred: bool
    fallback_reason: Optional[str] = None
    execution_time_ms: int
    session_id: Optional[str] = None
    language_detected: str
    created_at: str

class AIHealthResponse(BaseModel):
    status: str  # "HEALTHY", "DEGRADED", "OFFLINE"
    local_runtime: Dict[str, Any]
    cloud_providers: Dict[str, Any]
    active_default_provider: str
    storage: Dict[str, Any]
    timestamp: str

class AIProvidersResponse(BaseModel):
    default_provider: str
    configured_providers: List[Dict[str, Any]]

class AIInferenceTestResult(BaseModel):
    model_type: str  # "local" | "online"
    provider: str    # "ollama" | "gemini" | "openai" | "anthropic"
    model: str
    status: str      # "PASS" | "FAIL"
    latency_ms: int
    test_prompt: str
    response: Optional[str] = None
    error: Optional[str] = None
    tested_at: str

class AIDualModelStatus(BaseModel):
    current_mode: str  # "local" | "online" | "auto"
    local_model: Dict[str, Any]
    online_model: Dict[str, Any]
    storage: Dict[str, Any]
    active_in_ui: str
    both_working: bool = False
    timestamp: str

class AITestModelRequest(BaseModel):
    model: Optional[str] = None
    provider: Optional[str] = None
