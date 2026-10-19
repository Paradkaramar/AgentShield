const API_BASE = "http://127.0.0.1:8000";

let authToken = localStorage.getItem("agentshield_token") || "";

export function setAuthToken(token: string) {
  authToken = token;
  if (token) {
    localStorage.setItem("agentshield_token", token);
  } else {
    localStorage.removeItem("agentshield_token");
  }
}

export function getAuthToken(): string {
  return authToken;
}

export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string> || {})
  };

  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.detail || `Request failed with status ${response.status}`);
  }

  return response.json();
}

// JARVIS Assistant API
export async function sendJarvisMessage(
  message: string,
  options?: {
    sessionId?: string;
    language?: import("./types").JarvisLanguage;
    isVoice?: boolean;
    context?: import("./types").JarvisSecurityContext;
  }
) {
  return request<any>("/api/jarvis/chat", {
    method: "POST",
    body: JSON.stringify({
      message,
      session_id: options?.sessionId,
      language: options?.language || "auto",
      is_voice: options?.isVoice || false,
      context: options?.context
    })
  });
}

export async function confirmJarvisAction(
  actionId: string,
  confirmed: boolean,
  decisionNote?: string,
  idempotencyKey?: string
) {
  return request<{ success: boolean; status: string; message: string }>("/api/jarvis/confirm", {
    method: "POST",
    body: JSON.stringify({
      action_id: actionId,
      confirmed,
      decision_note: decisionNote,
      idempotency_key: idempotencyKey || ""
    })
  });
}

export async function getJarvisBriefing() {
  return request<import("./types").JarvisBriefing>("/api/jarvis/briefing");
}

export async function getJarvisTools() {
  return request<{ count: number; user_role: string; tools: Record<string, any> }>("/api/jarvis/tools");
}

export async function getJarvisSessions() {
  return request<any[]>("/api/jarvis/sessions");
}

export async function getJarvisHistory(sessionId: string) {
  return request<any[]>(`/api/jarvis/sessions/${sessionId}`);
}

export async function clearJarvisHistory(sessionId: string) {
  return request<{ message: string; session_id: string }>(`/api/jarvis/sessions/${sessionId}`, {
    method: "DELETE"
  });
}

export async function getJarvisPreferences() {
  return request<import("./types").JarvisPreferences>("/api/jarvis/preferences");
}

export async function saveJarvisPreferences(prefs: import("./types").JarvisPreferences) {
  return request<import("./types").JarvisPreferences>("/api/jarvis/preferences", {
    method: "POST",
    body: JSON.stringify(prefs)
  });
}

export async function getJarvisVoiceEngines() {
  return request<import("./types").JarvisVoiceEngineInfo>("/api/jarvis/voice/engines");
}

export async function transcribeAudio(
  audioBase64: string,
  language: import("./types").JarvisLanguage = "auto",
  audioFormat: string = "wav"
) {
  return request<{
    text: string;
    language: string;
    confidence: number;
    duration_seconds: number;
    engine: string;
    is_local: boolean;
    warning?: string;
  }>("/api/jarvis/voice/transcribe", {
    method: "POST",
    body: JSON.stringify({
      audio_base64: audioBase64,
      audio_format: audioFormat,
      language
    })
  });
}

export async function synthesizeAudioJson(
  text: string,
  language: string = "en",
  voiceId?: string,
  speed: number = 1.0,
  pitch: number = 1.0
) {
  return request<{
    audio_base64: string;
    format: string;
    duration_seconds: number;
    sample_rate: number;
    voice_id: string;
    is_local: boolean;
  }>("/api/jarvis/voice/synthesize-json", {
    method: "POST",
    body: JSON.stringify({
      text,
      language,
      voice_id: voiceId,
      speed,
      pitch
    })
  });
}

