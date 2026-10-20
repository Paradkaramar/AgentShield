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
    personalityMode?: "friendly" | "security";
  }
) {
  return request<any>("/api/jarvis/chat", {
    method: "POST",
    body: JSON.stringify({
      message,
      session_id: options?.sessionId,
      language: options?.language || "auto",
      is_voice: options?.isVoice || false,
      context: options?.context,
      personality_mode: options?.personalityMode || "friendly"
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

// ============================================================================
// Endpoint Security API Client Methods
// ============================================================================

export async function listEnrolledDevices() {
  return request<import("./types").EnrolledDevice[]>("/api/endpoint/devices");
}

export async function getDeviceDetails(deviceId: string) {
  return request<any>(`/api/endpoint/devices/${deviceId}`);
}

export async function pauseDeviceMonitoring(deviceId: string) {
  return request<{ status: string; device_id: string }>(`/api/endpoint/devices/${deviceId}/pause`, {
    method: "POST"
  });
}

export async function resumeDeviceMonitoring(deviceId: string) {
  return request<{ status: string; device_id: string }>(`/api/endpoint/devices/${deviceId}/resume`, {
    method: "POST"
  });
}

export async function disconnectDevice(deviceId: string) {
  return request<{ status: string; device_id: string }>(`/api/endpoint/devices/${deviceId}/disconnect`, {
    method: "POST"
  });
}

export async function revokeDevice(deviceId: string, reason: string) {
  return request<{ status: string; device_id: string; reason: string }>(`/api/endpoint/devices/${deviceId}/revoke?reason=${encodeURIComponent(reason)}`, {
    method: "POST"
  });
}

export async function getDeviceConsent(deviceId: string) {
  return request<import("./types").DeviceConsentRecord[]>(`/api/endpoint/devices/${deviceId}/consent`);
}

export async function updateDeviceConsent(deviceId: string, permissions: Record<string, boolean>) {
  return request<{ status: string; device_id: string; updated_permissions: Record<string, boolean> }>(`/api/endpoint/devices/${deviceId}/consent`, {
    method: "PUT",
    body: JSON.stringify({ permissions })
  });
}

export async function getDeviceProcesses(deviceId: string, suspiciousOnly: boolean = false) {
  return request<{ status: string; processes: import("./types").DeviceProcess[]; message?: string }>(`/api/endpoint/devices/${deviceId}/processes?suspicious_only=${suspiciousOnly}`);
}

export async function getDeviceConnections(deviceId: string, suspiciousOnly: boolean = false) {
  return request<{ status: string; connections: import("./types").DeviceConnection[]; message?: string }>(`/api/endpoint/devices/${deviceId}/connections?suspicious_only=${suspiciousOnly}`);
}

export async function getDeviceListeningPorts(deviceId: string) {
  return request<import("./types").DeviceListeningPort[]>(`/api/endpoint/devices/${deviceId}/listening-ports`);
}

export async function getDeviceFirewall(deviceId: string) {
  return request<import("./types").DeviceFirewallStatus>(`/api/endpoint/devices/${deviceId}/firewall`);
}

export async function getDeviceAlerts(deviceId: string, status?: string) {
  const url = status ? `/api/endpoint/devices/${deviceId}/alerts?status=${status}` : `/api/endpoint/devices/${deviceId}/alerts`;
  return request<import("./types").DeviceSecurityAlert[]>(url);
}

export async function resolveSecurityAlert(alertId: number) {
  return request<{ status: string; alert_id: number }>(`/api/endpoint/alerts/${alertId}/resolve`, {
    method: "POST"
  });
}

export async function requestFileScan(deviceId: string, filepath: string) {
  return request<any>(`/api/endpoint/devices/${deviceId}/scan-file`, {
    method: "POST",
    body: JSON.stringify({ filepath })
  });
}

export async function executeFirewallAction(deviceId: string, data: { action_type: string; target_value: string; reason: string; confirmation_code: string }) {
  return request<any>(`/api/endpoint/devices/${deviceId}/firewall-action`, {
    method: "POST",
    body: JSON.stringify(data)
  });
}

export async function createEnrollmentToken(validDays: number = 7) {
  return request<import("./types").EnrollmentToken>("/api/endpoint/enrollment-tokens", {
    method: "POST",
    body: JSON.stringify({ valid_days: validDays })
  });
}

export async function listEnrollmentTokens() {
  return request<import("./types").EnrollmentToken[]>("/api/endpoint/enrollment-tokens");
}

export async function enrollDevice(data: { token: string; device_name?: string; hostname?: string; os_type?: string; consent_permissions?: Record<string, boolean> }) {
  return request<any>("/api/endpoint/enroll", {
    method: "POST",
    body: JSON.stringify(data)
  });
}


