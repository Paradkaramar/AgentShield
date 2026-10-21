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

// ============================================================================
// Phase 3 & 5: Personal Assistant, Memory, and System Status API
// ============================================================================

export async function getJarvisReminders(includeCompleted: boolean = false) {
  return request<{ reminders: import("./types").JarvisReminder[] }>(`/api/jarvis/reminders?include_completed=${includeCompleted}`);
}

export async function createJarvisReminder(title: string, dueTime?: string, priority: string = "NORMAL") {
  return request<import("./types").JarvisReminder>("/api/jarvis/reminders", {
    method: "POST",
    body: JSON.stringify({ title, due_time: dueTime, priority })
  });
}

export async function deleteJarvisReminder(id: number) {
  return request<{ message: string }>(`/api/jarvis/reminders/${id}`, {
    method: "DELETE"
  });
}

export async function getJarvisNotes(query?: string) {
  const url = query ? `/api/jarvis/notes?query=${encodeURIComponent(query)}` : "/api/jarvis/notes";
  return request<{ notes: import("./types").JarvisNote[] }>(url);
}

export async function createJarvisNote(title: string, content: string, tags?: string[]) {
  return request<import("./types").JarvisNote>("/api/jarvis/notes", {
    method: "POST",
    body: JSON.stringify({ title, content, tags })
  });
}

export async function deleteJarvisNote(id: number) {
  return request<{ message: string }>(`/api/jarvis/notes/${id}`, {
    method: "DELETE"
  });
}

export async function getJarvisTodos(includeCompleted: boolean = true) {
  return request<{ todos: import("./types").JarvisTodo[] }>(`/api/jarvis/todos?include_completed=${includeCompleted}`);
}

export async function createJarvisTodo(task: string, priority: string = "NORMAL") {
  return request<import("./types").JarvisTodo>("/api/jarvis/todos", {
    method: "POST",
    body: JSON.stringify({ task, priority })
  });
}

export async function toggleJarvisTodo(id: number) {
  return request<{ id: number; completed: boolean; message: string }>(`/api/jarvis/todos/${id}/toggle`, {
    method: "PATCH"
  });
}

export async function getJarvisMemories() {
  return request<{ memories: import("./types").JarvisMemory[] }>("/api/jarvis/memories");
}

export async function createJarvisMemory(key: string, value: string, category: string = "preference") {
  return request<import("./types").JarvisMemory>("/api/jarvis/memories", {
    method: "POST",
    body: JSON.stringify({ key, value, category })
  });
}

export async function deleteJarvisMemory(key: string) {
  return request<{ message: string }>(`/api/jarvis/memories/${encodeURIComponent(key)}`, {
    method: "DELETE"
  });
}

export async function clearJarvisMemories() {
  return request<{ message: string; count: number }>("/api/jarvis/memories", {
    method: "DELETE"
  });
}

export async function searchJarvisHistory(q: string) {
  return request<{ query: string; count: number; results: any[] }>(`/api/jarvis/history/search?q=${encodeURIComponent(q)}`);
}

export async function getJarvisSystemStatus() {
  return request<import("./types").JarvisSystemStatus>("/api/jarvis/system/status");
}

// Live Intelligence APIs
export async function fetchLiveWeather(city?: string, lang: string = "auto") {
  const params = new URLSearchParams();
  if (city) params.set("city", city);
  if (lang) params.set("lang", lang);
  const qs = params.toString() ? `?${params.toString()}` : "";
  return request<import("./types").LiveWeatherResult>(`/api/jarvis/live/weather${qs}`);
}

export async function fetchLiveCyberAdvisories(cveId?: string, limit: number = 10) {
  const params = new URLSearchParams();
  if (cveId) params.set("cve_id", cveId);
  params.set("limit", limit.toString());
  return request<{ status: string; advisories: import("./types").LiveCyberAdvisory[]; retrieved_at?: string; total_source_records?: number }>(
    `/api/jarvis/live/cyber-advisories?${params.toString()}`
  );
}

export async function fetchLiveNews(topic: string = "all", freshness: string = "week", limit: number = 10) {
  const params = new URLSearchParams({ topic, freshness, limit: limit.toString() });
  return request<{ status: string; topic: string; freshness: string; articles: import("./types").LiveNewsArticle[]; retrieved_at?: string }>(
    `/api/jarvis/live/news?${params.toString()}`
  );
}

export async function performLiveResearch(query: string, lang: string = "auto") {
  return request<{ status: string; query: string; synthesis: string; spoken_summary: string; citations: any[]; retrieved_at?: string }>(
    "/api/jarvis/live/research",
    {
      method: "POST",
      body: JSON.stringify({ query, language: lang })
    }
  );
}

export async function fetchWindowsUpdates() {
  return request<import("./types").WindowsUpdateIntel>("/api/jarvis/live/windows-updates");
}

export async function fetchLiveHistory(limit: number = 20) {
  return request<{ queries: import("./types").LiveQueryHistoryItem[] }>(`/api/jarvis/live/history?limit=${limit}`);
}




