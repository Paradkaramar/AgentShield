const API_BASE = (typeof window !== "undefined" && window.location.port === "5173")
  ? ""
  : "http://127.0.0.1:8000";

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
  const isFormData = typeof FormData !== "undefined" && options?.body instanceof FormData;
  const headers: Record<string, string> = {
    ...(isFormData ? {} : { "Content-Type": "application/json" }),
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
    aiMode?: "local" | "online" | "auto";
    signal?: AbortSignal;
  }
) {
  return request<any>("/api/jarvis/chat", {
    method: "POST",
    signal: options?.signal,
    body: JSON.stringify({
      message,
      session_id: options?.sessionId,
      language: options?.language || "auto",
      is_voice: options?.isVoice || false,
      context: options?.context,
      personality_mode: options?.personalityMode || "friendly",
      ai_mode: options?.aiMode || "auto"
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

// =============================================================================
// REVERSE ENGINEERING LAB API
// =============================================================================

export async function uploadReLabFile(file: File): Promise<import("./types").ReLabAnalysis> {
  const formData = new FormData();
  formData.append("file", file);
  return request<import("./types").ReLabAnalysis>("/api/forensics/re-lab/upload", {
    method: "POST",
    body: formData
  });
}

export async function analyzeReLabCode(
  code: string,
  language: string,
  filename?: string
): Promise<import("./types").ReLabAnalysis> {
  return request<import("./types").ReLabAnalysis>("/api/forensics/re-lab/analyze-code", {
    method: "POST",
    body: JSON.stringify({ code, language, filename })
  });
}

export async function getReLabHistory(): Promise<import("./types").ReLabAnalysis[]> {
  return request<import("./types").ReLabAnalysis[]>("/api/forensics/re-lab/history");
}

export async function getReLabAnalysisDetail(analysisId: string): Promise<import("./types").ReLabAnalysis> {
  return request<import("./types").ReLabAnalysis>(`/api/forensics/re-lab/analysis/${encodeURIComponent(analysisId)}`);
}

export async function getReLabToolsStatus(): Promise<import("./types").ReLabToolsStatus> {
  return request<import("./types").ReLabToolsStatus>("/api/forensics/re-lab/tools-status");
}

export async function askAmojaReLab(
  analysisId: string,
  question: string,
  language: string = "auto"
): Promise<{ analysis_id: string; question: string; answer: string; language: string; grounded_sample: string }> {
  return request("/api/forensics/re-lab/ai-explain", {
    method: "POST",
    body: JSON.stringify({ analysis_id: analysisId, question, language })
  });
}

export function getReLabReportDownloadUrl(analysisId: string, format: "json" | "txt" = "json"): string {
  return `${API_BASE}/api/forensics/re-lab/report/${encodeURIComponent(analysisId)}/download?format=${format}`;
}

// =============================================================================
// REA (REVERSE ENGINEER ANYTHING) LAB API
// =============================================================================

export async function getReaStatus(): Promise<import("./types").ReaStatus> {
  return request<import("./types").ReaStatus>("/api/rea/status");
}

export async function uploadReaArtifact(file: File, workflow?: string): Promise<import("./types").ReaInvestigation> {
  const formData = new FormData();
  formData.append("file", file);
  if (workflow) formData.append("workflow", workflow);
  return request<import("./types").ReaInvestigation>("/api/rea/upload", {
    method: "POST",
    body: formData
  });
}

export async function inspectReaPath(path: string, workflow?: string): Promise<import("./types").ReaInvestigation> {
  return request<import("./types").ReaInvestigation>("/api/rea/inspect-path", {
    method: "POST",
    body: JSON.stringify({ path, workflow })
  });
}

export async function askAmojaRea(
  analysisId: string,
  question: string,
  language: string = "en"
): Promise<{
  analysis_id: string;
  filename: string;
  workflow: string;
  observed_facts: string[];
  inferred_risks: string[];
  limitations: string[];
  english_briefing: string;
  hinglish_briefing: string;
  custom_answer?: string | null;
  language_served: string;
}> {
  return request("/api/rea/explain", {
    method: "POST",
    body: JSON.stringify({ analysis_id: analysisId, question, language })
  });
}

export async function getReaHistory(): Promise<any[]> {
  return request<any[]>("/api/rea/history");
}

export async function getAuthorizedReaTargets(): Promise<import("./types").ReaAuthorizedTarget[]> {
  return request<import("./types").ReaAuthorizedTarget[]>("/api/rea/authorized-targets");
}

export async function validateReaTarget(targetPath: string): Promise<import("./types").ReaTargetValidation> {
  return request<import("./types").ReaTargetValidation>("/api/rea/validate-target", {
    method: "POST",
    body: JSON.stringify({ target_path: targetPath })
  });
}

export async function generateReaReport(
  analysisId?: string,
  investigation?: any
): Promise<import("./types").ReaForensicReport> {
  return request<import("./types").ReaForensicReport>("/api/rea/generate-report", {
    method: "POST",
    body: JSON.stringify({ analysis_id: analysisId, investigation })
  });
}

// =============================================================================
// PERSONAL ASSISTANT API (Windows Apps, Files, WhatsApp, System Status)
// =============================================================================

export async function getApprovedApps(): Promise<{ apps: Record<string, any> }> {
  return request<{ apps: Record<string, any> }>("/api/jarvis/personal/apps");
}

export async function launchApprovedApp(appName: string): Promise<any> {
  return request<any>("/api/jarvis/personal/launch-app", {
    method: "POST",
    body: JSON.stringify({ app_name: appName })
  });
}

export async function closeApprovedApp(appName: string, force = false): Promise<any> {
  return request<any>("/api/jarvis/personal/close-app", {
    method: "POST",
    body: JSON.stringify({ app_name: appName, force })
  });
}

export async function getAuthorizedFiles(query = "", scope?: string): Promise<{
  query: string;
  total_matches: number;
  authorized_scopes: string[];
  matches: Array<{
    name: string;
    filename: string;
    relative_path: string;
    full_path: string;
    scope: string;
    is_dir: boolean;
    size_bytes: number;
    modified_at: string;
  }>;
}> {
  const params = new URLSearchParams();
  if (query) params.append("query", query);
  if (scope) params.append("scope", scope);
  return request(`/api/jarvis/personal/files?${params.toString()}`);
}

export async function openAuthorizedFile(filepath: string): Promise<any> {
  return request<any>("/api/jarvis/personal/open-file", {
    method: "POST",
    body: JSON.stringify({ filepath })
  });
}

export async function prepareWhatsAppMessage(
  recipient: string,
  message: string,
  attachmentPath?: string
): Promise<any> {
  return request<any>("/api/jarvis/personal/whatsapp", {
    method: "POST",
    body: JSON.stringify({
      recipient,
      message,
      attachment_path: attachmentPath
    })
  });
}

export async function getWindowsSystemStatus(): Promise<any> {
  return request<any>("/api/jarvis/personal/windows-status");
}

export async function openWindowsSettings(settingPage: string = "settings"): Promise<any> {
  return request<any>("/api/jarvis/personal/windows-settings", {
    method: "POST",
    body: JSON.stringify({ setting_page: settingPage })
  });
}

// Unified Local & Cloud AI Router API
export async function getAIHealth(): Promise<import("./types").AIHealthResponsePayload> {
  return request<import("./types").AIHealthResponsePayload>("/api/ai/health");
}

export async function getAIProviders(): Promise<import("./types").AIProvidersResponsePayload> {
  return request<import("./types").AIProvidersResponsePayload>("/api/ai/providers");
}

export async function sendAIChat(
  payload: import("./types").AIChatRequestPayload
): Promise<import("./types").AIChatResponsePayload> {
  return request<import("./types").AIChatResponsePayload>("/api/ai/chat", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function getDualModelStatus(mode: string = "auto"): Promise<import("./types").AIDualModelStatusPayload> {
  return request<import("./types").AIDualModelStatusPayload>(`/api/ai/status?mode=${encodeURIComponent(mode)}`);
}

export async function testLocalModel(model?: string): Promise<import("./types").AIInferenceTestResultPayload> {
  return request<import("./types").AIInferenceTestResultPayload>("/api/ai/test/local", {
    method: "POST",
    body: JSON.stringify(model ? { model } : {})
  });
}

export async function testOnlineModel(provider?: string): Promise<import("./types").AIInferenceTestResultPayload> {
  return request<import("./types").AIInferenceTestResultPayload>("/api/ai/test/online", {
    method: "POST",
    body: JSON.stringify(provider ? { provider } : {})
  });
}

export async function getOllamaHealth(): Promise<import("./types").OllamaHealthPayload> {
  return request<import("./types").OllamaHealthPayload>("/api/ai/ollama/health");
}

export async function streamAIChat(
  payload: import("./types").AIChatRequestPayload,
  onToken: (token: string) => void,
  onComplete: (data: { model?: string; total_duration_ms?: number }) => void,
  onError: (err: string) => void,
  signal?: AbortSignal
): Promise<void> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json"
  };
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  try {
    const response = await fetch(`${API_BASE}/api/ai/chat/stream`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Stream request failed with status ${response.status}`);
    }

    if (!response.body) {
      throw new Error("ReadableStream not supported by browser environment.");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith("data: ")) {
          const jsonStr = trimmed.slice(6);
          try {
            const data: import("./types").AIStreamChunkPayload = JSON.parse(jsonStr);
            if (data.token) {
              onToken(data.token);
            }
            if (data.error) {
              onError(data.error);
            }
            if (data.done) {
              onComplete({ model: data.model, total_duration_ms: data.total_duration_ms });
            }
          } catch {
            // Ignore parse errors on malformed SSE chunks
          }
        }
      }
    }
  } catch (err: any) {
    if (err.name === "AbortError") {
      onComplete({});
      return;
    }
    onError(err.message || "Failed to stream AI response");
  }
}


