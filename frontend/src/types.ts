export type Agent = {
  id: string;
  name: string;
  owner: string;
  org_id?: string;
  model: string;
  purpose: string;
  tools: string[];
  permissions?: Record<string, string[]>;
  baseline_permissions?: Record<string, string[]>;
  status: "ACTIVE" | "DISABLED" | "KILLED" | "QUARANTINED";
  risk_score: number;
  trust_score: number;
  baseline_instructions?: string;
  current_instructions?: string;
  last_activity?: string;
  version?: string;
  created_at: string;
};

export type EventItem = {
  id: number;
  agent_id: string;
  action: string;
  target: string;
  decision: "ALLOW" | "BLOCK" | "ASK_HUMAN" | "APPROVED" | "REJECTED";
  risk_score: number;
  trust_score: number;
  reason: string;
  latency_ms?: number;
  payload_sanitized?: string;
  tool_id?: string;
  approver?: string;
  created_at: string;
};

export type Approval = {
  id: number;
  agent_id: string;
  action: string;
  target: string;
  payload?: string;
  reason: string;
  risk_score: number;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
  approver?: string;
  decision_note?: string;
  created_at: string;
};

export type Incident = {
  id: number;
  incident_number: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED";
  agent_id?: string;
  summary: string;
  root_cause?: string;
  attack_vector?: string;
  evidence_json?: string;
  evidence?: Record<string, any>;
  response_playbook?: string;
  created_at: string;
  updated_at: string;
};

export type AuditRecord = {
  id: number;
  actor: string;
  action: string;
  resource: string;
  details_json: string;
  details?: Record<string, any>;
  prev_hash: string;
  current_hash: string;
  timestamp: string;
};

export type Policy = {
  id: number;
  name: string;
  description?: string;
  action: string;
  target_pattern: string;
  effect: "ALLOW" | "BLOCK" | "ASK_HUMAN" | "QUARANTINE";
  risk_threshold: number;
  priority: number;
  enabled: number;
  created_at: string;
};

export type PolicyVersion = {
  id: number;
  version: string;
  policy_yaml: string;
  author: string;
  status: "DEPLOYED" | "DRAFT" | "SUPERSEDED";
  change_summary: string;
  created_at: string;
};

export type ShadowAIDetection = {
  id: number;
  process_name: string;
  destination_ip_host: string;
  token_signature: string;
  confidence: number;
  evidence: string;
  status: "DETECTED" | "INVESTIGATING" | "REGISTERED" | "BLOCKED";
  detected_at: string;
};

export type CanaryToken = {
  id: number;
  token_type: string;
  token_value: string;
  location_tag: string;
  triggered: number;
  last_triggered_at?: string;
  trigger_details?: string;
  created_at: string;
};

export type User = {
  id: number;
  username: string;
  role: "admin" | "security_analyst" | "operator" | "auditor";
  full_name: string;
  email: string;
  created_at: string;
  active: number;
};

export type SOC_Overview = {
  total_agents: number;
  active_agents: number;
  total_events: number;
  blocked_actions: number;
  pending_approvals: number;
  high_risk_events: number;
  open_incidents: number;
  canary_trips: number;
  shadow_ai_count: number;
  system_status: string;
  zero_trust_enforcement: string;
};

export type GraphNode = {
  id: string;
  label: string;
  type?: string;
  status?: string;
  risk?: number;
  trust?: number;
};

export type GraphEdge = {
  source: string;
  target: string;
  action?: string;
  decision?: string;
  is_blocked?: boolean;
  relationship?: string;
  risk?: number;
};

export type JarvisState = "IDLE" | "LISTENING" | "PROCESSING" | "SPEAKING" | "ERROR";
export type JarvisLanguage = "en" | "hi" | "mr" | "hinglish" | "auto";

export type JarvisToolCall = {
  tool_name: string;
  arguments: Record<string, any>;
  rationale?: string;
};

export type JarvisToolResult = {
  tool_name: string;
  success: boolean;
  data: any;
  error?: string;
  execution_time_ms?: number;
};

export type JarvisConfirmationRequest = {
  action_id: string;
  action_type: string;
  target_id: string;
  target_name?: string;
  risk_level: string;
  impact_explanation: string;
  idempotency_key: string;
  created_at: string;
};

export type JarvisSecurityContext = {
  selected_agent_id?: string;
  selected_incident_id?: string | number;
  selected_alert_id?: string | number;
  current_page?: string;
  zero_trust_status?: string;
  investigation_notes?: string;
};

export type JarvisMessage = {
  id?: number | string;
  role: "user" | "assistant" | "system";
  content: string;
  speech_text?: string;
  language?: string;
  tool_calls?: JarvisToolCall[];
  tool_results?: JarvisToolResult[];
  action_required?: JarvisConfirmationRequest | null;
  navigation_target?: string | null;
  created_at: string;
  audio_confidence?: number;
  is_local_mode?: boolean;
  audio_base64?: string;
};

export type JarvisBriefing = {
  timestamp: string;
  summary: string;
  threat_level: "LOW" | "ELEVATED" | "HIGH" | "CRITICAL";
  active_agents_count: number;
  open_incidents_count: number;
  pending_approvals_count: number;
  critical_alerts: any[];
  high_risk_agents: any[];
  suspicious_activities: any[];
  recommended_actions: string[];
};

export type JarvisPreferences = {
  voice_enabled: boolean;
  default_language: JarvisLanguage;
  selected_voice?: string;
  speech_rate: number;
  speech_pitch: number;
  auto_speak_responses: boolean;
  proactive_briefings_enabled: boolean;
  sound_effects_enabled: boolean;
  local_mode?: boolean;
};

export type JarvisVoiceEngineInfo = {
  local_mode_enabled: boolean;
  asr_engine: string;
  asr_model: string;
  asr_is_local: boolean;
  asr_supported_languages: string[];
  tts_engine: string;
  tts_is_local: boolean;
  tts_voices: Array<{
    id: string;
    name: string;
    language: string;
    gender: string;
    is_local: boolean;
    engine?: string;
  }>;
};

