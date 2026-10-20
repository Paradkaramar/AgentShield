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
  personality_mode?: "friendly" | "security";
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
  wake_word_enabled?: boolean;
  cloud_processing_consent?: boolean;
  push_to_talk_mode?: boolean;
  mic_muted?: boolean;
  personality_mode?: "friendly" | "security";
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

// --- Network Monitoring Control Plane Types ---

export type ScanJob = {
  id: string;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED" | "PAUSED";
  triggered_by: string;
  target_scope_json?: string;
  hosts_scanned: number;
  hosts_up: number;
  ports_found: number;
  changes_detected: number;
  alerts_generated: number;
  error_message?: string | null;
  started_at: string;
  completed_at?: string | null;
};

export type NetworkMonitoringStatus = {
  state: "ACTIVE" | "PAUSED" | "STOPPED" | "EMERGENCY_STOP" | "SCANNING" | "NOT_CONFIGURED";
  service_enabled: boolean;
  is_paused: boolean;
  emergency_stop: boolean;
  scan_interval_seconds: number;
  scan_duration_limit_seconds: number;
  max_concurrency: number;
  probe_timeout_seconds: number;
  last_scan_at: string | null;
  next_scan_at: string | null;
  seconds_until_next_scan: number;
  approved_scopes_count: number;
  exclusions_count: number;
  total_assets_known: number;
  reachable_assets: number;
  total_open_services: number;
  unresolved_alerts: number;
  current_job?: ScanJob | null;
  last_completed_job?: ScanJob | null;
};

export type ApprovedScope = {
  id: number;
  name: string;
  cidr_or_ip: string;
  is_approved: number;
  organization_id?: string;
  asset_tag: string;
  created_by: string;
  created_at: string;
};

export type NetworkExclusion = {
  id: number;
  scope_id?: number | null;
  ip_address: string;
  reason: string;
  created_by: string;
  created_at: string;
};

export type NetworkAsset = {
  id: string;
  ip_address: string;
  hostname?: string | null;
  mac_address?: string | null;
  status: "REACHABLE" | "OFFLINE" | "UNKNOWN";
  in_baseline: number;
  first_seen: string;
  last_seen: string;
  last_scan_job_id?: string | null;
  latency_ms?: number | null;
  open_ports_count?: number;
};

export type ServiceObservation = {
  id: number;
  asset_id: string;
  ip_address: string;
  port: number;
  protocol: string;
  service_name: string;
  banner?: string | null;
  state: "OPEN" | "CLOSED" | "FILTERED";
  is_baseline: number;
  first_observed: string;
  last_observed: string;
  last_scan_job_id?: string | null;
};

export type NetworkSecurityAlert = {
  id: number;
  scan_job_id?: string | null;
  alert_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  observed_fact: string;
  suspected_threat: string;
  target_ip: string;
  target_port?: number | null;
  evidence_json?: string;
  evidence?: Record<string, any>;
  status: "OPEN" | "ACKNOWLEDGED" | "RESOLVED";
  created_at: string;
};

export type ScanDiff = {
  newly_discovered_hosts: NetworkAsset[];
  unexpected_open_ports: ServiceObservation[];
  offline_baseline_hosts: NetworkAsset[];
  active_alerts: NetworkSecurityAlert[];
  total_discrepancies: number;
};

export type NetworkFirewallStatus = {
  layer_name: string;
  status: string;
  firewall_type: string;
  real_enforcement_capable: boolean;
  platform: string;
  diagnostics: string;
  management_ips: string[];
  ssh_port: number;
  app_ports: number[];
  postgres_port: number;
  postgres_isolated_to: string[];
  ssh_lockout_protected: boolean;
  total_network_drop_events: number;
  is_simulated_telemetry: boolean;
  notice: string;
};

export type ApplicationFirewallStatus = {
  layer_name: string;
  status: string;
  mode: "DETECTION_ONLY" | "BLOCKING";
  owasp_crs_active: boolean;
  rate_limit_rpm: number;
  max_body_bytes: number;
  trusted_proxies: string[];
  total_inspected_alerts: number;
  total_blocked_requests: number;
  reverse_proxy_modsec_compatible: boolean;
};

export type AIAgentFirewallStatus = {
  layer_name: string;
  status: string;
  mode: string;
  fail_closed_enabled: boolean;
  kill_switch_active: boolean;
  total_evaluations: number;
  total_blocked_actions: number;
  total_require_approvals: number;
  strict_schema_validation: boolean;
  prompt_injection_defense: boolean;
  outbound_dlp_checks: boolean;
};

export type UnifiedFirewallStatusResponse = {
  timestamp: string;
  layers: {
    layer1_network: NetworkFirewallStatus;
    layer2_application: ApplicationFirewallStatus;
    layer3_ai_agent: AIAgentFirewallStatus;
  };
};

export type NetworkRulesetPreview = {
  firewall_type: string;
  status: string;
  host_platform: string;
  real_enforcement_capable: boolean;
  nftables_conf: string;
  ufw_script: string;
  rollback_script: string;
  safety_checks: {
    operator_lockout_safe: boolean;
    postgres_public_exposure_blocked: boolean;
    ssh_port: number;
    management_cidrs_count: number;
    message: string;
  };
};

export type WAFEvent = {
  id: number;
  client_ip: string;
  method: string;
  path: string;
  rule_category: string;
  action_taken: string;
  matched_pattern: string;
  request_id: string;
  redacted_details: string;
  timestamp: string;
};

export type NetworkDropEvent = {
  id: number;
  source_ip: string;
  dest_port: number;
  protocol: string;
  action: string;
  rule_matched: string;
  is_simulated: number;
  timestamp: string;
};

export type AIFirewallEvent = {
  id: number;
  agent_id: string;
  user_id: string;
  tool_name: string;
  decision: "ALLOW" | "BLOCK" | "REQUIRE_HUMAN_APPROVAL";
  risk_score: number;
  risk_level: string;
  reason: string;
  prompt_injection_signal: number;
  dlp_violation: number;
  is_fail_closed: number;
  sanitized_args: string;
  timestamp: string;
};

export type EnrolledDevice = {
  id: string;
  device_name: string;
  hostname: string;
  os_type: "windows" | "linux" | "darwin" | string;
  os_release: string;
  os_version: string;
  agent_version: string;
  enrolled_at: string;
  last_heartbeat: string;
  monitoring_status: "ACTIVE" | "PAUSED" | "DISCONNECTED" | "REVOKED";
  is_revoked: number;
  revocation_reason?: string;
  ip_address?: string;
  mac_address?: string;
  cpu_cores: number;
  total_memory_mb: number;
  open_alerts_count?: number;
  firewall_enabled?: boolean;
  firewall_type?: string;
  is_online?: boolean;
};

export type DeviceConsentRecord = {
  id: number;
  device_id: string;
  permission_key: string;
  display_name: string;
  description: string;
  is_mandatory: number;
  granted: number;
  requires_admin: number;
  updated_at: string;
  consent_signature?: string;
};

export type DeviceProcess = {
  id: number;
  device_id: string;
  pid: number;
  name: string;
  username?: string;
  exe_path?: string;
  cmdline?: string;
  cpu_percent: number;
  memory_mb: number;
  is_suspicious: number;
  suspicious_reason?: string;
  fact_classification: "observed_fact" | "heuristic_flag" | "confirmed_threat";
  observed_at: string;
};

export type DeviceConnection = {
  id: number;
  device_id: string;
  local_ip: string;
  local_port: number;
  remote_ip?: string;
  remote_port?: number;
  protocol: string;
  status: string;
  pid?: number;
  process_name?: string;
  is_suspicious: number;
  suspicious_reason?: string;
  fact_classification: "observed_fact" | "heuristic_flag" | "confirmed_threat";
  observed_at: string;
};

export type DeviceListeningPort = {
  id: number;
  device_id: string;
  port: number;
  protocol: string;
  bind_address: string;
  pid?: number;
  service_name?: string;
  is_unexpected: number;
  observed_at: string;
};

export type DeviceFirewallStatus = {
  id: number;
  device_id: string;
  os_firewall_type: string;
  is_enabled: number;
  profile_statuses_json?: string;
  profile_statuses?: Record<string, string>;
  default_inbound: string;
  default_outbound: string;
  active_rules_count: number;
  last_inspected: string;
  raw_summary?: string;
};

export type DeviceSecurityAlert = {
  id: number;
  device_id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: string;
  title: string;
  description: string;
  evidence_json?: string;
  evidence?: Record<string, any>;
  classification: "observed_fact" | "heuristic_flag" | "confirmed_threat";
  status: "OPEN" | "ACKNOWLEDGED" | "RESOLVED";
  suggested_action?: string;
  created_at: string;
};

export type EnrollmentToken = {
  token: string;
  created_by: string;
  expires_at: string;
  used: number;
  used_by_device_id?: string;
  created_at: string;
};

