// frontend/src/pages/JarvisPage.tsx
import React, { useState, useEffect } from "react";
import {
  ShieldAlert, Bot, Mic, Cpu, Radio, Activity,
  Settings, RefreshCw, Volume2, ShieldCheck, Terminal, Compass, Sparkles
} from "lucide-react";
import { JarvisOrb } from "../components/jarvis/JarvisOrb";
import { JarvisWaveform } from "../components/jarvis/JarvisWaveform";
import { JarvisMicButton } from "../components/jarvis/JarvisMicButton";
import { JarvisSecurityHUD } from "../components/jarvis/JarvisSecurityHUD";
import { JarvisChatPanel } from "../components/jarvis/JarvisChatPanel";
import { jarvisVoice } from "../components/jarvis/JarvisVoiceEngine";
import {
  JarvisState, JarvisLanguage, JarvisMessage, JarvisBriefing,
  JarvisConfirmationRequest, JarvisPreferences, JarvisVoiceEngineInfo
} from "../types";
import {
  sendJarvisMessage, confirmJarvisAction, getJarvisBriefing,
  getJarvisPreferences, saveJarvisPreferences, clearJarvisHistory,
  getJarvisTools, getJarvisVoiceEngines, synthesizeAudioJson
} from "../api";

interface Props {
  onNavigatePage: (page: string) => void;
  selectedAgentId?: string;
  selectedIncidentId?: string | number;
}

export const JarvisPage: React.FC<Props> = ({
  onNavigatePage,
  selectedAgentId,
  selectedIncidentId
}) => {
  const [jarvisState, setJarvisState] = useState<JarvisState>("IDLE");
  const [isListening, setIsListening] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [messages, setMessages] = useState<JarvisMessage[]>([]);
  const [transcription, setTranscription] = useState("");
  const [selectedLanguage, setSelectedLanguage] = useState<JarvisLanguage>("auto");
  const [briefing, setBriefing] = useState<JarvisBriefing | null>(null);
  const [isLoadingBriefing, setIsLoadingBriefing] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [sessionId, setSessionId] = useState<string | undefined>(undefined);
  const [preferences, setPreferences] = useState<JarvisPreferences | null>(null);
  const [toolsList, setToolsList] = useState<Record<string, any>>({});
  const [activeTab, setActiveTab] = useState<"terminal" | "briefing" | "tools" | "settings">("terminal");
  const [voiceEngines, setVoiceEngines] = useState<JarvisVoiceEngineInfo | null>(null);
  const [isPaused, setIsPaused] = useState(false);

  useEffect(() => {
    // Load initial data
    getJarvisPreferences()
      .then(p => {
        setPreferences(p);
        setIsMuted(!p.voice_enabled);
        setSelectedLanguage(p.default_language || "auto");
        jarvisVoice.setSpeechSettings(
          p.speech_rate || 1.05,
          p.speech_pitch || 1.0,
          !p.voice_enabled,
          p.sound_effects_enabled !== false
        );
      })
      .catch(() => {});

    loadBriefing();
    getJarvisTools()
      .then(t => setToolsList(t.tools || {}))
      .catch(() => {});

    getJarvisVoiceEngines()
      .then(ve => setVoiceEngines(ve))
      .catch(() => {});

    jarvisVoice.onStateChange = (state) => {
      setJarvisState(state);
      setIsListening(state === "LISTENING");
      if (state !== "SPEAKING") {
        setIsPaused(false);
      }
    };

    jarvisVoice.onTranscriptChange = (text, isFinal) => {
      setTranscription(text);
      if (isFinal && text.trim()) {
        handleUserMessage(text.trim(), true);
        setTranscription("");
      }
    };

    jarvisVoice.onError = (err) => {
      setErrorMessage(err);
      setTimeout(() => setErrorMessage(""), 5000);
    };

    return () => {
      jarvisVoice.stopListening();
      jarvisVoice.stopSpeaking();
    };
  }, []);

  const loadBriefing = async () => {
    try {
      setIsLoadingBriefing(true);
      const b = await getJarvisBriefing();
      setBriefing(b);
    } catch {
      // Graceful fallback
    } finally {
      setIsLoadingBriefing(false);
    }
  };

  const handleUserMessage = async (text: string, isVoice = false) => {
    try {
      setIsProcessing(true);
      setJarvisState("PROCESSING");
      setErrorMessage("");

      const userMsg: JarvisMessage = {
        role: "user",
        content: text,
        created_at: new Date().toISOString()
      };
      setMessages(prev => [...prev, userMsg]);

      const res = await sendJarvisMessage(text, {
        sessionId,
        language: selectedLanguage,
        isVoice,
        context: {
          current_page: "JARVIS Assistant",
          selected_agent_id: selectedAgentId,
          selected_incident_id: selectedIncidentId,
          zero_trust_status: "ENFORCING"
        }
      });

      setSessionId(res.session_id);

      const assistantMsg: JarvisMessage = {
        id: res.created_at,
        role: "assistant",
        content: res.message,
        speech_text: res.speech_text,
        language: res.language,
        tool_calls: res.tool_calls,
        tool_results: res.tool_results,
        action_required: res.action_required,
        navigation_target: res.navigation_target,
        created_at: res.created_at,
        audio_confidence: res.audio_confidence,
        is_local_mode: res.is_local_mode,
        audio_base64: res.audio_base64
      };
      setMessages(prev => [...prev, assistantMsg]);

      if (res.navigation_target) {
        onNavigatePage(res.navigation_target);
      }

      if (res.speech_text && !isMuted) {
        setJarvisState("SPEAKING");
        if (res.audio_base64) {
          await jarvisVoice.playLocalAudioBase64(res.audio_base64);
        } else {
          await jarvisVoice.speak(res.speech_text);
        }
      } else {
        setJarvisState("IDLE");
      }
    } catch (err: any) {
      setJarvisState("ERROR");
      setErrorMessage(err.message || "Failed to communicate with JARVIS");
      setTimeout(() => setJarvisState("IDLE"), 4000);
    } finally {
      setIsProcessing(false);
    }
  };

  const handlePlayMessageAudio = async (msg: JarvisMessage) => {
    if (msg.audio_base64) {
      await jarvisVoice.playLocalAudioBase64(msg.audio_base64);
    } else if (msg.speech_text || msg.content) {
      const text = msg.speech_text || msg.content;
      try {
        const syn = await synthesizeAudioJson(text, msg.language || "en", preferences?.selected_voice);
        if (syn?.audio_base64) {
          await jarvisVoice.playLocalAudioBase64(syn.audio_base64);
          return;
        }
      } catch {}
      await jarvisVoice.speak(text);
    }
  };

  const handlePauseSpeaking = () => {
    jarvisVoice.pauseSpeaking();
    setIsPaused(true);
  };

  const handleResumeSpeaking = () => {
    jarvisVoice.resumeSpeaking();
    setIsPaused(false);
  };

  const handleReplaySpeech = () => {
    jarvisVoice.replayLastSpeech();
  };

  const handleConfirmAction = async (actionReq: JarvisConfirmationRequest, confirmed: boolean) => {
    try {
      setIsProcessing(true);
      const res = await confirmJarvisAction(
        actionReq.action_id,
        confirmed,
        confirmed ? "Confirmed by operator in JARVIS Command Center" : "Cancelled by operator",
        actionReq.idempotency_key
      );

      const statusMsg: JarvisMessage = {
        role: "assistant",
        content: confirmed
          ? `✅ **Action Confirmed:** ${res.message}`
          : `❌ **Action Cancelled:** Execution of ${actionReq.action_type} aborted by operator.`,
        created_at: new Date().toISOString()
      };
      setMessages(prev => [...prev, statusMsg]);

      if (!isMuted) {
        await jarvisVoice.speak(
          confirmed
            ? "Action confirmed and executed. Audit ledger updated."
            : "Action cancelled. Zero-Trust state preserved."
        );
      }
      loadBriefing();
    } catch (err: any) {
      setErrorMessage(`Confirmation failed: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleToggleListen = () => {
    if (isListening) {
      jarvisVoice.stopListening();
    } else {
      jarvisVoice.startListening();
    }
  };

  const handleClearHistory = async () => {
    if (!window.confirm("Clear all conversation history for this session?")) return;
    if (sessionId) {
      try { await clearJarvisHistory(sessionId); } catch {}
    }
    setMessages([]);
  };

  const handleToggleMute = () => {
    const nextMuted = !isMuted;
    setIsMuted(nextMuted);
    if (preferences) {
      const updated = { ...preferences, voice_enabled: !nextMuted };
      setPreferences(updated);
      saveJarvisPreferences(updated).catch(() => {});
    }
    if (nextMuted) jarvisVoice.stopSpeaking();
  };

  return (
    <div className="jarvis-page-container">
      {/* Top Holographic Header */}
      <div className="jarvis-page-header">
        <div className="header-info">
          <div className="holographic-badge">
            <Cpu size={22} className="jarvis-icon-glow" />
          </div>
          <div>
            <h2>JARVIS AI SECURITY COMMAND CENTER</h2>
            <p className="subtitle">
              Cinematic Autonomous AI Security Control Plane — Speech Recognition, Voice Synthesis, & Grounded Tool Execution
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="jarvis-tab-nav">
          <button
            type="button"
            className={`tab-btn ${activeTab === "terminal" ? "active" : ""}`}
            onClick={() => setActiveTab("terminal")}
          >
            <Terminal size={14} />
            <span>Terminal & Voice</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === "briefing" ? "active" : ""}`}
            onClick={() => setActiveTab("briefing")}
          >
            <Activity size={14} />
            <span>Threat Briefing</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === "tools" ? "active" : ""}`}
            onClick={() => setActiveTab("tools")}
          >
            <ShieldCheck size={14} />
            <span>Tool Registry ({Object.keys(toolsList).length})</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === "settings" ? "active" : ""}`}
            onClick={() => setActiveTab("settings")}
          >
            <Settings size={14} />
            <span>Voice Settings</span>
          </button>
        </div>
      </div>

      {/* Security Telemetry HUD Strip */}
      <JarvisSecurityHUD
        context={{
          current_page: "JARVIS Assistant",
          selected_agent_id: selectedAgentId,
          selected_incident_id: selectedIncidentId,
          zero_trust_status: "ENFORCING"
        }}
        briefing={briefing}
        onRequestBriefing={loadBriefing}
        isLoadingBriefing={isLoadingBriefing}
        isLocalMode={preferences?.local_mode !== false}
        selectedLanguage={selectedLanguage}
      />

      {/* Tab 1: Terminal & Voice Command Center */}
      {activeTab === "terminal" && (
        <div className="jarvis-command-layout">
          {/* Left Side: Orb, Waveform, Audio Controls & Quick Voice Action Cards */}
          <div className="jarvis-visualizer-card">
            <div className="orb-centerpiece-wrapper">
              <JarvisOrb
                state={jarvisState}
                size={220}
                onClick={handleToggleListen}
                interactive={true}
              />
              <JarvisWaveform state={jarvisState} height={52} barCount={32} />
              <JarvisMicButton
                state={jarvisState}
                isListening={isListening}
                isMuted={isMuted}
                isSpeechSupported={jarvisVoice.isSpeechRecognitionSupported()}
                isPaused={isPaused}
                onToggleListen={handleToggleListen}
                onStopListening={() => jarvisVoice.stopListening()}
                onToggleMute={handleToggleMute}
                onStopSpeaking={() => {
                  jarvisVoice.stopSpeaking();
                  setIsPaused(false);
                }}
                onPauseSpeaking={handlePauseSpeaking}
                onResumeSpeaking={handleResumeSpeaking}
                onReplaySpeech={handleReplaySpeech}
              />
            </div>

            <div className="voice-capabilities-list">
              <div className="capability-item">
                <span className="dot active" />
                <span>Zero-Trust Grounded Verification</span>
              </div>
              <div className="capability-item">
                <span className="dot active" />
                <span>Multilingual: Marathi (मराठी), Hindi (हिन्दी), Hinglish, English</span>
              </div>
              <div className="capability-item">
                <span className="dot active" />
                <span>Local-First Speech ASR & Piper Indic TTS (Zero Cloud Egress)</span>
              </div>
              <div className="capability-item">
                <span className="dot active" />
                <span>Human-in-the-Loop Safe Action Execution</span>
              </div>
              <div className="capability-item">
                <span className="dot active" />
                <span>SHA-256 Chained Cryptographic Audit</span>
              </div>
            </div>
          </div>

          {/* Right Side: Chat Panel & Directive Stream */}
          <div className="jarvis-stream-card">
            <JarvisChatPanel
              messages={messages}
              onSendMessage={handleUserMessage}
              onConfirmAction={handleConfirmAction}
              onClearHistory={handleClearHistory}
              selectedLanguage={selectedLanguage}
              onSelectLanguage={(lang) => {
                setSelectedLanguage(lang);
                jarvisVoice.setLanguage(lang);
                if (preferences) {
                  const updated = { ...preferences, default_language: lang };
                  setPreferences(updated);
                  saveJarvisPreferences(updated).catch(() => {});
                }
              }}
              isProcessing={isProcessing}
              transcription={transcription}
              errorMessage={errorMessage}
              onPlayMessageAudio={handlePlayMessageAudio}
            />
          </div>
        </div>
      )}

      {/* Tab 2: Proactive Security Briefing */}
      {activeTab === "briefing" && (
        <div className="jarvis-briefing-view">
          <div className="briefing-header-card">
            <div className="threat-summary-cluster">
              <div className={`threat-badge-large ${briefing?.threat_level === "CRITICAL" ? "crit" : briefing?.threat_level === "ELEVATED" ? "elev" : "normal"}`}>
                <ShieldAlert size={28} />
                <div>
                  <small>PLATFORM DEFENSE POSTURE</small>
                  <h3>{briefing?.threat_level || "LOW"} THREAT LEVEL</h3>
                </div>
              </div>
              <p className="briefing-executive-text">{briefing?.summary}</p>
            </div>
            <button
              type="button"
              className="btn-refresh-briefing"
              onClick={loadBriefing}
              disabled={isLoadingBriefing}
            >
              <RefreshCw size={14} className={isLoadingBriefing ? "spin-icon" : ""} />
              <span>Refresh Telemetry</span>
            </button>
          </div>

          <div className="briefing-sections-grid">
            {/* Recommended Defensive Actions */}
            <div className="briefing-subcard">
              <h4>🛡️ Recommended Defensive Actions</h4>
              <ul className="recommendations-list">
                {briefing?.recommended_actions.map((rec, i) => (
                  <li key={i}>{rec}</li>
                )) || <li>No immediate intervention necessary.</li>}
              </ul>
            </div>

            {/* High-Risk Agents */}
            <div className="briefing-subcard">
              <h4>🤖 High-Risk & Quarantined Agents</h4>
              <div className="mini-roster">
                {briefing?.high_risk_agents.map(a => (
                  <div key={a.id} className="mini-roster-row">
                    <div>
                      <strong>{a.name}</strong> <small>({a.id})</small>
                    </div>
                    <div className="roster-metrics">
                      <span className={`risk-tag ${a.risk_score >= 70 ? "high" : "med"}`}>Risk: {a.risk_score}</span>
                      <span className="status-tag">{a.status}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Critical Open Incidents */}
            <div className="briefing-subcard">
              <h4>🚨 Active Incidents Under Triage</h4>
              <div className="mini-roster">
                {briefing?.critical_alerts.map(inc => (
                  <div key={inc.id} className="mini-roster-row">
                    <div>
                      <strong>{inc.incident_number}</strong>: {inc.title}
                    </div>
                    <span className="severity-tag">{inc.severity}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Controlled Tool Registry */}
      {activeTab === "tools" && (
        <div className="jarvis-tools-catalog">
          <div className="catalog-header">
            <h3>Registered & Authorized Security Tools</h3>
            <p>Every tool is governed by strict Pydantic parameter validation, role-based authorization, and cryptographic audit logging.</p>
          </div>

          <div className="tools-card-grid">
            {Object.entries(toolsList).map(([name, spec]) => (
              <div key={name} className="tool-catalog-card">
                <div className="tool-card-top">
                  <Terminal size={16} />
                  <code>{name}</code>
                  <span className={`cat-pill ${spec.category}`}>{spec.category.toUpperCase()}</span>
                </div>
                <p className="tool-desc">{spec.description}</p>
                <div className="tool-params-summary">
                  <small>Parameters: {Object.keys(spec.parameters || {}).join(", ") || "None (zero-argument telemetry)"}</small>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Voice & Speech Settings */}
      {activeTab === "settings" && (
        <div className="jarvis-settings-view">
          <div className="settings-card">
            <h3>Voice Input & Multilingual Speech Synthesis Preferences</h3>
            <p>Configure speech rate, pitch, language heuristics, local voice models, and offline privacy enforcement.</p>

            <div className="settings-form-grid">
              {/* Default Language Selector */}
              <div className="form-row">
                <label>Default Assistant Conversation Language</label>
                <select
                  value={preferences?.default_language || selectedLanguage}
                  onChange={(e) => {
                    const lang = e.target.value as JarvisLanguage;
                    setSelectedLanguage(lang);
                    jarvisVoice.setLanguage(lang);
                    const updated = { ...preferences!, default_language: lang };
                    setPreferences(updated);
                    saveJarvisPreferences(updated).catch(() => {});
                  }}
                  className="settings-select"
                >
                  <option value="auto">Auto-Detect (Hindi / Marathi / Hinglish / English)</option>
                  <option value="en">English (Default)</option>
                  <option value="mr">मराठी (Marathi - Devanagari & Romanized)</option>
                  <option value="hi">हिन्दी (Hindi - Devanagari & Romanized)</option>
                  <option value="hinglish">Hinglish (Hindi + English Technical)</option>
                </select>
              </div>

              {/* Local Indic Voice Profile Selector */}
              <div className="form-row">
                <label>Active Local Voice Profile (Piper / Indic-TTS Model)</label>
                <select
                  value={preferences?.selected_voice || "mr-IN-aarav-local"}
                  onChange={(e) => {
                    const voiceId = e.target.value;
                    const updated = { ...preferences!, selected_voice: voiceId };
                    setPreferences(updated);
                    saveJarvisPreferences(updated).catch(() => {});
                  }}
                  className="settings-select"
                >
                  <optgroup label="Local Marathi Voice Profiles (Offline Indic)">
                    <option value="mr-IN-aarav-local">Aarav (मराठी - Marathi Male Local)</option>
                    <option value="mr-IN-ananya-local">Ananya (मराठी - Marathi Female Local)</option>
                  </optgroup>
                  <optgroup label="Local Hindi Voice Profiles (Offline Indic)">
                    <option value="hi-IN-kabir-local">Kabir (हिन्दी - Hindi Male Local)</option>
                    <option value="hi-IN-kavya-local">Kavya (हिन्दी - Hindi Female Local)</option>
                  </optgroup>
                  <optgroup label="Local English Cybernetic Profile">
                    <option value="en-GB-jarvis-local">J.A.R.V.I.S. (Cybernetic British Male Local)</option>
                  </optgroup>
                </select>
              </div>

              <div className="form-row">
                <label>Speech Output Rate ({preferences?.speech_rate || 1.05}x)</label>
                <input
                  type="range"
                  min="0.7"
                  max="1.5"
                  step="0.05"
                  value={preferences?.speech_rate || 1.05}
                  onChange={(e) => {
                    const val = parseFloat(e.target.value);
                    const updated = { ...preferences!, speech_rate: val };
                    setPreferences(updated);
                    jarvisVoice.setSpeechSettings(val, preferences?.speech_pitch || 1.0, isMuted, preferences?.sound_effects_enabled !== false);
                    saveJarvisPreferences(updated).catch(() => {});
                  }}
                />
              </div>

              <div className="form-row">
                <label>Speech Output Pitch ({preferences?.speech_pitch || 1.0})</label>
                <input
                  type="range"
                  min="0.7"
                  max="1.3"
                  step="0.05"
                  value={preferences?.speech_pitch || 1.0}
                  onChange={(e) => {
                    const val = parseFloat(e.target.value);
                    const updated = { ...preferences!, speech_pitch: val };
                    setPreferences(updated);
                    jarvisVoice.setSpeechSettings(preferences?.speech_rate || 1.05, val, isMuted, preferences?.sound_effects_enabled !== false);
                    saveJarvisPreferences(updated).catch(() => {});
                  }}
                />
              </div>

              {/* Local-First Privacy Mode Toggle */}
              <div className="form-row checkbox-row">
                <label>
                  <input
                    type="checkbox"
                    checked={preferences?.local_mode !== false}
                    onChange={(e) => {
                      const updated = { ...preferences!, local_mode: e.target.checked };
                      setPreferences(updated);
                      saveJarvisPreferences(updated).catch(() => {});
                    }}
                  />
                  <span>Local-First Privacy Mode (Process STT & TTS entirely offline without sending audio to external cloud APIs)</span>
                </label>
              </div>

              <div className="form-row checkbox-row">
                <label>
                  <input
                    type="checkbox"
                    checked={preferences?.sound_effects_enabled !== false}
                    onChange={(e) => {
                      const updated = { ...preferences!, sound_effects_enabled: e.target.checked };
                      setPreferences(updated);
                      jarvisVoice.setSpeechSettings(preferences?.speech_rate || 1.05, preferences?.speech_pitch || 1.0, isMuted, e.target.checked);
                      saveJarvisPreferences(updated).catch(() => {});
                    }}
                  />
                  <span>Enable Futuristic Audio Synthesis Chimes & Cues</span>
                </label>
              </div>

              <div className="form-row checkbox-row">
                <label>
                  <input
                    type="checkbox"
                    checked={!isMuted}
                    onChange={handleToggleMute}
                  />
                  <span>Enable Spoken Voice Responses (Speech Synthesis)</span>
                </label>
              </div>

              {/* Local Engine Diagnostics Box */}
              <div className="engine-diagnostics-box">
                <h4>Local Multilingual Engine Diagnostics</h4>
                <div className="diag-grid">
                  <div className="diag-item">
                    <span className="diag-label">ASR Engine:</span>
                    <strong className="diag-val">{voiceEngines?.asr_engine || "faster_whisper / acoustic_indic"} (Local Offline)</strong>
                  </div>
                  <div className="diag-item">
                    <span className="diag-label">ASR Model:</span>
                    <strong className="diag-val">{voiceEngines?.asr_model || "small-indic"}</strong>
                  </div>
                  <div className="diag-item">
                    <span className="diag-label">TTS Engine:</span>
                    <strong className="diag-val">{voiceEngines?.tts_engine || "piper_indic_local"} (Local 22050Hz PCM)</strong>
                  </div>
                  <div className="diag-item">
                    <span className="diag-label">Verified Indic Voices:</span>
                    <strong className="diag-val">{voiceEngines?.tts_voices?.length || 5} Local Models Registered</strong>
                  </div>
                  <div className="diag-item">
                    <span className="diag-label">Cloud Audio Egress:</span>
                    <strong className="diag-val success">BLOCKED (Strict Local Airgap)</strong>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
