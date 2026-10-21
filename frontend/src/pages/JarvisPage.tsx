import React, { useState, useEffect } from "react";
import {
  ShieldAlert, Bot, Mic, Cpu, Radio, Activity,
  Settings, RefreshCw, Volume2, ShieldCheck, Terminal, Compass, Sparkles, Square,
  Home, MessageSquare, Wrench, Shield, CheckSquare, Brain
} from "lucide-react";
import { JarvisOrb } from "../components/jarvis/JarvisOrb";
import { JarvisWaveform } from "../components/jarvis/JarvisWaveform";
import { JarvisMicButton } from "../components/jarvis/JarvisMicButton";
import { JarvisSecurityHUD } from "../components/jarvis/JarvisSecurityHUD";
import { JarvisChatPanel } from "../components/jarvis/JarvisChatPanel";
import { JarvisVoiceDiagnosticsPanel } from "../components/jarvis/JarvisVoiceDiagnosticsPanel";
import { JarvisMemoryPanel } from "../components/jarvis/JarvisMemoryPanel";
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

export type JarvisTab = "home" | "chat" | "memory" | "tools" | "agentshield" | "settings";

interface Props {
  onNavigatePage: (page: string) => void;
  selectedAgentId?: string;
  selectedIncidentId?: string | number;
}

export const JarvisPage: React.FC<Props> = ({
  onNavigatePage,
  selectedAgentId,
  selectedIncidentId,
}) => {
  const [jarvisState, setJarvisState] = useState<JarvisState>("IDLE");
  const [isListening, setIsListening] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [isMicMuted, setIsMicMuted] = useState(false);
  const [isContinuousVoice, setIsContinuousVoice] = useState(false);
  const [isWakeWordEnabled, setIsWakeWordEnabled] = useState(false);
  const [isPushToTalkActive, setIsPushToTalkActive] = useState(false);
  const [micPermission, setMicPermission] = useState<"granted" | "denied" | "prompt" | "unsupported">("prompt");
  const [recordingDuration, setRecordingDuration] = useState(0);
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
  const [activeTab, setActiveTab] = useState<JarvisTab>("home");
  const [voiceEngines, setVoiceEngines] = useState<JarvisVoiceEngineInfo | null>(null);
  const [isPaused, setIsPaused] = useState(false);
  const [personalityMode, setPersonalityMode] = useState<"friendly" | "security">("friendly");
  const [lastFailedQuery, setLastFailedQuery] = useState<{ text: string; isVoice: boolean } | null>(null);
  const isTurnInFlightRef = React.useRef(false);


  useEffect(() => {
    // Check mic permission
    jarvisVoice.checkMicrophonePermission().then(status => {
      setMicPermission(status);
    });

    // Load initial data
    getJarvisPreferences()
      .then(p => {
        setPreferences(p);
        setIsMuted(!p.voice_enabled);
        setIsMicMuted(Boolean(p.mic_muted));
        setIsWakeWordEnabled(Boolean(p.wake_word_enabled));
        setSelectedLanguage(p.default_language || "auto");
        jarvisVoice.setMicrophoneMuted(Boolean(p.mic_muted));
        jarvisVoice.setWakeWordEnabled(Boolean(p.wake_word_enabled));
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

    jarvisVoice.onWakeWordDetected = (phrase) => {
      setErrorMessage(`Wake word detected: "${phrase}". AMOJA listening...`);
      setTimeout(() => setErrorMessage(""), 3500);
    };

    jarvisVoice.onPermissionStatusChange = (status) => {
      setMicPermission(status);
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

  // Recording elapsed timer effect
  useEffect(() => {
    if (!isListening) {
      setRecordingDuration(0);
      return;
    }
    const interval = setInterval(() => {
      setRecordingDuration(jarvisVoice.getRecordingDurationSeconds());
    }, 500);
    return () => clearInterval(interval);
  }, [isListening]);

  // Spacebar Push-to-Talk & Escape Interruption keyboard listeners
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        handleInterruptPlayback();
        return;
      }
      if (e.code === "Space" && !e.repeat) {
        const activeTag = (document.activeElement?.tagName || "").toLowerCase();
        if (activeTag !== "input" && activeTag !== "textarea") {
          e.preventDefault();
          setIsPushToTalkActive(true);
          jarvisVoice.startPushToTalk();
        }
      }
    };

    const handleKeyUp = (e: KeyboardEvent) => {
      if (e.code === "Space") {
        const activeTag = (document.activeElement?.tagName || "").toLowerCase();
        if (activeTag !== "input" && activeTag !== "textarea") {
          e.preventDefault();
          setIsPushToTalkActive(false);
          jarvisVoice.stopPushToTalk();
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("keyup", handleKeyUp);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("keyup", handleKeyUp);
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
    if (!text.trim() || isTurnInFlightRef.current) return;
    isTurnInFlightRef.current = true;
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
        personalityMode,
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

      // Automatically configure voice engine locale to match the detected language
      if (res.language && selectedLanguage === "auto") {
        jarvisVoice.setLanguage(res.language);
      }

      if ((res.audio_base64 || res.speech_text) && !isMuted) {
        setJarvisState("SPEAKING");
        // CRITICAL ROOT-CAUSE FIX: Prioritize backend neural WAV (audio_base64) over browser speechSynthesis
        // Windows WebSpeech lacks Marathi/Hindi voices and frequently stalls.
        let audioPlayed = false;
        if (res.audio_base64) {
          try {
            await jarvisVoice.playLocalAudioBase64(res.audio_base64);
            audioPlayed = true;
          } catch (playbackErr) {
            console.warn("Backend audio_base64 playback failed, falling back to speech synthesis:", playbackErr);
          }
        }
        if (!audioPlayed && res.speech_text) {
          try {
            await jarvisVoice.speak(res.speech_text, res.language);
          } catch (speakErr) {
            console.warn("Speech synthesis fallback failed:", speakErr);
          }
        }
        setJarvisState("IDLE");
      } else {
        setJarvisState("IDLE");
      }
    } catch (err: any) {
      setJarvisState("ERROR");
      setLastFailedQuery({ text, isVoice });
      let clearMsg = err.message || "Failed to communicate with AMOJA AI";
      if (clearMsg.includes("Failed to fetch") || clearMsg.includes("NetworkError") || clearMsg.includes("Network request failed")) {
        clearMsg = "Cannot connect to AMOJA backend service (http://127.0.0.1:8000). Please ensure the backend is running.";
      }
      setErrorMessage(clearMsg);
      setTimeout(() => setJarvisState("IDLE"), 5000);
    } finally {
      setIsProcessing(false);
      isTurnInFlightRef.current = false;
    }
  };

  const handleRetryLastMessage = () => {
    if (lastFailedQuery) {
      const q = lastFailedQuery;
      setLastFailedQuery(null);
      handleUserMessage(q.text, q.isVoice);
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
      await jarvisVoice.speak(text, msg.language);
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

  const handleToggleMicMute = () => {
    const nextVal = !isMicMuted;
    setIsMicMuted(nextVal);
    jarvisVoice.setMicrophoneMuted(nextVal);
    if (preferences) {
      const updated = { ...preferences, mic_muted: nextVal };
      setPreferences(updated);
      saveJarvisPreferences(updated).catch(() => {});
    }
  };

  const handleToggleWakeWord = () => {
    const nextVal = !isWakeWordEnabled;
    setIsWakeWordEnabled(nextVal);
    jarvisVoice.setWakeWordEnabled(nextVal);
    if (preferences) {
      const updated = { ...preferences, wake_word_enabled: nextVal };
      setPreferences(updated);
      saveJarvisPreferences(updated).catch(() => {});
    }
  };

  const handleStartPushToTalk = () => {
    setIsPushToTalkActive(true);
    jarvisVoice.startPushToTalk();
  };

  const handleStopPushToTalk = () => {
    setIsPushToTalkActive(false);
    jarvisVoice.stopPushToTalk();
  };

  const handleRequestMicPermission = async () => {
    const granted = await jarvisVoice.requestMicrophonePermission();
    setMicPermission(granted ? "granted" : "denied");
  };

  const handleToggleContinuousVoice = () => {
    const nextVal = !isContinuousVoice;
    setIsContinuousVoice(nextVal);
    jarvisVoice.setContinuousMode(nextVal);
    if (nextVal && jarvisState === "IDLE") {
      jarvisVoice.startListening();
    }
  };

  const handleInterruptPlayback = () => {
    jarvisVoice.interruptPlayback();
    setJarvisState("IDLE");
    setIsPaused(false);
  };

  return (
    <div className="jarvis-page-container">
      {/* Top Holographic Header */}
      <div className="jarvis-page-header">
        <div className="header-info">
          <div className="holographic-badge">
            <Cpu size={22} className="jarvis-icon-glow" style={{ color: "#76b900" }} />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <h2>AMOJA AI // SECURITY COMMAND CENTER</h2>
              <span style={{ fontSize: "10px", padding: "3px 8px", background: "rgba(118, 185, 0, 0.2)", color: "#76b900", borderRadius: "4px", border: "1px solid rgba(118, 185, 0, 0.4)", fontWeight: 700, letterSpacing: "0.5px" }}>
                DGX ACCELERATED
              </span>
              <span style={{ fontSize: "10px", padding: "3px 8px", background: "rgba(0, 255, 136, 0.15)", color: "#00ff88", borderRadius: "4px", border: "1px solid rgba(0, 255, 136, 0.35)", fontWeight: 700 }}>
                FEMALE JARVIS
              </span>
            </div>
            <p className="subtitle">
              // NVIDIA AI ARCHITECTURE // Autonomous Cybersecurity Defense — Two-Way Continuous Voice, Barge-In Interruption, & Multilingual Grounded Execution
            </p>
          </div>
        </div>

        {/* Tab Navigation & Live Voice Controls */}
        <div className="jarvis-tab-nav" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {/* Personality Mode Toggle */}
          <button
            type="button"
            className="tab-btn"
            onClick={() => setPersonalityMode(m => m === "friendly" ? "security" : "friendly")}
            title={`Assistant Personality: ${personalityMode === "friendly" ? "Friendly Companion (Warm & Engaging)" : "SOC Security Analyst (Crisp & Direct)"}`}
            style={{
              borderColor: personalityMode === "friendly" ? "#76b900" : "#00ff88",
              color: personalityMode === "friendly" ? "#76b900" : "#00ff88",
              background: personalityMode === "friendly" ? "rgba(118, 185, 0, 0.18)" : "rgba(0, 255, 136, 0.15)",
              fontWeight: 700
            }}
          >
            <span>{personalityMode === "friendly" ? "🌱 MODE: FRIENDLY" : "🛡️ MODE: SECURITY"}</span>
          </button>

          {/* Optional Wake Word Header Toggle */}
          <button
            type="button"
            className={`tab-btn ${isWakeWordEnabled ? "active" : ""}`}
            onClick={handleToggleWakeWord}
            title={isWakeWordEnabled ? "Wake word active: say 'Hey Amoja' to command assistant" : "Enable 'Hey Amoja' wake-word activation"}
            style={{
              borderColor: isWakeWordEnabled ? "#76b900" : undefined,
              color: isWakeWordEnabled ? "#76b900" : undefined,
              background: isWakeWordEnabled ? "rgba(118, 185, 0, 0.2)" : undefined
            }}
          >
            <span>{isWakeWordEnabled ? "WAKE: HEY AMOJA" : "WAKE: OFF"}</span>
          </button>

          {/* Hands-Free Continuous Voice Toggle */}
          <button
            type="button"
            className={`tab-btn ${isContinuousVoice ? "active" : ""}`}
            onClick={handleToggleContinuousVoice}
            title={isContinuousVoice ? "Hands-free continuous conversation active. Click to disable." : "Enable hands-free continuous two-way conversation mode"}
            style={{
              borderColor: isContinuousVoice ? "#00ff88" : undefined,
              color: isContinuousVoice ? "#00ff88" : undefined,
              background: isContinuousVoice ? "rgba(0, 255, 136, 0.18)" : undefined
            }}
          >
            <Radio size={14} style={{ color: isContinuousVoice ? "#00ff88" : undefined }} />
            <span>{isContinuousVoice ? "LIVE VOICE ON" : "HANDS-FREE"}</span>
          </button>

          {/* Barge-In / Interrupt Button when AMOJA is speaking */}
          {jarvisState === "SPEAKING" && (
            <button
              type="button"
              className="tab-btn"
              onClick={handleInterruptPlayback}
              title="Barge-in / Interrupt AMOJA speaking immediately"
              style={{
                borderColor: "#ef4444",
                color: "#ef4444",
                background: "rgba(239, 68, 68, 0.2)"
              }}
            >
              <Square size={12} fill="currentColor" />
              <span>INTERRUPT</span>
            </button>
          )}

          {/* 6 Organized Views: Home, Chat, Memory, Tools, AgentShield, Settings */}
          <button
            type="button"
            className={`tab-btn ${activeTab === "home" ? "active" : ""}`}
            onClick={() => setActiveTab("home")}
          >
            <Sparkles size={14} />
            <span>Home</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === "chat" ? "active" : ""}`}
            onClick={() => setActiveTab("chat")}
          >
            <MessageSquare size={14} />
            <span>Chat ({messages.length})</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === "memory" ? "active" : ""}`}
            onClick={() => setActiveTab("memory")}
          >
            <Brain size={14} />
            <span>Memory</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === "tools" ? "active" : ""}`}
            onClick={() => setActiveTab("tools")}
          >
            <ShieldCheck size={14} />
            <span>Tools ({Object.keys(toolsList).length})</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === "agentshield" ? "active" : ""}`}
            onClick={() => setActiveTab("agentshield")}
          >
            <Activity size={14} />
            <span>AgentShield</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === "settings" ? "active" : ""}`}
            onClick={() => setActiveTab("settings")}
          >
            <Settings size={14} />
            <span>Settings</span>
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

      {/* View 1: Home Command Center & Assistant Orb */}
      {activeTab === "home" && (
        <div className="jarvis-home-overview">
          {/* Real-time Provider & Privacy Status Strip */}
          <div className="jarvis-provider-status-strip">
            <div className="provider-status-pill">
              <span className="indicator-dot" />
              <span>Local Indic Whisper (ASR): <strong>ONLINE (On-Device)</strong></span>
            </div>
            <div className="provider-status-pill">
              <span className="indicator-dot" />
              <span>Piper Indic TTS: <strong>ONLINE (22.05kHz PCM)</strong></span>
            </div>
            <div className="provider-status-pill">
              <span className="indicator-dot" />
              <span>AgentShield Zero-Trust: <strong>ENFORCING</strong></span>
            </div>
            <div className="provider-status-pill">
              <span className={`indicator-dot ${preferences?.cloud_processing_consent ? "standby" : ""}`} />
              <span>Cloud Egress: <strong>{preferences?.cloud_processing_consent ? "CONSENT GRANTED" : "BLOCKED (Local Airgap)"}</strong></span>
            </div>
          </div>

          <div className="jarvis-command-layout">
            {/* Centerpiece Orb & Live Waveform Visualizer */}
            <div className="jarvis-visualizer-card">
              <div className="orb-centerpiece-wrapper">
                <JarvisOrb
                  state={jarvisState}
                  size={220}
                  onClick={handleToggleListen}
                  interactive={true}
                />
                <div style={{ marginTop: "12px", textAlign: "center" }}>
                  <span style={{
                    fontSize: "12px",
                    fontWeight: 700,
                    letterSpacing: "0.8px",
                    textTransform: "uppercase",
                    color: jarvisState === "SPEAKING" ? "#76b900" : jarvisState === "LISTENING" ? "#00ff88" : jarvisState === "PROCESSING" ? "#00e5ff" : "#94a3b8"
                  }}>
                    {jarvisState === "LISTENING" ? "Listening to Voice Input..." :
                     jarvisState === "PROCESSING" ? "Analyzing Security Directive..." :
                     jarvisState === "SPEAKING" ? "Speaking Response..." : "Awaiting Directive"}
                  </span>
                </div>
                <JarvisWaveform state={jarvisState} height={52} barCount={32} />
                <JarvisMicButton
                  state={jarvisState}
                  isListening={isListening}
                  isMuted={isMuted}
                  isMicMuted={isMicMuted}
                  isSpeechSupported={jarvisVoice.isSpeechRecognitionSupported()}
                  isPaused={isPaused}
                  isWakeWordEnabled={isWakeWordEnabled}
                  isPushToTalkActive={isPushToTalkActive}
                  micPermissionStatus={micPermission}
                  recordingDurationSeconds={recordingDuration}
                  onToggleListen={handleToggleListen}
                  onStopListening={() => jarvisVoice.stopListening()}
                  onToggleMute={handleToggleMute}
                  onToggleMicMute={handleToggleMicMute}
                  onToggleWakeWord={handleToggleWakeWord}
                  onStartPushToTalk={handleStartPushToTalk}
                  onStopPushToTalk={handleStopPushToTalk}
                  onRequestMicPermission={handleRequestMicPermission}
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
                  <span>Multilingual: Hindi (हिन्दी), Marathi (मराठी), Hinglish, English</span>
                </div>
                <div className="capability-item">
                  <span className="dot active" />
                  <span>Local-First Speech ASR & Piper Indic TTS (Zero Cloud Audio Egress)</span>
                </div>
                <div className="capability-item">
                  <span className="dot active" />
                  <span>Zero-Trust Grounded Verification & Confirmation Required for Actions</span>
                </div>
                <div className="capability-item">
                  <span className="dot active" />
                  <span>SHA-256 Chained Cryptographic Security Audit Logs</span>
                </div>
              </div>
            </div>

            {/* Quick Action Tiles & Overview */}
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <div className="home-quick-actions-grid">
                <div className="home-action-tile" onClick={() => setActiveTab("chat")}>
                  <div className="tile-icon-box"><MessageSquare size={20} /></div>
                  <div className="tile-text">
                    <strong>Direct Chat & Transcript</strong>
                    <small>Open multi-turn conversation and text dialogue</small>
                  </div>
                </div>

                <div className="home-action-tile" onClick={() => setActiveTab("memory")}>
                  <div className="tile-icon-box"><Brain size={20} /></div>
                  <div className="tile-text">
                    <strong>Personal Memory Hub</strong>
                    <small>Reminders, notes, to-dos, and search history</small>
                  </div>
                </div>

                <div className="home-action-tile" onClick={() => setActiveTab("tools")}>
                  <div className="tile-icon-box"><ShieldCheck size={20} /></div>
                  <div className="tile-text">
                    <strong>Tool Registry ({Object.keys(toolsList).length})</strong>
                    <small>View approved security, personal & OSINT tools</small>
                  </div>
                </div>

                <div className="home-action-tile" onClick={() => setActiveTab("agentshield")}>
                  <div className="tile-icon-box"><Activity size={20} /></div>
                  <div className="tile-text">
                    <strong>AgentShield SOC</strong>
                    <small>Threat briefing, quarantined agents, triage</small>
                  </div>
                </div>

                <div className="home-action-tile" onClick={() => handleUserMessage("Launch calculator")}>
                  <div className="tile-icon-box"><Sparkles size={20} /></div>
                  <div className="tile-text">
                    <strong>Launch Calculator</strong>
                    <small>Quick test approved desktop application</small>
                  </div>
                </div>

                <div className="home-action-tile" onClick={() => setActiveTab("settings")}>
                  <div className="tile-icon-box"><Settings size={20} /></div>
                  <div className="tile-text">
                    <strong>Voice Diagnostics</strong>
                    <small>Real-time audio hardware & latency test</small>
                  </div>
                </div>
              </div>

              {/* Mini Recent Messages Stream */}
              <div className="jarvis-visualizer-card" style={{ flex: 1, padding: "16px", minHeight: "220px", justifyContent: "flex-start" }}>
                <div style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
                  <strong style={{ fontSize: "13px", color: "#fff" }}>Recent Conversation Stream</strong>
                  <button type="button" className="tab-btn" onClick={() => setActiveTab("chat")} style={{ padding: "4px 8px", fontSize: "11px" }}>
                    View All ({messages.length}) →
                  </button>
                </div>
                {messages.length === 0 ? (
                  <p style={{ color: "var(--text-dim)", fontSize: "12px", fontStyle: "italic", margin: "auto" }}>
                    No recent dialogue. Click the microphone orb or press space to give a command in Hindi, Marathi, Hinglish, or English.
                  </p>
                ) : (
                  <div style={{ width: "100%", display: "flex", flexDirection: "column", gap: "8px", overflowY: "auto", maxHeight: "200px" }}>
                    {messages.slice(-3).map((m, i) => (
                      <div key={i} style={{
                        padding: "8px 12px",
                        background: m.role === "user" ? "rgba(0, 229, 255, 0.08)" : "rgba(118, 185, 0, 0.08)",
                        border: `1px solid ${m.role === "user" ? "rgba(0, 229, 255, 0.2)" : "rgba(118, 185, 0, 0.2)"}`,
                        borderRadius: "6px",
                        fontSize: "12px"
                      }}>
                        <strong style={{ color: m.role === "user" ? "#00e5ff" : "#76b900", marginRight: "6px" }}>
                          {m.role === "user" ? "You" : "AMOJA"}:
                        </strong>
                        <span style={{ color: "#e2e8f0" }}>{m.content}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* View 2: Dedicated Chat & Directive Stream */}
      {activeTab === "chat" && (
        <div className="jarvis-stream-card" style={{ minHeight: "680px" }}>
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
            personalityMode={personalityMode}
            onTogglePersonalityMode={setPersonalityMode}
            onRetry={lastFailedQuery ? handleRetryLastMessage : undefined}
            isSpeaking={jarvisState === "SPEAKING"}
            onStopSpeaking={handleInterruptPlayback}
          />
        </div>
      )}

      {/* View 3: Personal Assistant Memory, Notes, Reminders & Searchable History */}
      {activeTab === "memory" && (
        <JarvisMemoryPanel />
      )}

      {/* View 5: AgentShield SOC Telemetry & Threat Briefing */}
      {activeTab === "agentshield" && (
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
                <label>Active Voice Profile (AMOJA Female Defense & Multilingual Models)</label>
                <select
                  value={preferences?.selected_voice || "en-US-amoja-female"}
                  onChange={(e) => {
                    const voiceId = e.target.value;
                    const updated = { ...preferences!, selected_voice: voiceId };
                    setPreferences(updated);
                    saveJarvisPreferences(updated).catch(() => {});
                  }}
                  className="settings-select"
                >
                  <optgroup label="AMOJA AI Autonomous Defense Female Profiles (Recommended)">
                    <option value="en-US-amoja-female">AMOJA AI (English Female - Autonomous Defense)</option>
                    <option value="hi-IN-amoja-female">AMOJA AI (हिन्दी - Hindi Female Defense)</option>
                    <option value="mr-IN-amoja-female">AMOJA AI (मराठी - Marathi Female Defense)</option>
                  </optgroup>
                  <optgroup label="Marathi Voice Profiles (मराठी)">
                    <option value="mr-IN-ananya-local">Ananya (मराठी - Marathi Female Local)</option>
                    <option value="mr-IN-aarav-local">Aarav (मराठी - Marathi Male Local)</option>
                  </optgroup>
                  <optgroup label="Hindi Voice Profiles (हिन्दी)">
                    <option value="hi-IN-kavya-local">Kavya (हिन्दी - Hindi Female Local)</option>
                    <option value="hi-IN-kabir-local">Kabir (हिन्दी - Hindi Male Local)</option>
                  </optgroup>
                  <optgroup label="English Voice Profiles">
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

              {/* Wake-Word Activation ("Hey Amoja") */}
              <div className="form-row checkbox-row">
                <label>
                  <input
                    type="checkbox"
                    checked={isWakeWordEnabled}
                    onChange={handleToggleWakeWord}
                  />
                  <span>Enable 'Hey Amoja' Wake-Word Activation (Continuously listens for "Hey Amoja" to trigger voice interaction)</span>
                </label>
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

              {/* Cloud Processing Consent Toggle */}
              <div className="form-row checkbox-row">
                <label>
                  <input
                    type="checkbox"
                    checked={Boolean(preferences?.cloud_processing_consent)}
                    onChange={(e) => {
                      const updated = { ...preferences!, cloud_processing_consent: e.target.checked };
                      setPreferences(updated);
                      saveJarvisPreferences(updated).catch(() => {});
                    }}
                  />
                  <span>Cloud Audio Processing Consent (Allow external cloud ASR/TTS when enabled; unchecked enforces strict local airgap)</span>
                </label>
              </div>

              {/* Hardware Microphone Mute Toggle */}
              <div className="form-row checkbox-row">
                <label>
                  <input
                    type="checkbox"
                    checked={isMicMuted}
                    onChange={handleToggleMicMute}
                  />
                  <span>Hardware Microphone Input Muted (Disables all voice recognition and wake-word listening)</span>
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

              {/* Embedded Live Diagnostics in Settings */}
              <div style={{ marginTop: "24px" }}>
                <h4 style={{ color: "#fff", marginBottom: "12px", fontSize: "14px" }}>Voice Pipeline Self-Diagnostics</h4>
                <JarvisVoiceDiagnosticsPanel
                  conversationState={jarvisState}
                  currentTranscript={transcription}
                  errorMessage={errorMessage}
                  onRetryConnection={loadBriefing}
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

