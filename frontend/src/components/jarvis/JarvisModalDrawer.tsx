import React, { useState, useEffect, useCallback } from "react";
import { X, Maximize2, Minimize2, Cpu, Volume2, Shield, Radio, Square } from "lucide-react";
import { JarvisOrb } from "./JarvisOrb";
import { JarvisWaveform } from "./JarvisWaveform";
import { JarvisMicButton } from "./JarvisMicButton";
import { JarvisSecurityHUD } from "./JarvisSecurityHUD";
import { JarvisChatPanel } from "./JarvisChatPanel";
import { jarvisVoice } from "./JarvisVoiceEngine";
import {
  JarvisState, JarvisLanguage, JarvisMessage, JarvisSecurityContext,
  JarvisBriefing, JarvisConfirmationRequest, JarvisPreferences
} from "../../types";
import {
  sendJarvisMessage, confirmJarvisAction, getJarvisBriefing,
  getJarvisPreferences, saveJarvisPreferences, clearJarvisHistory
} from "../../api";

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onNavigatePage: (page: string) => void;
  currentPage: string;
  selectedAgentId?: string;
  selectedIncidentId?: string | number;
}

export const JarvisModalDrawer: React.FC<Props> = ({
  isOpen,
  onClose,
  onNavigatePage,
  currentPage,
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
  const [isExpanded, setIsExpanded] = useState(false);
  const [personalityMode, setPersonalityMode] = useState<"friendly" | "security">("friendly");

  // Load preferences, permissions, and briefing on open
  useEffect(() => {
    if (!isOpen) return;

    jarvisVoice.checkMicrophonePermission().then(status => {
      setMicPermission(status);
    });

    getJarvisPreferences()
      .then(prefs => {
        setPreferences(prefs);
        setIsMuted(!prefs.voice_enabled);
        setIsMicMuted(Boolean(prefs.mic_muted));
        setIsWakeWordEnabled(Boolean(prefs.wake_word_enabled));
        setSelectedLanguage(prefs.default_language || "auto");
        jarvisVoice.setMicrophoneMuted(Boolean(prefs.mic_muted));
        jarvisVoice.setWakeWordEnabled(Boolean(prefs.wake_word_enabled));
        jarvisVoice.setSpeechSettings(
          prefs.speech_rate || 1.05,
          prefs.speech_pitch || 1.0,
          !prefs.voice_enabled,
          prefs.sound_effects_enabled !== false
        );
      })
      .catch(() => {});

    loadBriefing();
  }, [isOpen]);

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

  // Keyboard shortcut listener: Escape to close, Space to Push-to-Talk
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        jarvisVoice.stopListening();
        jarvisVoice.stopSpeaking();
        onClose();
      } else if (e.code === "Space" && !e.repeat) {
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
  }, [isOpen, onClose]);

  // Voice engine callbacks
  useEffect(() => {
    jarvisVoice.onStateChange = (state) => {
      setJarvisState(state);
      setIsListening(state === "LISTENING");
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

      const context: JarvisSecurityContext = {
        current_page: currentPage,
        selected_agent_id: selectedAgentId,
        selected_incident_id: selectedIncidentId,
        zero_trust_status: "ENFORCING"
      };

      // Add user message bubble immediately
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
        context
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
        created_at: res.created_at
      };
      setMessages(prev => [...prev, assistantMsg]);

      // Check if navigation tool was triggered
      if (res.navigation_target) {
        onNavigatePage(res.navigation_target);
      }

      // Speak response if voice output is enabled
      if (res.speech_text && !isMuted) {
        setJarvisState("SPEAKING");
        if (jarvisVoice.isSpeechSynthesisSupported()) {
          await jarvisVoice.speak(res.speech_text);
        } else if (res.audio_base64) {
          await jarvisVoice.playLocalAudioBase64(res.audio_base64);
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

  const handleConfirmAction = async (actionReq: JarvisConfirmationRequest, confirmed: boolean) => {
    try {
      setIsProcessing(true);
      const res = await confirmJarvisAction(
        actionReq.action_id,
        confirmed,
        confirmed ? "Confirmed by operator in JARVIS interface" : "Cancelled by operator",
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

  const handleStopListening = () => {
    jarvisVoice.stopListening();
  };

  const handleToggleMute = () => {
    const nextMuted = !isMuted;
    setIsMuted(nextMuted);
    if (preferences) {
      const updated = { ...preferences, voice_enabled: !nextMuted };
      setPreferences(updated);
      saveJarvisPreferences(updated).catch(() => {});
    }
    if (nextMuted) {
      jarvisVoice.stopSpeaking();
    }
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

  const handleStopSpeaking = () => {
    jarvisVoice.stopSpeaking();
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
  };

  const handleClearHistory = async () => {
    if (!window.confirm("Clear current conversation history with AMOJA AI?")) return;
    if (sessionId) {
      try {
        await clearJarvisHistory(sessionId);
      } catch {}
    }
    setMessages([]);
  };

  if (!isOpen) return null;

  return (
    <div className={`jarvis-drawer-overlay ${isExpanded ? "expanded-overlay" : ""}`}>
      <div className={`jarvis-drawer-panel ${isExpanded ? "expanded-panel" : ""}`}>
        {/* Top Cybernetic HUD Header */}
        <div className="drawer-header-bar">
          <div className="header-title-cluster">
            <div className="hologram-pulse-icon">
              <Cpu size={18} />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <h3>AMOJA AI SECURITY ASSISTANT</h3>
                <span style={{ fontSize: "10px", padding: "2px 6px", background: "rgba(16, 185, 129, 0.2)", color: "#10b981", borderRadius: "10px", border: "1px solid rgba(16, 185, 129, 0.4)", fontWeight: 600 }}>
                  FEMALE VOICE
                </span>
              </div>
              <small className="hud-subheading">Continuous Two-Way Voice • Push-to-Talk • "Hey Amoja" Wake-Word • Zero-Trust</small>
            </div>
          </div>

          <div className="header-window-controls" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            {/* Optional "Hey Amoja" Wake-Word Header Toggle */}
            <button
              type="button"
              className="btn-window-ctrl"
              onClick={handleToggleWakeWord}
              title={isWakeWordEnabled ? "Wake word active: say 'Hey Amoja' to command assistant" : "Enable 'Hey Amoja' wake-word activation"}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "5px",
                padding: "4px 8px",
                borderRadius: "4px",
                background: isWakeWordEnabled ? "rgba(56, 189, 248, 0.25)" : "rgba(255, 255, 255, 0.08)",
                border: isWakeWordEnabled ? "1px solid #38bdf8" : "1px solid rgba(255, 255, 255, 0.15)",
                color: isWakeWordEnabled ? "#38bdf8" : "#cbd5e1",
                fontSize: "11px",
                fontWeight: 600,
                cursor: "pointer"
              }}
            >
              <span>{isWakeWordEnabled ? "WAKE: HEY AMOJA" : "WAKE: OFF"}</span>
            </button>

            {/* Hands-Free Continuous Voice Toggle */}
            <button
              type="button"
              className="btn-window-ctrl"
              onClick={handleToggleContinuousVoice}
              title={isContinuousVoice ? "Hands-free continuous conversation active. Click to disable." : "Enable hands-free continuous two-way conversation mode"}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "5px",
                padding: "4px 8px",
                borderRadius: "4px",
                background: isContinuousVoice ? "rgba(16, 185, 129, 0.25)" : "rgba(255, 255, 255, 0.08)",
                border: isContinuousVoice ? "1px solid #10b981" : "1px solid rgba(255, 255, 255, 0.15)",
                color: isContinuousVoice ? "#10b981" : "#cbd5e1",
                fontSize: "11px",
                fontWeight: 600,
                cursor: "pointer"
              }}
            >
              <Radio size={13} style={{ color: isContinuousVoice ? "#10b981" : "#94a3b8" }} />
              <span>{isContinuousVoice ? "LIVE VOICE ON" : "HANDS-FREE"}</span>
            </button>

            {/* Barge-In / Interrupt Button when AMOJA is speaking */}
            {jarvisState === "SPEAKING" && (
              <button
                type="button"
                className="btn-window-ctrl"
                onClick={handleInterruptPlayback}
                title="Barge-in / Interrupt AMOJA speaking immediately"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "4px",
                  padding: "4px 8px",
                  borderRadius: "4px",
                  background: "rgba(239, 68, 68, 0.25)",
                  border: "1px solid #ef4444",
                  color: "#ef4444",
                  fontSize: "11px",
                  fontWeight: 600,
                  cursor: "pointer"
                }}
              >
                <Square size={11} fill="currentColor" />
                <span>INTERRUPT</span>
              </button>
            )}

            <button
              type="button"
              className="btn-window-ctrl"
              onClick={() => setIsExpanded(!isExpanded)}
              title={isExpanded ? "Restore panel size" : "Expand to wide view"}
              aria-label={isExpanded ? "Restore" : "Expand"}
            >
              {isExpanded ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
            </button>
            <button
              type="button"
              className="btn-window-ctrl close-ctrl"
              onClick={() => {
                jarvisVoice.stopListening();
                jarvisVoice.stopSpeaking();
                onClose();
              }}
              title="Close Assistant (Esc)"
              aria-label="Close"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Security Telemetry HUD Bar */}
        <JarvisSecurityHUD
          context={{
            current_page: currentPage,
            selected_agent_id: selectedAgentId,
            selected_incident_id: selectedIncidentId,
            zero_trust_status: "ENFORCING"
          }}
          briefing={briefing}
          onRequestBriefing={loadBriefing}
          isLoadingBriefing={isLoadingBriefing}
        />

        {/* Main Content Split: Orb & Waveform Hero Section */}
        <div className="drawer-body-grid">
          <div className="jarvis-hero-centerpiece">
            <JarvisOrb
              state={jarvisState}
              size={isExpanded ? 190 : 150}
              onClick={handleToggleListen}
              interactive={true}
            />

            <JarvisWaveform state={jarvisState} height={36} barCount={26} />

            <JarvisMicButton
              state={jarvisState}
              isListening={isListening}
              isMuted={isMuted}
              isMicMuted={isMicMuted}
              isSpeechSupported={jarvisVoice.isSpeechRecognitionSupported()}
              isWakeWordEnabled={isWakeWordEnabled}
              isPushToTalkActive={isPushToTalkActive}
              micPermissionStatus={micPermission}
              recordingDurationSeconds={recordingDuration}
              onToggleListen={handleToggleListen}
              onStopListening={handleStopListening}
              onToggleMute={handleToggleMute}
              onToggleMicMute={handleToggleMicMute}
              onToggleWakeWord={handleToggleWakeWord}
              onStartPushToTalk={handleStartPushToTalk}
              onStopPushToTalk={handleStopPushToTalk}
              onRequestMicPermission={handleRequestMicPermission}
              onStopSpeaking={handleStopSpeaking}
            />
          </div>

          {/* Interactive Chat Stream & Directive Panel */}
          <div className="jarvis-chat-stream-section">
            <JarvisChatPanel
              messages={messages}
              onSendMessage={handleUserMessage}
              onConfirmAction={handleConfirmAction}
              onClearHistory={handleClearHistory}
              selectedLanguage={selectedLanguage}
              onSelectLanguage={(lang) => {
                setSelectedLanguage(lang);
                jarvisVoice.setLanguage(lang);
              }}
              isProcessing={isProcessing}
              transcription={transcription}
              errorMessage={errorMessage}
              personalityMode={personalityMode}
              onTogglePersonalityMode={setPersonalityMode}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
