// frontend/src/components/jarvis/JarvisModalDrawer.tsx
import React, { useState, useEffect, useCallback } from "react";
import { X, Maximize2, Minimize2, Cpu, Volume2, Shield } from "lucide-react";
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

  // Load preferences and briefing on open
  useEffect(() => {
    if (!isOpen) return;

    getJarvisPreferences()
      .then(prefs => {
        setPreferences(prefs);
        setIsMuted(!prefs.voice_enabled);
        setSelectedLanguage(prefs.default_language || "auto");
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

  // Keyboard shortcut listener: Escape to close
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        jarvisVoice.stopListening();
        jarvisVoice.stopSpeaking();
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
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
        await jarvisVoice.speak(res.speech_text);
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

  const handleStopSpeaking = () => {
    jarvisVoice.stopSpeaking();
  };

  const handleClearHistory = async () => {
    if (!window.confirm("Clear current conversation history with JARVIS?")) return;
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
              <h3>JARVIS AI SECURITY ASSISTANT</h3>
              <small className="hud-subheading">Cinematic Zero-Trust Autonomous Control</small>
            </div>
          </div>

          <div className="header-window-controls">
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
              isSpeechSupported={jarvisVoice.isSpeechRecognitionSupported()}
              onToggleListen={handleToggleListen}
              onStopListening={handleStopListening}
              onToggleMute={handleToggleMute}
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
            />
          </div>
        </div>
      </div>
    </div>
  );
};
