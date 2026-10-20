// frontend/src/components/jarvis/JarvisChatPanel.tsx
import React, { useState, useRef, useEffect } from "react";
import {
  Send, Bot, User as UserIcon, ShieldAlert, CheckCircle2, XCircle,
  Terminal, Globe, Trash2, Mic, AlertCircle, ChevronDown, ChevronUp, Copy, Check,
  Volume2, Play, Pause, Download
} from "lucide-react";
import { JarvisMessage, JarvisLanguage, JarvisConfirmationRequest } from "../../types";

interface Props {
  messages: JarvisMessage[];
  onSendMessage: (text: string, isVoice?: boolean) => void;
  onConfirmAction: (actionReq: JarvisConfirmationRequest, confirmed: boolean) => void;
  onClearHistory: () => void;
  selectedLanguage: JarvisLanguage;
  onSelectLanguage: (lang: JarvisLanguage) => void;
  isProcessing: boolean;
  transcription?: string;
  errorMessage?: string;
  onPlayMessageAudio?: (m: JarvisMessage) => void;
  personalityMode?: "friendly" | "security";
  onTogglePersonalityMode?: (mode: "friendly" | "security") => void;
}

export const JarvisChatPanel: React.FC<Props> = ({
  messages,
  onSendMessage,
  onConfirmAction,
  onClearHistory,
  selectedLanguage,
  onSelectLanguage,
  isProcessing,
  transcription,
  errorMessage,
  onPlayMessageAudio,
  personalityMode = "friendly",
  onTogglePersonalityMode
}) => {
  const [inputText, setInputText] = useState("");
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, transcription, isProcessing]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || isProcessing) return;
    onSendMessage(inputText.trim(), false);
    setInputText("");
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportTranscript = () => {
    if (messages.length === 0) return;
    const header = `# AgentShield — AMOJA AI Conversation Transcript\nExported: ${new Date().toISOString()}\nZero-Trust Status: ENFORCING\nTotal Turns: ${messages.length}\n\n---\n\n`;
    const body = messages.map(m => {
      const role = m.role === "assistant" ? "AMOJA AI (Autonomous Defense)" : "Operator";
      const time = m.created_at ? new Date(m.created_at).toLocaleTimeString() : "";
      const tools = m.tool_calls && m.tool_calls.length > 0 ? `\n*Tools Executed:* ${m.tool_calls.map(tc => `\`${tc.tool_name}\``).join(", ")}` : "";
      return `### [${time}] ${role}\n${m.content}${tools}\n`;
    }).join("\n---\n\n");
    const blob = new Blob([header + body], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `amoja_conversation_transcript_${new Date().toISOString().slice(0, 19).replace(/[:.]/g, "-")}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleToolExpand = (key: string) => {
    setExpandedTools(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const quickPrompts = [
    { label: "Security Summary", text: "Give me the security summary" },
    { label: "Device Security", text: "Show device security status" },
    { label: "What about its connections?", text: "What about its open ports?" },
    { label: "सगळे धोके दाखव (मराठी)", text: "Amoja, mala sagle critical threats dakhav" },
    { label: "याच्याबद्दल सांगा (मराठी)", text: "याच्याबद्दल अधिक सांगा" },
    { label: "सारे खतरे दिखाओ (हिन्दी)", text: "Amoja, mujhe saare critical threats dikhao" },
    { label: "इसके बारे में बताओ (हिन्दी)", text: "इसके बारे में और बताओ" },
    { label: "Prompt Injections (Hinglish)", text: "Amoja, latest prompt injection attacks check karo" },
    { label: "Network Monitoring", text: "Show network monitoring status" },
    { label: "Trigger Scan Now", text: "Trigger a scan now" }
  ];

  return (
    <div className="jarvis-chat-panel">
      {/* Top Header Toolbar */}
      <div className="chat-panel-header">
        <div className="chat-branding">
          <Bot size={16} className="jarvis-icon-glow" style={{ color: "#76b900" }} />
          <span>AMOJA AI // DGX CONVERSATIONAL CORE</span>
          <span className="female-voice-tag" style={{ fontSize: "10px", padding: "2px 7px", background: "rgba(118, 185, 0, 0.18)", color: "#76b900", borderRadius: "4px", marginLeft: "8px", border: "1px solid rgba(118, 185, 0, 0.4)", fontWeight: 700, letterSpacing: "0.5px" }}>
            FEMALE VOICE
          </span>
        </div>

        <div className="chat-toolbar-actions">
          {/* Personality Mode Toggle: Friendly vs Security */}
          {onTogglePersonalityMode && (
            <button
              type="button"
              className={`btn-chat-tool personality-toggle-btn`}
              onClick={() => onTogglePersonalityMode(personalityMode === "friendly" ? "security" : "friendly")}
              title={`Switch Personality (Current: ${personalityMode === "friendly" ? "Friendly Companion" : "SOC Security Analyst"})`}
              aria-label="Toggle Assistant Personality"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "5px",
                fontSize: "11px",
                padding: "3px 8px",
                borderRadius: "4px",
                border: "1px solid rgba(118, 185, 0, 0.35)",
                background: personalityMode === "friendly" ? "rgba(118, 185, 0, 0.18)" : "rgba(16, 185, 129, 0.18)",
                color: personalityMode === "friendly" ? "#76b900" : "#00ff88",
                fontWeight: 700,
                cursor: "pointer"
              }}
            >
              <span>{personalityMode === "friendly" ? "🌱 FRIENDLY" : "🛡️ SECURITY"}</span>
            </button>
          )}

          {/* Language Selector */}
          <div className="lang-picker-group">
            <Globe size={14} />
            <select
              value={selectedLanguage}
              onChange={(e) => onSelectLanguage(e.target.value as JarvisLanguage)}
              className="lang-select"
              title="Select Conversation Language (English, Hindi, Marathi, Hinglish, Auto-Detect)"
              aria-label="Conversation language"
            >
              <option value="auto">Auto-Detect</option>
              <option value="en">English (AMOJA)</option>
              <option value="hi">हिन्दी - Hindi (AMOJA)</option>
              <option value="mr">मराठी - Marathi (AMOJA)</option>
              <option value="hinglish">Hinglish (AMOJA)</option>
            </select>
          </div>

          {/* Export Transcript */}
          {messages.length > 0 && (
            <button
              type="button"
              className="btn-chat-tool"
              onClick={handleExportTranscript}
              title="Export Full Conversation Transcript (Markdown)"
              aria-label="Export conversation transcript"
            >
              <Download size={14} />
            </button>
          )}

          {/* Clear History */}
          <button
            type="button"
            className="btn-chat-tool"
            onClick={onClearHistory}
            title="Clear Assistant Conversation History"
            aria-label="Clear conversation history"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* Message Feed */}
      <div className="chat-messages-container" ref={scrollRef} role="log" aria-live="polite">
        {messages.length === 0 && !transcription && (
          <div className="chat-empty-state">
            <div className="empty-radar-icon">
              <Bot size={36} />
            </div>
            <h4>AMOJA AI Autonomous Cybersecurity Defense</h4>
            <p>Speak naturally with continuous hands-free dialogue, interruption barge-in, and multi-turn context across English, Hindi, Marathi, and Hinglish.</p>

            <div className="quick-suggestions-box">
              <span className="suggestions-title">// RECOMMENDED MULTI-TURN DIRECTIVES //</span>
              <div className="quick-chip-grid">
                {quickPrompts.map((q) => (
                  <button
                    key={q.text}
                    type="button"
                    className="quick-chip"
                    onClick={() => onSendMessage(q.text, false)}
                  >
                    {q.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {messages.map((m, idx) => {
          const isAssistant = m.role === "assistant";
          const msgKey = `msg-${m.id || idx}`;

          return (
            <div key={msgKey} className={`chat-message-row ${isAssistant ? "assistant" : "user"}`}>
              <div className="message-avatar">
                {isAssistant ? <Bot size={16} /> : <UserIcon size={16} />}
              </div>

              <div className="message-bubble-wrapper">
                <div className="message-meta-header">
                  <strong>{isAssistant ? "AMOJA AI" : "Operator"}</strong>
                  <span className="timestamp">{m.created_at ? new Date(m.created_at).toLocaleTimeString() : ""}</span>
                  {m.language && (
                    <span className="msg-lang-badge">{m.language.toUpperCase()}</span>
                  )}
                  {isAssistant && onPlayMessageAudio && (
                    <button
                      type="button"
                      className="voice-tag voice-play-btn"
                      onClick={() => onPlayMessageAudio(m)}
                      title="Play/Replay Voice Synthesis"
                    >
                      <Volume2 size={11} /> Play Voice
                    </button>
                  )}
                  {m.audio_confidence !== undefined && m.audio_confidence !== null && (
                    <span className="confidence-pill" title="Transcription Confidence Score">
                      {Math.round(m.audio_confidence * 100)}% Conf
                    </span>
                  )}
                  {m.is_local_mode && (
                    <span className="local-privacy-badge" title="Processed locally without cloud transmission">
                      Local ASR/TTS
                    </span>
                  )}
                </div>

                <div className="message-content-body">
                  <div className="markdown-render">{m.content}</div>

                  {/* Tool Execution Tags */}
                  {m.tool_calls && m.tool_calls.length > 0 && (
                    <div className="tools-executed-container">
                      {m.tool_calls.map((tc, tcIdx) => {
                        const toolKey = `${msgKey}-tool-${tcIdx}`;
                        const isExpanded = Boolean(expandedTools[toolKey]);
                        const matchingResult = m.tool_results?.[tcIdx];

                        return (
                          <div key={toolKey} className="tool-execution-badge">
                            <button
                              type="button"
                              className="tool-badge-header"
                              onClick={() => toggleToolExpand(toolKey)}
                            >
                              <Terminal size={12} />
                              <span className="tool-name">Tool: <code>{tc.tool_name}</code></span>
                              {matchingResult?.success ? (
                                <CheckCircle2 size={12} className="tool-success" />
                              ) : (
                                <AlertCircle size={12} className="tool-warn" />
                              )}
                              {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                            </button>

                            {isExpanded && matchingResult && (
                              <div className="tool-payload-preview">
                                <pre><code>{JSON.stringify(matchingResult.data, null, 2)}</code></pre>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* Confirmation Request Card */}
                  {m.action_required && (
                    <div className="action-confirmation-card">
                      <div className="card-header">
                        <ShieldAlert size={18} className="warn-icon" />
                        <strong>SENSITIVE ACTION REQUIRES CONFIRMATION</strong>
                      </div>
                      <p className="card-impact">{m.action_required.impact_explanation}</p>
                      <div className="card-controls">
                        <button
                          type="button"
                          className="btn-action-confirm"
                          onClick={() => onConfirmAction(m.action_required!, true)}
                        >
                          <CheckCircle2 size={14} />
                          <span>Confirm Execution</span>
                        </button>
                        <button
                          type="button"
                          className="btn-action-cancel"
                          onClick={() => onConfirmAction(m.action_required!, false)}
                        >
                          <XCircle size={14} />
                          <span>Cancel Action</span>
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}

        {/* Live speech transcription preview */}
        {transcription && (
          <div className="chat-message-row user live-transcription-preview">
            <div className="message-avatar"><UserIcon size={16} /></div>
            <div className="message-bubble-wrapper">
              <div className="message-meta-header">
                <strong>Operator (Speaking)</strong>
                <span className="live-indicator"><span className="pulse-dot" /> Live Audio</span>
              </div>
              <div className="transcription-text">{transcription}</div>
            </div>
          </div>
        )}

        {/* Processing Indicator */}
        {isProcessing && (
          <div className="chat-message-row assistant processing-bubble">
            <div className="message-avatar"><Bot size={16} /></div>
            <div className="processing-indicator">
              <span className="processing-dot" />
              <span className="processing-dot" />
              <span className="processing-dot" />
              <span className="processing-label">JARVIS reasoning & verifying telemetry...</span>
            </div>
          </div>
        )}

        {/* Error notification banner */}
        {errorMessage && (
          <div className="chat-error-banner" role="alert">
            <AlertCircle size={14} />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>

      {/* Input Field & Submit Fallback */}
      <form onSubmit={handleSubmit} className="chat-input-bar">
        <input
          type="text"
          className="jarvis-text-input"
          placeholder="Ask JARVIS or type a voice directive... (e.g. 'Show critical threats', 'Suspend Agent-07')"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          disabled={isProcessing}
          aria-label="JARVIS message input"
        />
        <button
          type="submit"
          className="btn-jarvis-send"
          disabled={!inputText.trim() || isProcessing}
          title="Send message to JARVIS"
          aria-label="Send message"
        >
          <Send size={16} />
        </button>
      </form>
    </div>
  );
};
