// frontend/src/components/jarvis/JarvisChatPanel.tsx
import React, { useState, useRef, useEffect } from "react";
import {
  Send, Bot, User as UserIcon, ShieldAlert, CheckCircle2, XCircle,
  Terminal, Globe, Trash2, Mic, AlertCircle, ChevronDown, ChevronUp, Copy, Check,
  Volume2, Play, Pause, Download, RefreshCw, Square, MessageSquare, Folder, Monitor, Flame,
  ExternalLink
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
  onRetry?: () => void;
  isSpeaking?: boolean;
  onStopSpeaking?: () => void;
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
  onTogglePersonalityMode,
  onRetry,
  isSpeaking = false,
  onStopSpeaking
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
    // Live Intelligence & Knowledge Engine Directives
    { label: "🌦️ Pune Weather", text: "Amoja, aaj ka weather kaisa hai Pune mein?" },
    { label: "📰 AI & Tech Releases", text: "What are the latest AI models and tech launches this week?" },
    { label: "🛡️ CISA KEV Advisories", text: "Aaj ke important cybersecurity alerts aur CISA KEV advisories samjhao" },
    { label: "🪟 Windows Update Health", text: "Check Windows 11 release health and latest Patch Tuesday updates" },
    { label: "पुण्याचे हवामान (मराठी)", text: "अमोजा, पुण्यात आज हवामान कसे आहे?" },
    { label: "आजची टेक बातमी (हिन्दी)", text: "अमोजा, आज की लेटेस्ट टेक्नोलॉजी न्यूज़ बताओ" },
    // Windows Personal Assistant Directives
    { label: "💻 Check Windows Status", text: "Check my Windows system status, battery, and memory" },
    { label: "📝 Take a Note", text: "Take a note: Review AgentShield and personal assistant release" },
    { label: "⏰ Set Reminder", text: "Remind me to check SOC incident logs at 5 PM" },
    { label: "📂 Search Files in Documents", text: "Search authorized files in my documents" },
    { label: "🎵 Play Lofi on YouTube", text: "Play lofi chill beats on YouTube" },
    { label: "💬 Send WhatsApp", text: "Send WhatsApp message to +919876543210: Hello from Amoja AI" },
    { label: "🖥️ Mera PC check karo (Hinglish)", text: "Amoja, mera computer aur battery status check karo" },
    { label: "माझा कॉम्प्युटर तपासा (मराठी)", text: "अमोजा, माझा कॉम्प्युटर आणि बॅटरी स्टेटस तपासा" },
    // AgentShield Cybersecurity Directives
    { label: "🛡️ Security Summary", text: "Give me the security summary" },
    { label: "🔍 Analyze Suspicious Processes", text: "Analyze suspicious processes on my computer" },
    { label: "🔥 Check Firewall Status", text: "Show firewall status and active rules" },
    { label: "🌐 Network Monitoring", text: "Show network monitoring status and open ports" },
    { label: "सगळे धोके दाखव (मराठी)", text: "Amoja, mala sagle critical threats dakhav" },
    { label: "सारे खतरे दिखाओ (हिन्दी)", text: "Amoja, mujhe saare critical threats dikhao" },
    { label: "⚡ Trigger Scan Now", text: "Trigger a network scan now" }
  ];

  return (
    <div className="jarvis-chat-panel">
      {/* Top Header Toolbar */}
      <div className="chat-panel-header">
        <div className="chat-branding">
          <Bot size={16} className="jarvis-icon-glow" style={{ color: "#76b900" }} />
          <span>AMOJA AI // PERSONAL ASSISTANT & AGENTSHIELD SOC</span>
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
            <h4>AMOJA AI // Windows Personal Assistant & Cybersecurity Platform</h4>
            <p>One unified voice and chat interface for everyday Windows personal tasks (apps, websites, YouTube, files, WhatsApp, notes, reminders, system status) and AgentShield cybersecurity platform operations across English, Hindi, Marathi, and Hinglish.</p>

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
                  {m.live_intelligence && (
                    <span
                      className="live-verified-badge"
                      title={`Tool: ${m.live_intelligence.tool || 'Live Intel'} | Retrieved: ${m.live_intelligence.retrieved_at || 'Just now'} ${m.live_intelligence.cached ? '(Cached)' : '(Live)'}`}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "4px",
                        fontSize: "10px",
                        padding: "2px 6px",
                        borderRadius: "4px",
                        background: m.live_intelligence.cached ? "rgba(234, 179, 8, 0.15)" : "rgba(56, 189, 248, 0.15)",
                        color: m.live_intelligence.cached ? "#facc15" : "#38bdf8",
                        border: `1px solid ${m.live_intelligence.cached ? "rgba(234, 179, 8, 0.4)" : "rgba(56, 189, 248, 0.4)"}`,
                        fontWeight: 700,
                        letterSpacing: "0.5px"
                      }}
                    >
                      <Globe size={10} />
                      {m.live_intelligence.cached ? "CACHED INTEL" : "LIVE VERIFIED"}
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
                  {m.action_required && (() => {
                    const req = m.action_required;
                    const isWhatsApp = req.action_type === "SEND_WHATSAPP_MESSAGE";
                    const isFirewall = req.action_type.startsWith("FIREWALL_");
                    const isFileOp = req.action_type.startsWith("ORGANIZE_FILE_");

                    if (isWhatsApp) {
                      return (
                        <div className="action-confirmation-card whatsapp-confirm-card" style={{ border: "1px solid #25D366", background: "rgba(37, 211, 102, 0.08)", borderRadius: "8px", padding: "14px" }}>
                          <div className="card-header" style={{ display: "flex", alignItems: "center", gap: "8px", color: "#25D366", marginBottom: "8px" }}>
                            <MessageSquare size={18} />
                            <strong>WHATSAPP MESSAGE DISPATCH // CONFIRMATION REQUIRED</strong>
                          </div>
                          <div style={{ background: "rgba(0,0,0,0.3)", padding: "10px", borderRadius: "6px", marginBottom: "10px", fontSize: "12px", border: "1px solid rgba(37, 211, 102, 0.2)" }}>
                            <div style={{ marginBottom: "4px" }}>
                              <strong style={{ color: "#25D366" }}>Recipient: </strong>
                              <span style={{ color: "#fff", fontWeight: 600 }}>{req.details?.recipient || req.target_id}</span>
                            </div>
                            {req.details?.message && (
                              <div style={{ marginBottom: "4px" }}>
                                <strong style={{ color: "#25D366" }}>Message Preview: </strong>
                                <span style={{ color: "#e2e8f0", fontStyle: "italic" }}>"{req.details.message}"</span>
                              </div>
                            )}
                            {req.details?.attachment_path && (
                              <div>
                                <strong style={{ color: "#25D366" }}>Attachment: </strong>
                                <span style={{ color: "#94a3b8" }}>{req.details.attachment_path}</span>
                              </div>
                            )}
                          </div>
                          <p className="card-impact" style={{ fontSize: "12px", color: "#94a3b8", marginBottom: "12px" }}>{req.impact_explanation}</p>
                          <div className="card-controls" style={{ display: "flex", gap: "10px" }}>
                            <button
                              type="button"
                              className="btn-action-confirm"
                              style={{ background: "#25D366", color: "#000", fontWeight: 700 }}
                              onClick={() => onConfirmAction(req, true)}
                            >
                              <CheckCircle2 size={14} />
                              <span>Send WhatsApp Message</span>
                            </button>
                            <button
                              type="button"
                              className="btn-action-cancel"
                              onClick={() => onConfirmAction(req, false)}
                            >
                              <XCircle size={14} />
                              <span>Cancel</span>
                            </button>
                          </div>
                        </div>
                      );
                    }

                    if (isFirewall) {
                      return (
                        <div className="action-confirmation-card firewall-confirm-card" style={{ border: "1px solid #f59e0b", background: "rgba(245, 158, 11, 0.08)", borderRadius: "8px", padding: "14px" }}>
                          <div className="card-header" style={{ display: "flex", alignItems: "center", gap: "8px", color: "#f59e0b", marginBottom: "8px" }}>
                            <Flame size={18} />
                            <strong>FIREWALL CONFIGURATION CHANGE // HIGH RISK</strong>
                          </div>
                          <div style={{ background: "rgba(0,0,0,0.3)", padding: "10px", borderRadius: "6px", marginBottom: "10px", fontSize: "12px", border: "1px solid rgba(245, 158, 11, 0.2)" }}>
                            <div><strong style={{ color: "#f59e0b" }}>Rule Name: </strong><span>{req.details?.rule_name || req.target_id}</span></div>
                            {req.details?.port && (
                              <div><strong style={{ color: "#f59e0b" }}>Port: </strong><span>{req.details.port} ({req.details.protocol || "TCP"})</span></div>
                            )}
                            {req.details?.direction && (
                              <div><strong style={{ color: "#f59e0b" }}>Direction: </strong><span>{req.details.direction.toUpperCase()}BOUND</span></div>
                            )}
                          </div>
                          <p className="card-impact" style={{ fontSize: "12px", color: "#94a3b8", marginBottom: "12px" }}>{req.impact_explanation}</p>
                          <div className="card-controls" style={{ display: "flex", gap: "10px" }}>
                            <button
                              type="button"
                              className="btn-action-confirm"
                              style={{ background: "#f59e0b", color: "#000", fontWeight: 700 }}
                              onClick={() => onConfirmAction(req, true)}
                            >
                              <CheckCircle2 size={14} />
                              <span>Apply Firewall Rule</span>
                            </button>
                            <button
                              type="button"
                              className="btn-action-cancel"
                              onClick={() => onConfirmAction(req, false)}
                            >
                              <XCircle size={14} />
                              <span>Cancel</span>
                            </button>
                          </div>
                        </div>
                      );
                    }

                    if (isFileOp) {
                      return (
                        <div className="action-confirmation-card file-confirm-card" style={{ border: "1px solid #38bdf8", background: "rgba(56, 189, 248, 0.08)", borderRadius: "8px", padding: "14px" }}>
                          <div className="card-header" style={{ display: "flex", alignItems: "center", gap: "8px", color: "#38bdf8", marginBottom: "8px" }}>
                            <Folder size={18} />
                            <strong>FILE OPERATION CONFIRMATION</strong>
                          </div>
                          <div style={{ background: "rgba(0,0,0,0.3)", padding: "10px", borderRadius: "6px", marginBottom: "10px", fontSize: "12px", border: "1px solid rgba(56, 189, 248, 0.2)" }}>
                            <div><strong style={{ color: "#38bdf8" }}>Operation: </strong><span>{req.details?.operation || req.action_type}</span></div>
                            <div><strong style={{ color: "#38bdf8" }}>Source: </strong><span>{req.details?.source || req.target_id}</span></div>
                            {(req.details?.target || req.details?.new_name) && (
                              <div><strong style={{ color: "#38bdf8" }}>Destination: </strong><span>{req.details.target || req.details.new_name}</span></div>
                            )}
                          </div>
                          <p className="card-impact" style={{ fontSize: "12px", color: "#94a3b8", marginBottom: "12px" }}>{req.impact_explanation}</p>
                          <div className="card-controls" style={{ display: "flex", gap: "10px" }}>
                            <button
                              type="button"
                              className="btn-action-confirm"
                              style={{ background: "#38bdf8", color: "#000", fontWeight: 700 }}
                              onClick={() => onConfirmAction(req, true)}
                            >
                              <CheckCircle2 size={14} />
                              <span>Confirm File Action</span>
                            </button>
                            <button
                              type="button"
                              className="btn-action-cancel"
                              onClick={() => onConfirmAction(req, false)}
                            >
                              <XCircle size={14} />
                              <span>Cancel</span>
                            </button>
                          </div>
                        </div>
                      );
                    }

                    return (
                      <div className="action-confirmation-card">
                        <div className="card-header">
                          <ShieldAlert size={18} className="warn-icon" />
                          <strong>SENSITIVE ACTION REQUIRES CONFIRMATION</strong>
                        </div>
                        <p className="card-impact">{req.impact_explanation}</p>
                        <div className="card-controls">
                          <button
                            type="button"
                            className="btn-action-confirm"
                            onClick={() => onConfirmAction(req, true)}
                          >
                            <CheckCircle2 size={14} />
                            <span>Confirm Execution</span>
                          </button>
                          <button
                            type="button"
                            className="btn-action-cancel"
                            onClick={() => onConfirmAction(req, false)}
                          >
                            <XCircle size={14} />
                            <span>Cancel Action</span>
                          </button>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Verified Sources & Citations */}
                  {m.citations && m.citations.length > 0 && (
                    <div className="citations-container" style={{ marginTop: "12px", padding: "10px 12px", background: "rgba(15, 23, 42, 0.75)", borderRadius: "6px", border: "1px solid rgba(56, 189, 248, 0.3)" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "#38bdf8", fontWeight: 700, marginBottom: "8px", letterSpacing: "0.5px" }}>
                        <ExternalLink size={12} />
                        <span>VERIFIED SOURCES & CITATIONS ({m.citations.length})</span>
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                        {m.citations.map((c, cIdx) => (
                          <a
                            key={cIdx}
                            href={c.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="citation-chip"
                            title={c.snippet || c.title || c.url}
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "5px",
                              fontSize: "11px",
                              padding: "4px 8px",
                              background: "rgba(56, 189, 248, 0.12)",
                              border: "1px solid rgba(56, 189, 248, 0.35)",
                              borderRadius: "4px",
                              color: "#7dd3fc",
                              textDecoration: "none",
                              transition: "all 0.15s ease"
                            }}
                          >
                            <span style={{ fontWeight: 700, color: "#38bdf8" }}>[{cIdx + 1}]</span>
                            <span style={{ maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {c.publisher || c.title || "Source"}
                            </span>
                            {c.publication_date && (
                              <span style={{ opacity: 0.65, fontSize: "10px" }}>({c.publication_date.slice(0, 10)})</span>
                            )}
                            <ExternalLink size={10} style={{ opacity: 0.7 }} />
                          </a>
                        ))}
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

        {/* Speaking Status Banner & Interruption Control */}
        {isSpeaking && (
          <div className="chat-speaking-banner" role="status" aria-live="polite">
            <div className="speaking-indicator-left">
              <span className="pulse-dot" style={{ background: "#00e5ff" }} />
              <Volume2 size={14} className="text-cyan-400" />
              <span>AMOJA speaking... (Press Esc or click Interrupt)</span>
            </div>
            {onStopSpeaking && (
              <button
                type="button"
                className="btn-chat-interrupt"
                onClick={onStopSpeaking}
                title="Stop speaking immediately (Esc)"
              >
                <Square size={12} fill="currentColor" />
                <span>Stop Speaking</span>
              </button>
            )}
          </div>
        )}

        {/* Error notification banner with Retry button */}
        {errorMessage && (
          <div className="chat-error-banner" role="alert">
            <div className="error-banner-content">
              <AlertCircle size={14} className="shrink-0" />
              <span>{errorMessage}</span>
            </div>
            {onRetry && (
              <button
                type="button"
                className="btn-chat-retry"
                onClick={onRetry}
                title="Retry the last command"
              >
                <RefreshCw size={12} />
                <span>Retry</span>
              </button>
            )}
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
