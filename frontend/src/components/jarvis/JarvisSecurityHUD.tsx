import React from "react";
import { ShieldCheck, AlertTriangle, Bot, Radio, Compass, RefreshCw, FileText, Lock, Globe } from "lucide-react";
import { JarvisSecurityContext, JarvisBriefing } from "../../types";

interface Props {
  context?: JarvisSecurityContext | null;
  briefing?: JarvisBriefing | null;
  onRequestBriefing: () => void;
  isLoadingBriefing?: boolean;
  isLocalMode?: boolean;
  selectedLanguage?: string;
}

export const JarvisSecurityHUD: React.FC<Props> = ({
  context,
  briefing,
  onRequestBriefing,
  isLoadingBriefing = false,
  isLocalMode = true,
  selectedLanguage = "auto"
}) => {
  const threatLevel = briefing?.threat_level || "LOW";
  const threatClass = threatLevel === "CRITICAL" ? "threat-critical" : threatLevel === "ELEVATED" ? "threat-elevated" : "threat-low";

  return (
    <div className="jarvis-security-hud">
      <div className="hud-metric-pill">
        <span className="hud-pulse-dot" />
        <span className="hud-label">ZERO-TRUST:</span>
        <strong className="hud-value-highlight">ENFORCING</strong>
      </div>

      {/* Local Privacy Shield Indicator */}
      <div className="hud-metric-pill privacy-shield-pill" title="Local-First Privacy Mode: Speech Recognition & Voice Synthesis run entirely locally on-device without cloud egress">
        <Lock size={12} className="local-shield-icon" />
        <span className="hud-label">PRIVACY:</span>
        <strong className="hud-value-local">{isLocalMode ? "LOCAL SHIELD (OFFLINE)" : "CLOUD HYBRID"}</strong>
      </div>

      {/* Active Language Badge */}
      <div className="hud-metric-pill lang-badge-pill" title={`Active Language Model: ${selectedLanguage.toUpperCase()}`}>
        <Globe size={12} />
        <span className="hud-label">LANG:</span>
        <strong className="hud-value">{selectedLanguage.toUpperCase()}</strong>
      </div>

      <div className={`hud-metric-pill ${threatClass}`}>
        <AlertTriangle size={13} />
        <span className="hud-label">THREAT LEVEL:</span>
        <strong className="hud-value">{threatLevel}</strong>
      </div>

      {briefing && (
        <>
          <div className="hud-metric-pill">
            <Bot size={13} />
            <span className="hud-label">ACTIVE AGENTS:</span>
            <strong className="hud-value">{briefing.active_agents_count}</strong>
          </div>

          <div className="hud-metric-pill">
            <Radio size={13} />
            <span className="hud-label">OPEN INCIDENTS:</span>
            <strong className="hud-value">{briefing.open_incidents_count}</strong>
          </div>
        </>
      )}

      {context?.selected_agent_id && (
        <div className="hud-context-tag">
          <Compass size={12} />
          <span>Agent: <strong>{context.selected_agent_id}</strong></span>
        </div>
      )}

      {context?.selected_incident_id && (
        <div className="hud-context-tag">
          <AlertTriangle size={12} />
          <span>Incident: <strong>#{context.selected_incident_id}</strong></span>
        </div>
      )}

      <button
        type="button"
        className="hud-briefing-btn"
        onClick={onRequestBriefing}
        disabled={isLoadingBriefing}
        title="Request real-time Security Briefing"
      >
        {isLoadingBriefing ? (
          <RefreshCw size={12} className="spin-icon" />
        ) : (
          <FileText size={12} />
        )}
        <span>Briefing</span>
      </button>
    </div>
  );
};
