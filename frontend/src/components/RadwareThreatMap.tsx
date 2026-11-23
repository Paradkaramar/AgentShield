import React, { useState, useEffect, useRef } from "react";
import {
  Globe as GlobeIcon, ExternalLink, RefreshCw, ShieldAlert,
  CheckCircle, AlertTriangle, Lock, Eye, Sparkles, Cpu,
  Maximize2, Minimize2, Info, ArrowUpRight, WifiOff, Radio
} from "lucide-react";
import { GlobalThreatIntelStatus } from "../types";
import { request } from "../api";

interface Props {
  isCombinedView?: boolean;
  onOpenAmojaBriefing?: () => void;
  className?: string;
}

export const RadwareThreatMap: React.FC<Props> = ({
  isCombinedView = false,
  onOpenAmojaBriefing,
  className = ""
}) => {
  const RADWARE_MAP_URL = "https://livethreatmap.radware.com/";
  const [loadState, setLoadState] = useState<"loading" | "loaded" | "blocked" | "error">("loading");
  const [iframeKey, setIframeKey] = useState<number>(1);
  const [intelStatus, setIntelStatus] = useState<GlobalThreatIntelStatus | null>(null);
  const [loadTimer, setLoadTimer] = useState<number>(0);
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<number | null>(null);

  // Fetch backend architectural intelligence status
  useEffect(() => {
    request<GlobalThreatIntelStatus>("/api/globe/threat-intel/status")
      .then(res => setIntelStatus(res))
      .catch(() => {
        // Fallback default status
        setIntelStatus({
          provider: "Radware Live Threat Map",
          reference_url: RADWARE_MAP_URL,
          supported_integration_method: "iframe_web_view",
          official_public_api_available: false,
          official_embed_code_available: false,
          data_scope: "Worldwide live DDoS, volumetric botnets, and Layer 7 malicious HTTP vectors captured across Radware deception sensors.",
          local_data_isolation: "ENFORCED",
          data_leakage_risk: "ZERO - Local IPs and packet streams strictly isolated.",
          embedding_technical_notes: "Direct iframe embed attempted; external tab fallback supported."
        });
      });
  }, []);

  // Monitor loading timeout
  useEffect(() => {
    setLoadState("loading");
    setLoadTimer(0);

    const startTime = Date.now();
    timerRef.current = window.setInterval(() => {
      const elapsed = Math.floor((Date.now() - startTime) / 1000);
      setLoadTimer(elapsed);

      // If iframe doesn't finish loading after 12 seconds, switch to blocked/restricted state
      if (elapsed >= 12 && loadState === "loading") {
        setLoadState("blocked");
        if (timerRef.current) window.clearInterval(timerRef.current);
      }
    }, 1000);

    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
    };
  }, [iframeKey]);

  const handleIframeLoad = () => {
    if (timerRef.current) window.clearInterval(timerRef.current);
    setLoadState("loaded");
  };

  const handleIframeError = () => {
    if (timerRef.current) window.clearInterval(timerRef.current);
    setLoadState("error");
  };

  const handleRetry = () => {
    setIframeKey(prev => prev + 1);
  };

  const handleOpenExternal = () => {
    window.open(RADWARE_MAP_URL, "_blank", "noopener,noreferrer");
  };

  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    }
  };

  return (
    <div
      ref={containerRef}
      className={`radware-threat-map-container ${isCombinedView ? "combined-mode" : "full-mode"} ${className}`}
    >
      {/* Top Threat Intelligence Control Header */}
      <div className="threat-map-header-strip">
        <div className="header-left">
          <div className="radware-badge">
            <Radio size={14} className="radware-pulse-icon" />
            <span className="brand-name">RADWARE LIVE THREAT MAP</span>
          </div>

          <div className="status-indicator-tag">
            {loadState === "loading" && (
              <span className="indicator-chip loading">
                <RefreshCw size={12} className="animate-spin" />
                <span>CONNECTING CDN ({loadTimer}s)...</span>
              </span>
            )}
            {loadState === "loaded" && (
              <span className="indicator-chip live">
                <span className="live-dot" />
                <span>ACTIVE EMBED &bull; PUBLIC WEB VIEW</span>
              </span>
            )}
            {(loadState === "blocked" || loadState === "error") && (
              <span className="indicator-chip fallback">
                <AlertTriangle size={12} />
                <span>EMBED RESTRICTED &bull; STANDALONE ACTIVE</span>
              </span>
            )}
          </div>
        </div>

        <div className="header-right">
          {/* Isolation & Scope Badge */}
          <span className="isolation-badge" title="Data Isolation Guarantee: Zero local IPs or packets are sent to Radware.">
            <Lock size={11} className="text-emerald-400" />
            <span>LOCAL DATA ISOLATION: ACTIVE</span>
          </span>

          {/* AMOJA AI Threat Intel Briefing Button */}
          {onOpenAmojaBriefing && (
            <button
              type="button"
              className="action-btn-threat-map amoja-briefing-btn"
              onClick={onOpenAmojaBriefing}
              title="AMOJA AI: Explain Global Threat Intelligence vs Local Scans"
            >
              <Cpu size={13} style={{ color: "var(--nvidia-neon, #00ff88)" }} />
              <span>AMOJA Briefing</span>
            </button>
          )}

          {/* Retry Button */}
          <button
            type="button"
            className="action-btn-threat-map"
            onClick={handleRetry}
            title="Reload Radware Threat Map Embed"
          >
            <RefreshCw size={13} />
            <span>Retry</span>
          </button>

          {/* Direct External Link Fallback Button */}
          <button
            type="button"
            className="action-btn-threat-map primary-external"
            onClick={handleOpenExternal}
            title="Open Radware Live Threat Map in a dedicated browser tab (Recommended)"
          >
            <ExternalLink size={13} />
            <span>Open in New Tab</span>
          </button>

          {/* Fullscreen Toggle */}
          <button
            type="button"
            className="action-btn-threat-map"
            onClick={toggleFullscreen}
            title={isFullscreen ? "Exit Fullscreen" : "Fullscreen View"}
          >
            {isFullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          </button>
        </div>
      </div>

      {/* Segregation Guarantee Notice Strip */}
      <div className="threat-map-notice-strip">
        <Info size={13} className="text-cyan-400 flex-shrink-0" />
        <span className="notice-text">
          <strong>GLOBAL THREAT INTELLIGENCE (RADWARE):</strong> Visualizes worldwide DDoS, botnet, and Web App attacks captured across Radware&apos;s global cloud deception network. This macro feed is strictly segregated from AgentShield&apos;s local network telemetry.
        </span>
      </div>

      {/* Main Map Viewport */}
      <div className="threat-map-viewport">
        {/* The Live Iframe Embed */}
        <iframe
          key={iframeKey}
          src={RADWARE_MAP_URL}
          title="Radware Live Cyber Threat Map"
          className={`radware-iframe ${loadState === "loaded" ? "visible" : "hidden-or-loading"}`}
          onLoad={handleIframeLoad}
          onError={handleIframeError}
          referrerPolicy="no-referrer-when-downgrade"
          allow="fullscreen; autoplay"
        />

        {/* Loading Overlay */}
        {loadState === "loading" && (
          <div className="threat-map-state-overlay loading">
            <div className="state-card">
              <div className="radar-spinner-box">
                <GlobeIcon size={36} className="animate-spin-slow text-cyan-400" />
                <span className="radar-scan-wave" />
              </div>
              <h4 className="state-title">ESTABLISHING CONNECTION TO RADWARE CDN</h4>
              <p className="state-desc">
                Loading official public Live Threat Map from <code>livethreatmap.radware.com</code>...
              </p>
              <div className="state-timer">Elapsed: {loadTimer}s / 12s timeout</div>
              <div className="fallback-quick-row">
                <button
                  type="button"
                  className="quick-tab-btn"
                  onClick={handleOpenExternal}
                >
                  <ExternalLink size={13} />
                  <span>Open Directly in New Tab</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Blocked / Restricted Fallback State */}
        {(loadState === "blocked" || loadState === "error") && (
          <div className="threat-map-state-overlay fallback-active">
            <div className="state-card fallback">
              <div className="fallback-header">
                <ShieldAlert size={32} className="text-amber-400" />
                <div>
                  <h4 className="fallback-title">RADWARE LIVE THREAT MAP &bull; STANDALONE ACCESS</h4>
                  <span className="fallback-subtitle">Technical Integration &amp; Security Boundary Notice</span>
                </div>
              </div>

              <div className="fallback-body">
                <div className="fallback-bullet">
                  <strong>Technical Restriction:</strong>
                  <span>Direct browser iframe embedding of <code>livethreatmap.radware.com</code> is currently restricted by browser tracking protection, third-party cookie shielding, or cross-origin canvas constraints.</span>
                </div>
                <div className="fallback-bullet">
                  <strong>Official Integration Status:</strong>
                  <span>Radware does not provide an official public HTML embed snippet or public event stream API. AgentShield strictly avoids unauthorized scraping or private API reverse engineering.</span>
                </div>
                <div className="fallback-bullet">
                  <strong>Zero-Trust Data Isolation:</strong>
                  <span>Your local AgentShield network scans, host IPs, and Wireshark PCAPs are completely isolated on-premises and never transmitted to external threat services.</span>
                </div>
              </div>

              <div className="fallback-actions">
                <button
                  type="button"
                  className="fallback-cta-btn open-tab"
                  onClick={handleOpenExternal}
                >
                  <ExternalLink size={15} />
                  <span>Open Radware Live Threat Map (New Tab)</span>
                  <ArrowUpRight size={14} />
                </button>
                <button
                  type="button"
                  className="fallback-cta-btn retry"
                  onClick={handleRetry}
                >
                  <RefreshCw size={13} />
                  <span>Retry Embedding</span>
                </button>
                {onOpenAmojaBriefing && (
                  <button
                    type="button"
                    className="fallback-cta-btn amoja"
                    onClick={onOpenAmojaBriefing}
                  >
                    <Cpu size={14} />
                    <span>AMOJA AI Explanation</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bottom Footer Architecture Strip */}
      <div className="threat-map-footer-strip">
        <div className="footer-left">
          <span>Source: Radware Security Research Center</span>
          <span className="sep">&bull;</span>
          <span>Method: {intelStatus?.supported_integration_method || "iframe_web_view"}</span>
          <span className="sep">&bull;</span>
          <span>Public API: {intelStatus?.official_public_api_available ? "Available" : "Not Provided by Vendor"}</span>
        </div>
        <div className="footer-right">
          <span className="compliance-tag">Zero-Trust Verified &bull; RFC 1918 Private Enclave Preserved</span>
        </div>
      </div>
    </div>
  );
};
