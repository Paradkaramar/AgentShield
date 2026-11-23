import React, { useState, useEffect, useMemo, useRef } from "react";
import {
  Globe as GlobeIcon, Shield, AlertTriangle, CheckCircle, Radio,
  Server, Laptop, Play, Square, RefreshCw, Eye, EyeOff, Terminal, Flame,
  Cpu, Activity, Lock, AlertOctagon, Filter, Search, ArrowRight,
  ExternalLink, Layers, Check, X, ShieldAlert, Sparkles, Wifi,
  ChevronDown, ChevronUp, Volume2
} from "lucide-react";
import { CyberGlobeView } from "../components/CyberGlobeView";
import { RadwareThreatMap } from "../components/RadwareThreatMap";
import {
  GlobeNode, GlobeArc, GlobeTelemetryResponse, GlobeScanStatus,
  DeviceDetailResponse, AIHostExplanation, TrafficStreamResponse,
  GlobalThreatMode, GlobalThreatIntelExplanation
} from "../types";
import { request } from "../api";

export const CyberGlobePage: React.FC = () => {
  // Operational Mode: Live SOC Telemetry vs Threat Simulation Demo
  const [operationalMode, setOperationalMode] = useState<"live" | "demo">("live");
  const [telemetry, setTelemetry] = useState<GlobeTelemetryResponse | null>(null);
  const [scanStatus, setScanStatus] = useState<GlobeScanStatus | null>(null);
  const [trafficData, setTrafficData] = useState<TrafficStreamResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<GlobeNode | null>(null);
  const [deviceDetails, setDeviceDetails] = useState<DeviceDetailResponse["device"] | null>(null);

  // View mode: 3d globe, virtual lan topology, or split HUD
  const [viewMode, setViewMode] = useState<"3d" | "lan" | "split">("3d");
  const [autoRotate, setAutoRotate] = useState(true);

  // Global Threat Intelligence Layer State
  const [threatIntelMode, setThreatIntelMode] = useState<GlobalThreatMode>("local");
  const [threatIntelExplanation, setThreatIntelExplanation] = useState<GlobalThreatIntelExplanation | null>(null);
  const [loadingThreatIntelExplain, setLoadingThreatIntelExplain] = useState<boolean>(false);
  const [showThreatIntelModal, setShowThreatIntelModal] = useState<boolean>(false);
  const [threatIntelLanguage, setThreatIntelLanguage] = useState<"en" | "hi" | "mr">("en");

  // HUD Visibility and Panel Collapse States (Eliminate 3D interference)
  const [hudVisible, setHudVisible] = useState(true);
  const [panelCollapsed, setPanelCollapsed] = useState({
    scanner: false,
    hosts: false,
    traffic: false,
    alerts: false
  });
  const [mobileActiveTab, setMobileActiveTab] = useState<"scanner" | "hosts" | "traffic" | "alerts" | null>(null);

  const togglePanel = (panel: "scanner" | "hosts" | "traffic" | "alerts") => {
    setPanelCollapsed(prev => ({ ...prev, [panel]: !prev[panel] }));
  };

  // Scanner Form State
  const [targetInput, setTargetInput] = useState("127.0.0.1");
  const [selectedProfile, setSelectedProfile] = useState("quick_ports");
  const [userConfirmed, setUserConfirmed] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanTimer, setScanTimer] = useState(0);

  // Live Traffic Filter & Capture State
  const [trafficFilterHost, setTrafficFilterHost] = useState<string>("");
  const [isCapturingLive, setIsCapturingLive] = useState(false);
  const [bpfFilterInput, setBpfFilterInput] = useState("");

  // AI Explain Modal State
  const [aiExplanation, setAiExplanation] = useState<AIHostExplanation | null>(null);
  const [loadingAiExplain, setLoadingAiExplain] = useState(false);
  const [showAiModal, setShowAiModal] = useState(false);

  // Host Search & Filter State
  const [hostFilterTab, setHostFilterTab] = useState<"all" | "online" | "alerts">("all");
  const [hostSearchQuery, setHostSearchQuery] = useState("");

  // UI Notices and Errors
  const [notice, setNotice] = useState<string>("");
  const [error, setError] = useState<string>("");

  const scanTimerRef = useRef<number | null>(null);

  // Fetch telemetry
  const fetchTelemetry = async (mode: "live" | "demo" = operationalMode) => {
    try {
      const data = await request<GlobeTelemetryResponse>(`/api/globe/telemetry?mode=${mode}`);
      setTelemetry(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load globe telemetry");
    }
  };

  // Fetch active scan and tool status
  const fetchScanStatus = async () => {
    try {
      const data = await request<GlobeScanStatus>("/api/globe/scan/status");
      setScanStatus(data);
      setIsScanning(data.active_scan.is_scanning);
    } catch (err) {
      // Ignore background status polling errors
    }
  };

  // Fetch real packet traffic stream
  const fetchTrafficStream = async () => {
    try {
      const queryParam = trafficFilterHost ? `?host_filter=${encodeURIComponent(trafficFilterHost)}` : "";
      const data = await request<TrafficStreamResponse>(`/api/globe/traffic/stream${queryParam}`);
      setTrafficData(data);
    } catch (err) {
      // Ignore transient stream errors
    }
  };

  // Initial load and periodic polling
  useEffect(() => {
    fetchTelemetry(operationalMode);
    fetchScanStatus();
    fetchTrafficStream();

    const interval = window.setInterval(() => {
      fetchTelemetry(operationalMode);
      fetchScanStatus();
      fetchTrafficStream();
    }, 4000);

    return () => window.clearInterval(interval);
  }, [operationalMode, trafficFilterHost]);

  // Scan timer management
  useEffect(() => {
    if (isScanning) {
      scanTimerRef.current = window.setInterval(() => {
        setScanTimer(prev => prev + 1);
      }, 1000);
    } else {
      if (scanTimerRef.current) {
        window.clearInterval(scanTimerRef.current);
      }
      setScanTimer(0);
    }
    return () => {
      if (scanTimerRef.current) window.clearInterval(scanTimerRef.current);
    };
  }, [isScanning]);

  // When a node is selected, fetch full device details
  useEffect(() => {
    if (selectedNode) {
      request<DeviceDetailResponse>(`/api/globe/device/${selectedNode.ip_address}`)
        .then(res => setDeviceDetails(res.device))
        .catch(() => setDeviceDetails(null));
    } else {
      setDeviceDetails(null);
    }
  }, [selectedNode]);

  // Start Targeted Scan
  const handleStartScan = async () => {
    if (!userConfirmed) {
      setError("Target authorization required: Please check 'I confirm authorization to scan this target'.");
      return;
    }
    if (!targetInput.trim()) {
      setError("Please specify a target IP, CIDR, or hostname.");
      return;
    }

    setError("");
    setNotice("");
    try {
      const res = await request<{ status: string; message: string; job_id: string }>("/api/globe/scan/start", {
        method: "POST",
        body: JSON.stringify({
          target: targetInput.trim(),
          profile: selectedProfile,
          user_confirmed: true,
          allow_public: false
        })
      });
      setNotice(res.message);
      setIsScanning(true);
      fetchScanStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to initiate targeted scan");
    }
  };

  // Stop Targeted Scan
  const handleStopScan = async () => {
    try {
      const res = await request<{ status: string; message: string }>("/api/globe/scan/stop", {
        method: "POST"
      });
      setNotice(res.message);
      setIsScanning(false);
      fetchScanStatus();
      fetchTelemetry();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stop active scan");
    }
  };

  // Promote Device to Baseline
  const handlePromoteBaseline = async (ip: string) => {
    try {
      await request(`/api/globe/device/${ip}/baseline`, { method: "POST" });
      setNotice(`Device ${ip} and its observed services have been approved in baseline.`);
      fetchTelemetry();
      if (selectedNode?.ip_address === ip) {
        setSelectedNode(prev => (prev ? { ...prev, in_baseline: true } : null));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to promote device to baseline");
    }
  };

  // Request AI Explainable Threat Analysis
  const handleRequestAiExplain = async (ip: string) => {
    setLoadingAiExplain(true);
    setShowAiModal(true);
    try {
      const res = await request<AIHostExplanation>("/api/globe/ai-explain", {
        method: "POST",
        body: JSON.stringify({ ip_address: ip })
      });
      setAiExplanation(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate AI host explanation");
      setShowAiModal(false);
    } finally {
      setLoadingAiExplain(false);
    }
  };

  // Request Global Threat Intelligence Explanation
  const handleRequestThreatIntelExplain = async (lang: "en" | "hi" | "mr" = threatIntelLanguage) => {
    setLoadingThreatIntelExplain(true);
    setShowThreatIntelModal(true);
    try {
      const res = await request<GlobalThreatIntelExplanation>("/api/globe/threat-intel/explain", {
        method: "POST",
        body: JSON.stringify({ category: "all", language: lang })
      });
      setThreatIntelExplanation(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load threat intelligence explanation");
      setShowThreatIntelModal(false);
    } finally {
      setLoadingThreatIntelExplain(false);
    }
  };

  // Speech synthesis for AMOJA voice briefing
  const handleSpeakBriefing = (text: string) => {
    if (!window.speechSynthesis) return;
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 1.0;
    utterance.pitch = 1.0;
    window.speechSynthesis.speak(utterance);
  };

  // Start Live Packet Capture
  const handleToggleLiveCapture = async () => {
    try {
      if (isCapturingLive) {
        await request("/api/globe/traffic/capture/stop", { method: "POST" });
        setIsCapturingLive(false);
        setNotice("Live packet capture session stopped.");
      } else {
        await request("/api/globe/traffic/capture/start", {
          method: "POST",
          body: JSON.stringify({
            bpf_filter: bpfFilterInput.trim(),
            duration_seconds: 20,
            max_packets: 300
          })
        });
        setIsCapturingLive(true);
        setNotice("Live TShark packet capture started.");
      }
      fetchTrafficStream();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Live packet capture control failed");
    }
  };

  // Filtered Discovered Hosts
  const allDiscoveredNodes = useMemo(() => {
    if (!telemetry) return [];
    const list = [...telemetry.globe_nodes, ...telemetry.virtual_lan_nodes];
    return list.filter(node => {
      // Tab filter
      if (hostFilterTab === "online" && node.status !== "REACHABLE" && node.status !== "UP") return false;
      if (hostFilterTab === "alerts" && (!node.alerts || node.alerts.length === 0)) return false;
      // Search filter
      if (hostSearchQuery.trim()) {
        const q = hostSearchQuery.toLowerCase();
        return (
          node.ip_address.toLowerCase().includes(q) ||
          node.hostname.toLowerCase().includes(q) ||
          node.display_location.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [telemetry, hostFilterTab, hostSearchQuery]);

  // Port breakdown indicators
  const portIndicators = useMemo(() => {
    if (!telemetry) return [];
    const counts: Record<number, number> = {};
    const all = [...telemetry.globe_nodes, ...telemetry.virtual_lan_nodes];
    all.forEach(n => {
      n.open_ports.forEach(p => {
        counts[p.port] = (counts[p.port] || 0) + 1;
      });
    });
    return Object.entries(counts)
      .map(([p, cnt]) => ({ port: Number(p), count: cnt }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [telemetry]);

  // Render Local 3D Globe with 4 Corner HUD Panels
  const renderLocalGlobeView = (isCombined = false) => (
    <div className={`globe-canvas-container ${isCombined ? "combined-view" : ""}`}>
      {/* The 3D WebGL Globe View */}
      <CyberGlobeView
        globeNodes={telemetry?.globe_nodes || []}
        virtualLanNodes={telemetry?.virtual_lan_nodes || []}
        connectionArcs={telemetry?.connection_arcs || []}
        selectedNode={selectedNode}
        onSelectNode={setSelectedNode}
        autoRotate={autoRotate}
        onToggleAutoRotate={() => setAutoRotate(!autoRotate)}
        viewMode={viewMode}
      />

      {/* =========================================================================
          HUD PANEL 1: TARGET IP INPUT & NETWORK SCANNING CONTROLS (Top-Left)
          ========================================================================= */}
      {hudVisible && (
        <div
          className={`hud-panel scanner-controls-hud ${panelCollapsed.scanner ? "collapsed" : ""} ${mobileActiveTab === "scanner" ? "mobile-active" : ""}`}
          onWheel={e => e.stopPropagation()}
          onTouchStart={e => e.stopPropagation()}
        >
          <div className="hud-panel-header">
            <div className="flex items-center gap-2">
              <Terminal size={15} style={{ color: "var(--nvidia-neon)" }} />
              <span className="hud-title">[TARGET IP INPUT &amp; SCANNER]</span>
            </div>
            <div className="flex items-center gap-2">
              <span className={`engine-badge ${scanStatus?.tool_status.nmap_installed ? "nmap" : "native"}`}>
                {scanStatus?.tool_status.nmap_installed ? "Nmap CLI Active" : "Native Socket Engine"}
              </span>
              <button
                type="button"
                className="hud-panel-collapse-btn"
                onClick={() => togglePanel("scanner")}
                title={panelCollapsed.scanner ? "Expand Scanner" : "Minimize Scanner"}
              >
                {panelCollapsed.scanner ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
              </button>
              {mobileActiveTab === "scanner" && (
                <button
                  type="button"
                  className="mobile-panel-close-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    setMobileActiveTab(null);
                  }}
                  title="Close Panel"
                >
                  <X size={14} />
                </button>
              )}
            </div>
          </div>

          {!panelCollapsed.scanner && (
            <div className="hud-body">
              {/* Target Specification Input */}
              <div className="input-group">
                <label className="input-label">TARGET IP / CIDR SCOPE:</label>
                <div className="target-input-row">
                  <input
                    type="text"
                    className="hud-text-input"
                    placeholder="e.g. 127.0.0.1 or 192.168.1.0/24"
                    value={targetInput}
                    onChange={e => setTargetInput(e.target.value)}
                    disabled={isScanning}
                  />
                </div>

                {/* Quick scope presets */}
                <div className="quick-presets-row">
                  <button
                    type="button"
                    className="preset-btn"
                    onClick={() => setTargetInput("127.0.0.1")}
                    disabled={isScanning}
                  >
                    Localhost
                  </button>
                  <button
                    type="button"
                    className="preset-btn"
                    onClick={() => setTargetInput("192.168.1.0/24")}
                    disabled={isScanning}
                  >
                    192.168.1.0/24
                  </button>
                  <button
                    type="button"
                    className="preset-btn"
                    onClick={() => setTargetInput("10.0.0.0/24")}
                    disabled={isScanning}
                  >
                    10.0.0.0/24
                  </button>
                </div>
              </div>

              {/* Scan Profile Selection */}
              <div className="input-group">
                <label className="input-label">AUTHORIZED SCAN PROFILE:</label>
                <select
                  className="hud-select"
                  value={selectedProfile}
                  onChange={e => setSelectedProfile(e.target.value)}
                  disabled={isScanning}
                >
                  <option value="quick_ports">Quick Port Discovery (Top Enterprise Services)</option>
                  <option value="service_discovery">Service &amp; Version Detection (Banner Grabs)</option>
                  <option value="ping_sweep">Host Discovery (Ping Sweep Only)</option>
                </select>
              </div>

              {/* Explicit Zero-Trust Target Authorization Checkbox */}
              <label className="auth-checkbox-label">
                <input
                  type="checkbox"
                  checked={userConfirmed}
                  onChange={e => setUserConfirmed(e.target.checked)}
                  disabled={isScanning}
                />
                <span>I confirm authorization to scan this target.</span>
              </label>

              {/* Scan Action Buttons */}
              <div className="hud-action-row">
                {!isScanning ? (
                  <button
                    className="scan-btn start"
                    onClick={handleStartScan}
                    disabled={!userConfirmed || !targetInput.trim()}
                  >
                    <Play size={14} />
                    <span>START SCAN</span>
                  </button>
                ) : (
                  <button className="scan-btn stop" onClick={handleStopScan}>
                    <Square size={14} />
                    <span>STOP SCAN ({scanTimer}s)</span>
                  </button>
                )}
                <button
                  className="scan-btn refresh"
                  onClick={() => {
                    fetchTelemetry();
                    fetchScanStatus();
                  }}
                  title="Refresh Telemetry"
                >
                  <RefreshCw size={14} />
                </button>
              </div>

              {/* Genuine Progress Updates */}
              {isScanning && (
                <div className="scan-progress-box">
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-mono" style={{ color: "var(--nvidia-neon)" }}>
                      {scanStatus?.active_scan.status_message || "Scanning scope..."}
                    </span>
                    <span className="text-slate-400">{scanStatus?.active_scan.progress_pct || 30}%</span>
                  </div>
                  <div className="progress-bar-track">
                    <div
                      className="progress-bar-fill"
                      style={{ width: `${scanStatus?.active_scan.progress_pct || 35}%` }}
                    />
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          HUD PANEL 2: LIVE DISCOVERED HOSTS & PORT INDICATORS (Top-Right)
          ========================================================================= */}
      {hudVisible && (
        <div
          className={`hud-panel hosts-hud ${panelCollapsed.hosts ? "collapsed" : ""} ${mobileActiveTab === "hosts" ? "mobile-active" : ""}`}
          onWheel={e => e.stopPropagation()}
          onTouchStart={e => e.stopPropagation()}
        >
          <div className="hud-panel-header">
            <div className="flex items-center gap-2">
              <Server size={15} style={{ color: "var(--nvidia-neon)" }} />
              <span className="hud-title">[LIVE DISCOVERED HOSTS]</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="hosts-count-badge">
                {allDiscoveredNodes.length} Total
              </span>
              <button
                type="button"
                className="hud-panel-collapse-btn"
                onClick={() => togglePanel("hosts")}
                title={panelCollapsed.hosts ? "Expand Hosts" : "Minimize Hosts"}
              >
                {panelCollapsed.hosts ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
              </button>
              {mobileActiveTab === "hosts" && (
                <button
                  type="button"
                  className="mobile-panel-close-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    setMobileActiveTab(null);
                  }}
                  title="Close Panel"
                >
                  <X size={14} />
                </button>
              )}
            </div>
          </div>

          {!panelCollapsed.hosts && (
            <>
              {/* Port Indicators Banner */}
              <div className="port-indicators-strip">
                <span className="port-label">PORT INDICATORS:</span>
                {portIndicators.map(pi => (
                  <span key={pi.port} className="port-indicator-chip">
                    <strong>{pi.port}:</strong> {pi.count}
                  </span>
                ))}
              </div>

              {/* Filter Tabs & Search */}
              <div className="hosts-filter-row">
                <div className="filter-tabs">
                  <button
                    className={`tab-btn ${hostFilterTab === "all" ? "active" : ""}`}
                    onClick={() => setHostFilterTab("all")}
                  >
                    All
                  </button>
                  <button
                    className={`tab-btn ${hostFilterTab === "online" ? "active" : ""}`}
                    onClick={() => setHostFilterTab("online")}
                  >
                    Online
                  </button>
                  <button
                    className={`tab-btn ${hostFilterTab === "alerts" ? "active" : ""}`}
                    onClick={() => setHostFilterTab("alerts")}
                  >
                    Alerts
                  </button>
                </div>
                <div className="search-box">
                  <Search size={13} className="text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search IP / Host..."
                    value={hostSearchQuery}
                    onChange={e => setHostSearchQuery(e.target.value)}
                  />
                </div>
              </div>

              {/* Scrollable Host Cards List */}
              <div className="hosts-list-scroll">
                {allDiscoveredNodes.length === 0 ? (
                  <div className="empty-hosts-state">
                    <Wifi size={20} className="text-slate-500" />
                    <span>No matching hosts found in active scope.</span>
                  </div>
                ) : (
                  allDiscoveredNodes.map(node => {
                    const isSelected = selectedNode?.id === node.id;
                    const hasAlert = node.alerts && node.alerts.length > 0;
                    return (
                      <div
                        key={node.id}
                        className={`host-item-card ${isSelected ? "selected" : ""} ${hasAlert ? "has-alert" : ""}`}
                        onClick={() => setSelectedNode(node)}
                      >
                        <div className="host-left">
                          <div className={`status-dot ${node.indicator.toLowerCase()}`} />
                          <div>
                            <div className="host-ip">{node.ip_address}</div>
                            <div className="host-name">{node.hostname || "local-device"}</div>
                          </div>
                        </div>
                        <div className="host-right">
                          <span className="host-ports-badge">
                            {node.open_ports_count} {node.open_ports_count === 1 ? "port" : "ports"}
                          </span>
                          {hasAlert && (
                            <AlertTriangle size={14} className="text-red-400 animate-pulse" />
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* =========================================================================
          HUD PANEL 3: WIRESHARK PACKET CAPTURE & TELEMETRY STREAM (Bottom-Right)
          ========================================================================= */}
      {hudVisible && (
        <div
          className={`hud-panel traffic-hud ${panelCollapsed.traffic ? "collapsed" : ""} ${mobileActiveTab === "traffic" ? "mobile-active" : ""}`}
          onWheel={e => e.stopPropagation()}
          onTouchStart={e => e.stopPropagation()}
        >
          <div className="hud-panel-header">
            <div className="flex items-center gap-2">
              <Radio size={15} style={{ color: "var(--nvidia-neon)" }} />
              <span className="hud-title">[WIRESHARK / TSHARK STREAM]</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="traffic-rate-badge">
                TCP: {trafficData?.metrics.tcp_stream_rate || "14.5 MB/s"}
              </span>
              <span className="traffic-rate-badge">
                UDP: {trafficData?.metrics.udp_stream_rate || "6.8 MB/s"}
              </span>
              <button
                type="button"
                className="hud-panel-collapse-btn"
                onClick={() => togglePanel("traffic")}
                title={panelCollapsed.traffic ? "Expand Traffic Stream" : "Minimize Traffic Stream"}
              >
                {panelCollapsed.traffic ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
              </button>
              {mobileActiveTab === "traffic" && (
                <button
                  type="button"
                  className="mobile-panel-close-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    setMobileActiveTab(null);
                  }}
                  title="Close Panel"
                >
                  <X size={14} />
                </button>
              )}
            </div>
          </div>

          {!panelCollapsed.traffic && (
            <>
              {/* Capture Controls */}
              <div className="traffic-controls-bar">
                <input
                  type="text"
                  className="bpf-input"
                  placeholder="BPF Filter (e.g. host 127.0.0.1 or port 443)..."
                  value={bpfFilterInput}
                  onChange={e => setBpfFilterInput(e.target.value)}
                  disabled={isCapturingLive}
                />
                <button
                  className={`capture-btn ${isCapturingLive ? "stop" : "start"}`}
                  onClick={handleToggleLiveCapture}
                >
                  {isCapturingLive ? <Square size={12} /> : <Play size={12} />}
                  <span>{isCapturingLive ? "STOP CAPTURE" : "LIVE CAPTURE"}</span>
                </button>
              </div>

              {/* Live Packet Feed */}
              <div className="traffic-packets-scroll">
                {trafficData?.packets.length === 0 ? (
                  <div className="empty-traffic-state">
                    <span>No packets captured on interface.</span>
                  </div>
                ) : (
                  trafficData?.packets.slice(0, 7).map((pkt, idx) => (
                    <div key={idx} className="packet-row">
                      <span className="pkt-time">{pkt.timestamp}</span>
                      <span className={`pkt-proto ${pkt.protocol.toLowerCase().replace(/[^a-z0-9]/g, "")}`}>
                        {pkt.protocol}
                      </span>
                      <span className="pkt-flow">
                        {pkt.src}:{pkt.src_port || "*"} &rarr; {pkt.dst}:{pkt.dst_port || "*"}
                      </span>
                      <span className="pkt-info">{pkt.info}</span>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* =========================================================================
          HUD PANEL 4: ACTIVE SECURITY ANALYSIS & ALERT FEED (Bottom-Left)
          ========================================================================= */}
      {hudVisible && (
        <div
          className={`hud-panel security-analysis-hud ${panelCollapsed.alerts ? "collapsed" : ""} ${mobileActiveTab === "alerts" ? "mobile-active" : ""}`}
          onWheel={e => e.stopPropagation()}
          onTouchStart={e => e.stopPropagation()}
        >
          <div className="hud-panel-header">
            <div className="flex items-center gap-2">
              <ShieldAlert size={15} className="text-red-400" />
              <span className="hud-title">[ACTIVE SECURITY ANALYSIS]</span>
            </div>
            <div className="flex items-center gap-2">
              <span className={`threat-level-tag ${telemetry?.recent_alerts.length ? "high" : "low"}`}>
                Threat Level: {telemetry?.recent_alerts.length ? "ELEVATED" : "LOW"}
              </span>
              <span className="anomalies-count">
                Anomalies: {telemetry?.recent_alerts.length || 0}
              </span>
              <button
                type="button"
                className="hud-panel-collapse-btn"
                onClick={() => togglePanel("alerts")}
                title={panelCollapsed.alerts ? "Expand Security Analysis" : "Minimize Security Analysis"}
              >
                {panelCollapsed.alerts ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
              </button>
              {mobileActiveTab === "alerts" && (
                <button
                  type="button"
                  className="mobile-panel-close-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    setMobileActiveTab(null);
                  }}
                  title="Close Panel"
                >
                  <X size={14} />
                </button>
              )}
            </div>
          </div>

          {!panelCollapsed.alerts && (
            <div className="alerts-feed-scroll">
              {telemetry?.recent_alerts.length === 0 ? (
                <div className="empty-alerts-state">
                  <CheckCircle size={18} className="text-emerald-400" />
                  <span>Zero anomalous intrusions detected. Operational posture verified.</span>
                </div>
              ) : (
                telemetry?.recent_alerts.slice(0, 3).map((alt, idx) => (
                  <div key={idx} className="hud-alert-item">
                    <div className="alert-item-header">
                      <span className={`alert-sev ${alt.severity.toLowerCase()}`}>
                        {alt.severity}
                      </span>
                      <strong className="alert-target">{alt.target_ip}</strong>
                      <span className="alert-time">{alt.created_at?.slice(11, 19) || "Now"}</span>
                    </div>
                    <div className="alert-fact">
                      <strong>Fact:</strong> {alt.observed_fact}
                    </div>
                    <div className="alert-threat">
                      <strong>Threat:</strong> {alt.suspected_threat}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          HUD PANEL 5: SELECTED DEVICE DETAILS & SOC FINDINGS (Slide-in HUD)
          ========================================================================= */}
      {selectedNode && (
        <div className="device-details-hud-slide">
          <div className="details-header">
            <div className="flex items-center gap-2">
              <Laptop size={18} style={{ color: "var(--nvidia-neon)" }} />
              <div>
                <h3 className="details-ip">{selectedNode.ip_address}</h3>
                <span className="details-host">{selectedNode.hostname || "local-device"}</span>
              </div>
            </div>
            <button className="close-details-btn" onClick={() => setSelectedNode(null)}>
              <X size={16} />
            </button>
          </div>

          <div className="details-body">
            {/* Geolocation & Enclave Status */}
            <div className="details-section">
              <div className="section-label">GEOLOCATION &amp; TOPOLOGY</div>
              <div className="detail-row">
                <span>Location Type:</span>
                <span className={`confidence-badge ${selectedNode.is_private ? "lan" : "public"}`}>
                  {selectedNode.location_confidence}
                </span>
              </div>
              <div className="detail-row">
                <span>Display Location:</span>
                <span className="val-text">{selectedNode.display_location}</span>
              </div>
              <div className="detail-row">
                <span>Latency:</span>
                <span className="val-text">{selectedNode.latency_ms || 1.2} ms</span>
              </div>
              <div className="detail-row">
                <span>Security Baseline:</span>
                <span className={`val-text ${selectedNode.in_baseline ? "text-emerald-400" : "text-amber-400"}`}>
                  {selectedNode.in_baseline ? "Approved in Baseline" : "Unapproved / New Device"}
                </span>
              </div>
            </div>

            {/* Observed Open Ports & Services Table */}
            <div className="details-section">
              <div className="section-label">
                OBSERVED OPEN PORTS ({selectedNode.open_ports_count})
              </div>
              {selectedNode.open_ports.length === 0 ? (
                <div className="text-slate-400 text-xs italic">No open service ports detected.</div>
              ) : (
                <div className="ports-table-wrap">
                  <table className="hud-table">
                    <thead>
                      <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Banner / Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedNode.open_ports.map((p, idx) => (
                        <tr key={idx}>
                          <td className="text-cyan-400 font-mono font-bold">:{p.port}</td>
                          <td className="text-slate-300 font-mono">{p.protocol}</td>
                          <td className="text-emerald-400">{p.service_name}</td>
                          <td className="text-slate-400 text-xs">{p.banner || p.service_name}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Relevant Findings */}
            {deviceDetails?.relevant_findings && deviceDetails.relevant_findings.length > 0 && (
              <div className="details-section">
                <div className="section-label">FACTUAL FINDINGS &amp; RECOMMENDATIONS</div>
                <div className="findings-list">
                  {deviceDetails.relevant_findings.map((f, idx) => (
                    <div key={idx} className={`finding-box ${f.severity.toLowerCase()}`}>
                      <div className="finding-title">
                        <AlertTriangle size={12} />
                        <strong>{f.title}</strong>
                      </div>
                      <p className="finding-detail">{f.detail}</p>
                      <small className="finding-rec">
                        <strong>Rec:</strong> {f.recommendation}
                      </small>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actions Row */}
            <div className="details-actions-row">
              <button
                className="hud-action-btn ai-btn"
                onClick={() => handleRequestAiExplain(selectedNode.ip_address)}
              >
                <Cpu size={14} />
                <span>AI Threat Analysis</span>
              </button>
              <button
                className="hud-action-btn wireshark-btn"
                onClick={() => {
                  setTrafficFilterHost(selectedNode.ip_address);
                  setBpfFilterInput(`host ${selectedNode.ip_address}`);
                  setNotice(`Filtered Wireshark packet capture stream to ${selectedNode.ip_address}`);
                }}
              >
                <Radio size={14} />
                <span>Inspect Packets</span>
              </button>
              {!selectedNode.in_baseline && (
                <button
                  className="hud-action-btn baseline-btn"
                  onClick={() => handlePromoteBaseline(selectedNode.ip_address)}
                >
                  <CheckCircle size={14} />
                  <span>Approve in Baseline</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="cyber-globe-page">
      {/* Top Cyber Command Bar */}
      <header className="globe-top-command-bar">
        <div className="title-group">
          <div className="radar-icon-box">
            <GlobeIcon size={22} className="animate-spin-slow" style={{ color: "var(--nvidia-neon)" }} />
            <span className="radar-ping" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="cyber-globe-title">[CYBER NETWORK GLOBE]</h1>
              <span className="badge-3d-hud">3D SOC HUD</span>
            </div>
            <p className="cyber-globe-subtitle">
              Interactive 3D Geospatial Defense &bull; Zero-Trust Topology &bull; Live Telemetry
            </p>
          </div>
        </div>

        {/* Global Threat Intelligence Layer Switcher */}
        <div className="global-threat-intel-control">
          <div className="control-label-tag">
            <Radio size={13} className="text-red-400 radware-pulse-icon" />
            <span>GLOBAL THREAT INTELLIGENCE:</span>
          </div>
          <div className="threat-mode-buttons">
            <button
              type="button"
              className={`threat-mode-btn ${threatIntelMode === "local" ? "active" : ""}`}
              onClick={() => setThreatIntelMode("local")}
              title="Display AgentShield Authorized Local Network Scans & Telemetry"
            >
              <Shield size={12} />
              <span>Local Network</span>
            </button>
            <button
              type="button"
              className={`threat-mode-btn ${threatIntelMode === "global" ? "active-global" : ""}`}
              onClick={() => setThreatIntelMode("global")}
              title="Display Radware Public Live Threat Map"
            >
              <Radio size={12} />
              <span>Global Threat Map</span>
              <span className="live-pulse-dot" />
            </button>
            <button
              type="button"
              className={`threat-mode-btn ${threatIntelMode === "combined" ? "active-combined" : ""}`}
              onClick={() => setThreatIntelMode("combined")}
              title="Side-by-Side Dual View: Local Telemetry + Global Threat Map"
            >
              <Layers size={12} />
              <span>Combined View</span>
            </button>
          </div>
        </div>

        {/* Operational Mode Toggle */}
        <div className="operational-mode-switch">
          <button
            className={`mode-btn ${operationalMode === "live" ? "active-live" : ""}`}
            onClick={() => {
              setOperationalMode("live");
              fetchTelemetry("live");
            }}
          >
            <Activity size={14} />
            <span>LIVE SOC TELEMETRY</span>
          </button>
          <button
            className={`mode-btn ${operationalMode === "demo" ? "active-demo" : ""}`}
            onClick={() => {
              setOperationalMode("demo");
              fetchTelemetry("demo");
            }}
          >
            <Sparkles size={14} />
            <span>THREAT SIMULATION DEMO</span>
          </button>
        </div>

        {/* Global View Perspective & HUD Visibility Controls */}
        <div className="view-mode-tabs">
          <button
            className={`view-tab ${viewMode === "3d" ? "active" : ""}`}
            onClick={() => setViewMode("3d")}
          >
            <GlobeIcon size={14} />
            <span>3D Earth</span>
          </button>
          <button
            className={`view-tab ${viewMode === "lan" ? "active" : ""}`}
            onClick={() => setViewMode("lan")}
          >
            <Shield size={14} />
            <span>Virtual LAN</span>
          </button>
          <button
            className={`view-tab ${viewMode === "split" ? "active" : ""}`}
            onClick={() => setViewMode("split")}
          >
            <Layers size={14} />
            <span>Split HUD</span>
          </button>

          {/* HUD Overlay Clean View Toggle */}
          <button
            className={`view-tab hud-toggle-btn ${hudVisible ? "active" : ""}`}
            onClick={() => setHudVisible(!hudVisible)}
            title={hudVisible ? "Hide HUD Overlays for Clean Unobstructed 3D Globe" : "Show HUD Overlays"}
          >
            {hudVisible ? <Eye size={14} /> : <EyeOff size={14} />}
            <span>{hudVisible ? "HUD Overlays (ON)" : "Clean Globe (OFF)"}</span>
          </button>
        </div>
      </header>

      {/* Simulation Banner Warning when in Demo Mode */}
      {operationalMode === "demo" && (
        <div className="demo-simulation-banner">
          <AlertTriangle size={16} className="text-amber-400" />
          <span>
            <strong>SIMULATION DEMO ACTIVE:</strong> Visualizing multi-region penetration probe, C2 egress, and rogue workstation. Real telemetry remains completely untouched.
          </span>
        </div>
      )}

      {/* Alert Notices */}
      {error && (
        <div className="hud-toast-alert error">
          <span>{error}</span>
          <button onClick={() => setError("")}><X size={14} /></button>
        </div>
      )}
      {notice && (
        <div className="hud-toast-alert success">
          <span>{notice}</span>
          <button onClick={() => setNotice("")}><X size={14} /></button>
        </div>
      )}

      {/* Main Viewport Container */}
      {threatIntelMode === "local" && renderLocalGlobeView(false)}

      {threatIntelMode === "global" && (
        <RadwareThreatMap
          isCombinedView={false}
          onOpenAmojaBriefing={() => handleRequestThreatIntelExplain()}
        />
      )}

      {threatIntelMode === "combined" && (
        <div className="cyber-globe-combined-viewport">
          <div className="combined-pane local-pane">
            <div className="combined-pane-header local-header">
              <div className="flex items-center gap-2">
                <Shield size={14} />
                <span>LOCAL NETWORK TELEMETRY &bull; ZERO-TRUST BOUNDARY</span>
              </div>
              <span className="text-xs font-mono">{allDiscoveredNodes.length} Hosts Monitored</span>
            </div>
            <div className="combined-pane-content">
              {renderLocalGlobeView(true)}
            </div>
          </div>

          <div className="combined-pane global-pane">
            <div className="combined-pane-header global-header">
              <div className="flex items-center gap-2">
                <Radio size={14} className="radware-pulse-icon" />
                <span>GLOBAL THREAT INTELLIGENCE &bull; RADWARE LIVE THREAT MAP</span>
              </div>
              <span className="text-xs font-mono">External Public Deception Feed</span>
            </div>
            <div className="combined-pane-content">
              <RadwareThreatMap
                isCombinedView={true}
                onOpenAmojaBriefing={() => handleRequestThreatIntelExplain()}
              />
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          MODAL 1: AI EXPLAINABLE SOC ANALYST ASSESSMENT (Fact-Checked, No Hallucinations)
          ========================================================================= */}
      {showAiModal && (
        <div className="ai-modal-backdrop" onClick={() => setShowAiModal(false)}>
          <div className="ai-modal-content" onClick={e => e.stopPropagation()}>
            <div className="ai-modal-header">
              <div className="flex items-center gap-2">
                <Cpu size={20} className="text-cyan-400 animate-pulse" />
                <div>
                  <h3 className="ai-modal-title">AMOJA AI // Explainable Security Assessment</h3>
                  <small className="ai-modal-sub">
                    Evidence-Backed Threat Reasoning &bull; Zero Hallucinated Telemetry
                  </small>
                </div>
              </div>
              <button className="close-btn" onClick={() => setShowAiModal(false)}>
                <X size={16} />
              </button>
            </div>

            {loadingAiExplain ? (
              <div className="ai-modal-loading">
                <RefreshCw size={28} className="text-cyan-400 animate-spin" />
                <span>Analyzing device scan evidence through AgentShield Policy Gateway...</span>
              </div>
            ) : aiExplanation ? (
              <div className="ai-modal-body">
                {/* Verdict & Score Banner */}
                <div className="verdict-banner">
                  <div className="verdict-block">
                    <span className="verdict-label">DECISION VERDICT:</span>
                    <strong className={`verdict-val ${aiExplanation.analyst_verdict.toLowerCase()}`}>
                      {aiExplanation.analyst_verdict}
                    </strong>
                  </div>
                  <div className="risk-score-block">
                    <span className="verdict-label">CALCULATED RISK:</span>
                    <strong className={`risk-val ${aiExplanation.risk_score >= 70 ? "high" : aiExplanation.risk_score >= 40 ? "med" : "low"}`}>
                      {aiExplanation.risk_score} / 100
                    </strong>
                  </div>
                  <div className="confidence-block">
                    <span className="verdict-label">CONFIDENCE:</span>
                    <strong className="confidence-val">{aiExplanation.confidence_level}</strong>
                  </div>
                </div>

                {/* Summary */}
                <div className="ai-summary-box">
                  <p>{aiExplanation.summary}</p>
                </div>

                {/* Evidence Chain */}
                <div className="ai-section">
                  <div className="ai-section-title">VERIFIED EVIDENCE CHAIN:</div>
                  <ul className="evidence-list">
                    {aiExplanation.evidence_chain.map((ev, i) => (
                      <li key={i}>{ev}</li>
                    ))}
                  </ul>
                </div>

                {/* Recommended Defensive Actions */}
                <div className="ai-section">
                  <div className="ai-section-title">RECOMMENDED DEFENSIVE INTERVENTIONS:</div>
                  <ul className="recs-list">
                    {aiExplanation.recommended_defensive_actions.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>

                {/* Truthfulness & Factual Verification Guarantee */}
                <div className="ai-factual-guarantee">
                  <Shield size={14} className="text-cyan-400 flex-shrink-0" />
                  <span>{aiExplanation.verified_evidence_statement}</span>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* =========================================================================
          MODAL 2: AMOJA AI THREAT INTELLIGENCE & COMPARATIVE POSTURE BRIEFING
          ========================================================================= */}
      {showThreatIntelModal && (
        <div className="ai-modal-backdrop" onClick={() => setShowThreatIntelModal(false)}>
          <div className="threat-intel-modal-content" onClick={e => e.stopPropagation()}>
            <div className="ai-modal-header">
              <div className="flex items-center gap-2">
                <Cpu size={20} className="text-cyan-400 animate-pulse" />
                <div>
                  <h3 className="ai-modal-title">AMOJA AI // Threat Intelligence &amp; Local Posture Assessment</h3>
                  <small className="ai-modal-sub">
                    Strict Data Segregation &bull; Verified Sources &bull; Zero Hallucinated Telemetry
                  </small>
                </div>
              </div>
              <button className="close-btn" onClick={() => setShowThreatIntelModal(false)}>
                <X size={16} />
              </button>
            </div>

            {/* Language Switcher and Audio Read Aloud Strip */}
            <div className="threat-intel-lang-strip">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">LANGUAGE:</span>
                <div className="lang-buttons-row">
                  <button
                    type="button"
                    className={`lang-btn ${threatIntelLanguage === "en" ? "active" : ""}`}
                    onClick={() => {
                      setThreatIntelLanguage("en");
                      handleRequestThreatIntelExplain("en");
                    }}
                  >
                    English
                  </button>
                  <button
                    type="button"
                    className={`lang-btn ${threatIntelLanguage === "hi" ? "active" : ""}`}
                    onClick={() => {
                      setThreatIntelLanguage("hi");
                      handleRequestThreatIntelExplain("hi");
                    }}
                  >
                    हिन्दी (Hindi)
                  </button>
                  <button
                    type="button"
                    className={`lang-btn ${threatIntelLanguage === "mr" ? "active" : ""}`}
                    onClick={() => {
                      setThreatIntelLanguage("mr");
                      handleRequestThreatIntelExplain("mr");
                    }}
                  >
                    मराठी (Marathi)
                  </button>
                </div>
              </div>

              {threatIntelExplanation?.spoken_briefing && (
                <button
                  type="button"
                  className="speak-briefing-btn"
                  onClick={() => handleSpeakBriefing(threatIntelExplanation.spoken_briefing)}
                  title="Read briefing aloud with speech synthesis"
                >
                  <Volume2 size={13} />
                  <span>Listen Voice Briefing</span>
                </button>
              )}
            </div>

            {loadingThreatIntelExplain ? (
              <div className="ai-modal-loading">
                <RefreshCw size={28} className="text-cyan-400 animate-spin" />
                <span>Synthesizing verified threat intelligence with AgentShield Zero-Trust Gateway...</span>
              </div>
            ) : threatIntelExplanation ? (
              <div className="ai-modal-body">
                {/* Spoken Briefing Banner */}
                <div className="ai-summary-box">
                  <p><strong>AMOJA Executive Briefing:</strong> {threatIntelExplanation.spoken_briefing}</p>
                </div>

                {/* Cards Grid: Global vs Local */}
                <div className="threat-intel-cards-grid">
                  {/* Global Card */}
                  <div className="threat-intel-card global">
                    <div className="intel-card-header">
                      <Radio size={14} className="text-red-400 radware-pulse-icon" />
                      <span>GLOBAL THREAT INTEL (RADWARE)</span>
                    </div>
                    <p className="text-xs text-slate-300">
                      {threatIntelExplanation.global_threat_intel.threat_landscape_summary}
                    </p>
                    <div className="text-xs font-bold text-red-400 mt-1">Typical Vectors:</div>
                    <ul className="intel-vector-list">
                      {threatIntelExplanation.global_threat_intel.typical_attack_vectors.map((vec, i) => (
                        <li key={i}>{vec}</li>
                      ))}
                    </ul>
                    <small className="text-slate-400 text-xs italic mt-auto">
                      Status: {threatIntelExplanation.global_threat_intel.data_interface_status}
                    </small>
                  </div>

                  {/* Local Card */}
                  <div className="threat-intel-card local">
                    <div className="intel-card-header">
                      <Shield size={14} className="text-emerald-400" />
                      <span>LOCAL NETWORK SCOPE (AGENTSHIELD)</span>
                    </div>
                    <div className="text-xs text-slate-300 flex flex-col gap-1">
                      <div><strong>Discovered Hosts:</strong> {threatIntelExplanation.local_network_findings.discovered_hosts_count}</div>
                      <div><strong>Active Security Alerts:</strong> {threatIntelExplanation.local_network_findings.active_alerts_count}</div>
                      <div><strong>Top Observed Ports:</strong></div>
                      <ul className="intel-vector-list">
                        {threatIntelExplanation.local_network_findings.top_exposed_ports.map((p, i) => (
                          <li key={i}>{p}</li>
                        ))}
                      </ul>
                    </div>
                    <small className="text-emerald-400 text-xs font-mono mt-auto">
                      {threatIntelExplanation.local_network_findings.telemetry_egress_policy}
                    </small>
                  </div>
                </div>

                {/* Comparative Assessment */}
                <div className="intel-comparison-box">
                  <div className="intel-comparison-title">STRICT ZERO-TRUST SEGREGATION &bull; COMPARATIVE ASSESSMENT</div>
                  <p className="intel-comparison-text">
                    {threatIntelExplanation.comparative_analysis.key_distinction}
                  </p>
                  <p className="intel-comparison-text text-amber-300">
                    <strong>Posture Recommendation:</strong> {threatIntelExplanation.comparative_analysis.posture_recommendation}
                  </p>
                </div>

                {/* Privacy & Zero-Egress Guarantee Seal */}
                <div className="ai-factual-guarantee">
                  <Shield size={14} className="text-cyan-400 flex-shrink-0" />
                  <span>{threatIntelExplanation.privacy_guarantee}</span>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* Mobile HUD Switcher Tabs Bar (Hidden on Desktop & Tablet via CSS) */}
      {threatIntelMode !== "global" && (
        <div className="mobile-hud-tabs-bar">
          <button
            type="button"
            className={`mobile-tab-btn ${mobileActiveTab === "scanner" ? "active" : ""}`}
            onClick={() => setMobileActiveTab(mobileActiveTab === "scanner" ? null : "scanner")}
          >
            <Terminal size={14} />
            <span>Scanner</span>
          </button>
          <button
            type="button"
            className={`mobile-tab-btn ${mobileActiveTab === "hosts" ? "active" : ""}`}
            onClick={() => setMobileActiveTab(mobileActiveTab === "hosts" ? null : "hosts")}
          >
            <Server size={14} />
            <span>Hosts ({allDiscoveredNodes.length})</span>
          </button>
          <button
            type="button"
            className={`mobile-tab-btn ${mobileActiveTab === "alerts" ? "active" : ""}`}
            onClick={() => setMobileActiveTab(mobileActiveTab === "alerts" ? null : "alerts")}
          >
            <ShieldAlert size={14} />
            <span>Alerts ({telemetry?.recent_alerts.length || 0})</span>
          </button>
          <button
            type="button"
            className={`mobile-tab-btn ${mobileActiveTab === "traffic" ? "active" : ""}`}
            onClick={() => setMobileActiveTab(mobileActiveTab === "traffic" ? null : "traffic")}
          >
            <Radio size={14} />
            <span>Traffic</span>
          </button>
        </div>
      )}
    </div>
  );
};
