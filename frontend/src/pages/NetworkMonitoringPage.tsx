import React, { useState, useEffect } from "react";
import {
  Activity, Radio, Shield, ShieldAlert, ShieldCheck, Play, Pause,
  Square, AlertOctagon, RefreshCw, Plus, Trash2, CheckCircle2,
  Server, Globe, Clock, AlertTriangle, Eye, Layers, Wifi, WifiOff,
  Filter, Search, ArrowRight, Zap, Ban
} from "lucide-react";
import {
  NetworkMonitoringStatus, ApprovedScope, NetworkExclusion,
  NetworkAsset, ServiceObservation, NetworkSecurityAlert,
  ScanJob, ScanDiff
} from "../types";
import { request } from "../api";

export const NetworkMonitoringPage: React.FC = () => {
  const [status, setStatus] = useState<NetworkMonitoringStatus | null>(null);
  const [scopes, setScopes] = useState<ApprovedScope[]>([]);
  const [exclusions, setExclusions] = useState<NetworkExclusion[]>([]);
  const [assets, setAssets] = useState<NetworkAsset[]>([]);
  const [services, setServices] = useState<ServiceObservation[]>([]);
  const [alerts, setAlerts] = useState<NetworkSecurityAlert[]>([]);
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [diff, setDiff] = useState<ScanDiff | null>(null);

  const [activeTab, setActiveTab] = useState<
    "hosts" | "services" | "diff" | "alerts" | "history" | "scopes"
  >("hosts");

  const [loading, setLoading] = useState(false);
  const [scanningNow, setScanningNow] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  // Modals / forms
  const [showAddScope, setShowAddScope] = useState(false);
  const [newScopeName, setNewScopeName] = useState("");
  const [newScopeCidr, setNewScopeCidr] = useState("");
  const [newScopeTag, setNewScopeTag] = useState("Internal Enclave");

  const [showAddExclusion, setShowAddExclusion] = useState(false);
  const [newExclIp, setNewExclIp] = useState("");
  const [newExclReason, setNewExclReason] = useState("");

  const [showEmergencyModal, setShowEmergencyModal] = useState(false);
  const [emergencyReason, setEmergencyReason] = useState("");

  async function loadAllData() {
    try {
      const [st, scRes, asList, srvList, altList, jobList, diffRes] = await Promise.all([
        request<NetworkMonitoringStatus>("/api/network/status"),
        request<{ scopes: ApprovedScope[]; exclusions: NetworkExclusion[] }>("/api/network/scopes"),
        request<NetworkAsset[]>("/api/network/assets"),
        request<ServiceObservation[]>("/api/network/services"),
        request<NetworkSecurityAlert[]>("/api/network/alerts?limit=50"),
        request<ScanJob[]>("/api/network/jobs?limit=25"),
        request<ScanDiff>("/api/network/diff")
      ]);

      setStatus(st);
      setScopes(scRes.scopes);
      setExclusions(scRes.exclusions);
      setAssets(asList);
      setServices(srvList);
      setAlerts(altList);
      setJobs(jobList);
      setDiff(diffRes);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load network monitoring telemetry");
    }
  }

  useEffect(() => {
    loadAllData();
    const interval = window.setInterval(loadAllData, 5000);
    return () => window.clearInterval(interval);
  }, []);

  async function handleStart() {
    setLoading(true);
    try {
      await request("/api/network/controls/start", { method: "POST" });
      setNotice("Continuous network monitoring started.");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start monitoring");
    } finally {
      setLoading(false);
    }
  }

  async function handleStop() {
    setLoading(true);
    try {
      await request("/api/network/controls/stop", { method: "POST" });
      setNotice("Continuous network monitoring stopped.");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stop monitoring");
    } finally {
      setLoading(false);
    }
  }

  async function handlePause() {
    setLoading(true);
    try {
      await request("/api/network/controls/pause", { method: "POST" });
      setNotice("Continuous sweeps paused.");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to pause monitoring");
    } finally {
      setLoading(false);
    }
  }

  async function handleResume() {
    setLoading(true);
    try {
      await request("/api/network/controls/resume", { method: "POST" });
      setNotice("Continuous sweeps resumed.");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to resume monitoring");
    } finally {
      setLoading(false);
    }
  }

  async function handleEmergencyStop() {
    setLoading(true);
    try {
      await request("/api/network/controls/emergency-stop", {
        method: "POST",
        body: JSON.stringify({ reason: emergencyReason || "Operator manual emergency stop" })
      });
      setNotice("GLOBAL EMERGENCY STOP ACTIVATED. All network scans terminated.");
      setShowEmergencyModal(false);
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to trigger emergency stop");
    } finally {
      setLoading(false);
    }
  }

  async function handleResetEmergencyStop() {
    setLoading(true);
    try {
      await request("/api/network/controls/reset-emergency-stop", { method: "POST" });
      setNotice("Emergency stop cleared. Continuous scanning can be resumed.");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reset emergency stop");
    } finally {
      setLoading(false);
    }
  }

  async function handleScanNow() {
    setScanningNow(true);
    try {
      await request("/api/network/controls/scan-now", { method: "POST" });
      setNotice("Authorized scan sweep complete.");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan cycle failed");
    } finally {
      setScanningNow(false);
    }
  }

  async function handleAddScope(e: React.FormEvent) {
    e.preventDefault();
    if (!newScopeName || !newScopeCidr) return;
    try {
      await request("/api/network/scopes", {
        method: "POST",
        body: JSON.stringify({
          name: newScopeName,
          cidr_or_ip: newScopeCidr,
          asset_tag: newScopeTag
        })
      });
      setNotice(`Approved scope ${newScopeCidr} added.`);
      setShowAddScope(false);
      setNewScopeName("");
      setNewScopeCidr("");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add scope");
    }
  }

  async function handleDeleteScope(id: number) {
    if (!window.confirm("Remove this approved CIDR scope from monitoring?")) return;
    try {
      await request(`/api/network/scopes/${id}`, { method: "DELETE" });
      setNotice("Scope removed.");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove scope");
    }
  }

  async function handleAddExclusion(e: React.FormEvent) {
    e.preventDefault();
    if (!newExclIp || !newExclReason) return;
    try {
      await request("/api/network/exclusions", {
        method: "POST",
        body: JSON.stringify({
          ip_address: newExclIp,
          reason: newExclReason
        })
      });
      setNotice(`Host ${newExclIp} added to exclusions.`);
      setShowAddExclusion(false);
      setNewExclIp("");
      setNewExclReason("");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add exclusion");
    }
  }

  async function handleDeleteExclusion(id: number) {
    if (!window.confirm("Remove this IP exclusion?")) return;
    try {
      await request(`/api/network/exclusions/${id}`, { method: "DELETE" });
      setNotice("Exclusion removed.");
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove exclusion");
    }
  }

  async function handlePromoteBaseline(ip: string) {
    try {
      await request(`/api/network/assets/${ip}/baseline`, { method: "POST" });
      setNotice(`Asset ${ip} has been approved and promoted to the baseline.`);
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to promote asset");
    }
  }

  async function handleUpdateAlertStatus(id: number, newStatus: string) {
    try {
      await request(`/api/network/alerts/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: newStatus })
      });
      setNotice(`Alert #${id} updated to ${newStatus}.`);
      loadAllData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update alert");
    }
  }

  const filteredAssets = assets.filter(a => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      a.ip_address.toLowerCase().includes(q) ||
      (a.hostname && a.hostname.toLowerCase().includes(q))
    );
  });

  return (
    <div className="network-monitoring-page" style={{ padding: "1.5rem" }}>
      {/* Top Banner & Control Deck */}
      <div
        className="card control-header"
        style={{
          background: "linear-gradient(135deg, rgba(17, 24, 39, 0.95), rgba(15, 23, 42, 0.98))",
          border: "1px solid rgba(59, 130, 246, 0.2)",
          borderRadius: "12px",
          padding: "1.5rem",
          marginBottom: "1.5rem",
          boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.4)"
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.25rem" }}>
              <div
                style={{
                  background: "rgba(59, 130, 246, 0.15)",
                  color: "#3b82f6",
                  padding: "0.5rem",
                  borderRadius: "8px",
                  display: "flex"
                }}
              >
                <Radio size={24} className={status?.state === "SCANNING" ? "animate-pulse" : ""} />
              </div>
              <h1 style={{ margin: 0, fontSize: "1.5rem", fontWeight: "700", color: "#f8fafc" }}>
                Continuous Network Monitoring
              </h1>
              <span
                className={`badge badge-${
                  status?.state === "ACTIVE"
                    ? "success"
                    : status?.state === "SCANNING"
                    ? "primary"
                    : status?.state === "PAUSED"
                    ? "warning"
                    : status?.state === "EMERGENCY_STOP"
                    ? "danger"
                    : "secondary"
                }`}
                style={{
                  fontSize: "0.8rem",
                  padding: "0.35rem 0.75rem",
                  borderRadius: "9999px",
                  display: "flex",
                  alignItems: "center",
                  gap: "0.4rem"
                }}
              >
                <span
                  style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    background:
                      status?.state === "ACTIVE"
                        ? "#10b981"
                        : status?.state === "SCANNING"
                        ? "#3b82f6"
                        : status?.state === "EMERGENCY_STOP"
                        ? "#ef4444"
                        : "#f59e0b"
                  }}
                />
                {status?.state || "LOADING"}
              </span>
            </div>
            <p style={{ margin: 0, color: "#94a3b8", fontSize: "0.875rem" }}>
              Zero-Trust continuous discovery engine strictly confined to approved CIDR scopes.
              Empirical facts isolated from suspected threat assessments.
            </p>
          </div>

          {/* Action Toolbar */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
            <button
              className="btn btn-secondary"
              onClick={loadAllData}
              title="Refresh telemetry"
              style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}
            >
              <RefreshCw size={15} /> Refresh
            </button>

            {status?.state === "EMERGENCY_STOP" ? (
              <button
                className="btn btn-warning"
                onClick={handleResetEmergencyStop}
                disabled={loading}
                style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}
              >
                <ShieldCheck size={16} /> Reset Emergency Stop
              </button>
            ) : (
              <>
                {status?.service_enabled && !status.is_paused ? (
                  <button
                    className="btn btn-secondary"
                    onClick={handlePause}
                    disabled={loading}
                    style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}
                  >
                    <Pause size={15} /> Pause
                  </button>
                ) : status?.service_enabled && status.is_paused ? (
                  <button
                    className="btn btn-primary"
                    onClick={handleResume}
                    disabled={loading}
                    style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}
                  >
                    <Play size={15} /> Resume
                  </button>
                ) : (
                  <button
                    className="btn btn-success"
                    onClick={handleStart}
                    disabled={loading}
                    style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}
                  >
                    <Play size={15} /> Start Monitoring
                  </button>
                )}

                {status?.service_enabled && (
                  <button
                    className="btn btn-secondary"
                    onClick={handleStop}
                    disabled={loading}
                    style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}
                  >
                    <Square size={14} /> Stop
                  </button>
                )}

                <button
                  className="btn btn-primary"
                  onClick={handleScanNow}
                  disabled={scanningNow || status?.state === "SCANNING"}
                  style={{
                    background: "linear-gradient(135deg, #2563eb, #1d4ed8)",
                    display: "flex",
                    alignItems: "center",
                    gap: "0.4rem"
                  }}
                >
                  <Zap size={15} className={scanningNow ? "animate-spin" : ""} />
                  {scanningNow ? "Scanning Scope..." : "Scan Scope Now"}
                </button>

                <button
                  className="btn btn-danger"
                  onClick={() => setShowEmergencyModal(true)}
                  style={{
                    background: "#dc2626",
                    display: "flex",
                    alignItems: "center",
                    gap: "0.4rem"
                  }}
                >
                  <AlertOctagon size={16} /> Emergency Stop
                </button>
              </>
            )}
          </div>
        </div>

        {/* Alerts and Notices */}
        {error && (
          <div className="alert error" style={{ marginTop: "1rem" }}>
            <span><strong>Error:</strong> {error}</span>
            <button onClick={() => setError("")}>×</button>
          </div>
        )}
        {notice && (
          <div className="alert success" style={{ marginTop: "1rem" }}>
            <span>{notice}</span>
            <button onClick={() => setNotice("")}>×</button>
          </div>
        )}

        {/* Telemetry KPI Cards */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))",
            gap: "1rem",
            marginTop: "1.25rem"
          }}
        >
          <div className="card" style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)" }}>
            <div style={{ color: "#94a3b8", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Next Scheduled Scan
            </div>
            <div style={{ fontSize: "1.25rem", fontWeight: "700", color: "#60a5fa", marginTop: "0.25rem" }}>
              {status?.is_paused ? "PAUSED" : status?.service_enabled ? `in ${status.seconds_until_next_scan}s` : "DISABLED"}
            </div>
            <div style={{ color: "#64748b", fontSize: "0.75rem", marginTop: "0.25rem" }}>
              Interval: {status?.scan_interval_seconds || 60}s | Limit: {status?.scan_duration_limit_seconds || 120}s
            </div>
          </div>

          <div className="card" style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)" }}>
            <div style={{ color: "#94a3b8", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Approved Scope Enclave
            </div>
            <div style={{ fontSize: "1.25rem", fontWeight: "700", color: "#34d399", marginTop: "0.25rem" }}>
              {status?.approved_scopes_count || 0} Subnets
            </div>
            <div style={{ color: "#64748b", fontSize: "0.75rem", marginTop: "0.25rem" }}>
              {status?.exclusions_count || 0} Excluded Sensitive IPs
            </div>
          </div>

          <div className="card" style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)" }}>
            <div style={{ color: "#94a3b8", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Reachable Hosts & Assets
            </div>
            <div style={{ fontSize: "1.25rem", fontWeight: "700", color: "#f8fafc", marginTop: "0.25rem" }}>
              {status?.reachable_assets || 0} / {status?.total_assets_known || 0}
            </div>
            <div style={{ color: "#64748b", fontSize: "0.75rem", marginTop: "0.25rem" }}>
              {diff?.newly_discovered_hosts.length || 0} unbaselined new hosts
            </div>
          </div>

          <div className="card" style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)" }}>
            <div style={{ color: "#94a3b8", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Observed Open Services
            </div>
            <div style={{ fontSize: "1.25rem", fontWeight: "700", color: "#c084fc", marginTop: "0.25rem" }}>
              {status?.total_open_services || 0} Ports
            </div>
            <div style={{ color: "#64748b", fontSize: "0.75rem", marginTop: "0.25rem" }}>
              {diff?.unexpected_open_ports.length || 0} unexpected ports open
            </div>
          </div>

          <div className="card" style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)" }}>
            <div style={{ color: "#94a3b8", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Security Baseline Alerts
            </div>
            <div
              style={{
                fontSize: "1.25rem",
                fontWeight: "700",
                color: (status?.unresolved_alerts ?? 0) > 0 ? "#f87171" : "#10b981",
                marginTop: "0.25rem"
              }}
            >
              {status?.unresolved_alerts || 0} Open
            </div>
            <div style={{ color: "#64748b", fontSize: "0.75rem", marginTop: "0.25rem" }}>
              Verified Facts vs Threat Vectors
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div
        className="tabs-header"
        style={{
          display: "flex",
          gap: "0.5rem",
          borderBottom: "1px solid rgba(255, 255, 255, 0.1)",
          marginBottom: "1.5rem",
          overflowX: "auto"
        }}
      >
        <button
          className={`tab-btn ${activeTab === "hosts" ? "active" : ""}`}
          onClick={() => setActiveTab("hosts")}
          style={{
            padding: "0.75rem 1.25rem",
            background: "none",
            border: "none",
            borderBottom: activeTab === "hosts" ? "2px solid #3b82f6" : "2px solid transparent",
            color: activeTab === "hosts" ? "#60a5fa" : "#94a3b8",
            fontWeight: "600",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "0.4rem"
          }}
        >
          <Server size={16} /> Discovered Hosts ({assets.length})
        </button>

        <button
          className={`tab-btn ${activeTab === "services" ? "active" : ""}`}
          onClick={() => setActiveTab("services")}
          style={{
            padding: "0.75rem 1.25rem",
            background: "none",
            border: "none",
            borderBottom: activeTab === "services" ? "2px solid #3b82f6" : "2px solid transparent",
            color: activeTab === "services" ? "#60a5fa" : "#94a3b8",
            fontWeight: "600",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "0.4rem"
          }}
        >
          <Layers size={16} /> Open Services ({services.length})
        </button>

        <button
          className={`tab-btn ${activeTab === "diff" ? "active" : ""}`}
          onClick={() => setActiveTab("diff")}
          style={{
            padding: "0.75rem 1.25rem",
            background: "none",
            border: "none",
            borderBottom: activeTab === "diff" ? "2px solid #3b82f6" : "2px solid transparent",
            color: activeTab === "diff" ? "#60a5fa" : "#94a3b8",
            fontWeight: "600",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "0.4rem"
          }}
        >
          <Eye size={16} /> Changes Since Baseline ({diff?.total_discrepancies || 0})
        </button>

        <button
          className={`tab-btn ${activeTab === "alerts" ? "active" : ""}`}
          onClick={() => setActiveTab("alerts")}
          style={{
            padding: "0.75rem 1.25rem",
            background: "none",
            border: "none",
            borderBottom: activeTab === "alerts" ? "2px solid #3b82f6" : "2px solid transparent",
            color: activeTab === "alerts" ? "#60a5fa" : "#94a3b8",
            fontWeight: "600",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "0.4rem"
          }}
        >
          <ShieldAlert size={16} /> Security Alerts ({alerts.filter(a => a.status === "OPEN").length})
        </button>

        <button
          className={`tab-btn ${activeTab === "history" ? "active" : ""}`}
          onClick={() => setActiveTab("history")}
          style={{
            padding: "0.75rem 1.25rem",
            background: "none",
            border: "none",
            borderBottom: activeTab === "history" ? "2px solid #3b82f6" : "2px solid transparent",
            color: activeTab === "history" ? "#60a5fa" : "#94a3b8",
            fontWeight: "600",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "0.4rem"
          }}
        >
          <Clock size={16} /> Scan History & Errors ({jobs.length})
        </button>

        <button
          className={`tab-btn ${activeTab === "scopes" ? "active" : ""}`}
          onClick={() => setActiveTab("scopes")}
          style={{
            padding: "0.75rem 1.25rem",
            background: "none",
            border: "none",
            borderBottom: activeTab === "scopes" ? "2px solid #3b82f6" : "2px solid transparent",
            color: activeTab === "scopes" ? "#60a5fa" : "#94a3b8",
            fontWeight: "600",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "0.4rem"
          }}
        >
          <Globe size={16} /> Approved Scope & Exclusions ({scopes.length})
        </button>
      </div>

      {/* TAB 1: Discovered Hosts */}
      {activeTab === "hosts" && (
        <div className="card" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", flexWrap: "wrap", gap: "0.5rem" }}>
            <h2 style={{ margin: 0, fontSize: "1.1rem", fontWeight: "600" }}>Discovered Network Assets</h2>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <div style={{ position: "relative" }}>
                <Search size={14} style={{ position: "absolute", left: "10px", top: "10px", color: "#64748b" }} />
                <input
                  type="text"
                  placeholder="Filter IP or Hostname..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  style={{
                    padding: "0.45rem 0.75rem 0.45rem 2rem",
                    borderRadius: "6px",
                    border: "1px solid rgba(255, 255, 255, 0.15)",
                    background: "rgba(15, 23, 42, 0.6)",
                    color: "#fff",
                    fontSize: "0.85rem"
                  }}
                />
              </div>
            </div>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table className="table" style={{ width: "100%", textAlign: "left", fontSize: "0.875rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.1)", color: "#94a3b8" }}>
                  <th style={{ padding: "0.75rem" }}>Status</th>
                  <th style={{ padding: "0.75rem" }}>IP Address</th>
                  <th style={{ padding: "0.75rem" }}>Hostname</th>
                  <th style={{ padding: "0.75rem" }}>Baseline Approval</th>
                  <th style={{ padding: "0.75rem" }}>Open Ports</th>
                  <th style={{ padding: "0.75rem" }}>Latency</th>
                  <th style={{ padding: "0.75rem" }}>Last Seen</th>
                  <th style={{ padding: "0.75rem" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAssets.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ padding: "2rem", textAlign: "center", color: "#64748b" }}>
                      No network assets matching query.
                    </td>
                  </tr>
                ) : (
                  filteredAssets.map(asset => (
                    <tr key={asset.ip_address} style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.05)" }}>
                      <td style={{ padding: "0.75rem" }}>
                        <span
                          className={`badge badge-${asset.status === "REACHABLE" ? "success" : "secondary"}`}
                          style={{ display: "inline-flex", alignItems: "center", gap: "0.3rem" }}
                        >
                          {asset.status === "REACHABLE" ? <Wifi size={12} /> : <WifiOff size={12} />}
                          {asset.status}
                        </span>
                      </td>
                      <td style={{ padding: "0.75rem", fontFamily: "monospace", fontWeight: "600", color: "#93c5fd" }}>
                        {asset.ip_address}
                      </td>
                      <td style={{ padding: "0.75rem", color: "#e2e8f0" }}>
                        {asset.hostname || "—"}
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        {asset.in_baseline ? (
                          <span style={{ color: "#10b981", display: "inline-flex", alignItems: "center", gap: "0.3rem" }}>
                            <ShieldCheck size={14} /> Baselined
                          </span>
                        ) : (
                          <span style={{ color: "#f59e0b", display: "inline-flex", alignItems: "center", gap: "0.3rem" }}>
                            <AlertTriangle size={14} /> Unapproved / New
                          </span>
                        )}
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        <span className="badge badge-primary">{asset.open_ports_count ?? 0}</span>
                      </td>
                      <td style={{ padding: "0.75rem", color: "#94a3b8" }}>
                        {asset.latency_ms ? `${asset.latency_ms} ms` : "—"}
                      </td>
                      <td style={{ padding: "0.75rem", color: "#64748b", fontSize: "0.8rem" }}>
                        {new Date(asset.last_seen).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        {!asset.in_baseline && (
                          <button
                            className="btn btn-secondary"
                            onClick={() => handlePromoteBaseline(asset.ip_address)}
                            style={{ fontSize: "0.75rem", padding: "0.25rem 0.6rem" }}
                          >
                            + Promote to Baseline
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: Open Services */}
      {activeTab === "services" && (
        <div className="card" style={{ padding: "1.5rem" }}>
          <h2 style={{ margin: "0 0 1rem 0", fontSize: "1.1rem", fontWeight: "600" }}>
            Observed Service Endpoints & Protocols
          </h2>
          <div style={{ overflowX: "auto" }}>
            <table className="table" style={{ width: "100%", textAlign: "left", fontSize: "0.875rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.1)", color: "#94a3b8" }}>
                  <th style={{ padding: "0.75rem" }}>Host IP</th>
                  <th style={{ padding: "0.75rem" }}>Port</th>
                  <th style={{ padding: "0.75rem" }}>Protocol</th>
                  <th style={{ padding: "0.75rem" }}>Service Name</th>
                  <th style={{ padding: "0.75rem" }}>Observed Banner / Signature</th>
                  <th style={{ padding: "0.75rem" }}>Baseline Status</th>
                  <th style={{ padding: "0.75rem" }}>Last Observed</th>
                </tr>
              </thead>
              <tbody>
                {services.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ padding: "2rem", textAlign: "center", color: "#64748b" }}>
                      No active service endpoints detected.
                    </td>
                  </tr>
                ) : (
                  services.map(s => (
                    <tr key={`${s.ip_address}-${s.port}`} style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.05)" }}>
                      <td style={{ padding: "0.75rem", fontFamily: "monospace", color: "#93c5fd" }}>{s.ip_address}</td>
                      <td style={{ padding: "0.75rem", fontWeight: "700" }}>{s.port}</td>
                      <td style={{ padding: "0.75rem", textTransform: "uppercase" }}>{s.protocol}</td>
                      <td style={{ padding: "0.75rem", color: "#e2e8f0" }}>{s.service_name}</td>
                      <td style={{ padding: "0.75rem", fontFamily: "monospace", fontSize: "0.8rem", color: "#cbd5e1" }}>
                        {s.banner || "—"}
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        {s.is_baseline ? (
                          <span style={{ color: "#10b981" }}>Authorized</span>
                        ) : (
                          <span style={{ color: "#f87171", fontWeight: "600" }}>Unexpected Open Port</span>
                        )}
                      </td>
                      <td style={{ padding: "0.75rem", color: "#64748b", fontSize: "0.8rem" }}>
                        {new Date(s.last_observed).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: Changes & Baseline Diff */}
      {activeTab === "diff" && (
        <div className="card" style={{ padding: "1.5rem" }}>
          <h2 style={{ margin: "0 0 1rem 0", fontSize: "1.1rem", fontWeight: "600" }}>
            Deviations from Security Baseline
          </h2>
          <p style={{ color: "#94a3b8", fontSize: "0.875rem", marginBottom: "1.5rem" }}>
            Continuous comparison between verified telemetry and the approved infrastructure baseline profile.
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1.5rem" }}>
            {/* Newly Discovered Hosts */}
            <div className="card" style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)" }}>
              <h3 style={{ margin: "0 0 0.75rem 0", fontSize: "0.95rem", color: "#f59e0b", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <AlertTriangle size={16} /> Newly Discovered Unbaselined Hosts ({diff?.newly_discovered_hosts.length || 0})
              </h3>
              {diff?.newly_discovered_hosts.length === 0 ? (
                <p style={{ color: "#64748b", fontSize: "0.85rem", fontStyle: "italic" }}>
                  No unapproved hosts on network.
                </p>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                  {diff?.newly_discovered_hosts.map(h => (
                    <div
                      key={h.ip_address}
                      style={{
                        padding: "0.75rem",
                        background: "rgba(245, 158, 11, 0.08)",
                        border: "1px solid rgba(245, 158, 11, 0.2)",
                        borderRadius: "6px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center"
                      }}
                    >
                      <div>
                        <strong style={{ fontFamily: "monospace", color: "#fef08a" }}>{h.ip_address}</strong>
                        <div style={{ fontSize: "0.75rem", color: "#cbd5e1" }}>{h.hostname || "Unknown Host"}</div>
                      </div>
                      <button
                        className="btn btn-secondary"
                        onClick={() => handlePromoteBaseline(h.ip_address)}
                        style={{ fontSize: "0.7rem", padding: "0.2rem 0.5rem" }}
                      >
                        Approve
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Unexpected Open Ports */}
            <div className="card" style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)" }}>
              <h3 style={{ margin: "0 0 0.75rem 0", fontSize: "0.95rem", color: "#f87171", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <Ban size={16} /> Unexpected Open Ports ({diff?.unexpected_open_ports.length || 0})
              </h3>
              {diff?.unexpected_open_ports.length === 0 ? (
                <p style={{ color: "#64748b", fontSize: "0.85rem", fontStyle: "italic" }}>
                  All exposed ports conform to baseline.
                </p>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                  {diff?.unexpected_open_ports.map(p => (
                    <div
                      key={`${p.ip_address}-${p.port}`}
                      style={{
                        padding: "0.75rem",
                        background: "rgba(239, 68, 68, 0.08)",
                        border: "1px solid rgba(239, 68, 68, 0.2)",
                        borderRadius: "6px"
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ fontFamily: "monospace", color: "#fca5a5" }}>
                          {p.ip_address}:{p.port}
                        </span>
                        <span className="badge badge-danger">{p.service_name}</span>
                      </div>
                      <div style={{ fontSize: "0.75rem", color: "#94a3b8", marginTop: "0.25rem" }}>
                        Banner: {p.banner || "None"}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Offline Baselined Hosts */}
            <div className="card" style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)" }}>
              <h3 style={{ margin: "0 0 0.75rem 0", fontSize: "0.95rem", color: "#94a3b8", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <WifiOff size={16} /> Unreachable Baselined Nodes ({diff?.offline_baseline_hosts.length || 0})
              </h3>
              {diff?.offline_baseline_hosts.length === 0 ? (
                <p style={{ color: "#64748b", fontSize: "0.85rem", fontStyle: "italic" }}>
                  All baselined hosts responsive.
                </p>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                  {diff?.offline_baseline_hosts.map(h => (
                    <div
                      key={h.ip_address}
                      style={{
                        padding: "0.75rem",
                        background: "rgba(100, 116, 139, 0.1)",
                        borderRadius: "6px"
                      }}
                    >
                      <strong style={{ fontFamily: "monospace", color: "#e2e8f0" }}>{h.ip_address}</strong>
                      <div style={{ fontSize: "0.75rem", color: "#64748b" }}>{h.hostname}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: Security Alerts (Strict Fact vs Threat Separation) */}
      {activeTab === "alerts" && (
        <div className="card" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
            <div>
              <h2 style={{ margin: 0, fontSize: "1.1rem", fontWeight: "600" }}>Security Event Alerts</h2>
              <p style={{ margin: "0.25rem 0 0 0", color: "#94a3b8", fontSize: "0.85rem" }}>
                Strict architectural partition between verified empirical probe facts and suspected threat vectors.
              </p>
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            {alerts.length === 0 ? (
              <p style={{ padding: "2rem", textAlign: "center", color: "#64748b" }}>
                No security alerts logged.
              </p>
            ) : (
              alerts.map(alt => (
                <div
                  key={alt.id}
                  style={{
                    padding: "1.25rem",
                    borderRadius: "8px",
                    background: "rgba(15, 23, 42, 0.7)",
                    border:
                      alt.severity === "CRITICAL"
                        ? "1px solid rgba(239, 68, 68, 0.4)"
                        : alt.severity === "HIGH"
                        ? "1px solid rgba(245, 158, 11, 0.4)"
                        : "1px solid rgba(255, 255, 255, 0.1)"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem", flexWrap: "wrap" }}>
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.35rem" }}>
                        <span className={`badge badge-${alt.severity === "CRITICAL" ? "danger" : alt.severity === "HIGH" ? "warning" : "secondary"}`}>
                          {alt.severity}
                        </span>
                        <span className="badge badge-outline">{alt.alert_type}</span>
                        <span style={{ color: "#64748b", fontSize: "0.8rem" }}>
                          {new Date(alt.created_at).toLocaleString()}
                        </span>
                      </div>
                      <h3 style={{ margin: "0 0 0.5rem 0", fontSize: "1.05rem", color: "#f8fafc" }}>
                        {alt.title}
                      </h3>
                    </div>

                    <div style={{ display: "flex", gap: "0.5rem" }}>
                      {alt.status === "OPEN" ? (
                        <>
                          <button
                            className="btn btn-secondary"
                            onClick={() => handleUpdateAlertStatus(alt.id, "ACKNOWLEDGED")}
                            style={{ fontSize: "0.75rem", padding: "0.3rem 0.6rem" }}
                          >
                            Acknowledge
                          </button>
                          <button
                            className="btn btn-success"
                            onClick={() => handleUpdateAlertStatus(alt.id, "RESOLVED")}
                            style={{ fontSize: "0.75rem", padding: "0.3rem 0.6rem" }}
                          >
                            Resolve
                          </button>
                        </>
                      ) : (
                        <span className="badge badge-success">{alt.status}</span>
                      )}
                    </div>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginTop: "0.75rem" }}>
                    {/* Observed Fact */}
                    <div
                      style={{
                        padding: "0.75rem",
                        background: "rgba(59, 130, 246, 0.08)",
                        border: "1px solid rgba(59, 130, 246, 0.2)",
                        borderRadius: "6px"
                      }}
                    >
                      <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "#93c5fd", fontWeight: "700", marginBottom: "0.25rem" }}>
                        ✓ Verified Observed Fact
                      </div>
                      <div style={{ fontSize: "0.85rem", color: "#e2e8f0" }}>{alt.observed_fact}</div>
                    </div>

                    {/* Suspected Threat */}
                    <div
                      style={{
                        padding: "0.75rem",
                        background: "rgba(239, 68, 68, 0.08)",
                        border: "1px solid rgba(239, 68, 68, 0.2)",
                        borderRadius: "6px"
                      }}
                    >
                      <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "#fca5a5", fontWeight: "700", marginBottom: "0.25rem" }}>
                        ⚠️ Suspected Threat Assessment
                      </div>
                      <div style={{ fontSize: "0.85rem", color: "#e2e8f0" }}>{alt.suspected_threat}</div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 5: Scan History & Errors */}
      {activeTab === "history" && (
        <div className="card" style={{ padding: "1.5rem" }}>
          <h2 style={{ margin: "0 0 1rem 0", fontSize: "1.1rem", fontWeight: "600" }}>
            Scan Jobs Ledger & Incomplete Runs
          </h2>
          <div style={{ overflowX: "auto" }}>
            <table className="table" style={{ width: "100%", textAlign: "left", fontSize: "0.875rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.1)", color: "#94a3b8" }}>
                  <th style={{ padding: "0.75rem" }}>Job ID</th>
                  <th style={{ padding: "0.75rem" }}>Status</th>
                  <th style={{ padding: "0.75rem" }}>Trigger</th>
                  <th style={{ padding: "0.75rem" }}>Hosts Scanned / Up</th>
                  <th style={{ padding: "0.75rem" }}>Ports Found</th>
                  <th style={{ padding: "0.75rem" }}>Alerts</th>
                  <th style={{ padding: "0.75rem" }}>Started</th>
                  <th style={{ padding: "0.75rem" }}>Details / Errors</th>
                </tr>
              </thead>
              <tbody>
                {jobs.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ padding: "2rem", textAlign: "center", color: "#64748b" }}>
                      No scan jobs recorded.
                    </td>
                  </tr>
                ) : (
                  jobs.map(j => (
                    <tr key={j.id} style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.05)" }}>
                      <td style={{ padding: "0.75rem", fontFamily: "monospace", color: "#93c5fd" }}>{j.id}</td>
                      <td style={{ padding: "0.75rem" }}>
                        <span
                          className={`badge badge-${
                            j.status === "COMPLETED"
                              ? "success"
                              : j.status === "RUNNING"
                              ? "primary"
                              : j.status === "FAILED" || j.status === "CANCELLED"
                              ? "danger"
                              : "secondary"
                          }`}
                        >
                          {j.status}
                        </span>
                      </td>
                      <td style={{ padding: "0.75rem", fontSize: "0.8rem", color: "#cbd5e1" }}>{j.triggered_by}</td>
                      <td style={{ padding: "0.75rem" }}>
                        {j.hosts_up} / {j.hosts_scanned}
                      </td>
                      <td style={{ padding: "0.75rem" }}>{j.ports_found}</td>
                      <td style={{ padding: "0.75rem" }}>
                        {j.alerts_generated > 0 ? (
                          <span style={{ color: "#f87171", fontWeight: "700" }}>{j.alerts_generated}</span>
                        ) : (
                          "0"
                        )}
                      </td>
                      <td style={{ padding: "0.75rem", color: "#64748b", fontSize: "0.8rem" }}>
                        {new Date(j.started_at).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: "0.75rem", color: j.error_message ? "#f87171" : "#94a3b8", fontSize: "0.8rem" }}>
                        {j.error_message || "Completed nominal scan sweep"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 6: Approved Scope & Exclusions */}
      {activeTab === "scopes" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
          {/* Approved Subnets */}
          <div className="card" style={{ padding: "1.5rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
              <div>
                <h3 style={{ margin: 0, fontSize: "1.05rem", fontWeight: "600" }}>Approved CIDR Ranges</h3>
                <p style={{ margin: 0, color: "#94a3b8", fontSize: "0.8rem" }}>
                  Only authorized internal IP ranges can be scanned.
                </p>
              </div>
              <button
                className="btn btn-primary"
                onClick={() => setShowAddScope(true)}
                style={{ fontSize: "0.75rem", padding: "0.3rem 0.6rem", display: "flex", alignItems: "center", gap: "0.3rem" }}
              >
                <Plus size={14} /> Add Scope
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {scopes.map(s => (
                <div
                  key={s.id}
                  style={{
                    padding: "0.75rem",
                    background: "rgba(15, 23, 42, 0.6)",
                    border: "1px solid rgba(255, 255, 255, 0.1)",
                    borderRadius: "6px",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center"
                  }}
                >
                  <div>
                    <strong style={{ fontFamily: "monospace", color: "#60a5fa" }}>{s.cidr_or_ip}</strong>
                    <div style={{ color: "#e2e8f0", fontSize: "0.85rem" }}>{s.name}</div>
                    <div style={{ color: "#64748b", fontSize: "0.75rem" }}>Tag: {s.asset_tag}</div>
                  </div>
                  <button
                    className="btn btn-secondary"
                    onClick={() => handleDeleteScope(s.id)}
                    style={{ color: "#f87171", padding: "0.3rem" }}
                    title="Delete scope"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Exclusions */}
          <div className="card" style={{ padding: "1.5rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
              <div>
                <h3 style={{ margin: 0, fontSize: "1.05rem", fontWeight: "600" }}>Asset Exclusions</h3>
                <p style={{ margin: 0, color: "#94a3b8", fontSize: "0.8rem" }}>
                  Sensitive or routing nodes strictly skipped during sweeps.
                </p>
              </div>
              <button
                className="btn btn-primary"
                onClick={() => setShowAddExclusion(true)}
                style={{ fontSize: "0.75rem", padding: "0.3rem 0.6rem", display: "flex", alignItems: "center", gap: "0.3rem" }}
              >
                <Plus size={14} /> Add Exclusion
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {exclusions.length === 0 ? (
                <p style={{ color: "#64748b", fontSize: "0.85rem" }}>No asset exclusions configured.</p>
              ) : (
                exclusions.map(ex => (
                  <div
                    key={ex.id}
                    style={{
                      padding: "0.75rem",
                      background: "rgba(15, 23, 42, 0.6)",
                      border: "1px solid rgba(255, 255, 255, 0.1)",
                      borderRadius: "6px",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center"
                    }}
                  >
                    <div>
                      <strong style={{ fontFamily: "monospace", color: "#f87171" }}>{ex.ip_address}</strong>
                      <div style={{ color: "#94a3b8", fontSize: "0.8rem" }}>{ex.reason}</div>
                    </div>
                    <button
                      className="btn btn-secondary"
                      onClick={() => handleDeleteExclusion(ex.id)}
                      style={{ color: "#f87171", padding: "0.3rem" }}
                      title="Delete exclusion"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Add Scope Modal */}
      {showAddScope && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0,0,0,0.7)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000
          }}
        >
          <div className="card" style={{ width: "420px", padding: "1.5rem" }}>
            <h3 style={{ margin: "0 0 1rem 0" }}>Add Approved Network Scope</h3>
            <form onSubmit={handleAddScope}>
              <div style={{ marginBottom: "1rem" }}>
                <label style={{ display: "block", fontSize: "0.85rem", color: "#94a3b8", marginBottom: "0.3rem" }}>
                  Subnet Name
                </label>
                <input
                  type="text"
                  required
                  value={newScopeName}
                  onChange={e => setNewScopeName(e.target.value)}
                  placeholder="e.g. Finance Agent Enclave"
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "#0f172a", border: "1px solid #334155", color: "#fff" }}
                />
              </div>

              <div style={{ marginBottom: "1rem" }}>
                <label style={{ display: "block", fontSize: "0.85rem", color: "#94a3b8", marginBottom: "0.3rem" }}>
                  IPv4 CIDR or IP Address
                </label>
                <input
                  type="text"
                  required
                  value={newScopeCidr}
                  onChange={e => setNewScopeCidr(e.target.value)}
                  placeholder="e.g. 192.168.1.0/24 or 127.0.0.1/32"
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "#0f172a", border: "1px solid #334155", color: "#fff" }}
                />
              </div>

              <div style={{ marginBottom: "1.5rem" }}>
                <label style={{ display: "block", fontSize: "0.85rem", color: "#94a3b8", marginBottom: "0.3rem" }}>
                  Asset Tag / Category
                </label>
                <input
                  type="text"
                  value={newScopeTag}
                  onChange={e => setNewScopeTag(e.target.value)}
                  placeholder="Internal Infrastructure"
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "#0f172a", border: "1px solid #334155", color: "#fff" }}
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowAddScope(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Add Scope
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Exclusion Modal */}
      {showAddExclusion && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0,0,0,0.7)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000
          }}
        >
          <div className="card" style={{ width: "420px", padding: "1.5rem" }}>
            <h3 style={{ margin: "0 0 1rem 0" }}>Add Host Exclusion</h3>
            <form onSubmit={handleAddExclusion}>
              <div style={{ marginBottom: "1rem" }}>
                <label style={{ display: "block", fontSize: "0.85rem", color: "#94a3b8", marginBottom: "0.3rem" }}>
                  IP Address to Exclude
                </label>
                <input
                  type="text"
                  required
                  value={newExclIp}
                  onChange={e => setNewExclIp(e.target.value)}
                  placeholder="e.g. 192.168.1.1"
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "#0f172a", border: "1px solid #334155", color: "#fff" }}
                />
              </div>

              <div style={{ marginBottom: "1.5rem" }}>
                <label style={{ display: "block", fontSize: "0.85rem", color: "#94a3b8", marginBottom: "0.3rem" }}>
                  Reason for Exclusion
                </label>
                <input
                  type="text"
                  required
                  value={newExclReason}
                  onChange={e => setNewExclReason(e.target.value)}
                  placeholder="e.g. Critical Gateway Router"
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "#0f172a", border: "1px solid #334155", color: "#fff" }}
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowAddExclusion(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Add Exclusion
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Emergency Stop Modal */}
      {showEmergencyModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0,0,0,0.8)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1100
          }}
        >
          <div className="card" style={{ width: "480px", padding: "1.5rem", border: "1px solid #dc2626" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", color: "#f87171", marginBottom: "0.75rem" }}>
              <AlertOctagon size={28} />
              <h3 style={{ margin: 0, fontSize: "1.2rem" }}>Activate Global Emergency Stop</h3>
            </div>
            <p style={{ color: "#cbd5e1", fontSize: "0.875rem", lineHeight: "1.4" }}>
              This will immediately cancel any in-flight network sweep tasks, engage the emergency stop safety interlock,
              and append an immutable cryptographic record to the audit ledger. No automated or manual network scans can be
              executed until an administrator clears this stop.
            </p>

            <div style={{ margin: "1rem 0" }}>
              <label style={{ display: "block", fontSize: "0.85rem", color: "#94a3b8", marginBottom: "0.3rem" }}>
                Operational Justification / Incident Note
              </label>
              <textarea
                rows={3}
                value={emergencyReason}
                onChange={e => setEmergencyReason(e.target.value)}
                placeholder="Reason for emergency scan halt..."
                style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "#0f172a", border: "1px solid #334155", color: "#fff" }}
              />
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
              <button className="btn btn-secondary" onClick={() => setShowEmergencyModal(false)}>
                Cancel
              </button>
              <button className="btn btn-danger" onClick={handleEmergencyStop}>
                Confirm Emergency Stop
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
