import React, { useState, useEffect } from "react";
import {
  FileCode, Terminal, Upload, RefreshCw, CheckCircle2, AlertTriangle,
  Lock, Copy, Check, Eye, HelpCircle, Shield, Layers, Database,
  Cpu, Code, ArrowRight, ExternalLink, Zap, Info, Folder, Sparkles,
  FileText, Download, ShieldCheck, CheckCircle
} from "lucide-react";
import {
  ReaStatus, ReaInvestigation, ReaAuthorizedTarget,
  ReaTargetValidation, ReaForensicReport
} from "../types";
import {
  getReaStatus,
  uploadReaArtifact,
  inspectReaPath,
  askAmojaRea,
  getReaHistory,
  getAuthorizedReaTargets,
  validateReaTarget,
  generateReaReport
} from "../api";

export const ReaLabPanel: React.FC = () => {
  // Status and Engine telemetry
  const [status, setStatus] = useState<ReaStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);

  // Authorized Target Selection & Validation
  const [authorizedTargets, setAuthorizedTargets] = useState<ReaAuthorizedTarget[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<ReaAuthorizedTarget | null>(null);
  const [validation, setValidation] = useState<ReaTargetValidation | null>(null);
  const [validating, setValidating] = useState(false);

  // Analysis and Execution State
  const [investigation, setInvestigation] = useState<ReaInvestigation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedWorkflow, setSelectedWorkflow] = useState<string>("auto");
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  // Forensic Report State
  const [report, setReport] = useState<ReaForensicReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);

  // Input state
  const [inputMode, setInputMode] = useState<"targets" | "path" | "upload">("targets");
  const [customPath, setCustomPath] = useState<string>("desktop");
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Evidence view tabs
  const [evidenceTab, setEvidenceTab] = useState<"findings" | "limitations" | "raw" | "report">("findings");

  // AMOJA AI state
  const [aiLang, setAiLang] = useState<"en" | "hinglish">("en");
  const [aiQuestion, setAiQuestion] = useState("");
  const [aiAnswer, setAiAnswer] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);

  // History state
  const [history, setHistory] = useState<any[]>([]);

  useEffect(() => {
    loadStatusAndHistory();
  }, []);

  useEffect(() => {
    let interval: any = null;
    if (loading) {
      setElapsedSeconds(0);
      interval = setInterval(() => {
        setElapsedSeconds(s => s + 1);
      }, 1000);
    } else {
      setElapsedSeconds(0);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [loading]);

  async function loadStatusAndHistory() {
    setStatusLoading(true);
    try {
      const [s, h, targets] = await Promise.all([
        getReaStatus().catch(() => null),
        getReaHistory().catch(() => []),
        getAuthorizedReaTargets().catch(() => [])
      ]);
      setStatus(s);
      setHistory(h);
      setAuthorizedTargets(targets);
      // Auto-validate default target (e.g. desktop)
      if (targets && targets.length > 0) {
        const desktopTarget = targets.find(t => t.id === "app_electron_desktop") || targets[0];
        setSelectedTarget(desktopTarget);
        setCustomPath(desktopTarget.path);
        handleValidateTarget(desktopTarget.path);
      }
    } catch (err: any) {
      console.error("Failed to load REA status:", err);
    } finally {
      setStatusLoading(false);
    }
  }

  async function handleValidateTarget(targetPath: string) {
    if (!targetPath.trim()) return null;
    setValidating(true);
    try {
      const res = await validateReaTarget(targetPath.trim());
      setValidation(res);
      return res;
    } catch (err: any) {
      setValidation({
        valid: false,
        status: "DENIED",
        target_path: targetPath,
        resolved_path: "",
        error: err?.message || "Target validation failed."
      });
      return null;
    } finally {
      setValidating(false);
    }
  }

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 25 * 1024 * 1024) {
      alert("File exceeds maximum allowed size of 25MB.");
      return;
    }

    setLoading(true);
    setError(null);
    setAiAnswer(null);

    try {
      const workflowArg = selectedWorkflow === "auto" ? undefined : selectedWorkflow;
      const res = await uploadReaArtifact(file, workflowArg);
      setInvestigation(res);
      await loadStatusAndHistory();
    } catch (err: any) {
      setError(err?.message || "REA upload and analysis failed.");
    } finally {
      setLoading(false);
      e.target.value = "";
    }
  }

  async function handleInspectPath(pathArg?: string) {
    const target = pathArg || customPath;
    if (!target.trim()) return;

    setLoading(true);
    setError(null);
    setAiAnswer(null);

    try {
      const workflowArg = selectedWorkflow === "auto" ? undefined : selectedWorkflow;
      const res = await inspectReaPath(target.trim(), workflowArg);
      setInvestigation(res);
      await loadStatusAndHistory();
    } catch (err: any) {
      setError(err?.message || "REA workspace inspection failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleAskAmoja() {
    if (!investigation || !aiQuestion.trim()) return;
    setAiLoading(true);
    try {
      const res = await askAmojaRea(investigation.analysis_id, aiQuestion, aiLang);
      setAiAnswer(res.custom_answer || res.english_briefing);
    } catch (err: any) {
      alert(err?.message || "AMOJA AI query failed.");
    } finally {
      setAiLoading(false);
    }
  }

  async function handleGenerateReport() {
    if (!investigation) return;
    setReportLoading(true);
    try {
      const rep = await generateReaReport(investigation.analysis_id, investigation);
      setReport(rep);
      setEvidenceTab("report");
    } catch (err: any) {
      alert(err?.message || "Failed to generate forensic report.");
    } finally {
      setReportLoading(false);
    }
  }

  function handleDownloadReport(format: "markdown" | "json") {
    if (!report) return;
    let blob: Blob;
    let filename: string;
    if (format === "markdown") {
      blob = new Blob([report.markdown_report], { type: "text/markdown;charset=utf-8" });
      filename = `Forensic_Report_${report.analysis_id}_${report.filename}.md`;
    } else {
      blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json;charset=utf-8" });
      filename = `Forensic_Report_${report.analysis_id}_${report.filename}.json`;
    }
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  function handleCopyHash(text: string, label: string) {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  }

  // Extract structured findings from evidence
  const evidenceObj = investigation?.evidence || {};
  const normalizedObj = evidenceObj.normalized_result || evidenceObj;
  const schemaObj = normalizedObj.schema || {};
  const tables = schemaObj.tables || [];
  const indexes = schemaObj.indexes || [];
  const appGraph = normalizedObj.application_graph || {};
  const modules = appGraph.modules || [];
  const electronBounds = appGraph.electron_boundaries || [];
  const identity = normalizedObj.identity || {};

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* 1. REA Engine Status & Providers HUD */}
      <section className="panel" style={{ background: "rgba(10, 20, 15, 0.9)", borderColor: "var(--border)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <span className="badge" style={{ background: status?.installed ? "rgba(118, 185, 0, 0.2)" : "rgba(239, 68, 68, 0.2)", color: status?.installed ? "var(--primary)" : "var(--danger)", fontWeight: 700 }}>
                {status?.installed ? `REA v${status.version} ACTIVE` : "REA CLI NOT DETECTED"}
              </span>
              <span className="badge" style={{ background: "rgba(59, 130, 246, 0.15)", color: "#60a5fa" }}>
                Node.js: {status?.node_version || "Probing..."}
              </span>
              <span className="badge" style={{ background: "rgba(16, 185, 129, 0.15)", color: "#34d399" }}>
                Zero-Trust: {status?.zero_trust_status || "ENFORCING"}
              </span>
            </div>
            <h2 style={{ fontSize: 18, margin: 0, fontFamily: "var(--font-heading)" }}>
              REA (Reverse Engineer Anything) — Dedicated Forensics Subsystem
            </h2>
            <p style={{ margin: "4px 0 0", fontSize: 13, color: "var(--text-muted)" }}>
              Inspect native binary metadata, .NET CIL assemblies, JavaScript/Electron application graphs, AI models, and SQLite snapshots without executing untrusted code on the Windows host.
            </p>
          </div>

          <button
            className="secondary-button small-btn"
            onClick={loadStatusAndHistory}
            disabled={statusLoading}
            style={{ display: "flex", alignItems: "center", gap: 6 }}
          >
            <RefreshCw size={13} className={statusLoading ? "spin" : ""} />
            <span>Refresh Providers</span>
          </button>
        </div>

        {/* Provider Availability Strip */}
        <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px dashed var(--border)" }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 0.5, marginBottom: 8 }}>
            ANALYSIS ENGINES & DISASSEMBLER PROVIDERS:
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {status?.providers && status.providers.length > 0 ? (
              status.providers.map(p => {
                const isReady = p.status === "available";
                return (
                  <div
                    key={p.id}
                    title={p.reason || (isReady ? "Ready for disassembly" : "Unconfigured")}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      padding: "4px 10px",
                      borderRadius: 6,
                      background: isReady ? "rgba(118, 185, 0, 0.12)" : "rgba(255, 255, 255, 0.04)",
                      border: `1px solid ${isReady ? "var(--primary)" : "var(--border)"}`,
                      fontSize: 12
                    }}
                  >
                    <span style={{ width: 7, height: 7, borderRadius: "50%", background: isReady ? "var(--primary)" : "var(--text-muted)" }} />
                    <strong style={{ color: isReady ? "var(--primary)" : "var(--text)" }}>{p.name}</strong>
                    <span style={{ fontSize: 10, color: isReady ? "var(--primary)" : "var(--text-muted)" }}>
                      {isReady ? "READY" : "OPTIONAL"}
                    </span>
                  </div>
                );
              })
            ) : (
              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Built-in static providers active (JS/Electron, .NET CIL, SQLite, Models, Go)</span>
            )}
          </div>
        </div>

        {/* Capability Tags */}
        <div style={{ marginTop: 12, display: "flex", gap: 6, flexWrap: "wrap" }}>
          {status?.supported_workflows.map(wf => (
            <span key={wf} className="badge" style={{ fontSize: 10, background: "rgba(255, 255, 255, 0.04)", color: "var(--text-muted)", border: "1px solid var(--border)" }}>
              {wf}
            </span>
          ))}
        </div>
      </section>

      {/* 2. Target Selection & Action Workbench */}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2 style={{ fontSize: 16 }}>Select Target Artifact for REA Inspection</h2>
            <p style={{ fontSize: 13, color: "var(--text-muted)", margin: "4px 0 0" }}>
              Upload an artifact or inspect an authorized file/folder within the AgentShield workspace.
            </p>
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              className={`small-btn ${inputMode === "targets" ? "primary-button" : "secondary-button"}`}
              onClick={() => setInputMode("targets")}
            >
              <ShieldCheck size={13} style={{ marginRight: 4 }} />
              Authorized Applications
            </button>
            <button
              className={`small-btn ${inputMode === "path" ? "primary-button" : "secondary-button"}`}
              onClick={() => setInputMode("path")}
            >
              <Folder size={13} style={{ marginRight: 4 }} />
              Custom Path
            </button>
            <button
              className={`small-btn ${inputMode === "upload" ? "primary-button" : "secondary-button"}`}
              onClick={() => setInputMode("upload")}
            >
              <Upload size={13} style={{ marginRight: 4 }} />
              Upload Vault Artifact
            </button>
          </div>
        </div>

        {/* Workflow Selector Bar */}
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 16, flexWrap: "wrap" }}>
          <label style={{ fontSize: 12, color: "var(--text-muted)" }}>REA Workflow:</label>
          <select
            className="input"
            value={selectedWorkflow}
            onChange={e => setSelectedWorkflow(e.target.value)}
            style={{ width: "auto", minWidth: 240, fontSize: 12, padding: "6px 12px" }}
          >
            <option value="auto">Auto-Detect Format (Recommended)</option>
            <option value="inspect-sqlite-database">inspect-sqlite-database (SQLite Snapshots)</option>
            <option value="analyze-javascript-application">analyze-javascript-application (JS/Electron Graph)</option>
            <option value="inspect-artifact">inspect-artifact (General Artifact / Scripts / Models)</option>
            <option value="inspect-managed-artifact">inspect-managed-artifact (.NET PE/CLI)</option>
            <option value="inspect-go-binary">inspect-go-binary (Go Compiled Metadata)</option>
            <option value="inspect-rust-binary">inspect-rust-binary (Rust Cargo Audit Metadata)</option>
            <option value="inspect-wasm-artifact">inspect-wasm-artifact (WebAssembly)</option>
            <option value="inspect-binary-layout">inspect-binary-layout (Binary Layout & ELF)</option>
          </select>
        </div>

        {/* Mode: Authorized Pre-Approved Targets */}
        {inputMode === "targets" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
              Select an authorized harmless application, source tree, or database snapshot from the approved catalog:
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 12 }}>
              {authorizedTargets.map(tgt => {
                const isSelected = selectedTarget?.id === tgt.id || customPath === tgt.path;
                return (
                  <div
                    key={tgt.id}
                    onClick={() => {
                      setSelectedTarget(tgt);
                      setCustomPath(tgt.path);
                      handleValidateTarget(tgt.path);
                    }}
                    style={{
                      cursor: "pointer",
                      padding: 14,
                      borderRadius: 8,
                      border: `1.5px solid ${isSelected ? "var(--primary)" : "var(--border)"}`,
                      background: isSelected ? "rgba(118, 185, 0, 0.08)" : "rgba(0,0,0,0.25)",
                      display: "flex",
                      flexDirection: "column",
                      justifyContent: "space-between",
                      gap: 10,
                      transition: "all 0.2s"
                    }}
                  >
                    <div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8, marginBottom: 6 }}>
                        <strong style={{ fontSize: 13, color: isSelected ? "var(--primary)" : "var(--text)" }}>
                          {tgt.name}
                        </strong>
                        {tgt.is_harmless_test_app && (
                          <span className="badge" style={{ fontSize: 9, background: "rgba(16, 185, 129, 0.2)", color: "#34d399" }}>
                            Harmless Test App
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
                        {tgt.description}
                      </div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", fontSize: 10 }}>
                        <span className="badge" style={{ background: "rgba(59, 130, 246, 0.15)", color: "#60a5fa" }}>
                          {tgt.format}
                        </span>
                        <span className="badge" style={{ background: "rgba(255, 255, 255, 0.05)", color: "var(--text-muted)" }}>
                          {tgt.path}
                        </span>
                      </div>
                    </div>

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px dashed var(--border)", paddingTop: 8 }}>
                      <span style={{ fontSize: 10, color: "var(--primary)" }}>
                        {tgt.safety_posture.split("(")[0]}
                      </span>
                      <button
                        className={`small-btn ${isSelected ? "primary-button" : "secondary-button"}`}
                        style={{ fontSize: 11, padding: "3px 8px" }}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedTarget(tgt);
                          setCustomPath(tgt.path);
                          handleValidateTarget(tgt.path);
                        }}
                      >
                        {isSelected ? "Selected" : "Select Target"}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Mode: Workspace Path */}
        {inputMode === "path" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                type="text"
                className="input"
                placeholder="e.g. desktop, backend/data/agentshield.db, or frontend/src"
                value={customPath}
                onChange={e => {
                  setCustomPath(e.target.value);
                  handleValidateTarget(e.target.value);
                }}
                style={{ flex: 1, fontSize: 13 }}
              />
              <button
                className="primary-button"
                onClick={() => handleInspectPath()}
                disabled={loading || !customPath.trim()}
                style={{ display: "flex", alignItems: "center", gap: 6 }}
              >
                <Zap size={14} />
                <span>Run REA Inspection</span>
              </button>
            </div>

            {/* Quick-test Presets */}
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", fontSize: 12 }}>
              <span style={{ color: "var(--text-muted)" }}>Quick Presets:</span>
              <button
                className="secondary-button small-btn"
                onClick={() => {
                  setCustomPath("desktop");
                  handleValidateTarget("desktop");
                  handleInspectPath("desktop");
                }}
                style={{ fontSize: 11 }}
              >
                <Code size={11} style={{ marginRight: 4 }} />
                Inspect Desktop Electron App
              </button>
              <button
                className="secondary-button small-btn"
                onClick={() => {
                  setCustomPath("backend/data/agentshield.db");
                  handleValidateTarget("backend/data/agentshield.db");
                  handleInspectPath("backend/data/agentshield.db");
                }}
                style={{ fontSize: 11 }}
              >
                <Database size={11} style={{ marginRight: 4 }} />
                Inspect AgentShield DB (SQLite)
              </button>
              <button
                className="secondary-button small-btn"
                onClick={() => {
                  setCustomPath("frontend/src");
                  handleValidateTarget("frontend/src");
                  handleInspectPath("frontend/src");
                }}
                style={{ fontSize: 11 }}
              >
                <Layers size={11} style={{ marginRight: 4 }} />
                Inspect Frontend Application Graph (JS/TS)
              </button>
            </div>
          </div>
        )}

        {/* Mode: Upload */}
        {inputMode === "upload" && (
          <div style={{ border: "2px dashed var(--border)", borderRadius: 8, padding: 30, textAlign: "center", background: "rgba(0,0,0,0.2)" }}>
            <Upload size={32} style={{ color: "var(--primary)", margin: "0 auto 10px" }} />
            <h3 style={{ margin: "0 0 6px", fontSize: 15 }}>Upload Artifact into Quarantined Vault</h3>
            <p style={{ fontSize: 12, color: "var(--text-muted)", margin: "0 0 16px" }}>
              Supports SQLite (.db), .NET (.dll), JS/Electron (.js, .asar), Models (.gguf), and Go binaries up to 25MB.
            </p>
            <label className="primary-button" style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 8 }}>
              <Upload size={14} />
              <span>Choose File to Analyze with REA</span>
              <input type="file" onChange={handleFileUpload} style={{ display: "none" }} />
            </label>
          </div>
        )}

        {/* Pre-Flight Target Validation & Permission Card */}
        {validation && (
          <div style={{
            marginTop: 16,
            padding: 14,
            borderRadius: 8,
            background: validation.valid ? "rgba(16, 185, 129, 0.08)" : "rgba(239, 68, 68, 0.08)",
            border: `1px solid ${validation.valid ? "rgba(16, 185, 129, 0.3)" : "rgba(239, 68, 68, 0.3)"}`
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {validation.valid ? (
                  <CheckCircle size={16} style={{ color: "#34d399" }} />
                ) : (
                  <AlertTriangle size={16} style={{ color: "var(--danger)" }} />
                )}
                <span style={{ fontSize: 13, fontWeight: 700, color: validation.valid ? "#34d399" : "var(--danger)" }}>
                  Target Permission: {validation.status}
                </span>
                <span className="badge" style={{ fontSize: 10, background: "rgba(255,255,255,0.06)" }}>
                  Target: {validation.target_path}
                </span>
                {validation.recommended_workflow && (
                  <span className="badge" style={{ fontSize: 10, background: "rgba(59, 130, 246, 0.15)", color: "#60a5fa" }}>
                    Workflow: {validation.recommended_workflow}
                  </span>
                )}
              </div>

              {validation.valid && (
                <button
                  className="primary-button"
                  onClick={() => handleInspectPath(validation.target_path)}
                  disabled={loading}
                  style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 14px" }}
                >
                  <Zap size={13} />
                  <span>Execute Safe Static Analysis</span>
                </button>
              )}
            </div>

            <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)", display: "flex", gap: 16, flexWrap: "wrap" }}>
              <span>Policy: <strong>{validation.safety_posture || "STATIC_ANALYSIS_ONLY (Direct host execution prohibited)"}</strong></span>
              <span>Isolation: <strong>{validation.isolation || "HOST_SAFE_INERT_PARSING"}</strong></span>
              {validation.file_size ? <span>Size: <strong>{validation.file_size.toLocaleString()} bytes</strong></span> : null}
            </div>

            {validation.error && (
              <div style={{ marginTop: 6, fontSize: 11, color: "var(--danger)" }}>
                {validation.error}
              </div>
            )}
          </div>
        )}

        {/* Loading Spinner & Timer */}
        {loading && (
          <div style={{ textAlign: "center", padding: 30, background: "rgba(0,0,0,0.2)", borderRadius: 8, marginTop: 16 }}>
            <RefreshCw className="spin" size={28} style={{ color: "var(--primary)", margin: "0 auto 10px" }} />
            <h4 style={{ margin: 0, fontSize: 15 }}>Executing Real REA Static Analysis ({elapsedSeconds}s / 60s timeout)...</h4>
            <p style={{ color: "var(--text-muted)", fontSize: 12, margin: "6px 0 12px" }}>
              REA is parsing inert JavaScript/AST syntax, mapping Electron boundaries, and evaluating limitations without host execution.
            </p>
            <div style={{ width: "100%", maxWidth: 360, height: 4, background: "rgba(255,255,255,0.1)", borderRadius: 2, margin: "0 auto", overflow: "hidden" }}>
              <div style={{ width: `${Math.min(100, (elapsedSeconds / 60) * 100)}%`, height: "100%", background: "var(--primary)", transition: "width 0.5s ease" }} />
            </div>
          </div>
        )}

        {/* Error Notification */}
        {error && (
          <div className="decision-card block" style={{ marginTop: 16 }}>
            <AlertTriangle size={18} />
            <div>
              <strong>REA Analysis Error:</strong> {error}
            </div>
          </div>
        )}
      </section>

      {/* 3. Active Investigation Results */}
      {investigation && !loading && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {/* Identity & Metadata Strip */}
          <section className="panel" style={{ background: "rgba(10, 20, 15, 0.85)", borderColor: investigation.success ? "var(--primary)" : "var(--border)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <h2 style={{ margin: 0, fontSize: 18, fontFamily: "var(--font-heading)" }}>
                    {investigation.filename}
                  </h2>
                  <span className="badge" style={{ background: investigation.success ? "rgba(118, 185, 0, 0.2)" : "rgba(245, 158, 11, 0.2)", color: investigation.success ? "var(--primary)" : "var(--warning)" }}>
                    {investigation.success ? "REA_ANALYSIS_COMPLETE" : "LIMITED_BY_PROVIDER"}
                  </span>
                  <span className="badge" style={{ background: "rgba(59, 130, 246, 0.15)", color: "#60a5fa" }}>
                    Workflow: {investigation.workflow}
                  </span>
                </div>
                <p style={{ margin: "6px 0 0", fontSize: 13, color: "var(--text)" }}>
                  {investigation.summary}
                </p>
              </div>

              {/* Action buttons: Report & Hash */}
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <button
                  className="primary-button small-btn"
                  onClick={handleGenerateReport}
                  disabled={reportLoading}
                  style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11 }}
                >
                  <FileText size={12} />
                  <span>{reportLoading ? "Compiling..." : "Generate Forensic Report"}</span>
                </button>

                {investigation.hashes.sha256 && (
                  <button
                    className="secondary-button small-btn"
                    onClick={() => handleCopyHash(investigation.hashes.sha256, "sha256")}
                    style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11 }}
                  >
                    <Copy size={12} />
                    <span>SHA-256: {investigation.hashes.sha256.substring(0, 16)}...</span>
                    {copiedHash === "sha256" && <Check size={12} style={{ color: "var(--primary)" }} />}
                  </button>
                )}
              </div>
            </div>

            {/* Quick Metrics Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginTop: 16, paddingTop: 14, borderTop: "1px dashed var(--border)" }}>
              <div className="stat-card" style={{ padding: 10 }}>
                <span className="stat-label">File Size</span>
                <span className="stat-value" style={{ fontSize: 15 }}>{investigation.file_size.toLocaleString()} bytes</span>
              </div>
              <div className="stat-card" style={{ padding: 10 }}>
                <span className="stat-label">Confidence</span>
                <span className="stat-value" style={{ fontSize: 15, color: "var(--primary)" }}>{investigation.confidence}</span>
              </div>
              <div className="stat-card" style={{ padding: 10 }}>
                <span className="stat-label">Exit Code</span>
                <span className="stat-value" style={{ fontSize: 15 }}>{investigation.exit_code}</span>
              </div>
              <div className="stat-card" style={{ padding: 10 }}>
                <span className="stat-label">Host Execution</span>
                <span className="stat-value" style={{ fontSize: 15, color: "var(--danger)" }}>DISABLED</span>
              </div>
            </div>
          </section>

          {/* Two-Column Layout: Evidence Findings vs AMOJA AI Dossier */}
          <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 20 }}>
            {/* Left Column: Technical Evidence & Sub-Tabs */}
            <div className="panel" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {/* Evidence Sub-Tabs */}
              <div style={{ display: "flex", gap: 8, borderBottom: "1px solid var(--border)", paddingBottom: 10 }}>
                <button
                  className={`small-btn ${evidenceTab === "findings" ? "primary-button" : "secondary-button"}`}
                  onClick={() => setEvidenceTab("findings")}
                >
                  <Eye size={12} style={{ marginRight: 4 }} />
                  Observed Findings
                </button>
                <button
                  className={`small-btn ${evidenceTab === "limitations" ? "primary-button" : "secondary-button"}`}
                  onClick={() => setEvidenceTab("limitations")}
                >
                  <Info size={12} style={{ marginRight: 4 }} />
                  Limitations ({investigation.limitations.length})
                </button>
                <button
                  className={`small-btn ${evidenceTab === "raw" ? "primary-button" : "secondary-button"}`}
                  onClick={() => setEvidenceTab("raw")}
                >
                  <Terminal size={12} style={{ marginRight: 4 }} />
                  Raw JSON Envelope
                </button>
                <button
                  className={`small-btn ${evidenceTab === "report" ? "primary-button" : "secondary-button"}`}
                  onClick={() => {
                    if (!report) {
                      handleGenerateReport();
                    } else {
                      setEvidenceTab("report");
                    }
                  }}
                >
                  <FileText size={12} style={{ marginRight: 4 }} />
                  Forensic Dossier {report ? "(Ready)" : ""}
                </button>
              </div>

              {/* Sub-Tab 1: Findings */}
              {evidenceTab === "findings" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  {/* SQLite Schema Findings */}
                  {investigation.workflow === "inspect-sqlite-database" && (
                    <div>
                      <h4 style={{ fontSize: 14, margin: "0 0 10px", color: "var(--primary)" }}>
                        Database Schema ({tables.length} Tables, {indexes.length} Indexes)
                      </h4>
                      {tables.length > 0 ? (
                        <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 380, overflowY: "auto" }}>
                          {tables.map((t: any, idx: number) => (
                            <div key={idx} style={{ padding: 10, background: "rgba(0,0,0,0.3)", borderRadius: 6, border: "1px solid var(--border)", fontSize: 12 }}>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <strong style={{ color: "var(--primary)" }}>{t.name}</strong>
                                <span className="badge" style={{ fontSize: 10 }}>Columns: {t.column_count || t.columns?.length || "Schema preserved"}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p style={{ fontSize: 12, color: "var(--text-muted)" }}>No public tables returned in sample view.</p>
                      )}
                    </div>
                  )}

                  {/* JavaScript Application Graph Findings */}
                  {investigation.workflow === "analyze-javascript-application" && (
                    <div>
                      <h4 style={{ fontSize: 14, margin: "0 0 10px", color: "var(--primary)" }}>
                        Application Graph ({modules.length} Modules Mapped)
                      </h4>
                      {electronBounds.length > 0 && (
                        <div style={{ padding: 10, background: "rgba(245, 158, 11, 0.1)", border: "1px solid var(--warning)", borderRadius: 6, marginBottom: 12, fontSize: 12 }}>
                          <strong style={{ color: "var(--warning)" }}>Electron IPC Boundaries Detected:</strong>
                          <ul style={{ margin: "6px 0 0", paddingLeft: 16 }}>
                            {electronBounds.map((b: any, idx: number) => (
                              <li key={idx}>{b.name || JSON.stringify(b)}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      <div style={{ maxHeight: 340, overflowY: "auto", display: "flex", flexDirection: "column", gap: 6 }}>
                        {modules.slice(0, 30).map((m: any, idx: number) => (
                          <div key={idx} style={{ padding: "6px 10px", background: "rgba(0,0,0,0.25)", borderRadius: 4, fontSize: 12 }}>
                            <code>{m.path || m.name || JSON.stringify(m)}</code>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* .NET Assembly Findings */}
                  {investigation.workflow === "inspect-managed-artifact" && (
                    <div>
                      <h4 style={{ fontSize: 14, margin: "0 0 10px", color: "var(--primary)" }}>
                        .NET Managed Assembly Metadata
                      </h4>
                      <div style={{ padding: 12, background: "rgba(0,0,0,0.3)", borderRadius: 6, fontSize: 12, display: "flex", flexDirection: "column", gap: 6 }}>
                        <div>Assembly Name: <strong>{identity.name || investigation.filename}</strong></div>
                        <div>CLR Version: <strong>{identity.runtime || "v4.0.30319"}</strong></div>
                        <div>Architecture: <strong>{identity.architecture || "MSIL / AnyCPU"}</strong></div>
                      </div>
                    </div>
                  )}

                  {/* General Artifact Inspection Findings */}
                  {investigation.workflow === "inspect-artifact" && (
                    <div>
                      <h4 style={{ fontSize: 14, margin: "0 0 10px", color: "var(--primary)" }}>
                        Artifact Inspection Evidence
                      </h4>
                      <p style={{ fontSize: 12, color: "var(--text)", margin: "0 0 10px" }}>{investigation.summary}</p>
                      {normalizedObj.observations && normalizedObj.observations.length > 0 && (
                        <div style={{ marginBottom: 12 }}>
                          <strong style={{ fontSize: 12, color: "var(--text)" }}>Observations ({normalizedObj.observations.length}):</strong>
                          <div style={{ marginTop: 6, display: "flex", flexDirection: "column", gap: 6, maxHeight: 180, overflowY: "auto" }}>
                            {normalizedObj.observations.map((obs: any, idx: number) => (
                              <div key={idx} style={{ padding: "6px 10px", background: "rgba(0,0,0,0.25)", borderRadius: 4, fontSize: 12 }}>
                                <span className="badge" style={{ fontSize: 10, marginRight: 6 }}>{obs.kind || "observation"}</span>
                                <code>{JSON.stringify(obs.value || obs.subject || obs)}</code>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {normalizedObj.next_probes && normalizedObj.next_probes.length > 0 && (
                        <div>
                          <strong style={{ fontSize: 12, color: "var(--warning)" }}>Recommended Follow-up Probes:</strong>
                          <ul style={{ margin: "6px 0 0", paddingLeft: 16, fontSize: 12 }}>
                            {normalizedObj.next_probes.map((p: any, idx: number) => (
                              <li key={idx}><strong>{p.operation}</strong> — {p.rationale || "Available probe"}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Fallback Findings */}
                  {investigation.workflow !== "inspect-sqlite-database" && investigation.workflow !== "analyze-javascript-application" && investigation.workflow !== "inspect-managed-artifact" && investigation.workflow !== "inspect-artifact" && (
                    <div>
                      <h4 style={{ fontSize: 14, margin: "0 0 8px", color: "var(--primary)" }}>Inspection Result</h4>
                      <p style={{ fontSize: 12, color: "var(--text)" }}>{investigation.summary}</p>
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 2: Limitations */}
              {evidenceTab === "limitations" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  <h4 style={{ fontSize: 14, margin: 0, color: "var(--warning)" }}>
                    Documented Tool Limitations & Boundaries
                  </h4>
                  <p style={{ fontSize: 12, color: "var(--text-muted)", margin: 0 }}>
                    REA reports transparent limitations for evidence-based validation.
                  </p>
                  <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 380, overflowY: "auto" }}>
                    {investigation.limitations.map((lim, idx) => (
                      <div key={idx} style={{ padding: 10, background: "rgba(245, 158, 11, 0.08)", border: "1px solid rgba(245, 158, 11, 0.25)", borderRadius: 6, fontSize: 12 }}>
                        <span style={{ color: "var(--warning)", marginRight: 6 }}>⚠️</span>
                        {lim}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Sub-Tab 3: Raw JSON */}
              {evidenceTab === "raw" && (
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Complete Evidence Envelope</span>
                    <button
                      className="secondary-button small-btn"
                      onClick={() => handleCopyHash(JSON.stringify(investigation.raw_result, null, 2), "raw_json")}
                      style={{ fontSize: 11 }}
                    >
                      <Copy size={11} style={{ marginRight: 4 }} />
                      Copy JSON
                      {copiedHash === "raw_json" && <Check size={11} style={{ color: "var(--primary)", marginLeft: 4 }} />}
                    </button>
                  </div>
                  <pre style={{ maxHeight: 400, overflowY: "auto", background: "rgba(0,0,0,0.5)", padding: 12, borderRadius: 6, fontSize: 11, color: "#a7f3d0", lineHeight: 1.4 }}>
                    {JSON.stringify(investigation.raw_result, null, 2)}
                  </pre>
                </div>
              )}

              {/* Sub-Tab 4: Forensic Report Dossier */}
              {evidenceTab === "report" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
                    <div>
                      <h4 style={{ fontSize: 14, margin: 0, color: "var(--primary)" }}>
                        Evidence-Based Forensic Investigation Dossier
                      </h4>
                      <p style={{ margin: "2px 0 0", fontSize: 11, color: "var(--text-muted)" }}>
                        Cryptographically signed and formatted for audit compliance.
                      </p>
                    </div>

                    <div style={{ display: "flex", gap: 6 }}>
                      <button
                        className="secondary-button small-btn"
                        onClick={() => handleDownloadReport("markdown")}
                        disabled={!report}
                        style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
                      >
                        <Download size={12} />
                        Download .md
                      </button>
                      <button
                        className="secondary-button small-btn"
                        onClick={() => handleDownloadReport("json")}
                        disabled={!report}
                        style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
                      >
                        <Download size={12} />
                        Download .json
                      </button>
                    </div>
                  </div>

                  {report ? (
                    <div style={{
                      maxHeight: 440,
                      overflowY: "auto",
                      background: "rgba(0,0,0,0.4)",
                      padding: 16,
                      borderRadius: 6,
                      fontSize: 12,
                      lineHeight: 1.6,
                      whiteSpace: "pre-wrap",
                      fontFamily: "var(--font-mono, monospace)",
                      color: "#e2e8f0",
                      border: "1px solid var(--border)"
                    }}>
                      {report.markdown_report}
                    </div>
                  ) : (
                    <div style={{ textAlign: "center", padding: 30, background: "rgba(0,0,0,0.2)", borderRadius: 6 }}>
                      <FileText size={28} style={{ color: "var(--primary)", margin: "0 auto 8px" }} />
                      <p style={{ fontSize: 12, color: "var(--text-muted)", margin: "0 0 12px" }}>
                        Forensic report is not compiled yet for this analysis.
                      </p>
                      <button
                        className="primary-button small-btn"
                        onClick={handleGenerateReport}
                        disabled={reportLoading}
                      >
                        {reportLoading ? "Compiling Report..." : "Generate Official Forensic Dossier"}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Right Column: AMOJA AI Forensic Briefing & Interactive Q&A */}
            <div className="panel" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Sparkles size={16} style={{ color: "var(--primary)" }} />
                  <h3 style={{ margin: 0, fontSize: 16 }}>AMOJA AI Forensic Briefing</h3>
                </div>

                {/* Language Switch */}
                <div style={{ display: "flex", gap: 4 }}>
                  <button
                    className={`small-btn ${aiLang === "en" ? "primary-button" : "secondary-button"}`}
                    onClick={() => setAiLang("en")}
                    style={{ fontSize: 11, padding: "3px 8px" }}
                  >
                    English
                  </button>
                  <button
                    className={`small-btn ${aiLang === "hinglish" ? "primary-button" : "secondary-button"}`}
                    onClick={() => setAiLang("hinglish")}
                    style={{ fontSize: 11, padding: "3px 8px" }}
                  >
                    Hinglish (हिन्दी)
                  </button>
                </div>
              </div>

              {/* Formatted Briefing Text */}
              {investigation.amoja_briefing && (
                <div style={{ maxHeight: 380, overflowY: "auto", padding: 14, background: "rgba(0,0,0,0.3)", borderRadius: 6, fontSize: 12, lineHeight: 1.6 }}>
                  {aiLang === "en" ? (
                    <div>
                      <h4 style={{ margin: "0 0 8px", color: "var(--primary)" }}>1. Observed Facts (Verified Telemetry)</h4>
                      <ul style={{ margin: "0 0 12px", paddingLeft: 18 }}>
                        {investigation.amoja_briefing.observed_facts.map((f, i) => (
                          <li key={i}>{f}</li>
                        ))}
                      </ul>

                      <h4 style={{ margin: "0 0 8px", color: "var(--warning)" }}>2. Inferred Risks (Threat Assessment)</h4>
                      <ul style={{ margin: "0 0 12px", paddingLeft: 18 }}>
                        {investigation.amoja_briefing.inferred_risks.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>

                      <h4 style={{ margin: "0 0 8px", color: "#60a5fa" }}>3. Unknowns & Tool Boundaries</h4>
                      <ul style={{ margin: 0, paddingLeft: 18 }}>
                        {investigation.amoja_briefing.limitations.map((l, i) => (
                          <li key={i}>{l}</li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div>
                      <div style={{ whiteSpace: "pre-wrap" }}>
                        {investigation.amoja_briefing.hinglish_briefing}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Interactive Q&A */}
              <div style={{ borderTop: "1px dashed var(--border)", paddingTop: 14 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-muted)" }}>Ask AMOJA AI about this artifact:</span>
                <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                  <input
                    type="text"
                    className="input"
                    placeholder={aiLang === "en" ? "e.g. Does this artifact expose secrets or connections?" : "e.g. Amoja, key findings samjhao"}
                    value={aiQuestion}
                    onChange={e => setAiQuestion(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && handleAskAmoja()}
                    style={{ flex: 1, fontSize: 12 }}
                  />
                  <button
                    className="primary-button small-btn"
                    onClick={handleAskAmoja}
                    disabled={aiLoading || !aiQuestion.trim()}
                  >
                    {aiLoading ? <RefreshCw size={12} className="spin" /> : "Ask"}
                  </button>
                </div>

                {/* Quick Prompts */}
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
                  <button
                    className="secondary-button small-btn"
                    onClick={() => { setAiQuestion(aiLang === "en" ? "Summarize key observations and risks" : "Amoja, key findings explain karo"); }}
                    style={{ fontSize: 10, padding: "2px 8px" }}
                  >
                    Summarize Findings
                  </button>
                  <button
                    className="secondary-button small-btn"
                    onClick={() => { setAiQuestion(aiLang === "en" ? "Are any credentials or secrets exposed?" : "Kya isme credentials leak hue hain?"); }}
                    style={{ fontSize: 10, padding: "2px 8px" }}
                  >
                    Check Credentials
                  </button>
                  <button
                    className="secondary-button small-btn"
                    onClick={() => { setAiQuestion(aiLang === "en" ? "What are the limitations of this analysis?" : "Is inspection ki kya seemayein hain?"); }}
                    style={{ fontSize: 10, padding: "2px 8px" }}
                  >
                    Inspect Limitations
                  </button>
                </div>

                {/* AI Custom Answer */}
                {aiAnswer && (
                  <div style={{ marginTop: 12, padding: 12, background: "rgba(118, 185, 0, 0.1)", border: "1px solid var(--primary)", borderRadius: 6, fontSize: 12 }}>
                    <strong style={{ color: "var(--primary)" }}>AMOJA AI Response:</strong>
                    <p style={{ margin: "6px 0 0", color: "var(--text)" }}>{aiAnswer}</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
