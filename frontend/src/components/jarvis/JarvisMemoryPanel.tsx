// frontend/src/components/jarvis/JarvisMemoryPanel.tsx
import React, { useState, useEffect } from "react";
import {
  Brain, Search, Plus, Trash2, CheckCircle, Circle,
  Calendar, Clock, Tag, ShieldCheck, AlertCircle, RefreshCw, FileText, CheckSquare,
  Laptop, Folder, MessageCircle, Play, Square, ExternalLink, Cpu, Layers, Settings,
  AlertTriangle, HardDrive, Wifi, Activity, Terminal
} from "lucide-react";
import {
  getJarvisReminders, createJarvisReminder, deleteJarvisReminder,
  getJarvisNotes, createJarvisNote, deleteJarvisNote,
  getJarvisTodos, createJarvisTodo, toggleJarvisTodo,
  getJarvisMemories, createJarvisMemory, deleteJarvisMemory, clearJarvisMemories,
  searchJarvisHistory,
  getApprovedApps, launchApprovedApp, closeApprovedApp,
  getAuthorizedFiles, openAuthorizedFile, prepareWhatsAppMessage,
  getWindowsSystemStatus, openWindowsSettings
} from "../../api";
import { JarvisReminder, JarvisNote, JarvisTodo, JarvisMemory } from "../../types";

export type PersonalSubTab =
  | "apps"
  | "files"
  | "whatsapp"
  | "system"
  | "reminders"
  | "todos"
  | "notes"
  | "memories"
  | "history";

export const JarvisMemoryPanel: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<PersonalSubTab>("apps");
  const [isLoading, setIsLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Data states
  const [memories, setMemories] = useState<JarvisMemory[]>([]);
  const [reminders, setReminders] = useState<JarvisReminder[]>([]);
  const [todos, setTodos] = useState<JarvisTodo[]>([]);
  const [notes, setNotes] = useState<JarvisNote[]>([]);

  // Apps state
  const [approvedApps, setApprovedApps] = useState<Record<string, any>>({});
  const [appActionState, setAppActionState] = useState<Record<string, string>>({});

  // Files state
  const [fileQuery, setFileQuery] = useState("");
  const [fileScope, setFileScope] = useState<string>("workspace");
  const [fileResults, setFileResults] = useState<any[]>([]);
  const [isSearchingFiles, setIsSearchingFiles] = useState(false);

  // WhatsApp state
  const [waRecipient, setWaRecipient] = useState("");
  const [waMessage, setWaMessage] = useState("");
  const [waAttachment, setWaAttachment] = useState("");
  const [waConfirmation, setWaConfirmation] = useState<any | null>(null);
  const [isSendingWa, setIsSendingWa] = useState(false);

  // System Status state
  const [systemStatus, setSystemStatus] = useState<any | null>(null);
  const [isLoadingSystem, setIsLoadingSystem] = useState(false);

  // History search state
  const [historyQuery, setHistoryQuery] = useState("");
  const [historyResults, setHistoryResults] = useState<any[]>([]);
  const [isSearchingHistory, setIsSearchingHistory] = useState(false);

  // New item form inputs
  const [newMemKey, setNewMemKey] = useState("");
  const [newMemVal, setNewMemVal] = useState("");
  const [newMemCat, setNewMemCat] = useState("preference");

  const [newRemTitle, setNewRemTitle] = useState("");
  const [newRemTime, setNewRemTime] = useState("");
  const [newRemPriority, setNewRemPriority] = useState("NORMAL");

  const [newTodoTask, setNewTodoTask] = useState("");
  const [newTodoPriority, setNewTodoPriority] = useState("NORMAL");

  const [newNoteTitle, setNewNoteTitle] = useState("");
  const [newNoteContent, setNewNoteContent] = useState("");
  const [newNoteTags, setNewNoteTags] = useState("");

  const refreshData = async () => {
    setIsLoading(true);
    setStatusMessage(null);
    try {
      const [mRes, rRes, tRes, nRes, appsRes] = await Promise.all([
        getJarvisMemories().catch(() => ({ memories: [] })),
        getJarvisReminders(true).catch(() => ({ reminders: [] })),
        getJarvisTodos(true).catch(() => ({ todos: [] })),
        getJarvisNotes().catch(() => ({ notes: [] })),
        getApprovedApps().catch(() => ({ apps: {} }))
      ]);
      setMemories(mRes.memories || []);
      setReminders(rRes.reminders || []);
      setTodos(tRes.todos || []);
      setNotes(nRes.notes || []);
      setApprovedApps(appsRes.apps || {});
    } catch (err: any) {
      setStatusMessage(`Error loading items: ${err.message || String(err)}`);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    refreshData();
  }, []);

  // Fetch system status when system tab opens
  useEffect(() => {
    if (activeSubTab === "system" && !systemStatus) {
      fetchSystemTelemetry();
    }
    if (activeSubTab === "files" && fileResults.length === 0) {
      handleSearchFiles();
    }
  }, [activeSubTab]);

  const fetchSystemTelemetry = async () => {
    setIsLoadingSystem(true);
    try {
      const s = await getWindowsSystemStatus();
      setSystemStatus(s);
    } catch (err: any) {
      setStatusMessage(`Failed to read system status: ${err.message}`);
    } finally {
      setIsLoadingSystem(false);
    }
  };

  // --- Handlers for Approved Applications ---
  const handleLaunchApp = async (appKey: string, appName: string) => {
    setAppActionState(prev => ({ ...prev, [appKey]: "Launching..." }));
    try {
      const res = await launchApprovedApp(appKey);
      if (res.error) {
        setAppActionState(prev => ({ ...prev, [appKey]: `Error: ${res.error}` }));
        setStatusMessage(`Launch failed: ${res.error}`);
      } else if (res.requires_confirmation) {
        setAppActionState(prev => ({ ...prev, [appKey]: "Confirmation Required" }));
        setStatusMessage(`Action requires confirmation: ${res.impact_explanation}`);
      } else {
        setAppActionState(prev => ({ ...prev, [appKey]: `Launched (PID: ${res.pid || "Active"})` }));
        setStatusMessage(`Successfully launched ${appName} (PID: ${res.pid || "Active"}).`);
      }
    } catch (err: any) {
      setAppActionState(prev => ({ ...prev, [appKey]: "Failed" }));
      setStatusMessage(`Launch error: ${err.message}`);
    }
  };

  const handleCloseApp = async (appKey: string, appName: string) => {
    setAppActionState(prev => ({ ...prev, [appKey]: "Closing..." }));
    try {
      const res = await closeApprovedApp(appKey);
      if (res.error) {
        setAppActionState(prev => ({ ...prev, [appKey]: `Error: ${res.error}` }));
        setStatusMessage(`Close failed: ${res.error}`);
      } else {
        setAppActionState(prev => ({ ...prev, [appKey]: res.status || "Closed" }));
        setStatusMessage(res.message || `Closed ${appName}.`);
      }
    } catch (err: any) {
      setAppActionState(prev => ({ ...prev, [appKey]: "Failed" }));
      setStatusMessage(`Close error: ${err.message}`);
    }
  };

  // --- Handlers for File Search & Open ---
  const handleSearchFiles = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setIsSearchingFiles(true);
    try {
      const res = await getAuthorizedFiles(fileQuery, fileScope);
      setFileResults(res.matches || []);
    } catch (err: any) {
      setStatusMessage(`File search error: ${err.message}`);
    } finally {
      setIsSearchingFiles(false);
    }
  };

  const handleOpenFile = async (filepath: string) => {
    try {
      const res = await openAuthorizedFile(filepath);
      if (res.error) {
        setStatusMessage(`Cannot open: ${res.error}`);
      } else {
        setStatusMessage(`Opened: ${res.message || filepath}`);
      }
    } catch (err: any) {
      setStatusMessage(`Error opening file: ${err.message}`);
    }
  };

  // --- Handlers for WhatsApp ---
  const handlePrepareWhatsApp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!waRecipient.trim() || !waMessage.trim()) return;
    setIsSendingWa(true);
    setWaConfirmation(null);
    try {
      const res = await prepareWhatsAppMessage(waRecipient.trim(), waMessage.trim(), waAttachment.trim() || undefined);
      if (res.error) {
        setStatusMessage(`WhatsApp preparation failed: ${res.error}`);
      } else {
        setWaConfirmation(res);
        setStatusMessage("WhatsApp message verified. Human authorization required before dispatch.");
      }
    } catch (err: any) {
      setStatusMessage(`WhatsApp error: ${err.message}`);
    } finally {
      setIsSendingWa(false);
    }
  };

  const handleOpenSettings = async (page: string) => {
    try {
      const res = await openWindowsSettings(page);
      if (res.error) {
        setStatusMessage(`Settings error: ${res.error}`);
      } else {
        setStatusMessage(`Launched Windows Settings (${page}).`);
      }
    } catch (err: any) {
      setStatusMessage(`Failed to launch settings: ${err.message}`);
    }
  };

  // --- Handlers for User Memories ---
  const handleAddMemory = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMemKey.trim() || !newMemVal.trim()) return;
    try {
      await createJarvisMemory(newMemKey.trim(), newMemVal.trim(), newMemCat);
      setNewMemKey("");
      setNewMemVal("");
      setStatusMessage("Memory fact stored successfully.");
      refreshData();
    } catch (err: any) {
      setStatusMessage(`Failed to store memory: ${err.message}`);
    }
  };

  const handleDeleteMemory = async (key: string) => {
    try {
      await deleteJarvisMemory(key);
      setStatusMessage(`Memory '${key}' removed.`);
      refreshData();
    } catch (err: any) {
      setStatusMessage(`Failed to delete memory: ${err.message}`);
    }
  };

  const handleClearAllMemories = async () => {
    if (!window.confirm("Are you sure you want to clear all stored user memory facts?")) return;
    try {
      await clearJarvisMemories();
      setStatusMessage("All user memories cleared.");
      refreshData();
    } catch (err: any) {
      setStatusMessage(`Failed to clear memories: ${err.message}`);
    }
  };

  // --- Handlers for Reminders ---
  const handleAddReminder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRemTitle.trim()) return;
    try {
      await createJarvisReminder(newRemTitle.trim(), newRemTime.trim() || undefined, newRemPriority);
      setNewRemTitle("");
      setNewRemTime("");
      setStatusMessage("Reminder created.");
      refreshData();
    } catch (err: any) {
      setStatusMessage(`Failed to create reminder: ${err.message}`);
    }
  };

  const handleDeleteReminder = async (id: number) => {
    try {
      await deleteJarvisReminder(id);
      setStatusMessage("Reminder deleted.");
      refreshData();
    } catch (err: any) {
      setStatusMessage(`Failed to delete reminder: ${err.message}`);
    }
  };

  // --- Handlers for To-Dos ---
  const handleAddTodo = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTodoTask.trim()) return;
    try {
      await createJarvisTodo(newTodoTask.trim(), newTodoPriority);
      setNewTodoTask("");
      setStatusMessage("Task added to to-do list.");
      refreshData();
    } catch (err: any) {
      setStatusMessage(`Failed to add task: ${err.message}`);
    }
  };

  const handleToggleTodo = async (id: number) => {
    try {
      await toggleJarvisTodo(id);
      refreshData();
    } catch (err: any) {
      setStatusMessage(`Failed to toggle task: ${err.message}`);
    }
  };

  // --- Handlers for Notes ---
  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteContent.trim()) return;
    const tags = newNoteTags
      .split(",")
      .map(t => t.trim())
      .filter(Boolean);
    try {
      await createJarvisNote(newNoteTitle.trim() || "Untitled Note", newNoteContent.trim(), tags);
      setNewNoteTitle("");
      setNewNoteContent("");
      setNewNoteTags("");
      setStatusMessage("Note saved.");
      refreshData();
    } catch (err: any) {
      setStatusMessage(`Failed to save note: ${err.message}`);
    }
  };

  const handleDeleteNote = async (id: number) => {
    try {
      await deleteJarvisNote(id);
      setStatusMessage("Note deleted.");
      refreshData();
    } catch (err: any) {
      setStatusMessage(`Failed to delete note: ${err.message}`);
    }
  };

  // --- Handler for History Search ---
  const handleSearchHistory = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!historyQuery.trim()) return;
    setIsSearchingHistory(true);
    try {
      const res = await searchJarvisHistory(historyQuery.trim());
      setHistoryResults(res.results || []);
    } catch (err: any) {
      setStatusMessage(`Failed to search history: ${err.message}`);
    } finally {
      setIsSearchingHistory(false);
    }
  };

  return (
    <div className="jarvis-memory-hub">
      {/* Header Bar */}
      <div className="memory-hub-header">
        <div className="hub-title-group">
          <Brain size={24} className="neon-cyan" />
          <div>
            <h3>AMOJA AI Personal Windows Assistant & Workspace Hub</h3>
            <p>Permission-controlled applications, file explorer, WhatsApp dispatcher, system health, reminders, and notes.</p>
          </div>
        </div>
        <button
          type="button"
          className="btn-refresh-memory"
          onClick={refreshData}
          disabled={isLoading}
          title="Refresh Data"
        >
          <RefreshCw size={14} className={isLoading ? "spin-icon" : ""} />
          <span>Refresh</span>
        </button>
      </div>

      {statusMessage && (
        <div className="memory-status-alert">
          <ShieldCheck size={16} />
          <span>{statusMessage}</span>
        </div>
      )}

      {/* Sub-Tab Navigation */}
      <div className="memory-subtabs-nav" style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "apps" ? "active" : ""}`}
          onClick={() => setActiveSubTab("apps")}
        >
          <Laptop size={14} />
          <span>Approved Apps ({Object.keys(approvedApps).length})</span>
        </button>
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "files" ? "active" : ""}`}
          onClick={() => setActiveSubTab("files")}
        >
          <Folder size={14} />
          <span>Authorized Files</span>
        </button>
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "whatsapp" ? "active" : ""}`}
          onClick={() => setActiveSubTab("whatsapp")}
        >
          <MessageCircle size={14} />
          <span>WhatsApp</span>
        </button>
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "system" ? "active" : ""}`}
          onClick={() => setActiveSubTab("system")}
        >
          <Cpu size={14} />
          <span>Windows Status</span>
        </button>
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "reminders" ? "active" : ""}`}
          onClick={() => setActiveSubTab("reminders")}
        >
          <Clock size={14} />
          <span>Reminders ({reminders.length})</span>
        </button>
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "todos" ? "active" : ""}`}
          onClick={() => setActiveSubTab("todos")}
        >
          <CheckSquare size={14} />
          <span>To-Do List ({todos.length})</span>
        </button>
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "notes" ? "active" : ""}`}
          onClick={() => setActiveSubTab("notes")}
        >
          <FileText size={14} />
          <span>Notes ({notes.length})</span>
        </button>
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "memories" ? "active" : ""}`}
          onClick={() => setActiveSubTab("memories")}
        >
          <Brain size={14} />
          <span>Memories ({memories.length})</span>
        </button>
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "history" ? "active" : ""}`}
          onClick={() => setActiveSubTab("history")}
        >
          <Search size={14} />
          <span>History</span>
        </button>
      </div>

      {/* Content Area */}
      <div className="memory-tab-content">
        {/* SUBTAB: APPROVED APPLICATIONS */}
        {activeSubTab === "apps" && (
          <div className="personal-apps-view">
            <div className="apps-catalog-banner" style={{ marginBottom: "16px", padding: "12px 18px", background: "rgba(118, 185, 0, 0.08)", border: "1px solid rgba(118, 185, 0, 0.25)", borderRadius: "6px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <ShieldCheck size={18} style={{ color: "#76b900" }} />
                <strong>Zero-Trust Application Whitelist:</strong>
                <span style={{ fontSize: "12px", color: "rgba(255, 255, 255, 0.8)" }}>
                  Only explicitly approved binaries can be launched. Arbitrary shell commands and unapproved execution are strictly forbidden.
                </span>
              </div>
            </div>

            <div className="apps-grid" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "14px" }}>
              {Object.entries(approvedApps).map(([key, app]) => {
                const actionStatus = appActionState[key];
                return (
                  <div key={key} className="app-card" style={{ background: "rgba(10, 20, 14, 0.85)", border: "1px solid rgba(118, 185, 0, 0.2)", borderRadius: "8px", padding: "16px", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                    <div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                        <strong style={{ fontSize: "15px", color: "#ffffff" }}>{app.name}</strong>
                        <span style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "4px", background: app.requires_confirmation ? "rgba(239, 68, 68, 0.2)" : "rgba(118, 185, 0, 0.18)", color: app.requires_confirmation ? "#ef4444" : "#76b900", border: `1px solid ${app.requires_confirmation ? "rgba(239, 68, 68, 0.4)" : "rgba(118, 185, 0, 0.4)"}` }}>
                          {app.requires_confirmation ? "CONFIRMATION REQ" : "SAFE LAUNCH"}
                        </span>
                      </div>
                      <p style={{ fontSize: "12px", color: "rgba(255, 255, 255, 0.7)", margin: "4px 0 10px 0" }}>{app.description}</p>
                      <div style={{ fontSize: "11px", color: "rgba(255, 255, 255, 0.5)", fontFamily: "monospace" }}>
                        Binary: {app.executable}
                      </div>
                      {actionStatus && (
                        <div style={{ marginTop: "8px", fontSize: "11px", color: "#76b900", fontWeight: 600 }}>
                          Status: {actionStatus}
                        </div>
                      )}
                    </div>

                    <div style={{ display: "flex", gap: "8px", marginTop: "14px" }}>
                      <button
                        type="button"
                        onClick={() => handleLaunchApp(key, app.name)}
                        className="btn-mem-action"
                        style={{ flex: 1, padding: "8px 12px", fontSize: "12px", display: "inline-flex", alignItems: "center", justifyContent: "center", gap: "6px" }}
                      >
                        <Play size={13} /> Launch
                      </button>
                      <button
                        type="button"
                        onClick={() => handleCloseApp(key, app.name)}
                        className="btn-danger-outline"
                        style={{ padding: "8px 12px", fontSize: "12px", display: "inline-flex", alignItems: "center", justifyContent: "center", gap: "6px" }}
                        title="Close active instances"
                      >
                        <Square size={13} /> Close
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* SUBTAB: AUTHORIZED FILES */}
        {activeSubTab === "files" && (
          <div className="personal-files-view">
            <div style={{ display: "flex", gap: "10px", marginBottom: "16px", flexWrap: "wrap", alignItems: "center" }}>
              <form onSubmit={handleSearchFiles} style={{ display: "flex", gap: "8px", flex: 1, minWidth: "260px" }}>
                <input
                  type="text"
                  placeholder="Search file name (e.g. report, code, .pdf)..."
                  value={fileQuery}
                  onChange={e => setFileQuery(e.target.value)}
                  className="mem-input"
                  style={{ flex: 1 }}
                />
                <button type="submit" className="btn-mem-action" disabled={isSearchingFiles}>
                  <Search size={14} /> {isSearchingFiles ? "Searching..." : "Search"}
                </button>
              </form>

              <div style={{ display: "flex", gap: "6px" }}>
                {["workspace", "documents", "downloads", "desktop"].map(scope => (
                  <button
                    key={scope}
                    type="button"
                    onClick={() => {
                      setFileScope(scope);
                      getAuthorizedFiles(fileQuery, scope).then(r => setFileResults(r.matches || []));
                    }}
                    className={`mem-subtab ${fileScope === scope ? "active" : ""}`}
                    style={{ textTransform: "capitalize", padding: "6px 10px", fontSize: "11px" }}
                  >
                    {scope}
                  </button>
                ))}
              </div>
            </div>

            <div className="files-results-table" style={{ background: "rgba(8, 16, 11, 0.8)", border: "1px solid rgba(118, 185, 0, 0.2)", borderRadius: "6px", overflow: "hidden" }}>
              <div style={{ padding: "10px 16px", borderBottom: "1px solid rgba(118, 185, 0, 0.15)", display: "flex", justifyContent: "space-between", fontSize: "12px", color: "rgba(255, 255, 255, 0.7)" }}>
                <span>Found <strong>{fileResults.length}</strong> authorized items in scope <em>{fileScope}</em></span>
                <span style={{ fontSize: "11px", color: "#76b900" }}>Protected against path traversal</span>
              </div>

              {fileResults.length === 0 ? (
                <div style={{ padding: "30px", textAlign: "center", color: "rgba(255, 255, 255, 0.5)", fontSize: "13px" }}>
                  No matching files found in this authorized directory. Try a different search term or scope.
                </div>
              ) : (
                <div style={{ maxHeight: "380px", overflowY: "auto" }}>
                  {fileResults.map((f, i) => (
                    <div
                      key={i}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "10px 16px",
                        borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
                        gap: "12px"
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "10px", flex: 1, minWidth: 0 }}>
                        {f.is_dir ? <Folder size={16} style={{ color: "#eab308" }} /> : <FileText size={16} style={{ color: "#38bdf8" }} />}
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontWeight: 600, fontSize: "13px", color: "#ffffff", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {f.name}
                          </div>
                          <div style={{ fontSize: "11px", color: "rgba(255, 255, 255, 0.5)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {f.relative_path}
                          </div>
                        </div>
                      </div>

                      <div style={{ display: "flex", alignItems: "center", gap: "14px", flexShrink: 0 }}>
                        <span style={{ fontSize: "11px", color: "rgba(255, 255, 255, 0.6)" }}>
                          {f.is_dir ? "Folder" : `${Math.round(f.size_bytes / 1024)} KB`}
                        </span>
                        <button
                          type="button"
                          onClick={() => handleOpenFile(f.full_path)}
                          className="btn-mem-action"
                          style={{ padding: "5px 10px", fontSize: "11px", display: "inline-flex", alignItems: "center", gap: "4px" }}
                        >
                          <ExternalLink size={12} /> Open
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* SUBTAB: WHATSAPP MESSENGER */}
        {activeSubTab === "whatsapp" && (
          <div className="personal-whatsapp-view">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
              <div className="mem-form-card">
                <h4>Compose WhatsApp Message</h4>
                <p className="form-subtext">Recipient phone verification and mandatory human confirmation prior to dispatch.</p>

                <form onSubmit={handlePrepareWhatsApp} className="mem-form">
                  <div style={{ marginBottom: "10px" }}>
                    <label style={{ fontSize: "12px", color: "rgba(255, 255, 255, 0.8)", display: "block", marginBottom: "4px" }}>Recipient Phone Number</label>
                    <input
                      type="text"
                      placeholder="e.g. 9876543210 or +919876543210"
                      value={waRecipient}
                      onChange={e => setWaRecipient(e.target.value)}
                      className="mem-input"
                      required
                    />
                  </div>

                  <div style={{ marginBottom: "10px" }}>
                    <label style={{ fontSize: "12px", color: "rgba(255, 255, 255, 0.8)", display: "block", marginBottom: "4px" }}>Message Content</label>
                    <textarea
                      placeholder="Type your message here..."
                      value={waMessage}
                      onChange={e => setWaMessage(e.target.value)}
                      className="mem-input"
                      rows={4}
                      required
                      style={{ resize: "vertical" }}
                    />
                  </div>

                  <div style={{ marginBottom: "14px" }}>
                    <label style={{ fontSize: "12px", color: "rgba(255, 255, 255, 0.8)", display: "block", marginBottom: "4px" }}>Optional Attachment Path</label>
                    <input
                      type="text"
                      placeholder="e.g. reports/incident_101.pdf"
                      value={waAttachment}
                      onChange={e => setWaAttachment(e.target.value)}
                      className="mem-input"
                    />
                  </div>

                  <button type="submit" className="btn-mem-action" disabled={isSendingWa}>
                    <MessageCircle size={14} /> {isSendingWa ? "Verifying..." : "Verify & Prepare Message"}
                  </button>
                </form>
              </div>

              <div className="mem-list-card">
                <h4>Verification & Confirmation Preview</h4>
                {waConfirmation ? (
                  <div style={{ background: "rgba(118, 185, 0, 0.08)", border: "1px solid rgba(118, 185, 0, 0.3)", borderRadius: "6px", padding: "16px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
                      <AlertTriangle size={18} style={{ color: "#eab308" }} />
                      <strong style={{ color: "#ffffff" }}>Confirmation Required (Safety Barrier)</strong>
                    </div>

                    <p style={{ fontSize: "12px", color: "rgba(255, 255, 255, 0.85)", lineHeight: 1.5 }}>
                      {waConfirmation.impact_explanation}
                    </p>

                    <div style={{ marginTop: "12px", fontSize: "11px", color: "rgba(255, 255, 255, 0.6)", fontFamily: "monospace" }}>
                      <div>Formatted Recipient: <strong>{waConfirmation.target_id}</strong></div>
                      <div>Action ID: {waConfirmation.action_id}</div>
                      <div>Idempotency Key: {waConfirmation.idempotency_key}</div>
                    </div>

                    <div style={{ marginTop: "16px", display: "flex", gap: "8px" }}>
                      <button
                        type="button"
                        onClick={() => {
                          setStatusMessage(`WhatsApp dispatch confirmed to ${waConfirmation.target_id}.`);
                          setWaConfirmation(null);
                        }}
                        className="btn-mem-action"
                        style={{ flex: 1, padding: "8px" }}
                      >
                        Confirm Dispatch
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setWaConfirmation(null);
                          setStatusMessage("WhatsApp dispatch cancelled.");
                        }}
                        className="btn-danger-outline"
                        style={{ padding: "8px 14px" }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="empty-mem-placeholder">
                    Enter recipient and message details on the left. Once submitted, AMOJA verifies the phone format, checks attachments for path authorization, and presents an explicit confirmation card.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* SUBTAB: WINDOWS STATUS */}
        {activeSubTab === "system" && (
          <div className="personal-system-view">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
              <h4 style={{ margin: 0, color: "#ffffff" }}>Windows Device Diagnostics & Settings</h4>
              <button
                type="button"
                onClick={fetchSystemTelemetry}
                className="btn-mem-action"
                style={{ padding: "6px 12px", fontSize: "12px" }}
                disabled={isLoadingSystem}
              >
                <RefreshCw size={13} className={isLoadingSystem ? "spin-icon" : ""} /> Refresh Telemetry
              </button>
            </div>

            {systemStatus ? (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px", marginBottom: "20px" }}>
                <div style={{ background: "rgba(10, 20, 14, 0.85)", border: "1px solid rgba(118, 185, 0, 0.2)", borderRadius: "6px", padding: "14px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "rgba(255, 255, 255, 0.6)", fontSize: "12px" }}>
                    <Cpu size={15} style={{ color: "#76b900" }} /> CPU Usage
                  </div>
                  <div style={{ fontSize: "24px", fontWeight: 700, color: "#ffffff", marginTop: "6px" }}>
                    {systemStatus.cpu?.usage_percent}%
                  </div>
                  <div style={{ fontSize: "11px", color: "rgba(255, 255, 255, 0.5)", marginTop: "4px" }}>
                    {systemStatus.cpu?.cores_physical} Physical Cores ({systemStatus.cpu?.cores_logical} Logical)
                  </div>
                </div>

                <div style={{ background: "rgba(10, 20, 14, 0.85)", border: "1px solid rgba(118, 185, 0, 0.2)", borderRadius: "6px", padding: "14px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "rgba(255, 255, 255, 0.6)", fontSize: "12px" }}>
                    <Activity size={15} style={{ color: "#38bdf8" }} /> Memory RAM
                  </div>
                  <div style={{ fontSize: "24px", fontWeight: 700, color: "#ffffff", marginTop: "6px" }}>
                    {systemStatus.memory?.usage_percent}%
                  </div>
                  <div style={{ fontSize: "11px", color: "rgba(255, 255, 255, 0.5)", marginTop: "4px" }}>
                    {Math.round(systemStatus.memory?.used_mb / 1024 * 10) / 10} GB / {Math.round(systemStatus.memory?.total_mb / 1024 * 10) / 10} GB Used
                  </div>
                </div>

                <div style={{ background: "rgba(10, 20, 14, 0.85)", border: "1px solid rgba(118, 185, 0, 0.2)", borderRadius: "6px", padding: "14px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "rgba(255, 255, 255, 0.6)", fontSize: "12px" }}>
                    <HardDrive size={15} style={{ color: "#eab308" }} /> System Disk ({systemStatus.disk?.drive})
                  </div>
                  <div style={{ fontSize: "24px", fontWeight: 700, color: "#ffffff", marginTop: "6px" }}>
                    {systemStatus.disk?.free_gb} GB Free
                  </div>
                  <div style={{ fontSize: "11px", color: "rgba(255, 255, 255, 0.5)", marginTop: "4px" }}>
                    {systemStatus.disk?.used_gb} GB Used of {systemStatus.disk?.total_gb} GB ({systemStatus.disk?.usage_percent}%)
                  </div>
                </div>

                <div style={{ background: "rgba(10, 20, 14, 0.85)", border: "1px solid rgba(118, 185, 0, 0.2)", borderRadius: "6px", padding: "14px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "rgba(255, 255, 255, 0.6)", fontSize: "12px" }}>
                    <Clock size={15} style={{ color: "#a855f7" }} /> System Uptime
                  </div>
                  <div style={{ fontSize: "24px", fontWeight: 700, color: "#ffffff", marginTop: "6px" }}>
                    {systemStatus.uptime?.formatted}
                  </div>
                  <div style={{ fontSize: "11px", color: "rgba(255, 255, 255, 0.5)", marginTop: "4px" }}>
                    OS: {systemStatus.os}
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ padding: "20px", textAlign: "center" }}>Loading system diagnostics...</div>
            )}

            <div style={{ background: "rgba(8, 16, 11, 0.8)", border: "1px solid rgba(118, 185, 0, 0.2)", borderRadius: "6px", padding: "16px" }}>
              <h5 style={{ margin: "0 0 12px 0", color: "#ffffff" }}>Quick Windows Settings Launchers (Official ms-settings URIs)</h5>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                {[
                  { label: "Network & Wi-Fi", key: "network" },
                  { label: "Windows Update", key: "update" },
                  { label: "Sound & Audio", key: "sound" },
                  { label: "Display & Monitor", key: "display" },
                  { label: "Windows Security & Firewall", key: "firewall" },
                  { label: "Installed Apps", key: "apps" },
                  { label: "Power & Sleep", key: "power" }
                ].map(s => (
                  <button
                    key={s.key}
                    type="button"
                    onClick={() => handleOpenSettings(s.key)}
                    className="mem-subtab"
                    style={{ padding: "7px 12px", fontSize: "12px" }}
                  >
                    <Settings size={13} /> {s.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* SUBTAB: USER MEMORIES */}
        {activeSubTab === "memories" && (
          <div className="mem-view-grid">
            <div className="mem-form-card">
              <h4>Store New Memory Fact</h4>
              <p className="form-subtext">AMOJA remembers your preferences across sessions.</p>
              <form onSubmit={handleAddMemory} className="mem-form">
                <input
                  type="text"
                  placeholder="Key (e.g. favorite_browser, soc_shift, role)"
                  value={newMemKey}
                  onChange={e => setNewMemKey(e.target.value)}
                  className="mem-input"
                  required
                />
                <input
                  type="text"
                  placeholder="Value (e.g. Chrome, Night Shift, SOC Lead)"
                  value={newMemVal}
                  onChange={e => setNewMemVal(e.target.value)}
                  className="mem-input"
                  required
                />
                <select
                  value={newMemCat}
                  onChange={e => setNewMemCat(e.target.value)}
                  className="mem-select"
                >
                  <option value="preference">Preference</option>
                  <option value="profile">Profile</option>
                  <option value="schedule">Schedule</option>
                  <option value="workflow">Workflow</option>
                </select>
                <button type="submit" className="btn-mem-action">
                  <Plus size={14} /> Store Fact
                </button>
              </form>

              {memories.length > 0 && (
                <div style={{ marginTop: "1.5rem" }}>
                  <button
                    type="button"
                    onClick={handleClearAllMemories}
                    className="btn-danger-outline"
                  >
                    <Trash2 size={13} /> Clear All Memories
                  </button>
                </div>
              )}
            </div>

            <div className="mem-list-card">
              <h4>Active User Memories ({memories.length})</h4>
              {memories.length === 0 ? (
                <div className="empty-mem-placeholder">No stored user memories yet. Say "AMOJA, remember that my role is Lead Analyst" or add one above.</div>
              ) : (
                <div className="memories-flow">
                  {memories.map(m => (
                    <div key={m.id || m.memory_key} className="memory-chip">
                      <div className="chip-meta">
                        <span className="chip-cat">{m.category}</span>
                        <strong>{m.memory_key}:</strong>
                        <span>{m.memory_value}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleDeleteMemory(m.memory_key)}
                        className="btn-chip-delete"
                        title="Delete memory"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* SUBTAB: REMINDERS */}
        {activeSubTab === "reminders" && (
          <div className="mem-view-grid">
            <div className="mem-form-card">
              <h4>Create Reminder</h4>
              <p className="form-subtext">Set scheduled alerts and follow-ups.</p>
              <form onSubmit={handleAddReminder} className="mem-form">
                <input
                  type="text"
                  placeholder="Reminder Title (e.g. Check firewall logs at 5 PM)"
                  value={newRemTitle}
                  onChange={e => setNewRemTitle(e.target.value)}
                  className="mem-input"
                  required
                />
                <input
                  type="text"
                  placeholder="Due Time (e.g. 17:00, Tomorrow Morning)"
                  value={newRemTime}
                  onChange={e => setNewRemTime(e.target.value)}
                  className="mem-input"
                />
                <select
                  value={newRemPriority}
                  onChange={e => setNewRemPriority(e.target.value)}
                  className="mem-select"
                >
                  <option value="NORMAL">Normal Priority</option>
                  <option value="HIGH">High Priority</option>
                  <option value="CRITICAL">Critical Priority</option>
                </select>
                <button type="submit" className="btn-mem-action">
                  <Plus size={14} /> Add Reminder
                </button>
              </form>
            </div>

            <div className="mem-list-card">
              <h4>Active Reminders ({reminders.length})</h4>
              {reminders.length === 0 ? (
                <div className="empty-mem-placeholder">No active reminders. Tell AMOJA "Set a reminder to review incident #102 at 6 PM" or create one above.</div>
              ) : (
                <div className="reminders-list">
                  {reminders.map(r => (
                    <div key={r.id} className="reminder-item-card">
                      <div className="rem-header">
                        <div className="rem-title-block">
                          <span className={`priority-pill ${r.priority.toLowerCase()}`}>{r.priority}</span>
                          <strong>{r.title}</strong>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleDeleteReminder(r.id)}
                          className="btn-item-delete"
                          title="Delete reminder"
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                      <div className="rem-footer">
                        <span><Clock size={12} /> {r.due_time || "Soon"}</span>
                        <small>{new Date(r.created_at).toLocaleTimeString()}</small>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* SUBTAB: TO-DO LIST */}
        {activeSubTab === "todos" && (
          <div className="mem-view-grid">
            <div className="mem-form-card">
              <h4>Add To-Do Item</h4>
              <p className="form-subtext">Manage quick security checklists and tasks.</p>
              <form onSubmit={handleAddTodo} className="mem-form">
                <input
                  type="text"
                  placeholder="Task Description (e.g. Rotate API tokens)"
                  value={newTodoTask}
                  onChange={e => setNewTodoTask(e.target.value)}
                  className="mem-input"
                  required
                />
                <select
                  value={newTodoPriority}
                  onChange={e => setNewTodoPriority(e.target.value)}
                  className="mem-select"
                >
                  <option value="NORMAL">Normal Priority</option>
                  <option value="HIGH">High Priority</option>
                  <option value="CRITICAL">Critical Priority</option>
                </select>
                <button type="submit" className="btn-mem-action">
                  <Plus size={14} /> Add Task
                </button>
              </form>
            </div>

            <div className="mem-list-card">
              <h4>Your Tasks ({todos.length})</h4>
              {todos.length === 0 ? (
                <div className="empty-mem-placeholder">No items in your to-do list. Add one above or say "AMOJA, add audit review to my todo list".</div>
              ) : (
                <div className="todos-list">
                  {todos.map(t => (
                    <div
                      key={t.id}
                      className={`todo-item-row ${t.completed ? "completed" : ""}`}
                      onClick={() => handleToggleTodo(t.id)}
                    >
                      <button type="button" className="btn-check">
                        {t.completed ? <CheckCircle size={16} className="text-success" /> : <Circle size={16} />}
                      </button>
                      <div className="todo-text-block">
                        <span className="todo-title">{t.task}</span>
                        <span className={`priority-tag ${t.priority.toLowerCase()}`}>{t.priority}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* SUBTAB: NOTES */}
        {activeSubTab === "notes" && (
          <div className="mem-view-grid">
            <div className="mem-form-card">
              <h4>Take a Note</h4>
              <p className="form-subtext">Store persistent multi-line technical notes and snippets.</p>
              <form onSubmit={handleAddNote} className="mem-form">
                <input
                  type="text"
                  placeholder="Note Title (e.g. Honeypot Config Notes)"
                  value={newNoteTitle}
                  onChange={e => setNewNoteTitle(e.target.value)}
                  className="mem-input"
                />
                <textarea
                  placeholder="Write your note here..."
                  value={newNoteContent}
                  onChange={e => setNewNoteContent(e.target.value)}
                  className="mem-input"
                  rows={4}
                  required
                />
                <input
                  type="text"
                  placeholder="Tags (comma-separated, e.g. soc, incident, threat)"
                  value={newNoteTags}
                  onChange={e => setNewNoteTags(e.target.value)}
                  className="mem-input"
                />
                <button type="submit" className="btn-mem-action">
                  <Plus size={14} /> Save Note
                </button>
              </form>
            </div>

            <div className="mem-list-card">
              <h4>Saved Notes ({notes.length})</h4>
              {notes.length === 0 ? (
                <div className="empty-mem-placeholder">No notes found. Say "AMOJA, take a note that suspicious IP 192.168.1.50 was flagged" or create one above.</div>
              ) : (
                <div className="notes-grid">
                  {notes.map(n => (
                    <div key={n.id} className="note-card">
                      <div className="note-card-header">
                        <strong>{n.title}</strong>
                        <button
                          type="button"
                          onClick={() => handleDeleteNote(n.id)}
                          className="btn-item-delete"
                          title="Delete note"
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                      <p className="note-body">{n.content}</p>
                      {n.tags && n.tags.length > 0 && (
                        <div className="note-tags-row">
                          {n.tags.map((tag, idx) => (
                            <span key={idx} className="note-tag"><Tag size={10} /> {tag}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* SUBTAB: HISTORY */}
        {activeSubTab === "history" && (
          <div className="mem-history-view">
            <form onSubmit={handleSearchHistory} className="history-search-form">
              <input
                type="text"
                placeholder="Search past conversations by keyword (e.g. 'kill switch', 'firewall', 'incident')..."
                value={historyQuery}
                onChange={e => setHistoryQuery(e.target.value)}
                className="mem-input"
              />
              <button type="submit" className="btn-mem-action" disabled={isSearchingHistory}>
                <Search size={14} /> {isSearchingHistory ? "Searching..." : "Search History"}
              </button>
            </form>

            <div className="history-results-list" style={{ marginTop: "1rem" }}>
              {historyResults.length === 0 && historyQuery && !isSearchingHistory && (
                <div className="empty-mem-placeholder">No matching turns found for "{historyQuery}".</div>
              )}

              {historyResults.map((h, i) => (
                <div key={i} className="history-match-card" style={{ marginBottom: "0.75rem", padding: "12px", background: "rgba(10, 20, 14, 0.8)", border: "1px solid rgba(118, 185, 0, 0.2)", borderRadius: "4px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "rgba(255, 255, 255, 0.5)", marginBottom: "4px" }}>
                    <span>Role: <strong style={{ color: h.role === "assistant" ? "#76b900" : "#ffffff" }}>{h.role}</strong></span>
                    <span>{new Date(h.created_at).toLocaleString()}</span>
                  </div>
                  <div style={{ fontSize: "13px", color: "#ffffff", whiteSpace: "pre-wrap" }}>{h.content}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
