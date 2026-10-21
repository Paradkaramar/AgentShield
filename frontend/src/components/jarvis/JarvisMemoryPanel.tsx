// frontend/src/components/jarvis/JarvisMemoryPanel.tsx
import React, { useState, useEffect } from "react";
import {
  Brain, Search, Plus, Trash2, CheckCircle, Circle,
  Calendar, Clock, Tag, ShieldCheck, AlertCircle, RefreshCw, FileText, CheckSquare
} from "lucide-react";
import {
  getJarvisReminders, createJarvisReminder, deleteJarvisReminder,
  getJarvisNotes, createJarvisNote, deleteJarvisNote,
  getJarvisTodos, createJarvisTodo, toggleJarvisTodo,
  getJarvisMemories, createJarvisMemory, deleteJarvisMemory, clearJarvisMemories,
  searchJarvisHistory
} from "../../api";
import { JarvisReminder, JarvisNote, JarvisTodo, JarvisMemory } from "../../types";

export const JarvisMemoryPanel: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<"memories" | "reminders" | "todos" | "notes" | "history">("memories");
  const [isLoading, setIsLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Data states
  const [memories, setMemories] = useState<JarvisMemory[]>([]);
  const [reminders, setReminders] = useState<JarvisReminder[]>([]);
  const [todos, setTodos] = useState<JarvisTodo[]>([]);
  const [notes, setNotes] = useState<JarvisNote[]>([]);
  
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
      const [mRes, rRes, tRes, nRes] = await Promise.all([
        getJarvisMemories(),
        getJarvisReminders(true),
        getJarvisTodos(true),
        getJarvisNotes()
      ]);
      setMemories(mRes.memories || []);
      setReminders(rRes.reminders || []);
      setTodos(tRes.todos || []);
      setNotes(nRes.notes || []);
    } catch (err: any) {
      setStatusMessage(`Error loading memory items: ${err.message || String(err)}`);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    refreshData();
  }, []);

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
            <h3>JARVIS Personal Memory & Productivity Hub</h3>
            <p>User-controlled memories, reminders, task lists, and searchable audit history.</p>
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
      <div className="memory-subtabs-nav">
        <button
          type="button"
          className={`mem-subtab ${activeSubTab === "memories" ? "active" : ""}`}
          onClick={() => setActiveSubTab("memories")}
        >
          <Brain size={14} />
          <span>User Memory Facts ({memories.length})</span>
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
          className={`mem-subtab ${activeSubTab === "history" ? "active" : ""}`}
          onClick={() => setActiveSubTab("history")}
        >
          <Search size={14} />
          <span>Search Conversation History</span>
        </button>
      </div>

      {/* Content Area */}
      <div className="memory-tab-content">
        {/* SUBTAB 1: USER MEMORIES */}
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

        {/* SUBTAB 2: REMINDERS */}
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

        {/* SUBTAB 3: TO-DO LIST */}
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
                  <option value="CRITICAL">Critical</option>
                </select>
                <button type="submit" className="btn-mem-action">
                  <Plus size={14} /> Add Task
                </button>
              </form>
            </div>

            <div className="mem-list-card">
              <h4>Action Items ({todos.length})</h4>
              {todos.length === 0 ? (
                <div className="empty-mem-placeholder">No tasks in your to-do list. Tell AMOJA "Add task patch OpenSSL" or add one above.</div>
              ) : (
                <div className="todos-list">
                  {todos.map(t => {
                    const isDone = Boolean(t.completed);
                    return (
                      <div key={t.id} className={`todo-item-row ${isDone ? "completed" : ""}`}>
                        <button
                          type="button"
                          onClick={() => handleToggleTodo(t.id)}
                          className="btn-todo-check"
                        >
                          {isDone ? (
                            <CheckCircle size={18} className="neon-green" />
                          ) : (
                            <Circle size={18} className="text-muted" />
                          )}
                        </button>
                        <span className={`todo-text ${isDone ? "strikethrough" : ""}`}>
                          {t.task}
                        </span>
                        <span className={`priority-pill ${t.priority.toLowerCase()}`}>{t.priority}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* SUBTAB 4: NOTES */}
        {activeSubTab === "notes" && (
          <div className="mem-view-grid">
            <div className="mem-form-card">
              <h4>Create Secure Note</h4>
              <p className="form-subtext">Save investigation notes and snippets.</p>
              <form onSubmit={handleAddNote} className="mem-form">
                <input
                  type="text"
                  placeholder="Title (e.g. Honeypot Observation)"
                  value={newNoteTitle}
                  onChange={e => setNewNoteTitle(e.target.value)}
                  className="mem-input"
                />
                <textarea
                  placeholder="Note content..."
                  value={newNoteContent}
                  onChange={e => setNewNoteContent(e.target.value)}
                  className="mem-textarea"
                  rows={4}
                  required
                />
                <input
                  type="text"
                  placeholder="Tags comma-separated (e.g. soc, network, alert)"
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
              <h4>Personal Notes ({notes.length})</h4>
              {notes.length === 0 ? (
                <div className="empty-mem-placeholder">No personal notes saved yet. Tell AMOJA "Take a note about the morning scan" or create one above.</div>
              ) : (
                <div className="notes-list-grid">
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
                      <p className="note-content-preview">{n.content}</p>
                      <div className="note-tags-row">
                        {n.tags?.map((tag, idx) => (
                          <span key={idx} className="note-tag">#{tag}</span>
                        ))}
                      </div>
                      <small className="note-date">{new Date(n.updated_at).toLocaleDateString()}</small>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* SUBTAB 5: SEARCH CONVERSATION HISTORY */}
        {activeSubTab === "history" && (
          <div className="history-search-view">
            <form onSubmit={handleSearchHistory} className="history-search-bar">
              <Search size={18} className="search-icon" />
              <input
                type="text"
                placeholder="Search across all past conversation turns, commands, and security investigations..."
                value={historyQuery}
                onChange={e => setHistoryQuery(e.target.value)}
                className="history-input"
              />
              <button type="submit" className="btn-history-search" disabled={isSearchingHistory}>
                {isSearchingHistory ? "Searching..." : "Search"}
              </button>
            </form>

            <div className="history-results-container">
              {historyResults.length === 0 ? (
                <div className="empty-history-placeholder">
                  {historyQuery ? "No conversation matches found." : "Enter a search query to scan through your historical dialogue and commands."}
                </div>
              ) : (
                <div className="history-matches-list">
                  {historyResults.map((r, i) => (
                    <div key={i} className={`history-turn-item ${r.role}`}>
                      <div className="turn-meta">
                        <span className={`turn-role-pill ${r.role}`}>{r.role.toUpperCase()}</span>
                        <span className="turn-session-title">{r.session_title}</span>
                        <small>{new Date(r.created_at).toLocaleString()}</small>
                      </div>
                      <p className="turn-content">{r.content}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
