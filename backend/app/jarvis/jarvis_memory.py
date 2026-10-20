import json
import sqlite3
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from ..db.database import connect, now_iso
from .jarvis_schemas import JarvisSecurityContext, JarvisPreferences, JarvisLanguage

# In-memory sliding cache for fast sub-millisecond response during continuous voice conversations
_MEMORY_CACHE: Dict[str, List[Dict[str, Any]]] = {}
_CONTEXT_CACHE: Dict[str, Dict[str, Any]] = {}
MAX_CACHED_TURNS = 20

def get_or_create_session(session_id: Optional[str], user_id: str, org_id: str = "org-default") -> str:
    """Gets an existing session if valid for user, or creates a new isolated session."""
    with connect() as db:
        if session_id:
            row = db.execute("SELECT id FROM jarvis_sessions WHERE id = ? AND user_id = ?", (session_id, user_id)).fetchone()
            if row:
                return row["id"]

        new_session_id = f"jarvis-sess-{uuid.uuid4().hex[:12]}"
        now = now_iso()
        db.execute(
            """INSERT INTO jarvis_sessions (id, user_id, org_id, title, context_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, '{}', ?, ?)""",
            (new_session_id, user_id, org_id, "SOC Investigation Session", now, now)
        )
        _MEMORY_CACHE[new_session_id] = []
        _CONTEXT_CACHE[new_session_id] = {}
        return new_session_id

def append_message(
    session_id: str,
    role: str,
    content: str,
    speech_text: Optional[str] = None,
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    tool_results: Optional[List[Dict[str, Any]]] = None,
    navigation_target: Optional[str] = None,
    action_required: Optional[Dict[str, Any]] = None
) -> int:
    """Appends a conversation message to the bounded session history."""
    now = now_iso()
    tc_json = json.dumps(tool_calls or [])
    tr_json = json.dumps(tool_results or [])
    act_json = json.dumps(action_required) if action_required else None

    # Update in-memory cache
    if session_id not in _MEMORY_CACHE:
        _MEMORY_CACHE[session_id] = []
    
    _MEMORY_CACHE[session_id].append({
        "role": role,
        "content": content,
        "speech_text": speech_text,
        "tool_calls": tool_calls or [],
        "tool_results": tool_results or [],
        "navigation_target": navigation_target,
        "action_required": action_required,
        "created_at": now
    })
    if len(_MEMORY_CACHE[session_id]) > MAX_CACHED_TURNS:
        _MEMORY_CACHE[session_id] = _MEMORY_CACHE[session_id][-MAX_CACHED_TURNS:]

    # Persist to database
    with connect() as db:
        cursor = db.execute(
            """INSERT INTO jarvis_messages 
               (session_id, role, content, speech_text, tool_calls_json, tool_results_json, navigation_target, action_required_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, role, content, speech_text, tc_json, tr_json, navigation_target, act_json, now)
        )
        msg_id = cursor.lastrowid
        db.execute("UPDATE jarvis_sessions SET updated_at = ? WHERE id = ?", (now, session_id))
        return msg_id

def get_session_history(session_id: str, user_id: str, limit: int = 25) -> List[Dict[str, Any]]:
    """Retrieves conversation turns for a session ensuring user isolation."""
    with connect() as db:
        sess = db.execute("SELECT * FROM jarvis_sessions WHERE id=? AND user_id=?", (session_id, user_id)).fetchone()
        if not sess:
            return []

        rows = db.execute(
            "SELECT * FROM jarvis_messages WHERE session_id=? ORDER BY id ASC LIMIT ?",
            (session_id, limit)
        ).fetchall()

        messages = []
        for r in rows:
            m = dict(r)
            m["tool_calls"] = json.loads(m["tool_calls_json"]) if m.get("tool_calls_json") else []
            m["tool_results"] = json.loads(m["tool_results_json"]) if m.get("tool_results_json") else []
            m["action_required"] = json.loads(m["action_required_json"]) if m.get("action_required_json") else None
            messages.append(m)
        return messages

def clear_session_history(session_id: str, user_id: str) -> bool:
    """Clears history for a session upon user request."""
    with connect() as db:
        sess = db.execute("SELECT id FROM jarvis_sessions WHERE id=? AND user_id=?", (session_id, user_id)).fetchone()
        if not sess:
            return False

        db.execute("DELETE FROM jarvis_messages WHERE session_id=?", (session_id,))
        db.execute("UPDATE jarvis_sessions SET context_json='{}', updated_at=? WHERE id=?", (now_iso(), session_id))
        
        if session_id in _MEMORY_CACHE:
            _MEMORY_CACHE[session_id] = []
        if session_id in _CONTEXT_CACHE:
            _CONTEXT_CACHE[session_id] = {}
        return True

def update_session_context(session_id: str, user_id: str, context: JarvisSecurityContext) -> None:
    """Updates active investigation context while preserving existing contextual entities if not explicitly overridden."""
    ctx_dict = context.model_dump() if hasattr(context, "model_dump") else dict(context)
    existing = get_session_context(session_id, user_id)
    merged = {**existing}
    for k, v in ctx_dict.items():
        if v is not None and v != "":
            merged[k] = v
    _CONTEXT_CACHE[session_id] = merged
    with connect() as db:
        db.execute(
            "UPDATE jarvis_sessions SET context_json = ?, updated_at = ? WHERE id = ? AND user_id = ?",
            (json.dumps(merged), now_iso(), session_id, user_id)
        )

def set_session_context_field(session_id: str, user_id: str, field_name: str, value: Any) -> None:
    """Safely updates a specific field in the session context (e.g. last_topic, last_tool, selected_device_id)."""
    existing = get_session_context(session_id, user_id)
    existing[field_name] = value
    _CONTEXT_CACHE[session_id] = existing
    with connect() as db:
        db.execute(
            "UPDATE jarvis_sessions SET context_json = ?, updated_at = ? WHERE id = ? AND user_id = ?",
            (json.dumps(existing), now_iso(), session_id, user_id)
        )

def get_session_context(session_id: str, user_id: str) -> Dict[str, Any]:
    """Retrieves cached or persisted investigation context."""
    if session_id in _CONTEXT_CACHE and _CONTEXT_CACHE[session_id]:
        return _CONTEXT_CACHE[session_id]
    with connect() as db:
        row = db.execute("SELECT context_json FROM jarvis_sessions WHERE id=? AND user_id=?", (session_id, user_id)).fetchone()
        if row and row["context_json"]:
            try:
                ctx = json.loads(row["context_json"])
                _CONTEXT_CACHE[session_id] = ctx
                return ctx
            except Exception:
                pass
    return {}

def get_recent_turn_context(session_id: str, user_id: str) -> Dict[str, Any]:
    """Extracts recent conversation turn signals including last tool executed and referenced entities."""
    ctx = dict(get_session_context(session_id, user_id))
    turns = _MEMORY_CACHE.get(session_id, [])
    if not turns:
        history = get_session_history(session_id, user_id, limit=3)
        turns = history
    if turns:
        # Scan backward from most recent turn for last assistant tool calls
        for t in reversed(turns):
            if t.get("tool_calls"):
                t_calls = t["tool_calls"]
                if t_calls and isinstance(t_calls, list):
                    last_tc = t_calls[0]
                    t_name = last_tc.get("tool_name") if isinstance(last_tc, dict) else getattr(last_tc, "tool_name", "")
                    if t_name and "last_tool" not in ctx:
                        ctx["last_tool"] = t_name
                    # Infer topic from tool
                    if "device" in t_name or "suspicious_connections" in t_name or "firewall" in t_name:
                        ctx.setdefault("last_topic", "endpoint")
                    elif "network" in t_name:
                        ctx.setdefault("last_topic", "network")
                    elif "incident" in t_name or "alert" in t_name:
                        ctx.setdefault("last_topic", "incident")
                    elif "agent" in t_name or "risk" in t_name:
                        ctx.setdefault("last_topic", "agent")
                break
    return ctx

def list_user_sessions(user_id: str, limit: int = 15) -> List[Dict[str, Any]]:
    """Lists recent conversation sessions for a user."""
    with connect() as db:
        rows = db.execute(
            """SELECT s.id, s.title, s.created_at, s.updated_at, s.context_json, COUNT(m.id) as message_count
               FROM jarvis_sessions s
               LEFT JOIN jarvis_messages m ON s.id = m.session_id
               WHERE s.user_id = ?
               GROUP BY s.id
               ORDER BY s.updated_at DESC LIMIT ?""",
            (user_id, limit)
        ).fetchall()

        results = []
        for r in rows:
            d = dict(r)
            d["context"] = json.loads(d["context_json"]) if d.get("context_json") else {}
            results.append(d)
        return results

def get_user_preferences(user_id: str) -> JarvisPreferences:
    """Retrieves user preferences for voice and assistant behavior."""
    with connect() as db:
        row = db.execute("SELECT preferences_json FROM jarvis_preferences WHERE user_id=?", (user_id,)).fetchone()
        if row and row["preferences_json"]:
            try:
                data = json.loads(row["preferences_json"])
                return JarvisPreferences(**data)
            except Exception:
                pass
    return JarvisPreferences()

def save_user_preferences(user_id: str, prefs: JarvisPreferences) -> None:
    """Saves user preferences for voice and assistant behavior."""
    now = now_iso()
    data_json = prefs.model_dump_json()
    with connect() as db:
        db.execute(
            """INSERT INTO jarvis_preferences (user_id, preferences_json, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET preferences_json=excluded.preferences_json, updated_at=excluded.updated_at""",
            (user_id, data_json, now)
        )
