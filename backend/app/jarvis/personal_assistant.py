# backend/app/jarvis/personal_assistant.py
"""Personal Assistant Engine for AMOJA AI & AgentShield.
Provides reminders, notes, to-do lists, approved application launcher,
safe scoped file searching, and user-controlled memories with strict
Zero-Trust guardrails (no arbitrary shell execution).
"""

import os
import json
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from ..db.database import connect, now_iso

# Approved Whitelist of desktop productivity applications
APPROVED_APPLICATIONS: Dict[str, Dict[str, Any]] = {
    "notepad": {
        "name": "Notepad",
        "executable": "notepad.exe",
        "description": "Windows Text Editor",
        "requires_confirmation": False
    },
    "calculator": {
        "name": "Calculator",
        "executable": "calc.exe",
        "description": "Windows Standard Calculator",
        "requires_confirmation": False
    },
    "calc": {
        "name": "Calculator",
        "executable": "calc.exe",
        "description": "Windows Standard Calculator",
        "requires_confirmation": False
    },
    "paint": {
        "name": "Paint",
        "executable": "mspaint.exe",
        "description": "Windows Paint Graphics Editor",
        "requires_confirmation": False
    },
    "explorer": {
        "name": "File Explorer",
        "executable": "explorer.exe",
        "description": "Windows File System Explorer",
        "requires_confirmation": False
    },
    "taskmgr": {
        "name": "Task Manager",
        "executable": "taskmgr.exe",
        "description": "Windows Task Manager (System Diagnostics)",
        "requires_confirmation": True
    }
}

# --- 1. Reminders ---

def create_reminder(user_id: str, title: str, due_time: Optional[str] = None, priority: str = "NORMAL") -> Dict[str, Any]:
    """Creates a new reminder for the user."""
    clean_title = (title or "").strip()
    if not clean_title:
        return {"error": "Reminder title cannot be empty."}

    now = now_iso()
    with connect() as db:
        cursor = db.execute(
            """INSERT INTO jarvis_reminders (user_id, title, due_time, priority, completed, created_at)
               VALUES (?, ?, ?, ?, 0, ?)""",
            (user_id, clean_title, due_time or "Soon", priority.upper(), now)
        )
        rem_id = cursor.lastrowid
        return {
            "id": rem_id,
            "title": clean_title,
            "due_time": due_time or "Soon",
            "priority": priority.upper(),
            "completed": False,
            "created_at": now,
            "message": f"Reminder '{clean_title}' saved successfully."
        }

def list_reminders(user_id: str, include_completed: bool = False) -> List[Dict[str, Any]]:
    """Lists reminders for the active user."""
    with connect() as db:
        query = "SELECT * FROM jarvis_reminders WHERE user_id = ?"
        params: List[Any] = [user_id]
        if not include_completed:
            query += " AND completed = 0"
        query += " ORDER BY id DESC LIMIT 50"
        rows = db.execute(query, params).fetchall()
        return [dict(r) for r in rows]

def delete_reminder(reminder_id: int, user_id: str) -> bool:
    """Deletes or marks completed a user reminder."""
    with connect() as db:
        res = db.execute("DELETE FROM jarvis_reminders WHERE id = ? AND user_id = ?", (reminder_id, user_id))
        return res.rowcount > 0


# --- 2. Notes ---

def create_note(user_id: str, title: str, content: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """Creates a persistent note."""
    clean_title = (title or "Untitled Note").strip()
    clean_content = (content or "").strip()
    if not clean_content:
        return {"error": "Note content cannot be empty."}

    now = now_iso()
    tags_json = json.dumps(tags or [])
    with connect() as db:
        cursor = db.execute(
            """INSERT INTO jarvis_notes (user_id, title, content, tags, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, clean_title, clean_content, tags_json, now, now)
        )
        note_id = cursor.lastrowid
        return {
            "id": note_id,
            "title": clean_title,
            "content": clean_content,
            "tags": tags or [],
            "created_at": now,
            "message": f"Note '{clean_title}' saved successfully."
        }

def search_notes(user_id: str, query: str) -> List[Dict[str, Any]]:
    """Searches user notes by title or content."""
    clean_q = f"%{(query or '').strip()}%"
    with connect() as db:
        rows = db.execute(
            """SELECT * FROM jarvis_notes 
               WHERE user_id = ? AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)
               ORDER BY updated_at DESC LIMIT 20""",
            (user_id, clean_q, clean_q, clean_q)
        ).fetchall()
        notes = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
            notes.append(d)
        return notes

def list_notes(user_id: str, limit: int = 25) -> List[Dict[str, Any]]:
    """Lists recent notes for the user."""
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM jarvis_notes WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
            (user_id, limit)
        ).fetchall()
        notes = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
            notes.append(d)
        return notes

def delete_note(note_id: int, user_id: str) -> bool:
    """Deletes a note."""
    with connect() as db:
        res = db.execute("DELETE FROM jarvis_notes WHERE id = ? AND user_id = ?", (note_id, user_id))
        return res.rowcount > 0


# --- 3. To-Do Items ---

def add_todo_item(user_id: str, task: str, priority: str = "NORMAL") -> Dict[str, Any]:
    """Adds a task to the user's to-do list."""
    clean_task = (task or "").strip()
    if not clean_task:
        return {"error": "Task description cannot be empty."}

    now = now_iso()
    with connect() as db:
        cursor = db.execute(
            """INSERT INTO jarvis_todos (user_id, task, completed, priority, created_at)
               VALUES (?, ?, 0, ?, ?)""",
            (user_id, clean_task, priority.upper(), now)
        )
        return {
            "id": cursor.lastrowid,
            "task": clean_task,
            "completed": False,
            "priority": priority.upper(),
            "created_at": now,
            "message": f"Task '{clean_task}' added to your to-do list."
        }

def list_todo_items(user_id: str, include_completed: bool = True) -> List[Dict[str, Any]]:
    """Lists to-do items."""
    with connect() as db:
        query = "SELECT * FROM jarvis_todos WHERE user_id = ?"
        params: List[Any] = [user_id]
        if not include_completed:
            query += " AND completed = 0"
        query += " ORDER BY completed ASC, id DESC LIMIT 50"
        rows = db.execute(query, params).fetchall()
        return [dict(r) for r in rows]

def toggle_todo_item(todo_id: int, user_id: str) -> Dict[str, Any]:
    """Toggles completion status of a to-do item."""
    with connect() as db:
        row = db.execute("SELECT completed FROM jarvis_todos WHERE id = ? AND user_id = ?", (todo_id, user_id)).fetchone()
        if not row:
            return {"error": f"To-do item #{todo_id} not found."}
        new_val = 0 if row["completed"] else 1
        db.execute("UPDATE jarvis_todos SET completed = ? WHERE id = ? AND user_id = ?", (new_val, todo_id, user_id))
        return {
            "id": todo_id,
            "completed": bool(new_val),
            "message": f"Task #{todo_id} marked as {'completed' if new_val else 'incomplete'}."
        }


# --- 4. User-Controlled Memory ---

def store_user_memory(user_id: str, key: str, value: str, category: str = "preference") -> Dict[str, Any]:
    """Saves a user-controlled long-term memory fact (e.g. favorite tool, role, schedule)."""
    clean_k = (key or "").strip().lower()
    clean_v = (value or "").strip()
    if not clean_k or not clean_v:
        return {"error": "Memory key and value cannot be empty."}

    now = now_iso()
    with connect() as db:
        db.execute(
            """INSERT INTO jarvis_user_memories (user_id, memory_key, memory_value, category, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id, memory_key) DO UPDATE SET memory_value=excluded.memory_value, updated_at=excluded.updated_at""",
            (user_id, clean_k, clean_v, category, now, now)
        )
        return {
            "key": clean_k,
            "value": clean_v,
            "category": category,
            "updated_at": now,
            "message": f"Memory '{clean_k}' saved."
        }

def list_user_memories(user_id: str) -> List[Dict[str, Any]]:
    """Lists all active user memories."""
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM jarvis_user_memories WHERE user_id = ? ORDER BY memory_key ASC",
            (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]

def delete_user_memory(user_id: str, key: str) -> bool:
    """Deletes a memory key upon user request."""
    clean_k = (key or "").strip().lower()
    with connect() as db:
        res = db.execute("DELETE FROM jarvis_user_memories WHERE user_id = ? AND memory_key = ?", (user_id, clean_k))
        return res.rowcount > 0

def clear_all_user_memories(user_id: str) -> int:
    """Clears all stored memories for a user."""
    with connect() as db:
        res = db.execute("DELETE FROM jarvis_user_memories WHERE user_id = ?", (user_id,))
        return res.rowcount


# --- 5. Approved Application Launcher (Strict Zero-Trust) ---

def launch_approved_application(app_name: str, user_role: str = "operator") -> Dict[str, Any]:
    """Launches an approved desktop application from the whitelist without arbitrary shell commands."""
    normalized = (app_name or "").strip().lower()
    
    # 1. Zero-Trust Metacharacter & Injection Guardrail
    forbidden_chars = [";", "&", "|", "`", "$", "<", ">", "\n", "\r", "/", "\\"]
    if any(char in normalized for char in forbidden_chars):
        return {
            "error": f"Security violation: Illegal characters detected in '{app_name}'. Arbitrary shell execution is forbidden by Zero-Trust policy.",
            "security_guardrail": "Zero-Trust prevents command chaining and metacharacter execution."
        }

    # 2. Strict Whitelist Matching
    clean_app = normalized.replace(".exe", "").strip()
    matched_key = None
    for key, spec in APPROVED_APPLICATIONS.items():
        if clean_app == key or clean_app == spec["name"].lower() or clean_app == spec["executable"].lower():
            matched_key = key
            break

    if not matched_key:
        allowed = ", ".join([spec["name"] for spec in APPROVED_APPLICATIONS.values()])
        return {
            "error": f"Application '{app_name}' is not in the approved application whitelist.",
            "allowed_applications": list(APPROVED_APPLICATIONS.keys()),
            "security_guardrail": f"Zero-Trust prevents launching unapproved binaries. Approved: {allowed}."
        }


    app_spec = APPROVED_APPLICATIONS[matched_key]
    
    # Check if application requires confirmation
    if app_spec.get("requires_confirmation") and user_role != "admin":
        return {
            "requires_confirmation": True,
            "action_id": f"act-launch-{matched_key}-{int(datetime.now().timestamp())}",
            "action_type": "LAUNCH_APPLICATION",
            "target_id": app_spec["executable"],
            "target_name": app_spec["name"],
            "risk_level": "HIGH",
            "impact_explanation": f"Launching {app_spec['name']} grants system-level process visibility.",
            "idempotency_key": f"launch-{matched_key}-{now_iso()[:19]}"
        }

    try:
        # Launch directly without shell=True to eliminate command injection
        process = subprocess.Popen(
            [app_spec["executable"]],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return {
            "success": True,
            "application": app_spec["name"],
            "pid": process.pid,
            "status": "LAUNCHED",
            "message": f"Successfully launched approved application: {app_spec['name']} (PID: {process.pid})."
        }
    except Exception as e:
        return {
            "error": f"Failed to launch application '{app_spec['name']}': {str(e)}",
            "success": False
        }


# --- 6. Safe Scoped Workspace File Search ---

def search_workspace_files(query: str, root_dir: Optional[str] = None, max_results: int = 15) -> Dict[str, Any]:
    """Searches for files within the authorized project directory without path traversal."""
    clean_q = (query or "").strip().lower()
    if not clean_q:
        return {"error": "Search query cannot be empty.", "matches": []}

    base_path = Path(root_dir or os.getcwd()).resolve()
    
    # Path traversal security check
    if ".." in clean_q or "/" in clean_q or "\\" in clean_q:
        clean_q = Path(clean_q).name.lower()

    allowed_extensions = {".py", ".ts", ".tsx", ".js", ".json", ".md", ".txt", ".yaml", ".yml", ".sql", ".css", ".html"}
    matches = []

    try:
        for p in base_path.rglob(f"*{clean_q}*"):
            # Exclude node_modules, .venv, .git, build directories
            parts = p.parts
            if any(ignored in parts for ignored in [".git", "node_modules", ".venv", "dist", "__pycache__", ".pytest_cache"]):
                continue

            if p.is_file() and (p.suffix.lower() in allowed_extensions or not p.suffix):
                try:
                    stat = p.stat()
                    matches.append({
                        "filename": p.name,
                        "relative_path": str(p.relative_to(base_path)),
                        "size_bytes": stat.st_size,
                        "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                    })
                except Exception:
                    continue

            if len(matches) >= max_results:
                break

        return {
            "query": clean_q,
            "total_matches": len(matches),
            "root_scope": str(base_path),
            "matches": matches
        }
    except Exception as e:
        return {
            "error": f"File search error: {str(e)}",
            "matches": []
        }
