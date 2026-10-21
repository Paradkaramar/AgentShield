# backend/app/jarvis/personal_assistant.py
"""Personal Assistant Engine for AMOJA AI & AgentShield.
Provides complete Windows personal assistant capabilities:
- Launching and closing approved Windows applications safely.
- Opening websites and searching/playing YouTube content.
- Searching, opening, and organizing user-authorized files and folders.
- Sending WhatsApp messages and attachments with recipient verification and confirmation.
- Creating reminders, notes, and to-do lists.
- Reading approved Windows system status and launching Windows settings.
- Running multi-step tasks with verified result reporting.
- Strict Zero-Trust guardrails (no unrestricted shell execution, no path traversal).
"""

import os
import sys
import json
import re
import shutil
import sqlite3
import subprocess
import webbrowser
import urllib.parse
import hashlib
import platform
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import psutil

from ..db.database import connect, now_iso

# Approved Whitelist of desktop productivity applications
APPROVED_APPLICATIONS: Dict[str, Dict[str, Any]] = {
    "notepad": {
        "name": "Notepad",
        "executable": "notepad.exe",
        "process_names": ["notepad.exe"],
        "description": "Windows Text Editor",
        "requires_confirmation": False
    },
    "calculator": {
        "name": "Calculator",
        "executable": "calc.exe",
        "process_names": ["calc.exe", "CalculatorApp.exe", "Calculator.exe"],
        "description": "Windows Standard Calculator",
        "requires_confirmation": False
    },
    "calc": {
        "name": "Calculator",
        "executable": "calc.exe",
        "process_names": ["calc.exe", "CalculatorApp.exe", "Calculator.exe"],
        "description": "Windows Standard Calculator",
        "requires_confirmation": False
    },
    "paint": {
        "name": "Paint",
        "executable": "mspaint.exe",
        "process_names": ["mspaint.exe", "PaintApp.exe"],
        "description": "Windows Paint Graphics Editor",
        "requires_confirmation": False
    },
    "explorer": {
        "name": "File Explorer",
        "executable": "explorer.exe",
        "process_names": ["explorer.exe"],
        "description": "Windows File System Explorer",
        "requires_confirmation": False
    },
    "taskmgr": {
        "name": "Task Manager",
        "executable": "taskmgr.exe",
        "process_names": ["taskmgr.exe", "TaskManager.exe"],
        "description": "Windows Task Manager (System Diagnostics)",
        "requires_confirmation": True
    },
    "edge": {
        "name": "Microsoft Edge",
        "executable": "msedge.exe",
        "process_names": ["msedge.exe"],
        "description": "Microsoft Edge Web Browser",
        "requires_confirmation": False
    },
    "msedge": {
        "name": "Microsoft Edge",
        "executable": "msedge.exe",
        "process_names": ["msedge.exe"],
        "description": "Microsoft Edge Web Browser",
        "requires_confirmation": False
    },
    "chrome": {
        "name": "Google Chrome",
        "executable": "chrome.exe",
        "process_names": ["chrome.exe"],
        "description": "Google Chrome Web Browser",
        "requires_confirmation": False
    },
    "code": {
        "name": "Visual Studio Code",
        "executable": "code.cmd",
        "process_names": ["Code.exe", "code.exe"],
        "description": "Visual Studio Code Development Editor",
        "requires_confirmation": False
    },
    "vscode": {
        "name": "Visual Studio Code",
        "executable": "code.cmd",
        "process_names": ["Code.exe", "code.exe"],
        "description": "Visual Studio Code Development Editor",
        "requires_confirmation": False
    }
}

# Approved Windows Settings URI Mapping
WINDOWS_SETTINGS_MAP: Dict[str, str] = {
    "network": "ms-settings:network",
    "wifi": "ms-settings:network-wifi",
    "update": "ms-settings:windowsupdate",
    "windowsupdate": "ms-settings:windowsupdate",
    "display": "ms-settings:display",
    "sound": "ms-settings:sound",
    "bluetooth": "ms-settings:bluetooth",
    "battery": "ms-settings:powersleep",
    "power": "ms-settings:powersleep",
    "storage": "ms-settings:storagesense",
    "privacy": "ms-settings:privacy",
    "firewall": "ms-settings:windowsdefender",
    "security": "ms-settings:windowsdefender",
    "apps": "ms-settings:appsfeatures",
    "settings": "ms-settings:"
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


# --- 5. Approved Application Launcher & Closer (Strict Zero-Trust) ---

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
        allowed = ", ".join(sorted(set(spec["name"] for spec in APPROVED_APPLICATIONS.values())))
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

def close_approved_application(app_name: str, force: bool = False, user_role: str = "operator") -> Dict[str, Any]:
    """Closes running instances of an approved application safely from the whitelist."""
    normalized = (app_name or "").strip().lower()
    
    # Zero-Trust Injection screening
    forbidden_chars = [";", "&", "|", "`", "$", "<", ">", "\n", "\r", "/", "\\"]
    if any(char in normalized for char in forbidden_chars):
        return {
            "error": f"Security violation: Illegal characters detected in '{app_name}'. Command injection is blocked by Zero-Trust.",
            "success": False
        }

    clean_app = normalized.replace(".exe", "").strip()
    matched_key = None
    for key, spec in APPROVED_APPLICATIONS.items():
        if clean_app == key or clean_app == spec["name"].lower() or clean_app == spec["executable"].lower():
            matched_key = key
            break

    if not matched_key:
        allowed = ", ".join(sorted(set(spec["name"] for spec in APPROVED_APPLICATIONS.values())))
        return {
            "error": f"Application '{app_name}' is not in the approved application whitelist.",
            "allowed_applications": list(APPROVED_APPLICATIONS.keys()),
            "security_guardrail": f"Zero-Trust prevents terminating unapproved processes. Approved: {allowed}."
        }

    app_spec = APPROVED_APPLICATIONS[matched_key]
    target_procs = [p.lower() for p in app_spec.get("process_names", [app_spec["executable"]])]

    # Critical shell protection: prevent terminating explorer without admin role
    if matched_key == "explorer" and user_role != "admin":
        return {
            "error": "Closing File Explorer shell requires administrative privileges to avoid disrupting the Windows desktop UI.",
            "success": False
        }

    closed_count = 0
    closed_pids = []

    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info.get('name')
                if name and name.lower() in target_procs:
                    pid = proc.info.get('pid')
                    proc.terminate()
                    closed_pids.append(pid)
                    closed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if closed_count > 0:
            if force:
                for pid in closed_pids:
                    try:
                        p = psutil.Process(pid)
                        p.kill()
                    except Exception:
                        pass
            return {
                "success": True,
                "application": app_spec["name"],
                "closed_count": closed_count,
                "closed_pids": closed_pids,
                "status": "TERMINATED",
                "message": f"Successfully closed {closed_count} running instance(s) of {app_spec['name']}."
            }
        else:
            return {
                "success": True,
                "application": app_spec["name"],
                "closed_count": 0,
                "status": "NOT_RUNNING",
                "message": f"No active instances of {app_spec['name']} were found running."
            }
    except Exception as e:
        # Fallback to taskkill on Windows
        try:
            exe = app_spec["executable"]
            res = subprocess.run(["taskkill", "/IM", exe, "/F"], capture_output=True, text=True)
            if res.returncode == 0:
                return {
                    "success": True,
                    "application": app_spec["name"],
                    "closed_count": 1,
                    "status": "TERMINATED",
                    "message": f"Successfully closed {app_spec['name']}."
                }
            return {
                "success": True,
                "application": app_spec["name"],
                "closed_count": 0,
                "status": "NOT_RUNNING",
                "message": f"No running instances of {app_spec['name']} found."
            }
        except Exception as e2:
            return {
                "error": f"Failed to close application '{app_spec['name']}': {str(e2)}",
                "success": False
            }


# --- 6. Web and YouTube Browsing Tools ---

def open_website_or_search(query_or_url: str) -> Dict[str, Any]:
    """Opens authorized web URLs or initiates a search query in the user's default browser."""
    clean = (query_or_url or "").strip()
    if not clean:
        return {"error": "Website URL or search query cannot be empty.", "success": False}

    lowered = clean.lower()
    for bad_scheme in ["javascript:", "data:", "vbscript:", "file:", "about:"]:
        if lowered.startswith(bad_scheme):
            return {
                "error": f"Security violation: Scheme '{bad_scheme}' is forbidden by Zero-Trust policy.",
                "success": False
            }

    forbidden_tokens = [";", "&&", "||", "`", "$", "<", ">"]
    if any(token in clean for token in forbidden_tokens):
        return {
            "error": "Security violation: Shell metacharacters are forbidden in web requests.",
            "success": False
        }

    is_url = bool(re.match(r"^(?:https?:\/\/)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/.*)?$", clean))

    if is_url:
        target_url = clean if clean.startswith("http://") or clean.startswith("https://") else f"https://{clean}"
        action_type = "OPEN_URL"
    else:
        encoded = urllib.parse.quote_plus(clean)
        target_url = f"https://www.google.com/search?q={encoded}"
        action_type = "WEB_SEARCH"

    try:
        webbrowser.open(target_url, new=2)
        return {
            "success": True,
            "action_type": action_type,
            "target_url": target_url,
            "query": clean,
            "status": "OPENED",
            "message": f"Successfully launched {action_type.lower().replace('_', ' ')}: {target_url}"
        }
    except Exception as e:
        return {
            "error": f"Failed to open browser: {str(e)}",
            "success": False
        }

def search_or_play_youtube(query: str, autoplay: bool = True) -> Dict[str, Any]:
    """Searches YouTube or opens videos/music safely in the default browser."""
    clean = (query or "").strip()
    if not clean:
        return {"error": "YouTube query cannot be empty.", "success": False}

    clean_q = re.sub(r"^(?:play|search|look\s+up|find)\s+(?:on\s+youtube|youtube\s+pe)?\s*", "", clean, flags=re.IGNORECASE)
    clean_q = re.sub(r"\s+(?:on\s+youtube|in\s+youtube|youtube\s+par|youtube\s+var)$", "", clean_q, flags=re.IGNORECASE).strip()
    if not clean_q:
        clean_q = clean

    forbidden_tokens = [";", "&&", "||", "`", "$", "<", ">"]
    if any(token in clean_q for token in forbidden_tokens):
        return {"error": "Security violation: Shell metacharacters forbidden.", "success": False}

    encoded = urllib.parse.quote_plus(clean_q)
    youtube_url = f"https://www.youtube.com/results?search_query={encoded}"

    try:
        webbrowser.open(youtube_url, new=2)
        return {
            "success": True,
            "query": clean_q,
            "youtube_url": youtube_url,
            "status": "OPENED",
            "message": f"Successfully opened YouTube for '{clean_q}': {youtube_url}"
        }
    except Exception as e:
        return {"error": f"Failed to open YouTube: {str(e)}", "success": False}


# --- 7. Safe Scoped Authorized File and Folder Tools ---

def get_authorized_roots() -> Dict[str, Path]:
    """Returns valid user-authorized directory roots (workspace, Documents, Downloads, Desktop)."""
    home = Path.home()
    roots = {
        "workspace": Path(os.getcwd()).resolve(),
        "documents": (home / "Documents").resolve(),
        "downloads": (home / "Downloads").resolve(),
        "desktop": (home / "Desktop").resolve()
    }
    return {k: v for k, v in roots.items() if v.exists()}

def is_path_authorized(target_path: Path) -> bool:
    """Verifies that target_path falls strictly within authorized user roots without system directory traversal."""
    try:
        resolved = target_path.resolve()
        resolved_str = str(resolved).lower()
        forbidden_patterns = ["windows", "system32", "syswow64", "program files", "program files (x86)", "appdata"]
        if any(f"\\{fp}\\" in resolved_str or resolved_str.endswith(f"\\{fp}") for fp in forbidden_patterns):
            return False

        auth_roots = get_authorized_roots()
        for root in auth_roots.values():
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False
    except Exception:
        return False

def search_workspace_files(query: str, root_dir: Optional[str] = None, max_results: int = 15) -> Dict[str, Any]:
    """Backward-compatible file search within workspace directory."""
    return search_authorized_files(query=query, scope="workspace", max_results=max_results)

def search_authorized_files(query: str, scope: Optional[str] = None, max_results: int = 20) -> Dict[str, Any]:
    """Searches for files and folders safely within authorized scopes without path traversal."""
    clean_q = (query or "").strip().lower()
    if not clean_q:
        return {"error": "Search query cannot be empty.", "matches": []}

    if ".." in clean_q or "/" in clean_q or "\\" in clean_q:
        clean_q = Path(clean_q).name.lower()

    auth_roots = get_authorized_roots()
    if scope and scope.lower() in auth_roots:
        search_roots = [auth_roots[scope.lower()]]
    else:
        search_roots = list(auth_roots.values())

    allowed_extensions = {".py", ".ts", ".tsx", ".js", ".json", ".md", ".txt", ".yaml", ".yml", ".sql", ".css", ".html", ".pdf", ".docx", ".xlsx", ".png", ".jpg"}
    matches = []

    for root in search_roots:
        try:
            for p in root.rglob(f"*{clean_q}*"):
                parts = p.parts
                if any(ignored in parts for ignored in [".git", "node_modules", ".venv", "dist", "__pycache__", ".pytest_cache"]):
                    continue

                if not is_path_authorized(p):
                    continue

                if p.is_file() and (p.suffix.lower() in allowed_extensions or not p.suffix):
                    try:
                        stat = p.stat()
                        matches.append({
                            "name": p.name,
                            "filename": p.name,
                            "relative_path": str(p.relative_to(root)),
                            "full_path": str(p),
                            "scope": root.name,
                            "is_dir": False,
                            "size_bytes": stat.st_size,
                            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                        })
                    except Exception:
                        continue
                elif p.is_dir():
                    matches.append({
                        "name": p.name,
                        "filename": p.name,
                        "relative_path": str(p.relative_to(root)),
                        "full_path": str(p),
                        "scope": root.name,
                        "is_dir": True,
                        "size_bytes": 0,
                        "modified_at": datetime.now(timezone.utc).isoformat()
                    })

                if len(matches) >= max_results:
                    break
        except Exception:
            continue
        if len(matches) >= max_results:
            break

    return {
        "query": clean_q,
        "total_matches": len(matches),
        "authorized_scopes": list(auth_roots.keys()),
        "matches": matches
    }

def open_authorized_file_or_folder(filepath: str) -> Dict[str, Any]:
    """Safely opens an authorized file or reveals a folder in Windows File Explorer."""
    clean = (filepath or "").strip()
    if not clean:
        return {"error": "File or folder path cannot be empty.", "success": False}

    target = Path(clean).resolve()
    if not target.exists():
        found = False
        for root in get_authorized_roots().values():
            cand = (root / clean).resolve()
            if cand.exists():
                target = cand
                found = True
                break
        if not found:
            return {"error": f"Path '{filepath}' does not exist.", "success": False}

    if not is_path_authorized(target):
        return {
            "error": f"Security violation: Access to '{target}' is not authorized. Scoped only to workspace, Documents, Downloads, Desktop.",
            "success": False
        }

    try:
        if sys.platform == "win32":
            os.startfile(str(target))
        else:
            subprocess.Popen(["xdg-open", str(target)])

        return {
            "success": True,
            "path": str(target),
            "is_dir": target.is_dir(),
            "status": "OPENED",
            "message": f"Successfully opened {'folder' if target.is_dir() else 'file'}: {target.name}"
        }
    except Exception as e:
        return {"error": f"Failed to open '{target.name}': {str(e)}", "success": False}

def organize_authorized_files(
    operation: str,
    source_path: str,
    target_path: Optional[str] = None,
    new_name: Optional[str] = None,
    user_role: str = "operator"
) -> Dict[str, Any]:
    """Organizes authorized files (move, rename, create_folder) with explicit confirmation."""
    clean_op = (operation or "").strip().lower()
    if clean_op not in {"move", "rename", "create_folder"}:
        return {"error": f"Invalid operation '{operation}'. Supported: move, rename, create_folder.", "success": False}

    src = Path(source_path).resolve()

    if clean_op in {"move", "rename"}:
        if not src.exists():
            return {"error": f"Source '{source_path}' does not exist.", "success": False}
        if not is_path_authorized(src):
            return {"error": f"Source path '{source_path}' is not within authorized user directories.", "success": False}

    if clean_op == "create_folder":
        if not is_path_authorized(src):
            return {"error": f"Target folder location '{source_path}' is not authorized.", "success": False}
        try:
            src.mkdir(parents=True, exist_ok=True)
            return {
                "success": True,
                "operation": "create_folder",
                "folder_path": str(src),
                "message": f"Successfully created folder: {src.name}"
            }
        except Exception as e:
            return {"error": f"Failed to create folder: {str(e)}", "success": False}

    dest_desc = target_path or new_name
    return {
        "requires_confirmation": True,
        "action_id": f"act-file-{clean_op}-{int(datetime.now().timestamp())}",
        "action_type": f"ORGANIZE_FILE_{clean_op.upper()}",
        "target_id": str(src),
        "target_name": src.name,
        "risk_level": "MEDIUM",
        "impact_explanation": f"Will {clean_op} '{src.name}' to '{dest_desc}'.",
        "details": {
            "operation": clean_op,
            "source": str(src),
            "target": target_path,
            "new_name": new_name
        },
        "idempotency_key": f"file-{clean_op}-{hashlib.sha256(str(src).encode()).hexdigest()[:10]}-{now_iso()[:19]}"
    }


# --- 8. WhatsApp Automation with Recipient Verification & Confirmation ---

def prepare_whatsapp_message(
    recipient: str,
    message: str,
    attachment_path: Optional[str] = None,
    user_role: str = "operator"
) -> Dict[str, Any]:
    """Prepares WhatsApp message automation with recipient verification and mandatory human confirmation."""
    clean_recip = (recipient or "").strip()
    clean_msg = (message or "").strip()

    if not clean_recip:
        return {"error": "WhatsApp recipient phone number or contact name cannot be empty.", "success": False}
    if not clean_msg:
        return {"error": "WhatsApp message content cannot be empty.", "success": False}
    if len(clean_msg) > 2000:
        return {"error": "WhatsApp message exceeds maximum 2000 character limit.", "success": False}

    # Recipient verification: format phone number if numeric
    digits = re.sub(r"[^\d+]", "", clean_recip)
    if digits.startswith("+"):
        formatted_phone = digits
    elif len(digits) == 10:
        formatted_phone = f"+91{digits}"
    elif len(digits) >= 11:
        formatted_phone = f"+{digits}"
    else:
        formatted_phone = clean_recip

    verified_attachment = None
    if attachment_path:
        att = Path(attachment_path).resolve()
        if not att.exists() or not att.is_file():
            return {"error": f"Attachment file '{attachment_path}' does not exist.", "success": False}
        if not is_path_authorized(att):
            return {"error": f"Attachment file '{attachment_path}' is not within user-authorized directories.", "success": False}
        verified_attachment = str(att)

    action_id = f"act-whatsapp-{int(datetime.now().timestamp())}"
    idem_key = f"wa-{hashlib.sha256((formatted_phone + clean_msg).encode()).hexdigest()[:12]}-{now_iso()[:19]}"

    return {
        "requires_confirmation": True,
        "action_id": action_id,
        "action_type": "SEND_WHATSAPP_MESSAGE",
        "target_id": formatted_phone,
        "target_name": f"WhatsApp: {formatted_phone}",
        "risk_level": "HIGH",
        "impact_explanation": f"Explicit confirmation required before dispatching WhatsApp message to '{formatted_phone}'. Message preview: \"{clean_msg[:100]}{'...' if len(clean_msg) > 100 else ''}\"",
        "details": {
            "recipient": formatted_phone,
            "raw_recipient": clean_recip,
            "message": clean_msg,
            "attachment_path": verified_attachment
        },
        "idempotency_key": idem_key
    }


# --- 9. Approved Windows System Status & Settings ---

def get_windows_system_status() -> Dict[str, Any]:
    """Reads approved Windows system status: CPU, memory, disk, battery, OS version, uptime, and network adapters."""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count_phys = psutil.cpu_count(logical=False) or 1
        cpu_count_log = psutil.cpu_count(logical=True) or 1

        mem = psutil.virtual_memory()
        mem_total_mb = round(mem.total / (1024 * 1024), 1)
        mem_used_mb = round(mem.used / (1024 * 1024), 1)
        mem_avail_mb = round(mem.available / (1024 * 1024), 1)
        mem_percent = mem.percent

        drive = "C:\\" if sys.platform == "win32" else "/"
        try:
            disk = psutil.disk_usage(drive)
            disk_total_gb = round(disk.total / (1024**3), 1)
            disk_used_gb = round(disk.used / (1024**3), 1)
            disk_free_gb = round(disk.free / (1024**3), 1)
            disk_percent = disk.percent
        except Exception:
            disk_total_gb, disk_used_gb, disk_free_gb, disk_percent = 0, 0, 0, 0

        battery_data = {"has_battery": False, "percent": 100, "power_plugged": True, "status": "Desktop / A/C Connected"}
        try:
            sensors = psutil.sensors_battery()
            if sensors is not None:
                battery_data = {
                    "has_battery": True,
                    "percent": sensors.percent,
                    "power_plugged": sensors.power_plugged,
                    "status": "Charging" if sensors.power_plugged else "On Battery",
                    "secs_left": sensors.secsleft if sensors.secsleft != psutil.POWER_TIME_UNLIMITED else None
                }
        except Exception:
            pass

        boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
        uptime_seconds = int((datetime.now(timezone.utc) - boot_time).total_seconds())
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60

        net_adapters = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface, addr_list in addrs.items():
                is_up = stats[iface].isup if iface in stats else True
                ipv4 = [a.address for a in addr_list if getattr(a.family, "name", "") == "AF_INET" and not a.address.startswith("127.")]
                if ipv4 and is_up:
                    net_adapters.append({"interface": iface, "ip": ipv4[0], "is_up": is_up})
        except Exception:
            pass

        return {
            "status": "HEALTHY",
            "os": f"Windows {platform.release()} ({platform.machine()})" if sys.platform == "win32" else f"{platform.system()} {platform.release()}",
            "hostname": platform.node(),
            "cpu": {
                "usage_percent": cpu_percent,
                "cores_physical": cpu_count_phys,
                "cores_logical": cpu_count_log
            },
            "memory": {
                "total_mb": mem_total_mb,
                "used_mb": mem_used_mb,
                "available_mb": mem_avail_mb,
                "usage_percent": mem_percent
            },
            "disk": {
                "drive": drive,
                "total_gb": disk_total_gb,
                "used_gb": disk_used_gb,
                "free_gb": disk_free_gb,
                "usage_percent": disk_percent
            },
            "battery": battery_data,
            "uptime": {
                "boot_time": boot_time.isoformat(),
                "uptime_hours": hours,
                "uptime_minutes": minutes,
                "formatted": f"{hours}h {minutes}m"
            },
            "network_adapters": net_adapters
        }
    except Exception as e:
        return {"error": f"Failed to inspect system status: {str(e)}", "status": "ERROR"}

def open_windows_settings(setting_page: str = "settings") -> Dict[str, Any]:
    """Opens approved Windows Settings pages safely using official ms-settings URIs."""
    clean = (setting_page or "settings").strip().lower()

    uri = WINDOWS_SETTINGS_MAP.get(clean)
    if not uri:
        for k, v in WINDOWS_SETTINGS_MAP.items():
            if k in clean:
                uri = v
                clean = k
                break

    if not uri:
        allowed = ", ".join(WINDOWS_SETTINGS_MAP.keys())
        return {
            "error": f"Settings page '{setting_page}' not recognized. Allowed: {allowed}",
            "allowed_pages": list(WINDOWS_SETTINGS_MAP.keys()),
            "success": False
        }

    try:
        if sys.platform == "win32":
            os.startfile(uri)
        else:
            return {"error": "Windows Settings URI is only available on Windows operating system.", "success": False}

        return {
            "success": True,
            "page": clean,
            "uri": uri,
            "status": "OPENED",
            "message": f"Successfully opened Windows Settings ({clean}): {uri}"
        }
    except Exception as e:
        return {"error": f"Failed to launch Windows Settings: {str(e)}", "success": False}


# --- 10. AgentShield Process Analysis & Firewall Control ---

def analyze_suspicious_processes(top_n: int = 15) -> Dict[str, Any]:
    """Analyzes active Windows processes for suspicious activity, anomalous CPU/RAM, unverified paths, and non-standard sockets."""
    try:
        suspicious_list = []
        normal_count = 0
        suspicious_dir_patterns = ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
        known_masquerade = {"scvhost.exe", "svch0st.exe", "lsasss.exe", "csrsss.exe", "taskmg.exe"}

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info', 'status']):
            try:
                name = proc.info.get('name') or "unknown"
                exe = proc.info.get('exe') or ""
                mem_bytes = proc.info.get('memory_info').rss if proc.info.get('memory_info') else 0
                mem_mb = round(mem_bytes / (1024 * 1024), 1)
                cpu = proc.info.get('cpu_percent') or 0.0
                pid = proc.info.get('pid')

                low_name = name.lower()
                low_exe = exe.lower()

                flags = []
                risk_score = 5

                if low_name in known_masquerade:
                    flags.append(f"Known disguise/masquerading binary name: '{name}'")
                    risk_score += 65

                if low_name == "svchost.exe" and exe and "\\system32\\" not in low_exe:
                    flags.append(f"svchost running from non-System32 path: {exe}")
                    risk_score += 70

                if any(sp in low_exe for sp in suspicious_dir_patterns):
                    flags.append(f"Process running from temporary/downloads location: {exe}")
                    risk_score += 40

                if mem_mb > 1500 and low_name not in {"chrome.exe", "msedge.exe", "code.exe", "python.exe"}:
                    flags.append(f"High memory consumption: {mem_mb} MB")
                    risk_score += 20

                if flags:
                    severity = "CRITICAL" if risk_score >= 70 else ("HIGH" if risk_score >= 40 else "MEDIUM")
                    suspicious_list.append({
                        "pid": pid,
                        "name": name,
                        "executable": exe or name,
                        "memory_mb": mem_mb,
                        "cpu_percent": cpu,
                        "risk_score": min(100, risk_score),
                        "severity": severity,
                        "reasons": flags
                    })
                else:
                    normal_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        suspicious_list.sort(key=lambda x: x["risk_score"], reverse=True)
        suspicious_top = suspicious_list[:top_n]

        return {
            "status": "COMPLETED",
            "total_processes_scanned": normal_count + len(suspicious_list),
            "suspicious_count": len(suspicious_list),
            "normal_count": normal_count,
            "threat_detected": len(suspicious_list) > 0,
            "findings": suspicious_top
        }
    except Exception as e:
        return {"error": f"Failed to analyze processes: {str(e)}", "status": "ERROR"}

def prepare_firewall_rule_change(
    action: str,
    rule_name: str,
    direction: str = "in",
    port: Optional[int] = None,
    protocol: str = "TCP",
    user_role: str = "operator"
) -> Dict[str, Any]:
    """Prepares carefully approved host firewall configuration changes with mandatory confirmation."""
    clean_action = (action or "").strip().lower()
    clean_name = (rule_name or "").strip()
    clean_dir = (direction or "in").strip().lower()
    clean_proto = (protocol or "TCP").strip().upper()

    if clean_action not in {"add_block_rule", "add_allow_rule", "delete_rule"}:
        return {
            "error": f"Invalid action '{action}'. Supported actions: add_block_rule, add_allow_rule, delete_rule.",
            "success": False
        }

    if not clean_name:
        return {"error": "Firewall rule name cannot be empty.", "success": False}

    if clean_dir not in {"in", "out"}:
        return {"error": "Firewall direction must be 'in' or 'out'.", "success": False}

    if clean_proto not in {"TCP", "UDP"}:
        return {"error": "Firewall protocol must be TCP or UDP.", "success": False}

    if port is not None and (port < 1 or port > 65535):
        return {"error": "Port number must be between 1 and 65535.", "success": False}

    if any(c in clean_name for c in [";", "&", "|", "`", "$", "<", ">", "\"", "'"]):
        return {"error": "Illegal characters in firewall rule name.", "success": False}

    action_id = f"act-firewall-{clean_action}-{int(datetime.now().timestamp())}"
    idem_key = f"fw-{clean_action}-{hashlib.sha256((clean_name + str(port)).encode()).hexdigest()[:10]}-{now_iso()[:19]}"

    impact = f"Firewall configuration change: {clean_action.replace('_', ' ')} on rule '{clean_name}' (Direction: {clean_dir.upper()}, Port: {port or 'ALL'}, Protocol: {clean_proto})."

    return {
        "requires_confirmation": True,
        "action_id": action_id,
        "action_type": f"FIREWALL_{clean_action.upper()}",
        "target_id": clean_name,
        "target_name": f"Firewall Rule: {clean_name}",
        "risk_level": "HIGH",
        "impact_explanation": impact,
        "details": {
            "action": clean_action,
            "rule_name": clean_name,
            "direction": clean_dir,
            "port": port,
            "protocol": clean_proto
        },
        "idempotency_key": idem_key
    }


# --- 11. Multi-Step Task Execution Planner ---

def execute_multistep_task(
    task_description: str,
    steps: List[Dict[str, Any]],
    user: Dict[str, Any]
) -> Dict[str, Any]:
    """Runs a multi-step task sequentially and reports verified results at every step."""
    from .jarvis_tools import dispatch_tool

    results = []
    for idx, step in enumerate(steps):
        tool_name = step.get("tool_name")
        args = step.get("arguments", {})
        description = step.get("description", f"Step {idx+1}")

        t_start = datetime.now(timezone.utc)
        step_res = dispatch_tool(tool_name, args, user)
        dur = int((datetime.now(timezone.utc) - t_start).total_seconds() * 1000)

        if isinstance(step_res, dict) and step_res.get("requires_confirmation"):
            return {
                "multistep_status": "PAUSED_FOR_CONFIRMATION",
                "completed_steps": results,
                "paused_at_step": idx + 1,
                "current_step_description": description,
                "requires_confirmation": True,
                "confirmation_data": step_res
            }

        is_success = "error" not in step_res if isinstance(step_res, dict) else True
        results.append({
            "step_number": idx + 1,
            "description": description,
            "tool_name": tool_name,
            "success": is_success,
            "result": step_res,
            "duration_ms": dur
        })

        if not is_success:
            return {
                "multistep_status": "FAILED_AT_STEP",
                "failed_step": idx + 1,
                "error": step_res.get("error", "Step failed") if isinstance(step_res, dict) else "Step failed",
                "completed_steps": results
            }

    return {
        "multistep_status": "COMPLETED",
        "task_description": task_description,
        "total_steps": len(steps),
        "steps_results": results,
        "message": f"Successfully completed all {len(steps)} steps of task: '{task_description}'."
    }
