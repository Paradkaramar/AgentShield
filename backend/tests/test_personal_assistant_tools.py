# backend/tests/test_personal_assistant_tools.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.db.database import init_db
from app.main import app
from app.jarvis.personal_assistant import (
    create_reminder, list_reminders, delete_reminder,
    create_note, list_notes, search_notes, delete_note,
    add_todo_item, list_todo_items, toggle_todo_item,
    store_user_memory, list_user_memories, delete_user_memory, clear_all_user_memories,
    launch_approved_application, search_workspace_files,
    APPROVED_APPLICATIONS
)
from app.jarvis.jarvis_memory import search_conversation_history, append_message, get_or_create_session
from app.core.auth import create_access_token

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    init_db()

@pytest.fixture
def auth_headers():
    token = create_access_token({"username": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_user():
    return "test_operator_42"

# --- 1. Reminders Unit Tests ---
def test_reminders_lifecycle(test_user):
    rem = create_reminder(test_user, "Submit SOC incident report", due_time="17:00", priority="HIGH")
    assert rem.get("id") is not None
    assert rem["title"] == "Submit SOC incident report"
    assert rem["priority"] == "HIGH"
    
    items = list_reminders(test_user)
    assert any(r["id"] == rem["id"] for r in items)

    deleted = delete_reminder(rem["id"], test_user)
    assert deleted is True

    items_after = list_reminders(test_user)
    assert not any(r["id"] == rem["id"] for r in items_after)

def test_reminder_empty_title_validation(test_user):
    res = create_reminder(test_user, "   ")
    assert "error" in res

# --- 2. Notes Unit Tests ---
def test_notes_lifecycle_and_search(test_user):
    note1 = create_note(test_user, "Firewall Config", "Rule 443 allows TLS traffic.", tags=["network", "firewall"])
    note2 = create_note(test_user, "Team Standup", "Discuss AgentShield release.", tags=["meeting"])
    assert note1.get("id") is not None

    all_notes = list_notes(test_user)
    assert len(all_notes) >= 2

    search_res = search_notes(test_user, "TLS")
    assert len(search_res) >= 1
    assert any(n["id"] == note1["id"] for n in search_res)

    deleted = delete_note(note1["id"], test_user)
    assert deleted is True
    delete_note(note2["id"], test_user)

# --- 3. To-Do Unit Tests ---
def test_todo_lifecycle(test_user):
    todo = add_todo_item(test_user, "Patch vulnerable OpenSSL library", priority="CRITICAL")
    assert todo.get("id") is not None
    assert todo["completed"] is False

    items = list_todo_items(test_user)
    assert any(t["id"] == todo["id"] for t in items)

    toggled = toggle_todo_item(todo["id"], test_user)
    assert toggled["completed"] is True

    toggled_back = toggle_todo_item(todo["id"], test_user)
    assert toggled_back["completed"] is False

# --- 4. User-Controlled Memory Unit Tests ---
def test_user_memory_lifecycle(test_user):
    res = store_user_memory(test_user, "preferred_language", "marathi", category="profile")
    assert res.get("key") == "preferred_language"
    assert res.get("value") == "marathi"

    memories = list_user_memories(test_user)
    assert any(m["memory_key"] == "preferred_language" and m["memory_value"] == "marathi" for m in memories)

    # Test update
    store_user_memory(test_user, "preferred_language", "hindi", category="profile")
    updated = list_user_memories(test_user)
    val = [m["memory_value"] for m in updated if m["memory_key"] == "preferred_language"][0]
    assert val == "hindi"

    # Test delete
    deleted = delete_user_memory(test_user, "preferred_language")
    assert deleted is True

    # Test clear all
    store_user_memory(test_user, "pref_1", "v1")
    store_user_memory(test_user, "pref_2", "v2")
    cleared_count = clear_all_user_memories(test_user)
    assert cleared_count >= 2

# --- 5. Application Launcher Zero-Trust Guardrails ---
def test_app_launcher_approved_app():
    with patch("subprocess.Popen") as mock_popen:
        res = launch_approved_application("notepad")
        assert res.get("success") is True
        assert "Notepad" in res["application"]
        mock_popen.assert_called_once()
        # Verify shell=False is strictly enforced
        args, kwargs = mock_popen.call_args
        assert kwargs.get("shell") is False

def test_app_launcher_blocks_unauthorized_shell():
    bad_commands = [
        "powershell -c evil",
        "cmd.exe",
        "calc.exe; rm -rf /",
        "malware.exe",
        "explorer.exe & whoami"
    ]
    for cmd in bad_commands:
        res = launch_approved_application(cmd)
        assert "error" in res
        assert "Zero-Trust" in res.get("security_guardrail", "") or "not in the approved" in res["error"]

def test_app_launcher_requires_confirmation_for_taskmgr():
    res = launch_approved_application("taskmgr", user_role="operator")
    assert res.get("requires_confirmation") is True

# --- 6. Safe Workspace File Search ---
def test_file_search_workspace():
    res = search_workspace_files("database.py")
    assert "error" not in res
    assert res["total_matches"] >= 1
    assert any("database.py" in m["filename"] for m in res["matches"])

def test_file_search_blocks_path_traversal():
    bad_patterns = [
        "../../windows/system32",
        "../../*",
        "C:\\Windows\\System32\\cmd.exe",
        "/etc/passwd"
    ]
    for pat in bad_patterns:
        res = search_workspace_files(pat)
        # Even with path traversal attempts, search is strictly sanitized to basename and scoped to workspace root
        assert "error" not in res
        for m in res.get("matches", []):
            assert ".." not in m["relative_path"]
            assert "system32" not in m["relative_path"].lower()


# --- 7. Conversation History Search ---
def test_search_conversation_history(test_user):
    sess_id = get_or_create_session(None, test_user)
    append_message(sess_id, "user", "Please check network traffic for anomalies.")
    append_message(sess_id, "assistant", "Network scan initialized. Zero anomalies detected.")

    results = search_conversation_history(test_user, "network traffic")
    assert len(results) >= 1
    assert any("network traffic" in r["content"] for r in results)

# --- 8. REST API Endpoints Integration Tests ---
def test_reminders_api(auth_headers):
    # Create
    post_res = client.post("/api/jarvis/reminders", json={
        "title": "API Test Reminder",
        "due_time": "18:00",
        "priority": "HIGH"
    }, headers=auth_headers)
    assert post_res.status_code == 200
    rem_id = post_res.json()["id"]

    # List
    list_res = client.get("/api/jarvis/reminders", headers=auth_headers)
    assert list_res.status_code == 200
    assert any(r["id"] == rem_id for r in list_res.json()["reminders"])

    # Delete
    del_res = client.delete(f"/api/jarvis/reminders/{rem_id}", headers=auth_headers)
    assert del_res.status_code == 200

def test_notes_api(auth_headers):
    post_res = client.post("/api/jarvis/notes", json={
        "title": "API Security Note",
        "content": "Verify JWT token validation expiration.",
        "tags": ["security", "auth"]
    }, headers=auth_headers)
    assert post_res.status_code == 200
    note_id = post_res.json()["id"]

    list_res = client.get(f"/api/jarvis/notes?query=JWT", headers=auth_headers)
    assert list_res.status_code == 200
    assert any(n["id"] == note_id for n in list_res.json()["notes"])

    del_res = client.delete(f"/api/jarvis/notes/{note_id}", headers=auth_headers)
    assert del_res.status_code == 200

def test_todos_api(auth_headers):
    post_res = client.post("/api/jarvis/todos", json={
        "task": "Review API endpoints",
        "priority": "NORMAL"
    }, headers=auth_headers)
    assert post_res.status_code == 200
    todo_id = post_res.json()["id"]

    toggle_res = client.patch(f"/api/jarvis/todos/{todo_id}/toggle", headers=auth_headers)
    assert toggle_res.status_code == 200
    assert toggle_res.json()["completed"] is True

def test_memories_api(auth_headers):
    post_res = client.post("/api/jarvis/memories", json={
        "key": "soc_shift",
        "value": "Morning 09:00 - 17:00",
        "category": "schedule"
    }, headers=auth_headers)
    assert post_res.status_code == 200

    list_res = client.get("/api/jarvis/memories", headers=auth_headers)
    assert list_res.status_code == 200
    assert any(m["memory_key"] == "soc_shift" for m in list_res.json()["memories"])

    del_res = client.delete("/api/jarvis/memories/soc_shift", headers=auth_headers)
    assert del_res.status_code == 200

def test_system_status_api(auth_headers):
    res = client.get("/api/jarvis/system/status", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["zero_trust_status"] == "ENFORCING"
    assert "local_asr" in data["providers"]
    assert "local_tts" in data["providers"]
    assert "approved_apps" in data
