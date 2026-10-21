# backend/tests/test_personal_assistant_tools.py
import pytest
from fastapi.testclient import TestClient
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.db.database import init_db
from app.main import app
from app.jarvis.personal_assistant import (
    create_reminder, list_reminders, delete_reminder,
    create_note, list_notes, search_notes, delete_note,
    add_todo_item, list_todo_items, toggle_todo_item,
    store_user_memory, list_user_memories, delete_user_memory, clear_all_user_memories,
    launch_approved_application, search_workspace_files,
    close_approved_application, open_website_or_search, search_or_play_youtube,
    search_authorized_files, open_authorized_file_or_folder, organize_authorized_files,
    prepare_whatsapp_message, get_windows_system_status, open_windows_settings,
    analyze_suspicious_processes, prepare_firewall_rule_change, execute_multistep_task,
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


# --- 9. Application Closing Guardrails ---
def test_close_approved_application():
    mock_proc = MagicMock()
    mock_proc.info = {"pid": 1234, "name": "notepad.exe"}
    with patch("psutil.process_iter", return_value=[mock_proc]):
        res = close_approved_application("notepad")
        assert res.get("success") is True
        assert res["status"] in {"TERMINATED", "NOT_RUNNING"}


def test_close_unauthorized_application():
    res = close_approved_application("malicious_tool.exe")
    assert "error" in res
    assert "approved" in res["error"]


# --- 10. Web and YouTube Browsing Safe Tools ---
def test_open_website_or_search():
    with patch("webbrowser.open") as mock_web:
        # Search query
        res = open_website_or_search("python asyncio tutorial")
        assert res["success"] is True
        assert res["action_type"] == "WEB_SEARCH"
        assert "google.com" in res["target_url"]

        # Valid website URL
        res2 = open_website_or_search("https://github.com")
        assert res2["success"] is True
        assert res2["action_type"] == "OPEN_URL"
        assert res2["target_url"] == "https://github.com"
        assert mock_web.call_count == 2


def test_open_website_blocks_malicious_schemes():
    bad_urls = [
        "javascript:alert(1)",
        "file:///C:/Windows/System32/cmd.exe",
        "data:text/html,<script>alert(1)</script>",
        "calc.exe; notepad.exe"
    ]
    for bad in bad_urls:
        res = open_website_or_search(bad)
        assert res["success"] is False
        assert "error" in res


def test_search_or_play_youtube():
    with patch("webbrowser.open") as mock_web:
        res = search_or_play_youtube("lofi hip hop radio")
        assert res["success"] is True
        assert "youtube.com/results?search_query=" in res["youtube_url"]
        mock_web.assert_called_once()


# --- 11. Scoped Authorized File Operations ---
def test_search_authorized_files():
    res = search_authorized_files("main.py", scope="workspace")
    assert "error" not in res
    assert res["total_matches"] >= 1
    assert any("main.py" in m["name"] for m in res["matches"])


def test_open_authorized_file_or_folder():
    with patch("os.startfile", create=True) as mock_start, patch("subprocess.Popen") as mock_popen:
        res = open_authorized_file_or_folder("requirements.txt")
        assert res["success"] is True
        assert res["status"] == "OPENED"


def test_organize_authorized_files_move_confirmation():
    res = organize_authorized_files(
        operation="move",
        source_path="requirements.txt",
        target_path="requirements_backup.txt"
    )
    assert res.get("requires_confirmation") is True
    assert res["action_type"] == "ORGANIZE_FILE_MOVE"
    assert res["risk_level"] == "MEDIUM"
    assert "action_id" in res


def test_organize_authorized_files_create_folder():
    new_dir = Path("test_scratch_folder").resolve()
    if new_dir.exists():
        new_dir.rmdir()
    try:
        res = organize_authorized_files(
            operation="create_folder",
            source_path=str(new_dir)
        )
        assert res["success"] is True
        assert new_dir.exists()
    finally:
        if new_dir.exists():
            new_dir.rmdir()


# --- 12. WhatsApp Automation Verification & Human Confirmation ---
def test_prepare_whatsapp_message_confirmation():
    res = prepare_whatsapp_message(
        recipient="+919876543210",
        message="Hello, SOC team! Daily health check report is ready."
    )
    assert res.get("requires_confirmation") is True
    assert res["action_type"] == "SEND_WHATSAPP_MESSAGE"
    assert res["target_id"] == "+919876543210"
    assert res["risk_level"] == "HIGH"
    assert "action_id" in res
    assert "idempotency_key" in res


def test_prepare_whatsapp_message_validation():
    # Empty recipient
    res1 = prepare_whatsapp_message("", "Hello")
    assert res1.get("success") is False
    assert "error" in res1

    # Empty message
    res2 = prepare_whatsapp_message("9876543210", "")
    assert res2.get("success") is False
    assert "error" in res2


# --- 13. Windows System Status & Settings ---
def test_get_windows_system_status():
    status = get_windows_system_status()
    assert status.get("status") == "HEALTHY"
    assert "cpu" in status
    assert "memory" in status
    assert "disk" in status
    assert "battery" in status
    assert "uptime" in status


def test_open_windows_settings():
    with patch("os.startfile", create=True) as mock_start:
        res = open_windows_settings("network")
        assert res["success"] is True
        assert res["page"] == "network"
        assert res["uri"] == "ms-settings:network"

    # Invalid setting page
    bad_res = open_windows_settings("non_existent_page_12345")
    assert bad_res.get("success") is False
    assert "error" in bad_res
    assert "allowed_pages" in bad_res


# --- 14. Suspicious Process Analysis ---
def test_analyze_suspicious_processes():
    res = analyze_suspicious_processes(top_n=10)
    assert res.get("status") == "COMPLETED"
    assert "total_processes_scanned" in res
    assert "findings" in res
    assert isinstance(res["findings"], list)


# --- 15. Host Firewall Configuration Change Confirmation ---
def test_prepare_firewall_rule_change_confirmation():
    res = prepare_firewall_rule_change(
        action="add_block_rule",
        rule_name="AMOJA_Block_Port_4444",
        direction="in",
        port=4444,
        protocol="TCP"
    )
    assert res.get("requires_confirmation") is True
    assert res["action_type"] == "FIREWALL_ADD_BLOCK_RULE"
    assert res["target_id"] == "AMOJA_Block_Port_4444"
    assert res["risk_level"] == "HIGH"
    assert res["details"]["port"] == 4444


def test_prepare_firewall_rule_change_invalid_args():
    res = prepare_firewall_rule_change(
        action="invalid_action",
        rule_name="bad_rule"
    )
    assert res.get("success") is False
    assert "error" in res


# --- 16. Multi-Step Task Execution ---
def test_execute_multistep_task():
    user = {"username": "admin", "role": "admin"}
    steps = [
        {
            "description": "Create a note for SOC meeting",
            "tool_name": "create_note",
            "arguments": {"title": "MultiStep Note", "content": "SOC Meeting notes."}
        },
        {
            "description": "Add todo for SOC meeting",
            "tool_name": "add_todo_item",
            "arguments": {"task": "Review firewall rules"}
        }
    ]
    res = execute_multistep_task("Morning SOC Setup", steps, user)
    assert res.get("multistep_status") == "COMPLETED"
    assert res["total_steps"] == 2
    assert len(res["steps_results"]) == 2
    assert res["steps_results"][0]["success"] is True
    assert res["steps_results"][1]["success"] is True


def test_execute_multistep_task_pauses_on_confirmation():
    user = {"username": "admin", "role": "admin"}
    steps = [
        {
            "description": "Prepare WhatsApp notice",
            "tool_name": "prepare_whatsapp_message",
            "arguments": {"recipient": "+919876543210", "message": "Incident detected"}
        }
    ]
    res = execute_multistep_task("Incident Notification Task", steps, user)
    assert res.get("multistep_status") == "PAUSED_FOR_CONFIRMATION"
    assert res["requires_confirmation"] is True
    assert res["paused_at_step"] == 1

