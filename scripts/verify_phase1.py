"""scripts/verify_phase1.py
Phase 1 Foundation Verification Script for AMOJA AI + AgentShield
Probes FastAPI startup, database integrity, health endpoints, AI router connectivity,
and desktop application configuration.
"""

import sys
import time
import urllib.request
import json
import subprocess
import importlib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
DESKTOP_DIR = BASE_DIR / "desktop"
VENV_PYTHON = BACKEND_DIR / ".venv" / "Scripts" / "python.exe"

# Ensure backend directory is in sys.path
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def verify_database_and_models():
    print("[1/5] Checking Database & Core Schemas...")
    db_mod = importlib.import_module("app.db.database")
    audit_mod = importlib.import_module("app.core.audit")
    config_mod = importlib.import_module("app.core.config")

    init_db = db_mod.init_db
    connect = db_mod.connect
    verify_audit_integrity = audit_mod.verify_audit_integrity
    DB_PATH = config_mod.DB_PATH

    init_db()
    assert DB_PATH.exists(), f"Database file {DB_PATH} not found!"

    with connect() as db:
        integrity = verify_audit_integrity(db)
        print(f"      Database verified: {integrity.get('records_verified', 0)} audit logs checked.")
        print(f"      Chained audit integrity: {integrity.get('status')}, chain_intact={integrity.get('chain_intact')}")
        assert integrity.get("chain_intact") is True and integrity.get("status") in ("VALID", "VERIFIED")


def verify_event_bus():
    print("[2/5] Checking Asynchronous Event Bus...")
    bus_mod = importlib.import_module("app.core.event_bus")
    event_bus = bus_mod.event_bus
    Event = bus_mod.Event
    import asyncio

    async def _test():
        received = []
        def handler(evt: Event):
            received.append(evt.data)
        event_bus.subscribe("test.verify", handler)
        await event_bus.publish("test.verify", {"verified": True})
        assert len(received) == 1 and received[0]["verified"] is True
        event_bus.unsubscribe("test.verify", handler)

    asyncio.run(_test())
    print("      EventBus pub/sub verified.")


def verify_testclient_endpoints():
    print("[3/5] Testing FastAPI Endpoints via TestClient...")
    tc_mod = importlib.import_module("fastapi.testclient")
    main_mod = importlib.import_module("app.main")
    TestClient = tc_mod.TestClient
    app = main_mod.app

    client = TestClient(app)

    # 1. Root & HEAD
    head_resp = client.head("/")
    assert head_resp.status_code == 200, f"HEAD / failed: {head_resp.status_code}"
    get_resp = client.get("/")
    assert get_resp.status_code == 200
    assert get_resp.json().get("status") == "ok"

    # 2. Health check
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json().get("zero_trust") == "ENFORCING"

    # 3. AI Health
    ai_health = client.get("/api/ai/health")
    assert ai_health.status_code == 200
    ai_data = ai_health.json()
    print(f"      AI Health: status={ai_data.get('status')}, default_provider={ai_data.get('default_provider')}")
    print(f"      Local Ollama: online={ai_data.get('local_runtime', {}).get('online')}, model={ai_data.get('local_runtime', {}).get('model')}")

    # 4. Audit Verify
    audit_resp = client.get("/api/audit/verify")
    assert audit_resp.status_code == 200
    assert audit_resp.json().get("status") in ("VALID", "VERIFIED") and audit_resp.json().get("chain_intact") is True

    print("      All required health endpoints verified.")


def verify_desktop_configuration():
    print("[4/5] Checking Desktop Shell Configuration...")
    package_json = DESKTOP_DIR / "package.json"
    main_js = DESKTOP_DIR / "main.js"
    preload_js = DESKTOP_DIR / "preload.js"
    run_desktop_js = DESKTOP_DIR / "run_desktop.js"

    assert package_json.exists(), "desktop/package.json missing"
    assert main_js.exists(), "desktop/main.js missing"
    assert preload_js.exists(), "desktop/preload.js missing"
    assert run_desktop_js.exists(), "desktop/run_desktop.js missing"

    content = main_js.read_text(encoding="utf-8")
    assert "contextIsolation: true" in content
    assert "nodeIntegration: false" in content
    assert "http://127.0.0.1:8000/health" in content
    print("      Electron desktop security policies and health IPC verified.")


def verify_live_server_lifecycle():
    print("[5/5] Testing Live Uvicorn Lifecycle on http://127.0.0.1:8000...")
    proc = subprocess.Popen(
        [str(VENV_PYTHON), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(BACKEND_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    try:
        # Wait up to 10 seconds for Uvicorn to start
        online = False
        for _ in range(20):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=1.0) as res:
                    if res.status == 200:
                        online = True
                        break
            except Exception:
                pass

        assert online, "Live Uvicorn server failed to respond on http://127.0.0.1:8000/health within 10s"

        # Probe HEAD /
        head_req = urllib.request.Request("http://127.0.0.1:8000/", method="HEAD")
        with urllib.request.urlopen(head_req, timeout=2.0) as head_res:
            assert head_res.status == 200, f"Live HEAD / failed: {head_res.status}"

        # Probe /api/audit/verify
        with urllib.request.urlopen("http://127.0.0.1:8000/api/audit/verify", timeout=2.0) as audit_res:
            assert audit_res.status == 200

        print("      Live Uvicorn bound successfully on port 8000 and answered health checks.")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("      Live server gracefully shut down.")


if __name__ == "__main__":
    print("==================================================")
    print("AMOJA AI + AGENTSHIELD: PHASE 1 FOUNDATION VERIFIER")
    print("==================================================")
    verify_database_and_models()
    verify_event_bus()
    verify_testclient_endpoints()
    verify_desktop_configuration()
    verify_live_server_lifecycle()
    print("==================================================")
    print("PHASE 1 FOUNDATION VERIFICATION: ALL CHECKS PASSED")
    print("==================================================")
