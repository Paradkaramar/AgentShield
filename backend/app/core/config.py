import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

JWT_SECRET = os.getenv("AGENTSHIELD_JWT_SECRET", "agentshield-super-secure-production-secret-key-32bytes-min")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

DATABASE_URL = os.getenv("DATABASE_URL", "")
DB_PATH = BASE_DIR / "agentshield.db"

CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

# Development secret vault store (simulated secure enclave)
SECRET_VAULT = {
    "OPENAI_API_KEY": "sk-proj-demo-mock-key-shield-vaulted-9941",
    "ANTHROPIC_API_KEY": "sk-ant-demo-mock-key-shield-vaulted-3829",
    "DB_PROD_PASSWORD": "vaulted_db_pass_redacted_for_security",
    "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T00/B00/X00MOCK",
}
