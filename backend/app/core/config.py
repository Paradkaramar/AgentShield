import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load environment variables from backend/.env or root .env if present
# Existing OS environment variables take precedence (override=False)
if (BASE_DIR / ".env").exists():
    load_dotenv(BASE_DIR / ".env", override=False)
elif (BASE_DIR.parent / ".env").exists():
    load_dotenv(BASE_DIR.parent / ".env", override=False)

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

# Local AI Runtime & Router Configuration (Ollama / Hugging Face GGUF)
LLM_PROVIDER = os.getenv("LLM_PROVIDER", os.getenv("AI_DEFAULT_PROVIDER", "ollama")).lower()
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "dolphinlabs/qwen3.5-uncensored:latest")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "120.0"))
OLLAMA_MODELS_DIR = os.getenv("OLLAMA_MODELS", str(BASE_DIR.parent / "ollama_models"))
OLLAMA_CONTEXT_WINDOW = int(os.getenv("OLLAMA_CONTEXT_WINDOW", "4096"))
AI_AUTO_FALLBACK = os.getenv("AI_AUTO_FALLBACK", "false").lower() in ("true", "1", "yes")

# Multi-Provider AI Gateway Configuration (Gemini, Groq, OpenRouter)
AI_DEFAULT_PROVIDER = os.getenv("AI_DEFAULT_PROVIDER", os.getenv("AI_ROUTER_DEFAULT_PROVIDER", LLM_PROVIDER)).lower()
AI_ROUTER_DEFAULT_PROVIDER = AI_DEFAULT_PROVIDER
AI_GATEWAY_TIMEOUT = float(os.getenv("AI_GATEWAY_TIMEOUT", "20.0"))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct")

# Legacy / Optional Cloud AI Providers
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

