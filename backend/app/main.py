from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .core.config import CORS_ORIGINS
from .db.database import init_db
from .api import (
    auth_routes,
    agents_routes,
    action_routes,
    approvals_routes,
    events_routes,
    incidents_routes,
    audit_routes,
    analytics_routes,
    policy_routes,
    shadow_ai_routes,
    canary_routes,
    simulation_routes,
    digital_twin_routes,
    forensics_routes,
    jarvis_routes
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables and seed baseline data
    init_db()
    yield

app = FastAPI(
    title="AgentShield — AI Agent Security Platform",
    description="Who Controls the AI? — Zero-Trust Security Control Plane for Autonomous AI Agents.",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all modular API routers
app.include_router(analytics_routes.router)
app.include_router(auth_routes.router)
app.include_router(agents_routes.router)
app.include_router(action_routes.router)
app.include_router(approvals_routes.router)
app.include_router(events_routes.router)
app.include_router(incidents_routes.router)
app.include_router(audit_routes.router)
app.include_router(policy_routes.router)
app.include_router(shadow_ai_routes.router)
app.include_router(canary_routes.router)
app.include_router(simulation_routes.router)
app.include_router(digital_twin_routes.router)
app.include_router(forensics_routes.router)
app.include_router(jarvis_routes.router)

@app.get("/health", tags=["Health & Status"])
def health_check():
    return {
        "status": "ok",
        "service": "AgentShield AI Agent Security Control Plane",
        "version": "1.0.0",
        "tagline": "Who Controls the AI?",
        "zero_trust": "ENFORCING"
    }
