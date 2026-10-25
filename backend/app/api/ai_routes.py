from fastapi import APIRouter, HTTPException, Depends, status, Request, Query
from typing import Dict, Any, Optional

from ..core.auth import get_current_user
from ..jarvis.jarvis_schemas import (
    AIChatRequest,
    AIChatResponse,
    AIHealthResponse,
    AIProvidersResponse,
    AIInferenceTestResult,
    AIDualModelStatus,
    AITestModelRequest
)
from ..jarvis.ai_router import (
    ai_router,
    AIRuntimeUnavailableError,
    AIModelNotFoundError,
    AIInferenceTimeoutError,
    AIProviderError
)

router = APIRouter(prefix="/api/ai", tags=["Local & Cloud AI Router"])

@router.post("/chat", response_model=AIChatResponse)
async def ai_chat_endpoint(
    payload: AIChatRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Unified AI chat endpoint for AMOJA AI supporting three operational modes:
    - 'local': Strictly local Hugging Face GGUF model via Ollama. No cloud egress.
    - 'online': Strictly verified cloud model via provider API (Gemini/OpenAI).
    - 'auto': Intelligent task-based routing with graceful fallback.
    """
    # Enforce safe message bounds
    msg = payload.message.strip()
    if not msg:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message content cannot be empty."
        )
    if len(msg) > 4000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message exceeds maximum allowed limit of 4000 characters."
        )

    try:
        response = await ai_router.route_and_generate(payload, user=current_user)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI Router execution failure: {str(e)}"
        )

@router.get("/status", response_model=AIDualModelStatus)
async def ai_dual_model_status_endpoint(
    mode: str = Query("auto", description="Current AI mode: local, online, auto"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns unified status telemetry for both the Local GGUF model and Online Cloud model,
    including genuine test results and storage headroom.
    """
    try:
        return await ai_router.get_dual_model_status(current_mode=mode)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve dual model status: {str(e)}"
        )

@router.post("/test/local", response_model=AIInferenceTestResult)
async def ai_test_local_endpoint(
    payload: Optional[AITestModelRequest] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Executes a real on-device inference test against the local Ollama runtime.
    Measures genuine roundtrip latency and verifies model text generation.
    """
    model_name = payload.model if payload else None
    return await ai_router.test_local_model(model=model_name)

@router.post("/test/online", response_model=AIInferenceTestResult)
async def ai_test_online_endpoint(
    payload: Optional[AITestModelRequest] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Executes a real cloud API inference test against the configured online model provider.
    Measures genuine API latency and verifies cloud model text generation.
    """
    provider_name = payload.provider if payload else None
    return await ai_router.test_online_model(provider=provider_name)

@router.get("/health", response_model=AIHealthResponse)
async def ai_health_endpoint(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns live health telemetry for local Ollama daemon, Hugging Face GGUF models,
    cloud API provider configurations, and drive storage headroom.
    """
    try:
        return await ai_router.get_health_status()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check AI health status: {str(e)}"
        )

@router.get("/providers", response_model=AIProvidersResponse)
def ai_providers_endpoint(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Discovers all supported AI inference providers, models, and zero-cloud offline status.
    """
    return ai_router.list_providers()
