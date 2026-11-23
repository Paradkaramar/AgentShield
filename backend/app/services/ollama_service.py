"""backend/app/services/ollama_service.py
Dedicated Ollama Local AI Inference Service for AMOJA AI + AgentShield
Provides asynchronous HTTP communication, token streaming, GPU/VRAM telemetry,
conversation history formatting, thinking-tag scrubbing, and zero-trust error handling.
"""

import os
import re
import time
import json
import logging
from typing import Dict, Any, List, Optional, AsyncGenerator

import httpx

from ..core.config import (
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_API_KEY,
    OLLAMA_TIMEOUT,
    OLLAMA_CONTEXT_WINDOW
)
from ..core.prompts import get_system_prompt

logger = logging.getLogger("agentshield.ollama_service")


class OllamaServiceError(Exception):
    """Base exception for Ollama service operations."""
    pass


class OllamaConnectionError(OllamaServiceError):
    """Raised when Ollama daemon is unreachable."""
    pass


class OllamaModelNotFoundError(OllamaServiceError):
    """Raised when the specified model is not installed."""
    pass


class OllamaTimeoutError(OllamaServiceError):
    """Raised when inference exceeds deadline."""
    pass


class OllamaOutOfMemoryError(OllamaServiceError):
    """Raised when GPU VRAM or system RAM is exhausted."""
    pass


class OllamaResponseError(OllamaServiceError):
    """Raised when Ollama returns an error payload."""
    pass


def clean_thinking_tags(text: str) -> str:
    """
    Strips internal Qwen3 / DeepSeek reasoning blocks (<think>...</think>)
    so chat users receive clean assistant output.
    """
    if not text:
        return ""
    # Remove closed thinking tags
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", text)
    # Remove unclosed opening tag if generation stopped mid-think
    if "<think>" in cleaned and "</think>" not in cleaned:
        cleaned = re.sub(r"<think>[\s\S]*", "", cleaned)
    return cleaned.strip()


class OllamaService:
    """
    Dedicated local inference client for Ollama running on localhost.
    Accelerated via local NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM).
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        default_model: Optional[str] = None,
        timeout: Optional[float] = None,
        api_key: Optional[str] = None
    ):
        self.base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        self.default_model = default_model or OLLAMA_MODEL
        self.timeout = timeout or OLLAMA_TIMEOUT
        self.api_key = api_key if api_key is not None else OLLAMA_API_KEY
        self.context_window = OLLAMA_CONTEXT_WINDOW

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def check_health(self) -> Dict[str, Any]:
        """
        Probes Ollama daemon health, installed models, and GPU-resident models via /api/tags & /api/ps.
        """
        start_time = time.time()
        health: Dict[str, Any] = {
            "online": False,
            "reachable": False,
            "base_url": self.base_url,
            "default_model": self.default_model,
            "target_model": self.default_model,
            "model_installed": False,
            "model_loaded": False,
            "installed_models": [],
            "models_count": 0,
            "running_models": [],
            "gpu_status": "UNKNOWN",
            "gpu_offload": "UNKNOWN",
            "latency_ms": 0,
            "error": None
        }

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                # 1. Probe /api/tags for catalog
                tags_res = await client.get(f"{self.base_url}/api/tags", headers=self._get_headers())
                if tags_res.status_code == 200:
                    health["online"] = True
                    health["reachable"] = True
                    data = tags_res.json()
                    models_raw = data.get("models", [])
                    installed = [m.get("name") or m.get("model") for m in models_raw if m]
                    health["installed_models"] = installed
                    health["models_count"] = len(installed)

                    # Check if target model is present
                    target_base = self.default_model.split(":")[0].lower()
                    health["model_installed"] = any(
                        self.default_model.lower() == m.lower() or
                        target_base in m.lower()
                        for m in installed
                    )

                # 2. Probe /api/ps for active memory/GPU allocation
                try:
                    ps_res = await client.get(f"{self.base_url}/api/ps", headers=self._get_headers())
                    if ps_res.status_code == 200:
                        ps_data = ps_res.json()
                        running = ps_data.get("models", [])
                        health["running_models"] = running
                        if running:
                            active = running[0]
                            health["model_loaded"] = True
                            proc = active.get("processor", "Unknown")
                            health["gpu_status"] = proc  # e.g. "100% GPU"
                            health["gpu_offload"] = proc
                            health["active_loaded_model"] = active.get("name")
                except Exception:
                    pass

                health["latency_ms"] = int((time.time() - start_time) * 1000)

        except httpx.ConnectError:
            health["error"] = "Connection refused: Ollama daemon is not running on 127.0.0.1:11434"
        except httpx.TimeoutException:
            health["error"] = "Health probe timed out after 4 seconds"
        except Exception as exc:
            health["error"] = str(exc)

        return health

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        system_prompt: Optional[str] = None,
        num_ctx: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes non-streaming chat completion with automatic thinking tag sanitization.
        """
        target_model = model or self.default_model
        sys_prompt = system_prompt or get_system_prompt()

        # Prepend system prompt if not already present
        prepared_messages: List[Dict[str, str]] = []
        has_system = any(m.get("role") == "system" for m in messages)
        if not has_system:
            prepared_messages.append({"role": "system", "content": sys_prompt})
        prepared_messages.extend(messages)

        payload = {
            "model": target_model,
            "messages": prepared_messages,
            "stream": False,
            "options": {
                "temperature": max(0.0, min(temperature, 2.0)),
                "num_predict": max_tokens,
                "num_ctx": num_ctx or self.context_window
            }
        }

        start_t = time.time()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                    headers=self._get_headers()
                )

                if res.status_code == 404:
                    raise OllamaModelNotFoundError(
                        f"Model '{target_model}' was not found in Ollama. "
                        f"Please install it using: ollama pull {target_model}"
                    )
                elif res.status_code != 200:
                    err_msg = res.text
                    try:
                        err_msg = res.json().get("error", err_msg)
                    except Exception:
                        pass
                    if "out of memory" in err_msg.lower() or "cuda" in err_msg.lower():
                        raise OllamaOutOfMemoryError(f"Ollama GPU VRAM / Memory exhausted: {err_msg}")
                    raise OllamaResponseError(f"Ollama returned HTTP {res.status_code}: {err_msg}")

                data = res.json()
                raw_text = data.get("message", {}).get("content", "")
                if not raw_text:
                    thinking_text = data.get("message", {}).get("thinking", "")
                    if thinking_text:
                        non_empty_lines = [l.strip() for l in thinking_text.splitlines() if l.strip()]
                        if non_empty_lines:
                            raw_text = non_empty_lines[-1]
                if not raw_text:
                    raise OllamaResponseError("Ollama returned an empty response message.")

                clean_text = clean_thinking_tags(raw_text)
                duration_ms = int((time.time() - start_t) * 1000)

                return {
                    "text": clean_text,
                    "raw_text": raw_text,
                    "model": target_model,
                    "provider": "ollama",
                    "is_local": True,
                    "duration_ms": duration_ms,
                    "eval_count": data.get("eval_count"),
                    "eval_duration": data.get("eval_duration")
                }

        except httpx.ConnectError as exc:
            raise OllamaConnectionError(
                f"Cannot connect to Ollama runtime at {self.base_url}. Please run: ollama serve"
            ) from exc
        except httpx.TimeoutException as exc:
            raise OllamaTimeoutError(
                f"Ollama inference timed out after {self.timeout}s for model '{target_model}'."
            ) from exc

    async def chat_stream(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        system_prompt: Optional[str] = None,
        num_ctx: Optional[int] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Asynchronously streams token chunks from Ollama line-by-line via NDJSON.
        Yields structured events: {"token": "...", "done": False} and final {"done": True, "full_text": "..."}.
        """
        target_model = model or self.default_model
        sys_prompt = system_prompt or get_system_prompt()

        prepared_messages: List[Dict[str, str]] = []
        if not any(m.get("role") == "system" for m in messages):
            prepared_messages.append({"role": "system", "content": sys_prompt})
        prepared_messages.extend(messages)

        payload = {
            "model": target_model,
            "messages": prepared_messages,
            "stream": True,
            "options": {
                "temperature": max(0.0, min(temperature, 2.0)),
                "num_predict": max_tokens,
                "num_ctx": num_ctx or self.context_window
            }
        }

        accumulated_text = ""
        in_thinking_block = False

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/api/chat",
                    json=payload,
                    headers=self._get_headers()
                ) as stream:
                    if stream.status_code == 404:
                        raise OllamaModelNotFoundError(f"Model '{target_model}' not found in Ollama.")
                    elif stream.status_code != 200:
                        body = await stream.aread()
                        raise OllamaResponseError(f"Ollama returned HTTP {stream.status_code}: {body.decode('utf-8', errors='replace')}")

                    async for line in stream.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        token = chunk.get("message", {}).get("content", "")
                        accumulated_text += token
                        is_done = chunk.get("done", False)

                        # Filter out thinking tags on the fly
                        if in_thinking_block:
                            if "</think>" in token:
                                in_thinking_block = False
                                token = token.split("</think>", 1)[1]
                            else:
                                continue

                        if "<think>" in token:
                            in_thinking_block = True
                            parts = token.split("<think>", 1)
                            before_think = parts[0]
                            after_open = parts[1]
                            if "</think>" in after_open:
                                in_thinking_block = False
                                token = before_think + after_open.split("</think>", 1)[1]
                            else:
                                token = before_think

                        if token and not in_thinking_block:
                            yield {
                                "token": token,
                                "done": False,
                                "model": target_model
                            }

                        if is_done:
                            clean_full = clean_thinking_tags(accumulated_text)
                            yield {
                                "token": "",
                                "done": True,
                                "full_text": clean_full,
                                "model": target_model,
                                "total_duration": chunk.get("total_duration"),
                                "eval_count": chunk.get("eval_count")
                            }
                            break

        except httpx.ConnectError as exc:
            raise OllamaConnectionError(f"Cannot connect to Ollama runtime at {self.base_url}.") from exc
        except httpx.TimeoutException as exc:
            raise OllamaTimeoutError(f"Ollama streaming timed out after {self.timeout}s.") from exc


# Global Singleton Ollama Service instance
ollama_service = OllamaService()
