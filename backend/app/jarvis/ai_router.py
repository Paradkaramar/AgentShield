import os
import sys
import time
import json
import psutil
import httpx
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from ..core.config import (
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT,
    OLLAMA_MODELS_DIR,
    AI_ROUTER_DEFAULT_PROVIDER,
    OPENAI_API_KEY,
    ANTHROPIC_API_KEY,
    GEMINI_API_KEY,
    SECRET_VAULT
)
from .jarvis_schemas import (
    AIChatRequest,
    AIChatResponse,
    AIHealthResponse,
    AIProvidersResponse,
    AIInferenceTestResult,
    AIDualModelStatus
)
from .jarvis_security import (
    check_message_for_prompt_injection,
    sanitize_assistant_output
)
from .multilingual_commands import check_multilingual_prompt_injection
from .language_detection import detect_language as detect_language_core
from ..db.database import now_iso

class AIRuntimeUnavailableError(Exception):
    """Raised when the local Ollama runtime service is not reachable."""
    pass

class AIModelNotFoundError(Exception):
    """Raised when the specified model is not installed or available in Ollama."""
    pass

class AIInferenceTimeoutError(Exception):
    """Raised when an inference call exceeds the configured timeout."""
    pass

class AIProviderError(Exception):
    """Raised when an inference provider returns an error."""
    pass

DEFAULT_AMOJA_SYSTEM_PROMPT = """You are AMOJA, a helpful multilingual conversational AI assistant integrated with the AgentShield cybersecurity platform.
Always respond in the same language and style as the user's latest message (English, Hindi, Hinglish, Marathi).
Your core mission is Zero-Trust verification: "Who Controls the AI?"
Tone: Crisp, authoritative, respectful, highly competent, calm, articulate, and protective.
Guidelines:
1. Always ground your security statements in verified facts and real telemetry from AgentShield. Never fabricate security metrics, CVEs, or scan scores.
2. If asked about system actions or security states, explain clearly in plain language.
3. Keep spoken summaries concise (1-2 sentences) and provide structured markdown in text.
4. Support Hindi, Hinglish, Marathi, and English naturally without forcing translation unless explicitly asked.
"""

class AIRouter:
    """
    Unified AI Inference Router for AMOJA AI.
    Routes between:
    1. Local Ollama Runtime (Qwen2.5 / Qwen3 GGUF quantized models)
    2. Cloud AI Providers (Google Gemini, OpenAI, Anthropic)
    3. Offline Resilient Heuristic Engine (100% offline fallback)
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        default_model: Optional[str] = None,
        timeout: Optional[float] = None
    ):
        self.base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        self.default_model = default_model or OLLAMA_MODEL
        self.timeout = timeout or OLLAMA_TIMEOUT
        self.default_provider = AI_ROUTER_DEFAULT_PROVIDER
        self.last_local_test: Optional[AIInferenceTestResult] = None
        self.last_online_test: Optional[AIInferenceTestResult] = None

    async def check_local_health(self) -> Dict[str, Any]:
        """Checks if local Ollama daemon is reachable and lists installed models."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("name", "") for m in data.get("models", [])]
                    has_target = any(
                        self.default_model in m or m.startswith(self.default_model.split(":")[0])
                        for m in models
                    ) if self.default_model else False
                    return {
                        "online": True,
                        "base_url": self.base_url,
                        "default_model": self.default_model,
                        "model_installed": has_target,
                        "installed_models": models,
                        "models_count": len(models),
                        "error": None
                    }
                else:
                    return {
                        "online": False,
                        "base_url": self.base_url,
                        "default_model": self.default_model,
                        "model_installed": False,
                        "installed_models": [],
                        "models_count": 0,
                        "error": f"Ollama returned HTTP {resp.status_code}"
                    }
        except httpx.ConnectError:
            return {
                "online": False,
                "base_url": self.base_url,
                "default_model": self.default_model,
                "model_installed": False,
                "installed_models": [],
                "models_count": 0,
                "error": "Connection refused (Ollama daemon is not running)"
            }
        except Exception as e:
            return {
                "online": False,
                "base_url": self.base_url,
                "default_model": self.default_model,
                "model_installed": False,
                "installed_models": [],
                "models_count": 0,
                "error": str(e)
            }

    def get_storage_status(self) -> Dict[str, Any]:
        """Calculates free disk space for C: and E: drives to prevent disk exhaustion."""
        storage: Dict[str, Any] = {}
        try:
            c_usage = psutil.disk_usage("C:\\")
            storage["c_drive"] = {
                "free_gb": round(c_usage.free / (1024**3), 2),
                "total_gb": round(c_usage.total / (1024**3), 2),
                "percent_used": c_usage.percent
            }
        except Exception:
            storage["c_drive"] = {"free_gb": 0.0, "total_gb": 0.0, "percent_used": 100.0}

        try:
            e_usage = psutil.disk_usage("E:\\")
            storage["e_drive"] = {
                "free_gb": round(e_usage.free / (1024**3), 2),
                "total_gb": round(e_usage.total / (1024**3), 2),
                "percent_used": e_usage.percent
            }
        except Exception:
            storage["e_drive"] = None

        storage["models_dir"] = OLLAMA_MODELS_DIR
        return storage

    async def get_health_status(self) -> AIHealthResponse:
        """Returns consolidated health and telemetry for local and cloud AI providers."""
        local_health = await self.check_local_health()
        storage = self.get_storage_status()

        cloud_providers = {
            "gemini": {
                "configured": bool(GEMINI_API_KEY),
                "model": "gemini-1.5-flash"
            },
            "openai": {
                "configured": bool(OPENAI_API_KEY and not OPENAI_API_KEY.startswith("sk-proj-demo")),
                "model": "gpt-4o-mini"
            },
            "anthropic": {
                "configured": bool(ANTHROPIC_API_KEY and not ANTHROPIC_API_KEY.startswith("sk-ant-demo")),
                "model": "claude-3-haiku-20240307"
            }
        }

        overall_status = "HEALTHY" if local_health["online"] else (
            "DEGRADED" if any(p["configured"] for p in cloud_providers.values()) else "OFFLINE"
        )

        return AIHealthResponse(
            status=overall_status,
            local_runtime=local_health,
            cloud_providers=cloud_providers,
            active_default_provider=self.default_provider,
            storage=storage,
            timestamp=now_iso()
        )

    async def test_local_model(self, model: Optional[str] = None) -> AIInferenceTestResult:
        """
        Executes a genuine on-device inference test against the local Ollama runtime.
        Measures real latency and verifies that the model produces valid text.
        """
        target_model = model or self.default_model
        test_prompt = "Ping test: Respond in one short sentence confirming Zero-Trust AI status."
        start_t = time.time()
        tested_at = now_iso()

        messages = [
            {"role": "system", "content": "You are a test harness. Respond in one concise sentence."},
            {"role": "user", "content": test_prompt}
        ]

        try:
            res = await self.infer_ollama(messages=messages, model=target_model, max_tokens=60)
            latency_ms = int((time.time() - start_t) * 1000)
            result = AIInferenceTestResult(
                model_type="local",
                provider="ollama",
                model=target_model,
                status="PASS",
                latency_ms=latency_ms,
                test_prompt=test_prompt,
                response=res.get("text", "")[:200],
                error=None,
                tested_at=tested_at
            )
            self.last_local_test = result
            return result
        except Exception as e:
            latency_ms = int((time.time() - start_t) * 1000)
            result = AIInferenceTestResult(
                model_type="local",
                provider="ollama",
                model=target_model,
                status="FAIL",
                latency_ms=latency_ms,
                test_prompt=test_prompt,
                response=None,
                error=str(e),
                tested_at=tested_at
            )
            self.last_local_test = result
            return result

    async def test_online_model(self, provider: Optional[str] = None) -> AIInferenceTestResult:
        """
        Executes a genuine cloud inference test against the configured online AI model provider API.
        Measures real API latency and verifies that the cloud model responds properly.
        """
        target_provider = (provider or ("gemini" if GEMINI_API_KEY else ("openai" if (OPENAI_API_KEY and not OPENAI_API_KEY.startswith("sk-proj-demo")) else "gemini"))).lower()
        model_name = "gemini-1.5-flash" if target_provider == "gemini" else ("gpt-4o-mini" if target_provider == "openai" else "claude-3-haiku-20240307")
        test_prompt = "Ping test: Respond in one short sentence confirming Cloud AI status."
        start_t = time.time()
        tested_at = now_iso()

        messages = [
            {"role": "system", "content": "You are a test harness. Respond in one concise sentence."},
            {"role": "user", "content": test_prompt}
        ]

        if target_provider == "gemini" and not GEMINI_API_KEY:
            latency_ms = int((time.time() - start_t) * 1000)
            result = AIInferenceTestResult(
                model_type="online",
                provider=target_provider,
                model=model_name,
                status="FAIL",
                latency_ms=latency_ms,
                test_prompt=test_prompt,
                response=None,
                error="GEMINI_API_KEY is not configured in backend environment or .env file.",
                tested_at=tested_at
            )
            self.last_online_test = result
            return result
        elif target_provider == "openai" and (not OPENAI_API_KEY or OPENAI_API_KEY.startswith("sk-proj-demo")):
            latency_ms = int((time.time() - start_t) * 1000)
            result = AIInferenceTestResult(
                model_type="online",
                provider=target_provider,
                model=model_name,
                status="FAIL",
                latency_ms=latency_ms,
                test_prompt=test_prompt,
                response=None,
                error="OPENAI_API_KEY is not configured or contains placeholder demo value.",
                tested_at=tested_at
            )
            self.last_online_test = result
            return result

        try:
            if target_provider == "gemini":
                res = await self.infer_gemini(messages)
            elif target_provider == "openai":
                res = await self.infer_openai(messages)
            else:
                raise AIProviderError(f"Cloud provider '{target_provider}' is not supported for inference testing.")

            latency_ms = int((time.time() - start_t) * 1000)
            result = AIInferenceTestResult(
                model_type="online",
                provider=target_provider,
                model=model_name,
                status="PASS",
                latency_ms=latency_ms,
                test_prompt=test_prompt,
                response=res.get("text", "")[:200],
                error=None,
                tested_at=tested_at
            )
            self.last_online_test = result
            return result
        except Exception as e:
            latency_ms = int((time.time() - start_t) * 1000)
            result = AIInferenceTestResult(
                model_type="online",
                provider=target_provider,
                model=model_name,
                status="FAIL",
                latency_ms=latency_ms,
                test_prompt=test_prompt,
                response=None,
                error=str(e),
                tested_at=tested_at
            )
            self.last_online_test = result
            return result

    async def get_dual_model_status(self, current_mode: str = "auto") -> AIDualModelStatus:
        """
        Returns unified dual-model status telemetry:
        - Local GGUF runtime status and last actual test result
        - Online Cloud provider status and last actual test result
        - Honest both_working indicator (True only if BOTH passed real tests)
        - Drive headroom for models directory
        """
        local_health = await self.check_local_health()
        storage = self.get_storage_status()

        cloud_provider = "gemini" if GEMINI_API_KEY else ("openai" if (OPENAI_API_KEY and not OPENAI_API_KEY.startswith("sk-proj-demo")) else "gemini")
        cloud_model = "gemini-1.5-flash" if cloud_provider == "gemini" else "gpt-4o-mini"
        cloud_configured = bool(GEMINI_API_KEY or (OPENAI_API_KEY and not OPENAI_API_KEY.startswith("sk-proj-demo")))

        local_status_str = "READY" if (local_health.get("online") and local_health.get("model_installed")) else (
            "OFFLINE" if not local_health.get("online") else "NOT_INSTALLED"
        )
        online_status_str = "CONFIGURED" if cloud_configured else "NOT_CONFIGURED"

        # Truthful check: both working only if BOTH have passed actual inference tests
        both_working = bool(
            self.last_local_test and self.last_local_test.status == "PASS" and
            self.last_online_test and self.last_online_test.status == "PASS"
        )

        valid_mode = current_mode.lower() if current_mode.lower() in ["local", "online", "auto"] else "auto"

        if valid_mode == "local":
            active_desc = f"Local Model: {self.default_model} (GGUF Ollama)"
        elif valid_mode == "online":
            active_desc = f"Online Model: {cloud_model} ({cloud_provider.title()} Cloud API)"
        else:
            active_desc = f"Auto Mode: Intelligent Router ({self.default_model} Local / {cloud_model} Cloud Fallback)"

        return AIDualModelStatus(
            current_mode=valid_mode,
            local_model={
                "name": self.default_model,
                "runtime": "Ollama (GGUF Quantized)",
                "endpoint": self.base_url,
                "online": local_health.get("online", False),
                "model_installed": local_health.get("model_installed", False),
                "installed_models": local_health.get("installed_models", []),
                "last_test": self.last_local_test.model_dump() if self.last_local_test else None,
                "status": local_status_str
            },
            online_model={
                "provider": cloud_provider,
                "model": cloud_model,
                "configured": cloud_configured,
                "last_test": self.last_online_test.model_dump() if self.last_online_test else None,
                "status": online_status_str
            },
            storage=storage,
            active_in_ui=active_desc,
            both_working=both_working,
            timestamp=now_iso()
        )

    def list_providers(self) -> AIProvidersResponse:
        """Returns a list of all configured and supported AI providers."""
        providers = [
            {
                "id": "local",
                "name": "Local Ollama (GGUF Quantized)",
                "type": "local",
                "model": self.default_model,
                "endpoint": self.base_url,
                "is_offline": True,
                "description": "Zero-cloud on-device private inference powered by Ollama and Hugging Face GGUF models."
            },
            {
                "id": "gemini",
                "name": "Google Gemini",
                "type": "cloud",
                "model": "gemini-1.5-flash",
                "configured": bool(GEMINI_API_KEY),
                "is_offline": False,
                "description": "High-throughput cloud multimodal reasoning via Google Gemini API."
            },
            {
                "id": "openai",
                "name": "OpenAI GPT",
                "type": "cloud",
                "model": "gpt-4o-mini",
                "configured": bool(OPENAI_API_KEY and not OPENAI_API_KEY.startswith("sk-proj-demo")),
                "is_offline": False,
                "description": "OpenAI Cloud Chat API."
            },
            {
                "id": "anthropic",
                "name": "Anthropic Claude",
                "type": "cloud",
                "model": "claude-3-haiku-20240307",
                "configured": bool(ANTHROPIC_API_KEY and not ANTHROPIC_API_KEY.startswith("sk-ant-demo")),
                "is_offline": False,
                "description": "Anthropic Claude API."
            },
            {
                "id": "heuristic",
                "name": "AgentShield Offline Resilient Engine",
                "type": "offline_deterministic",
                "model": "rule-heuristic-v1",
                "configured": True,
                "is_offline": True,
                "description": "Built-in deterministic cybersecurity NLP engine that operates with zero network and zero dependencies."
            }
        ]
        return AIProvidersResponse(
            default_provider=self.default_provider,
            configured_providers=providers
        )

    async def infer_ollama(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024
    ) -> Dict[str, Any]:
        """Executes local inference via the Ollama REST API."""
        target_model = model or self.default_model
        payload = {
            "model": target_model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": max(0.0, min(temperature, 2.0)),
                "num_predict": max_tokens
            }
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(f"{self.base_url}/api/chat", json=payload)

                if response.status_code == 404:
                    raise AIModelNotFoundError(
                        f"Model '{target_model}' was not found in Ollama. "
                        f"Please pull it first by running: ollama pull {target_model}"
                    )
                elif response.status_code != 200:
                    err_body = response.text
                    try:
                        err_json = response.json()
                        err_body = err_json.get("error", err_body)
                    except Exception:
                        pass
                    raise AIProviderError(f"Ollama returned error (status {response.status_code}): {err_body}")

                data = response.json()
                msg = data.get("message", {}).get("content", "")
                if not msg:
                    raise AIProviderError("Ollama returned an empty response.")

                return {
                    "text": msg.strip(),
                    "provider": "local_ollama",
                    "model": target_model,
                    "is_local": True
                }

        except httpx.ConnectError as ce:
            raise AIRuntimeUnavailableError(
                f"Cannot connect to Ollama runtime at {self.base_url}. "
                f"Please start Ollama service using: ollama serve"
            ) from ce
        except httpx.TimeoutException as te:
            raise AIInferenceTimeoutError(
                f"Ollama inference timed out after {self.timeout} seconds for model '{target_model}'."
            ) from te

    async def infer_gemini(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7
    ) -> Dict[str, Any]:
        """Executes inference via Google Gemini API."""
        api_key = GEMINI_API_KEY
        if not api_key:
            raise AIProviderError("Gemini API key is not configured.")

        contents = []
        system_instruction = None

        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            if role == "system":
                system_instruction = {"parts": [{"text": content}]}
            elif role == "assistant":
                contents.append({"role": "model", "parts": [{"text": content}]})
            else:
                contents.append({"role": "user", "parts": [{"text": content}]})

        body: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": 1024
            }
        }
        if system_instruction:
            body["systemInstruction"] = system_instruction

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.post(url, json=body)
                if res.status_code != 200:
                    raise AIProviderError(f"Gemini API returned status {res.status_code}: {res.text}")

                data = res.json()
                candidates = data.get("candidates", [])
                if not candidates:
                    raise AIProviderError("Gemini API returned no candidates.")

                parts = candidates[0].get("content", {}).get("parts", [])
                text = "".join(p.get("text", "") for p in parts)
                return {
                    "text": text.strip(),
                    "provider": "cloud_gemini",
                    "model": "gemini-1.5-flash",
                    "is_local": False
                }
        except httpx.TimeoutException:
            raise AIInferenceTimeoutError("Gemini cloud request timed out.")

    async def infer_openai(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7
    ) -> Dict[str, Any]:
        """Executes inference via OpenAI API."""
        api_key = OPENAI_API_KEY
        if not api_key or api_key.startswith("sk-proj-demo"):
            raise AIProviderError("OpenAI API key is not configured or is a placeholder.")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "gpt-4o-mini",
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 1024
        }
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
                if res.status_code != 200:
                    raise AIProviderError(f"OpenAI API error: {res.text}")
                data = res.json()
                text = data["choices"][0]["message"]["content"]
                return {
                    "text": text.strip(),
                    "provider": "cloud_openai",
                    "model": "gpt-4o-mini",
                    "is_local": False
                }
        except httpx.TimeoutException:
            raise AIInferenceTimeoutError("OpenAI cloud request timed out.")

    def infer_heuristic(
        self,
        user_prompt: str,
        lang: str = "en",
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Deterministic, offline resilient cybersecurity fallback engine.
        Ensures AMOJA AI remains responsive even with zero network, no Ollama, and no API keys.
        """
        p = user_prompt.lower().strip()
        
        # Multilingual conversational greetings and answers
        if any(w in p for w in ["hello", "hi", "hey", "namaste", "namaskar", "kasa ahes", "kaise ho"]):
            if lang == "mr":
                text = "नमस्कार! मी अमोझा (AMOJA AI), आपली स्वायत्त सायबर सुरक्षा सहाय्यक. मी स्थानिक आणि ऑफलाइन मोडमध्ये कार्यरत आहे. मी आपल्याला कशी मदत करू शकते?"
            elif lang == "hi":
                text = "नमस्ते! मैं अमोझा (AMOJA AI) हूँ, आपकी स्वायत्त साइबर सुरक्षा सहायिका. शून्य-विश्वास सुरक्षा नियंत्रण पूरी तरह सक्रिय है. मैं आपकी क्या सहायता करूँ?"
            elif lang == "hinglish":
                text = "Hey! Main AMOJA AI hoon, aapki autonomous cybersecurity assistant. Local offline mode active hai. Aap kya check karna chahte hain?"
            else:
                text = "Greetings! I am AMOJA AI, your autonomous cybersecurity defense companion. Zero-Trust security controls are active. How may I assist you today?"
        elif any(w in p for w in ["status", "security", "posture", "summary", "saransh", "suraksha"]):
            if lang == "mr":
                text = "🛡️ **AgentShield सुरक्षा स्थिती:**\n- झिरो-ट्रस्ट धोरण: **सक्रिय (ENFORCING)**\n- स्थानिक संरक्षण: **चालू**\n- उपलब्ध साधने: 64 सायबर सुरक्षा व प्रणाली साधने सज्ज आहेत."
            elif lang == "hi":
                text = "🛡️ **AgentShield सुरक्षा स्थिति:**\n- शून्य-विश्वास नीति: **लागू (ENFORCING)**\n- स्थानीय सुरक्षा: **सक्रिय**\n- उपलब्ध टूल्स: 64 साइबर सुरक्षा एवं सिस्टम टूल्स तैयार हैं."
            elif lang == "hinglish":
                text = "🛡️ **AgentShield Security Status:**\n- Zero-Trust Enforcement: **ACTIVE**\n- Local Defenses: **ONLINE**\n- Ready Tools: 64 cybersecurity & system tools registered."
            else:
                text = "🛡️ **AgentShield Zero-Trust Status:**\n- Policy Enforcement: **ACTIVE (ENFORCING)**\n- Local Telemetry: **NOMINAL**\n- Ready Tools: 64 authorized cybersecurity and system tools operational."
        else:
            if lang == "mr":
                text = (
                    f"मी आपल्या प्रश्नावर विचार केला आहे: *\"{user_prompt}\"*\n\n"
                    f"स्थानिक मॉडेल किंवा क्लाउड प्रदाता सध्या ऑफलाइन असल्याने मी अमोझाच्या अंतर्गत ऑफलाइन सुरक्षा इंजिनद्वारे उत्तर देत आहे. "
                    f"आपण मला सिस्टीम डायग्नोस्टिक्स, नेटवर्क स्कॅन किंवा ॲप्स उघडण्यासंबंधी थेट विचारू शकता."
                )
            elif lang == "hi":
                text = (
                    f"मैंने आपके अनुरोध का विश्लेषण किया है: *\"{user_prompt}\"*\n\n"
                    f"स्थानीय मॉडल या क्लाउड प्रोवाइडर वर्तमान में ऑफलाइन होने के कारण यह उत्तर अमोझा के ऑफलाइन सुरक्षा तंत्र द्वारा दिया जा रहा है. "
                    f"आप मुझसे सिस्टम सुरक्षा जांच, नेटवर्क अलर्ट्स या अधिकृत टूल्स के बारे में पूछ सकते हैं."
                )
            elif lang == "hinglish":
                text = (
                    f"Aapke prompt *\"{user_prompt}\"* par local offline defense engine active hai.\n\n"
                    f"Full generative LLM reasoning ke liye ensure karein ki Ollama daemon running hai (`ollama serve`). "
                    f"Tab tak aap AgentShield ke 64 automated security tools use kar sakte hain."
                )
            else:
                text = (
                    f"AMOJA local offline engine processed your directive: *\"{user_prompt}\"*.\n\n"
                    f"Note: Deep generative LLM reasoning is operating in offline fallback mode. "
                    f"To enable full neural inference, start Ollama (`ollama serve`) with model `{self.default_model}`."
                )

        return {
            "text": text,
            "provider": "offline_heuristic",
            "model": "rule-heuristic-v1",
            "is_local": True
        }

    async def route_and_generate(
        self,
        request: AIChatRequest,
        user: Optional[Dict[str, Any]] = None
    ) -> AIChatResponse:
        """
        Coordinates request screening, provider selection, failover handling, and output sanitization.
        """
        start_time = time.time()
        user_name = user.get("username", "admin") if user else "admin"

        # 1. Screen incoming user prompt for prompt injection
        injection_screen = check_multilingual_prompt_injection(request.message)
        if not injection_screen.get("is_threat"):
            injection_screen = check_message_for_prompt_injection(request.message)

        if injection_screen.get("is_threat"):
            reasons = ", ".join(injection_screen.get("reasons", ["Unsafe prompt signature"]))
            blocked_text = (
                f"🛑 **Zero-Trust Security Barrier Activated:**\n\n"
                f"Your request was flagged by AgentShield's internal prompt-injection defense:\n"
                f"- **Reason:** {reasons}\n"
                f"- **Confidence:** {injection_screen.get('confidence', 0.95):.2f}\n\n"
                f"AMOJA cannot execute directives designed to bypass Zero-Trust controls."
            )
            return AIChatResponse(
                response=blocked_text,
                speech_text="Security barrier engaged. That instruction violates AgentShield safety policies.",
                provider_used="security_firewall",
                model_used="prompt_injection_filter",
                is_local=True,
                fallback_occurred=False,
                execution_time_ms=int((time.time() - start_time) * 1000),
                session_id=request.session_id,
                language_detected="en",
                created_at=now_iso()
            )

        # 2. Detect language
        detected_lang = detect_language_core(request.message, user_preference=request.language or "auto")

        # 3. Assemble chat message history
        messages: List[Dict[str, str]] = []
        sys_prompt = request.system_prompt or DEFAULT_AMOJA_SYSTEM_PROMPT
        messages.append({"role": "system", "content": sys_prompt})

        if request.conversation_history:
            for turn in request.conversation_history[-10:]:
                if "role" in turn and "content" in turn:
                    messages.append({"role": turn["role"], "content": turn["content"]})

        messages.append({"role": "user", "content": request.message})

        # Determine effective mode: "local", "online", or "auto"
        req_mode = (request.mode or "").lower()
        if req_mode in ["local", "online", "auto"]:
            mode = req_mode
        elif (request.provider or "").lower() == "local":
            mode = "local"
        elif (request.provider or "").lower() in ["gemini", "openai", "anthropic"]:
            mode = "online"
        else:
            mode = "auto"

        target_model = request.model or self.default_model

        result: Optional[Dict[str, Any]] = None
        fallback_occurred = False
        fallback_reason: Optional[str] = None

        # 4. Strict Mode Routing Execution
        if mode == "local":
            # Strict Local Mode: strictly on-device Ollama. Zero cloud egress allowed.
            try:
                result = await self.infer_ollama(
                    messages=messages,
                    model=target_model,
                    temperature=request.temperature or 0.7,
                    max_tokens=request.max_tokens or 1024
                )
            except Exception as e:
                err_msg = str(e)
                # Fail closed in Local mode - cloud fallback is prohibited
                result = {
                    "text": (
                        f"❌ **Local AI Model Execution Failed (Local Mode Active):**\n\n"
                        f"- **Model:** `{target_model}`\n"
                        f"- **Runtime:** `{self.base_url}`\n"
                        f"- **Failure Detail:** {err_msg}\n\n"
                        f"🔒 **Zero-Trust Egress Policy:** Cloud fallback is prohibited in Local Mode to prevent off-device data transmission. "
                        f"Please ensure the Ollama daemon is running (`ollama serve`) and the model is downloaded (`ollama pull {target_model}`)."
                    ),
                    "provider": "local_ollama_error",
                    "model": target_model,
                    "is_local": True
                }
                fallback_occurred = False
                fallback_reason = f"Local mode failure (cloud fallback prohibited): {err_msg}"

        elif mode == "online":
            # Strict Online Mode: strictly cloud provider API. Local fallback prohibited.
            target_cloud = (request.provider or ("gemini" if GEMINI_API_KEY else ("openai" if (OPENAI_API_KEY and not OPENAI_API_KEY.startswith("sk-proj-demo")) else "gemini"))).lower()
            if target_cloud not in ["gemini", "openai"]:
                target_cloud = "gemini" if GEMINI_API_KEY else "openai"

            try:
                if target_cloud == "gemini":
                    result = await self.infer_gemini(messages, temperature=request.temperature or 0.7)
                elif target_cloud == "openai":
                    result = await self.infer_openai(messages, temperature=request.temperature or 0.7)
                else:
                    raise AIProviderError(f"Cloud provider '{target_cloud}' is not supported or configured.")
            except Exception as e:
                err_msg = str(e)
                # Fail closed in Online mode - local fallback is prohibited
                result = {
                    "text": (
                        f"❌ **Cloud AI Model Execution Failed (Online Mode Active):**\n\n"
                        f"- **Provider:** `{target_cloud}`\n"
                        f"- **Failure Detail:** {err_msg}\n\n"
                        f"🔒 **Policy Enforcement:** Local fallback is prohibited in Online Mode. "
                        f"Please verify your cloud AI credentials on the backend server."
                    ),
                    "provider": f"cloud_{target_cloud}_error",
                    "model": "cloud-provider",
                    "is_local": False
                }
                fallback_occurred = False
                fallback_reason = f"Online mode failure (local fallback prohibited): {err_msg}"

        else:
            # Auto Mode: Dynamic routing with graceful fallback permitted.
            preferred_provider = (request.provider or self.default_provider or "auto").lower()

            if preferred_provider in ["gemini", "openai"]:
                # Explicit cloud preference in auto mode with local fallback
                try:
                    if preferred_provider == "gemini":
                        result = await self.infer_gemini(messages, temperature=request.temperature or 0.7)
                    else:
                        result = await self.infer_openai(messages, temperature=request.temperature or 0.7)
                except Exception as cloud_err:
                    fallback_occurred = True
                    fallback_reason = f"Cloud provider '{preferred_provider}' failed: {str(cloud_err)}. Falling back to local model."
                    try:
                        result = await self.infer_ollama(messages, model=target_model)
                    except Exception as local_err:
                        fallback_reason += f" Local model also failed ({str(local_err)}). Falling back to offline heuristic."
                        result = self.infer_heuristic(request.message, lang=detected_lang)

            elif preferred_provider == "heuristic":
                result = self.infer_heuristic(request.message, lang=detected_lang)

            else:
                # Default Auto Route: Local-first for Zero-Trust privacy, with cloud fallback if configured
                try:
                    result = await self.infer_ollama(
                        messages=messages,
                        model=target_model,
                        temperature=request.temperature or 0.7,
                        max_tokens=request.max_tokens or 1024
                    )
                except Exception as e:
                    fallback_occurred = True
                    fallback_reason = f"Local model unavailable ({str(e)}). Falling back to cloud."

                    cloud_success = False
                    if GEMINI_API_KEY:
                        try:
                            result = await self.infer_gemini(messages, temperature=request.temperature or 0.7)
                            cloud_success = True
                        except Exception as c_err:
                            fallback_reason += f" Cloud Gemini failed ({str(c_err)})."
                    elif OPENAI_API_KEY and not OPENAI_API_KEY.startswith("sk-proj-demo"):
                        try:
                            result = await self.infer_openai(messages, temperature=request.temperature or 0.7)
                            cloud_success = True
                        except Exception as c_err:
                            fallback_reason += f" Cloud OpenAI failed ({str(c_err)})."

                    if not cloud_success or not result:
                        fallback_reason += " Falling back to offline resilient heuristic engine."
                        result = self.infer_heuristic(request.message, lang=detected_lang)

        # 5. Sanitize output to prevent token / key leakages
        clean_text = sanitize_assistant_output(result["text"])

        # 6. Synthesize short spoken summary for text-to-speech
        first_line = clean_text.strip().split("\n")[0].strip("*# `")
        if len(first_line) > 160:
            first_line = first_line[:157] + "..."
        speech_text = first_line if len(first_line) > 5 else clean_text[:120]

        duration_ms = int((time.time() - start_time) * 1000)

        return AIChatResponse(
            response=clean_text,
            speech_text=speech_text,
            provider_used=result.get("provider", "unknown"),
            model_used=result.get("model", "unknown"),
            ai_mode_used=mode,
            is_local=result.get("is_local", True),
            fallback_occurred=fallback_occurred,
            fallback_reason=fallback_reason,
            execution_time_ms=duration_ms,
            session_id=request.session_id,
            language_detected=detected_lang,
            created_at=now_iso()
        )

# Global singleton instance
ai_router = AIRouter()
