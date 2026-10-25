# AMOJA AI — Hugging Face & Local Model (GGUF) Windows Setup Guide

**Tagline:** *"Who Controls the AI?"*  
**Architecture:** Zero-Trust Autonomous Cybersecurity Assistant with On-Device AI  
**Target Hardware:** Windows 10/11 | 16 GB RAM | Low Storage Optimized (Zero C: Drive Model Footprint)  

---

## 1. Prerequisites Check

Open Windows PowerShell (Run as Administrator or standard user) and verify your development environment:

```powershell
# 1. Check Python version (Python 3.10+ supported, 3.14 verified)
python --version

# 2. Check Git installation
git --version

# 3. Check disk storage across drives
Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{Name="FreeGB";Expression={[math]::Round($_.Free/1GB, 2)}}, @{Name="TotalGB";Expression={[math]::Round(($_.Free+$_.Used)/1GB, 2)}}
```

---

## 2. Configure Model Storage on E: Drive (Preserving C: Drive)

By default, Ollama stores downloaded model weights in `C:\Users\<username>\.ollama\models`. Because your C: drive has ~13.8 GB free while your E: drive has ~87 GB free, set the `OLLAMA_MODELS` environment variable to store all models on E: drive:

```powershell
# Create models directory on E: drive
New-Item -ItemType Directory -Path "E:\ollama_models" -Force

# Set persistent User environment variable
[System.Environment]::SetEnvironmentVariable("OLLAMA_MODELS", "E:\ollama_models", "User")

# Set for current PowerShell session
$env:OLLAMA_MODELS = "E:\ollama_models"
```

---

## 3. Install the Local Model Runtime (Ollama)

Download and install Ollama for Windows using the official installer:

```powershell
# Download Ollama installer to Temp directory
curl.exe -L -o "$env:TEMP\OllamaSetup.exe" https://ollama.com/download/OllamaSetup.exe

# Run silent installation
Start-Process -FilePath "$env:TEMP\OllamaSetup.exe" -ArgumentList "/VERYSILENT /NORESTART" -Wait

# Verify installation (Ensure Ollama is in session PATH)
$env:PATH = "$env:LOCALAPPDATA\Programs\Ollama;$env:PATH"
ollama --version
```

---

## 4. Download and Validate the Selected Local Model

The recommended candidate is **Qwen2.5-3B-Instruct** (quantized 4-bit `Q4_K_M` GGUF, Apache 2.0 license).
- **Download Size:** ~1.9 GB
- **RAM Footprint:** ~3.2 GB to 4.0 GB (leaves ~12 GB free for Windows and AgentShield)
- **Languages:** English, Hindi, Hinglish, Marathi, plus technical code reasoning.

```powershell
# Download the model to E:\ollama_models
ollama pull qwen2.5:3b

# Verify model is registered
ollama list

# Test command-line inference
ollama run qwen2.5:3b "Namaste AMOJA! Introduce yourself in Hindi and English in 2 sentences."
```

*(Optional: If you wish to use a custom Hugging Face GGUF file such as `Qwen3-4B` or custom quant:*
```dockerfile
# Create Modelfile:
# FROM E:\path\to\your_custom_model.gguf
# Run:
# ollama create custom-amoja -f Modelfile
```
*Then set `OLLAMA_MODEL=custom-amoja` in your `.env` file.)*

---

## 5. Configure Project Environment Variables

Navigate to the project directory and verify/update `.env`:

```powershell
cd E:\AgentShield_Starter_Project
```

Ensure your `.env` contains:

```env
# Local AI Runtime Configuration
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:3b
OLLAMA_TIMEOUT=45.0
OLLAMA_MODELS=E:\ollama_models

# AI Router Settings (auto, local, gemini, openai, anthropic, heuristic)
JARVIS_LLM_PROVIDER=auto
AI_ROUTER_DEFAULT_PROVIDER=auto

# Local Privacy Mode (100% On-Device)
JARVIS_LOCAL_MODE=true
JARVIS_VOICE_SYNTHESIS=true
JARVIS_STT_ENGINE=whisper_local
JARVIS_TTS_ENGINE=piper_indic_local

# Cloud Providers (Optional)
GEMINI_API_KEY=
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
```

---

## 6. Start the AMOJA AI & AgentShield Platform

Open two terminal windows:

### Terminal 1: Backend Service (FastAPI)
```powershell
cd E:\AgentShield_Starter_Project\backend
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend will be running at:* `http://127.0.0.1:8000`  
*Interactive Swagger Docs:* `http://127.0.0.1:8000/docs`

### Terminal 2: Frontend Dashboard (Vite + React)
```powershell
cd E:\AgentShield_Starter_Project\frontend
npm run dev
```
*Frontend will be running at:* `http://localhost:5173`

---

## 7. Testing and Verification Directives

### 1. Test AI Health & Storage Telemetry
```powershell
curl.exe http://127.0.0.1:8000/api/ai/health
```
*Expected Output:*
```json
{
  "status": "HEALTHY",
  "local_runtime": {
    "online": true,
    "default_model": "qwen2.5:3b",
    "model_installed": true,
    "installed_models": ["qwen2.5:3b"]
  },
  "storage": {
    "c_drive": {"free_gb": 13.79},
    "e_drive": {"free_gb": 85.08},
    "models_dir": "E:\\ollama_models"
  }
}
```

### 2. Test Local Chat Inference
```powershell
curl.exe -X POST http://127.0.0.1:8000/api/ai/chat `
  -H "Content-Type: application/json" `
  -d '{"message": "Hello AMOJA, what is my system security posture?", "provider": "local"}'
```

### 3. Test Multilingual Interaction (Hindi / Marathi / Hinglish)
```powershell
# Hindi Test
curl.exe -X POST http://127.0.0.1:8000/api/ai/chat `
  -H "Content-Type: application/json" `
  -d '{"message": "नमस्ते, एजेंटशील्ड का सुरक्षा सारांश बताओ"}'

# Marathi Test
curl.exe -X POST http://127.0.0.1:8000/api/ai/chat `
  -H "Content-Type: application/json" `
  -d '{"message": "नमस्कार, सुरक्षा अलर्ट्स काय आहेत?"}'
```

### 4. Test Offline Airgap Operation
Stop your network connection or stop cloud services. AMOJA will seamlessly execute inference locally via Ollama. If Ollama itself is stopped (`Stop-Process -Name ollama`), AMOJA automatically falls back to its built-in offline resilient heuristic defense engine with zero crash and zero downtime.

---

## 8. Safe Model Removal & Storage Reclamation

If you ever need to reclaim disk space:

```powershell
# List installed models
ollama list

# Remove model from E:\ollama_models (reclaims ~1.9 GB instantly)
ollama rm qwen2.5:3b

# Verify removal
ollama list
```
*(No user files, operating system files, or project code are ever deleted.)*

---

## 9. Troubleshooting & FAQ

| Issue | Root Cause | Solution |
|---|---|---|
| `Connection refused (Ollama daemon is not running)` | Ollama service is stopped | Run `ollama serve` or launch Ollama from Windows Start Menu. |
| `Model 'qwen2.5:3b' was not found in Ollama` | Model not downloaded yet | Run `ollama pull qwen2.5:3b`. |
| C: Drive getting low on disk space | Ollama models saving to default AppData | Ensure `$env:OLLAMA_MODELS = "E:\ollama_models"` is set in Windows Environment Variables. |
| `Permission denied` on Port 8000 | Existing uvicorn instance running | Run `Get-Process python \| Stop-Process -Force`. |
| Microphone permission denied in browser | Browser security policy | Go to `chrome://settings/content/microphone` and allow `http://localhost:5173`. |
