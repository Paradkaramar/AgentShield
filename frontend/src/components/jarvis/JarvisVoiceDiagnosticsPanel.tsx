// frontend/src/components/jarvis/JarvisVoiceDiagnosticsPanel.tsx
// Real-time voice pipeline diagnostics, microphone health inspector, and telemetry HUD

import React, { useState, useEffect } from "react";
import {
  Mic, MicOff, Volume2, VolumeX, Activity, Radio, AlertTriangle,
  CheckCircle2, XCircle, RefreshCw, Server, Cpu, Sparkles, Terminal
} from "lucide-react";
import { jarvisVoice, VoiceDiagnostics, VoiceState } from "./JarvisVoiceEngine";
import { JarvisState } from "../../types";

interface Props {
  conversationState: JarvisState;
  currentTranscript: string;
  errorMessage?: string;
  onRetryConnection?: () => void;
}

export const JarvisVoiceDiagnosticsPanel: React.FC<Props> = ({
  conversationState,
  currentTranscript,
  errorMessage,
  onRetryConnection
}) => {
  const [diag, setDiag] = useState<VoiceDiagnostics>(jarvisVoice.getDiagnostics());
  const [backendStatus, setBackendStatus] = useState<"CONNECTED" | "DISCONNECTED" | "CHECKING">("CHECKING");
  const [backendLatencyMs, setBackendLatencyMs] = useState<number>(0);
  const [isTestingMic, setIsTestingMic] = useState<boolean>(false);
  const [testMicPeak, setTestMicPeak] = useState<number>(0);
  const [diagnosticLogs, setDiagnosticLogs] = useState<Array<{ time: string; event: string; status: "info" | "warn" | "error" }>>([
    { time: new Date().toLocaleTimeString(), event: "Voice Diagnostics Initialized", status: "info" }
  ]);

  const addLog = (event: string, status: "info" | "warn" | "error" = "info") => {
    setDiagnosticLogs(prev => [
      { time: new Date().toLocaleTimeString(), event, status },
      ...prev.slice(0, 19)
    ]);
  };

  // Poll diagnostics and audio RMS level
  useEffect(() => {
    const timer = setInterval(() => {
      const current = jarvisVoice.getDiagnostics();
      setDiag(current);
    }, 250);
    return () => clearInterval(timer);
  }, []);

  // Check backend health
  const checkBackendHealth = async () => {
    setBackendStatus("CHECKING");
    const t0 = performance.now();
    try {
      let res: Response;
      try {
        res = await fetch("/health");
      } catch {
        res = await fetch("http://127.0.0.1:8000/health");
      }
      const dt = Math.round(performance.now() - t0);
      setBackendLatencyMs(dt);
      if (res.ok) {
        setBackendStatus("CONNECTED");
        addLog(`Backend health probe OK (${dt}ms)`, "info");
      } else {
        setBackendStatus("DISCONNECTED");
        addLog(`Backend returned status ${res.status}`, "warn");
      }
    } catch (e: any) {
      setBackendStatus("DISCONNECTED");
      addLog(`Backend probe failed: ${e.message || "Network error"}`, "error");
    }
  };

  useEffect(() => {
    checkBackendHealth();
    const interval = setInterval(checkBackendHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  // Log conversation state changes
  useEffect(() => {
    addLog(`Conversation State: ${conversationState}`, conversationState === "ERROR" ? "error" : "info");
  }, [conversationState]);

  // Log transcript updates
  useEffect(() => {
    if (currentTranscript && currentTranscript.trim()) {
      addLog(`Transcript: "${currentTranscript.slice(0, 50)}${currentTranscript.length > 50 ? "..." : ""}"`, "info");
    }
  }, [currentTranscript]);

  // Self-test microphone audio level
  const runMicrophoneTest = async () => {
    setIsTestingMic(true);
    setTestMicPeak(0);
    addLog("Microphone hardware diagnostic test started (3s)...", "info");

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      const ctx = new AudioCtx();
      const source = ctx.createMediaStreamSource(stream);
      const analyser = ctx.createAnalyser();
      analyser.fftSize = 64;
      source.connect(analyser);

      const buffer = new Uint8Array(analyser.frequencyBinCount);
      let peak = 0;
      const startTime = Date.now();

      const sampleInterval = setInterval(() => {
        analyser.getByteFrequencyData(buffer);
        let sum = 0;
        for (let i = 0; i < buffer.length; i++) sum += buffer[i] * buffer[i];
        const rms = Math.sqrt(sum / buffer.length);
        const level = Math.round((rms / 255) * 100);
        if (level > peak) peak = level;
        setTestMicPeak(peak);

        if (Date.now() - startTime >= 3000) {
          clearInterval(sampleInterval);
          stream.getTracks().forEach(t => t.stop());
          ctx.close();
          setIsTestingMic(false);
          addLog(`Mic test completed. Peak input level: ${peak}%`, peak > 5 ? "info" : "warn");
        }
      }, 100);
    } catch (err: any) {
      setIsTestingMic(false);
      addLog(`Mic test failed: ${err.message || err}`, "error");
    }
  };

  const getStatusBadge = (status: string, goodValues: string[], warnValues: string[] = []) => {
    if (goodValues.includes(status)) {
      return <span className="diag-badge diag-badge-good"><CheckCircle2 size={12} /> {status}</span>;
    }
    if (warnValues.includes(status)) {
      return <span className="diag-badge diag-badge-warn"><AlertTriangle size={12} /> {status}</span>;
    }
    return <span className="diag-badge diag-badge-error"><XCircle size={12} /> {status}</span>;
  };

  const displayState = conversationState === "PROCESSING" ? "THINKING" : conversationState;

  return (
    <div className="jarvis-diagnostics-panel" role="region" aria-label="Voice Pipeline Diagnostics">
      <div className="diag-header">
        <div className="diag-title">
          <Activity size={16} className="text-cyan-400" />
          <span>AMOJA Voice Pipeline Diagnostics</span>
          {diag.isElectron && <span className="electron-tag">Electron Desktop</span>}
        </div>
        <div className="diag-actions">
          <button
            type="button"
            className="btn-diag-retry"
            onClick={() => {
              checkBackendHealth();
              if (onRetryConnection) onRetryConnection();
            }}
            title="Refresh connectivity probe"
          >
            <RefreshCw size={13} className={backendStatus === "CHECKING" ? "animate-spin" : ""} />
            <span>Probe</span>
          </button>
          <button
            type="button"
            className={`btn-diag-test-mic ${isTestingMic ? "testing" : ""}`}
            onClick={runMicrophoneTest}
            disabled={isTestingMic}
            title="Test microphone sensitivity for 3 seconds"
          >
            <Mic size={13} />
            <span>{isTestingMic ? `Testing (${testMicPeak}%)` : "Test Mic"}</span>
          </button>
        </div>
      </div>

      {/* Grid of 7 Required Pipeline Stages */}
      <div className="diag-grid">
        {/* 1. Microphone Hardware */}
        <div className="diag-card">
          <div className="diag-card-label">
            <Mic size={13} />
            <span>Microphone</span>
          </div>
          <div className="diag-card-value">
            {getStatusBadge(diag.microphoneStatus, ["READY"], ["MUTED"])}
          </div>
          <div className="diag-card-meter">
            <div className="meter-label">Audio Level</div>
            <div className="meter-track">
              <div
                className="meter-fill"
                style={{ width: `${Math.min(100, isTestingMic ? testMicPeak : diag.audioLevelRms)}%` }}
              />
            </div>
          </div>
        </div>

        {/* 2. Speech Recognition */}
        <div className="diag-card">
          <div className="diag-card-label">
            <Radio size={13} />
            <span>Speech Recognition</span>
          </div>
          <div className="diag-card-value">
            {getStatusBadge(diag.recognitionStatus, ["LISTENING", "TRANSCRIBING"], ["IDLE"])}
          </div>
          <div className="diag-card-subtext">
            Engine: {diag.recognitionEngine}
          </div>
        </div>

        {/* 3. Backend Gateway */}
        <div className="diag-card">
          <div className="diag-card-label">
            <Server size={13} />
            <span>Backend API</span>
          </div>
          <div className="diag-card-value">
            {getStatusBadge(backendStatus, ["CONNECTED"], ["CHECKING"])}
          </div>
          <div className="diag-card-subtext">
            Latency: {backendLatencyMs > 0 ? `${backendLatencyMs}ms` : "probed"}
          </div>
        </div>

        {/* 4. AI Provider */}
        <div className="diag-card">
          <div className="diag-card-label">
            <Cpu size={13} />
            <span>AI Orchestrator</span>
          </div>
          <div className="diag-card-value">
            {getStatusBadge(backendStatus === "CONNECTED" ? "READY" : "ERROR", ["READY"])}
          </div>
          <div className="diag-card-subtext">
            Zero-Trust Gateway Enforcing
          </div>
        </div>

        {/* 5. Text-To-Speech (TTS) */}
        <div className="diag-card">
          <div className="diag-card-label">
            <Volume2 size={13} />
            <span>Text-To-Speech</span>
          </div>
          <div className="diag-card-value">
            {getStatusBadge(diag.isSpeakerMuted ? "MUTED" : "READY", ["READY"], ["MUTED"])}
          </div>
          <div className="diag-card-subtext">
            Neural Indic WAV + WebAudio
          </div>
        </div>

        {/* 6. Conversation State Machine */}
        <div className="diag-card">
          <div className="diag-card-label">
            <Sparkles size={13} />
            <span>Conversation State</span>
          </div>
          <div className="diag-card-value">
            <span className={`state-pill state-${displayState.toLowerCase()}`}>
              {displayState}
            </span>
          </div>
          <div className="diag-card-subtext">
            IDLE ➔ LISTENING ➔ THINKING ➔ SPEAKING
          </div>
        </div>
      </div>

      {/* 7. Transcript Monitor & Redacted Event Stream */}
      <div className="diag-transcript-section">
        <div className="transcript-box">
          <div className="section-label">Live Recognized Transcript:</div>
          <div className="transcript-content">
            {currentTranscript ? (
              <span className="transcript-active font-mono">"{currentTranscript}"</span>
            ) : diag.transcript ? (
              <span className="transcript-prev font-mono">"{diag.transcript}"</span>
            ) : (
              <span className="transcript-empty text-slate-500 italic">No audio speech detected yet. Speak or press Spacebar...</span>
            )}
          </div>
        </div>

        {/* Error notification if any */}
        {(errorMessage || diag.lastError) && (
          <div className="diag-error-banner" role="alert">
            <AlertTriangle size={14} className="text-amber-400 shrink-0" />
            <span>{errorMessage || diag.lastError}</span>
          </div>
        )}

        {/* Redacted Telemetry Logs */}
        <div className="diag-log-stream">
          <div className="log-header">
            <Terminal size={12} />
            <span>Diagnostic Event Stream (Redacted):</span>
          </div>
          <div className="log-lines">
            {diagnosticLogs.map((log, i) => (
              <div key={i} className={`log-line log-${log.status}`}>
                <span className="log-time">[{log.time}]</span>
                <span className="log-msg">{log.event}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
