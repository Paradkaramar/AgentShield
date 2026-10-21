import React from "react";
import {
  Mic, MicOff, Volume2, VolumeX, Square, Loader2, AlertCircle,
  Pause, Play, RotateCcw, Radio, Sparkles, ShieldCheck, ShieldAlert,
  Hand
} from "lucide-react";
import { JarvisState } from "../../types";

interface Props {
  state: JarvisState;
  isListening: boolean;
  isMuted: boolean;              // Speaker TTS mute
  isMicMuted?: boolean;          // Microphone hardware input mute
  isSpeechSupported: boolean;
  isPaused?: boolean;
  isWakeWordEnabled?: boolean;
  isPushToTalkActive?: boolean;
  micPermissionStatus?: "granted" | "denied" | "prompt" | "unsupported";
  recordingDurationSeconds?: number;
  onToggleListen: () => void;
  onStopListening: () => void;
  onToggleMute: () => void;      // Toggle speaker mute
  onToggleMicMute?: () => void;  // Toggle mic mute
  onToggleWakeWord?: () => void; // Toggle "Hey Amoja" wake-word
  onStartPushToTalk?: () => void;
  onStopPushToTalk?: () => void;
  onRequestMicPermission?: () => void;
  onStopSpeaking: () => void;
  onPauseSpeaking?: () => void;
  onResumeSpeaking?: () => void;
  onReplaySpeech?: () => void;
}

export const JarvisMicButton: React.FC<Props> = ({
  state,
  isListening,
  isMuted,
  isMicMuted = false,
  isSpeechSupported,
  isPaused = false,
  isWakeWordEnabled = false,
  isPushToTalkActive = false,
  micPermissionStatus = "granted",
  recordingDurationSeconds = 0,
  onToggleListen,
  onStopListening,
  onToggleMute,
  onToggleMicMute,
  onToggleWakeWord,
  onStartPushToTalk,
  onStopPushToTalk,
  onRequestMicPermission,
  onStopSpeaking,
  onPauseSpeaking,
  onResumeSpeaking,
  onReplaySpeech
}) => {
  const formatTimer = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  };

  return (
    <div className="jarvis-voice-controls-cluster">
      {/* Visible Recording Indicator Banner */}
      {isListening && (
        <div className="jarvis-live-recording-indicator" role="status" aria-live="assertive">
          <span className="live-rec-dot" />
          <span className="live-rec-label">
            {isPushToTalkActive ? "PUSH-TO-TALK (LIVE)" : "LISTENING (LIVE)"}
          </span>
          <span className="live-rec-timer">{formatTimer(recordingDurationSeconds)}</span>
        </div>
      )}

      {/* Permission warning banner if microphone access is blocked */}
      {micPermissionStatus === "denied" && (
        <div className="jarvis-perm-banner-alert" role="alert">
          <ShieldAlert size={14} className="perm-alert-icon" />
          <span>Microphone access blocked in browser.</span>
          {onRequestMicPermission && (
            <button
              type="button"
              className="btn-grant-permission"
              onClick={onRequestMicPermission}
            >
              Grant Access
            </button>
          )}
        </div>
      )}

      {/* Primary Microphone Trigger Button (Centered Hero) */}
      <div className="jarvis-primary-mic-wrapper">
        <button
          type="button"
          className={`jarvis-mic-btn state-${state.toLowerCase()} ${isListening ? "active-listening" : ""} ${isPushToTalkActive ? "ptt-pressed" : ""} ${isMicMuted ? "btn-mic-muted" : ""}`}
          onClick={onToggleListen}
          onMouseDown={onStartPushToTalk ? onStartPushToTalk : undefined}
          onMouseUp={onStopPushToTalk ? onStopPushToTalk : undefined}
          onTouchStart={onStartPushToTalk ? onStartPushToTalk : undefined}
          onTouchEnd={onStopPushToTalk ? onStopPushToTalk : undefined}
          disabled={(!isSpeechSupported && !isListening) || isMicMuted}
          title={
            isMicMuted
              ? "Microphone is muted. Unmute mic to speak."
              : !isSpeechSupported
              ? "Speech recognition not supported in this browser. Please use text input."
              : isListening
              ? "Listening to voice input... Click or release to submit."
              : "Click to toggle or Hold to Push-to-Talk (Spacebar)"
          }
          aria-label={isListening ? "Stop voice listening" : "Start voice listening"}
        >
          <div className="mic-outer-ring" />
          <div className="mic-inner-core">
            {state === "PROCESSING" ? (
              <Loader2 size={24} className="spin-icon" />
            ) : isMicMuted ? (
              <MicOff size={24} className="mic-icon-disabled" />
            ) : isListening ? (
              <Mic size={24} className="mic-icon-active" />
            ) : !isSpeechSupported ? (
              <MicOff size={24} className="mic-icon-disabled" />
            ) : state === "ERROR" ? (
              <AlertCircle size={24} />
            ) : (
              <Mic size={24} />
            )}
          </div>
        </button>
      </div>

      {/* Push-to-Talk Helper Cue directly beneath Central Mic */}
      <div className="ptt-helper-cue">
        <Hand size={12} />
        <span>Hold Mic button or <strong>Spacebar</strong> to Push-to-Talk</span>
      </div>

      {/* Auxiliary Voice Control Buttons (Responsive Grid) */}
      <div className="jarvis-audio-controls">
        {/* Contextual: Stop Listening when actively recording */}
        {isListening && (
          <button
            type="button"
            className="btn-jarvis-control stop-listening-btn"
            onClick={onStopListening}
            title="Stop listening (Esc or say 'Stop listening')"
            aria-label="Stop listening"
          >
            <Square size={14} fill="currentColor" />
            <span>Stop Listening</span>
          </button>
        )}

        {/* Contextual: Stop Speaking if speech output is playing */}
        {(state === "SPEAKING" || isPaused) && (
          <button
            type="button"
            className="btn-jarvis-control stop-speaking-btn"
            onClick={onStopSpeaking}
            title="Silence speech output"
            aria-label="Stop speech playback"
          >
            <VolumeX size={15} />
            <span>Stop Speech</span>
          </button>
        )}

        {/* Pause/Resume buttons */}
        {state === "SPEAKING" && onPauseSpeaking && (
          <button
            type="button"
            className="btn-jarvis-control"
            onClick={onPauseSpeaking}
            title="Pause speech playback"
            aria-label="Pause speech"
          >
            <Pause size={14} />
            <span>Pause</span>
          </button>
        )}

        {isPaused && onResumeSpeaking && (
          <button
            type="button"
            className="btn-jarvis-control"
            onClick={onResumeSpeaking}
            title="Resume speech playback"
            aria-label="Resume speech"
          >
            <Play size={14} />
            <span>Resume</span>
          </button>
        )}

        {/* 1. Microphone Hardware Input Mute Toggle */}
        {onToggleMicMute && (
          <button
            type="button"
            className={`btn-jarvis-control mic-mute-btn ${isMicMuted ? "active-muted" : ""}`}
            onClick={onToggleMicMute}
            title={isMicMuted ? "Unmute Microphone (Allow Voice Capture)" : "Mute Microphone (Hardware Input Disabled)"}
            aria-label={isMicMuted ? "Unmute Microphone" : "Mute Microphone"}
          >
            {isMicMuted ? <MicOff size={15} className="text-red" /> : <Mic size={15} />}
            <span>{isMicMuted ? "MIC MUTED" : "MIC ON"}</span>
          </button>
        )}

        {/* 2. "Hey Amoja" Wake-Word Activation Toggle */}
        {onToggleWakeWord && (
          <button
            type="button"
            className={`btn-jarvis-control wake-word-toggle-btn ${isWakeWordEnabled ? "active-wake" : ""}`}
            onClick={onToggleWakeWord}
            title={isWakeWordEnabled ? "Wake-Word Active: say 'Hey Amoja' to command assistant" : "Enable 'Hey Amoja' wake-word activation"}
            aria-label={isWakeWordEnabled ? "Disable Wake Word" : "Enable Wake Word"}
          >
            <Sparkles size={14} className={isWakeWordEnabled ? "sparkle-glow" : ""} />
            <span>{isWakeWordEnabled ? "HEY AMOJA: ON" : "WAKE: OFF"}</span>
          </button>
        )}

        {/* 3. Replay Last Spoken Response */}
        {onReplaySpeech && state !== "SPEAKING" && !isListening && (
          <button
            type="button"
            className="btn-jarvis-control replay-speech-btn"
            onClick={onReplaySpeech}
            title="Replay last speech output"
            aria-label="Replay speech"
          >
            <RotateCcw size={14} />
            <span>Replay</span>
          </button>
        )}

        {/* 4. Speaker Audio Output Mute Toggle */}
        <button
          type="button"
          className={`btn-jarvis-control mute-toggle-btn ${isMuted ? "muted" : ""}`}
          onClick={onToggleMute}
          title={isMuted ? "Unmute spoken responses" : "Mute spoken responses (Silent Text-Only Mode)"}
          aria-label={isMuted ? "Unmute audio responses" : "Mute audio responses"}
        >
          {isMuted ? <VolumeX size={15} className="text-red" /> : <Volume2 size={15} />}
          <span>{isMuted ? "AUDIO OFF" : "AUDIO ON"}</span>
        </button>
      </div>
    </div>
  );
};

