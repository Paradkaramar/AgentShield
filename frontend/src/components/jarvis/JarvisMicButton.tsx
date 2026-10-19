import React from "react";
import {
  Mic, MicOff, Volume2, VolumeX, Square, Loader2, AlertCircle,
  Pause, Play, RotateCcw
} from "lucide-react";
import { JarvisState } from "../../types";

interface Props {
  state: JarvisState;
  isListening: boolean;
  isMuted: boolean;
  isSpeechSupported: boolean;
  isPaused?: boolean;
  onToggleListen: () => void;
  onStopListening: () => void;
  onToggleMute: () => void;
  onStopSpeaking: () => void;
  onPauseSpeaking?: () => void;
  onResumeSpeaking?: () => void;
  onReplaySpeech?: () => void;
}

export const JarvisMicButton: React.FC<Props> = ({
  state,
  isListening,
  isMuted,
  isSpeechSupported,
  isPaused = false,
  onToggleListen,
  onStopListening,
  onToggleMute,
  onStopSpeaking,
  onPauseSpeaking,
  onResumeSpeaking,
  onReplaySpeech
}) => {
  return (
    <div className="jarvis-audio-controls">
      {/* Explicit Stop Listening button when actively recording */}
      {isListening && (
        <button
          type="button"
          className="btn-jarvis-control stop-listening-btn"
          onClick={onStopListening}
          title="Stop listening (Esc or say 'Stop listening')"
          aria-label="Stop listening"
        >
          <Square size={16} fill="currentColor" />
          <span>Stop Listening</span>
        </button>
      )}

      {/* Stop Speaking button if speech output is currently playing */}
      {(state === "SPEAKING" || isPaused) && (
        <button
          type="button"
          className="btn-jarvis-control stop-speaking-btn"
          onClick={onStopSpeaking}
          title="Silence speech output"
          aria-label="Stop speech playback"
        >
          <VolumeX size={16} />
          <span>Stop</span>
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
          <Pause size={16} />
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
          <Play size={16} />
          <span>Resume</span>
        </button>
      )}

      {/* Replay button */}
      {onReplaySpeech && state !== "SPEAKING" && !isListening && (
        <button
          type="button"
          className="btn-jarvis-control"
          onClick={onReplaySpeech}
          title="Replay last speech output"
          aria-label="Replay speech"
        >
          <RotateCcw size={16} />
          <span>Replay</span>
        </button>
      )}

      {/* Primary Microphone Trigger Button */}
      <button
        type="button"
        className={`jarvis-mic-btn state-${state.toLowerCase()} ${isListening ? "active-listening" : ""}`}
        onClick={onToggleListen}
        disabled={!isSpeechSupported && !isListening}
        title={
          !isSpeechSupported
            ? "Speech recognition not supported in this browser. Please use text input."
            : isListening
            ? "Listening to voice input... Click to stop."
            : "Click to speak to JARVIS"
        }
        aria-label={isListening ? "Stop voice listening" : "Start voice listening"}
      >
        <div className="mic-outer-ring" />
        <div className="mic-inner-core">
          {state === "PROCESSING" ? (
            <Loader2 size={24} className="spin-icon" />
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

      {/* Mute Voice Responses Toggle */}
      <button
        type="button"
        className={`btn-jarvis-control mute-toggle-btn ${isMuted ? "muted" : ""}`}
        onClick={onToggleMute}
        title={isMuted ? "Unmute voice responses" : "Mute voice responses"}
        aria-label={isMuted ? "Unmute voice" : "Mute voice"}
      >
        {isMuted ? <VolumeX size={18} /> : <Volume2 size={18} />}
      </button>
    </div>
  );
};
