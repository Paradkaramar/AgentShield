// frontend/src/components/jarvis/JarvisOrb.tsx
import React, { useEffect, useState } from "react";
import { JarvisState } from "../../types";

interface Props {
  state: JarvisState;
  size?: number;
  onClick?: () => void;
  interactive?: boolean;
}

export const JarvisOrb: React.FC<Props> = ({
  state,
  size = 180,
  onClick,
  interactive = true,
}) => {
  const [pulsePhase, setPulsePhase] = useState(0);

  useEffect(() => {
    let animId: number;
    let startTime = performance.now();

    const loop = (currentTime: number) => {
      const elapsed = (currentTime - startTime) / 1000;
      // Adjust speed based on state
      const speed = state === "PROCESSING" ? 3.5 : state === "SPEAKING" ? 2.8 : state === "LISTENING" ? 2.2 : 1.0;
      setPulsePhase((elapsed * speed) % (Math.PI * 2));
      animId = requestAnimationFrame(loop);
    };

    animId = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(animId);
  }, [state]);

  const baseColors = {
    IDLE: { core: "#00e5ff", glow: "rgba(0, 229, 255, 0.4)", ring: "#0099ff", energy: "#38bdf8" },
    LISTENING: { core: "#00ffcc", glow: "rgba(0, 255, 204, 0.65)", ring: "#00e5ff", energy: "#7dd3fc" },
    PROCESSING: { core: "#38bdf8", glow: "rgba(56, 189, 248, 0.6)", ring: "#f59e0b", energy: "#fbbf24" },
    SPEAKING: { core: "#00f0ff", glow: "rgba(0, 240, 255, 0.75)", ring: "#60a5fa", energy: "#93c5fd" },
    ERROR: { core: "#ef4444", glow: "rgba(239, 68, 68, 0.75)", ring: "#dc2626", energy: "#fca5a5" },
  };

  const currentTheme = baseColors[state] || baseColors.IDLE;
  const pulseScale = 1 + Math.sin(pulsePhase) * (state === "SPEAKING" ? 0.08 : state === "LISTENING" ? 0.05 : 0.02);

  return (
    <div
      className={`jarvis-orb-container state-${state.toLowerCase()} ${interactive ? "clickable" : ""}`}
      style={{ width: size, height: size }}
      onClick={interactive ? onClick : undefined}
      title={interactive ? "Click to toggle JARVIS voice input" : undefined}
      role={interactive ? "button" : undefined}
      tabIndex={interactive ? 0 : undefined}
      onKeyDown={interactive ? (e) => { if (e.key === "Enter" || e.key === " ") { onClick?.(); } } : undefined}
      aria-label={`JARVIS AI Orb - Status: ${state}`}
    >
      <svg
        viewBox="0 0 200 200"
        className="jarvis-orb-svg"
        style={{ transform: `scale(${pulseScale})` }}
      >
        <defs>
          {/* Radial gradient for glowing plasma core */}
          <radialGradient id={`coreGlow-${state}`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.95" />
            <stop offset="35%" stopColor={currentTheme.core} stopOpacity="0.8" />
            <stop offset="70%" stopColor={currentTheme.ring} stopOpacity="0.3" />
            <stop offset="100%" stopColor="transparent" stopOpacity="0" />
          </radialGradient>

          {/* Filter for electric holographic glow */}
          <filter id={`neonGlow-${state}`} x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="4.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Ambient background energy aura */}
        <circle
          cx="100"
          cy="100"
          r="86"
          fill="none"
          stroke={currentTheme.glow}
          strokeWidth="1"
          opacity="0.3"
        />

        {/* Outer segmented radar ring */}
        <circle
          cx="100"
          cy="100"
          r="82"
          fill="none"
          stroke={currentTheme.ring}
          strokeWidth="1.5"
          strokeDasharray="8 6 2 6 24 6"
          className="orb-ring-outer"
          filter={`url(#neonGlow-${state})`}
        />

        {/* Middle reverse-rotating telemetry ring */}
        <circle
          cx="100"
          cy="100"
          r="68"
          fill="none"
          stroke={currentTheme.energy}
          strokeWidth="1.2"
          strokeDasharray="4 8 16 8"
          className="orb-ring-middle"
          opacity="0.85"
        />

        {/* High-frequency inner orbital ring */}
        <circle
          cx="100"
          cy="100"
          r="54"
          fill="none"
          stroke={currentTheme.core}
          strokeWidth="1.8"
          strokeDasharray="28 8 6 8"
          className="orb-ring-inner"
          filter={`url(#neonGlow-${state})`}
        />

        {/* HUD Crosshair compass ticks */}
        <line x1="100" y1="12" x2="100" y2="24" stroke={currentTheme.ring} strokeWidth="1.5" opacity="0.7" />
        <line x1="100" y1="176" x2="100" y2="188" stroke={currentTheme.ring} strokeWidth="1.5" opacity="0.7" />
        <line x1="12" y1="100" x2="24" y2="100" stroke={currentTheme.ring} strokeWidth="1.5" opacity="0.7" />
        <line x1="176" y1="100" x2="188" y2="100" stroke={currentTheme.ring} strokeWidth="1.5" opacity="0.7" />

        {/* Glowing Plasma Core */}
        <circle
          cx="100"
          cy="100"
          r="38"
          fill={`url(#coreGlow-${state})`}
          className="orb-core-pulse"
        />

        {/* Central white-hot focal singularity */}
        <circle
          cx="100"
          cy="100"
          r="10"
          fill="#ffffff"
          opacity="0.85"
          filter={`url(#neonGlow-${state})`}
        />

        {/* Acoustic ripple waves when speaking */}
        {state === "SPEAKING" && (
          <>
            <circle cx="100" cy="100" r="46" fill="none" stroke={currentTheme.core} strokeWidth="1" className="orb-acoustic-wave-1" />
            <circle cx="100" cy="100" r="58" fill="none" stroke={currentTheme.energy} strokeWidth="1" className="orb-acoustic-wave-2" />
          </>
        )}

        {/* Radar sweep during listening */}
        {state === "LISTENING" && (
          <path
            d="M 100 100 L 100 25 A 75 75 0 0 1 155 45 Z"
            fill={currentTheme.glow}
            opacity="0.45"
            className="orb-radar-sweep"
          />
        )}
      </svg>

      {/* State label badge below or within */}
      <div className="orb-status-text">
        <span className="orb-status-dot" style={{ backgroundColor: currentTheme.core }} />
        <span className="orb-status-name">{state}</span>
      </div>
    </div>
  );
};
