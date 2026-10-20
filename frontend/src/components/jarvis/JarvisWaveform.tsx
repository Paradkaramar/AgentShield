// frontend/src/components/jarvis/JarvisWaveform.tsx
import React, { useEffect, useRef } from "react";
import { JarvisState } from "../../types";
import { jarvisVoice } from "./JarvisVoiceEngine";

interface Props {
  state: JarvisState;
  height?: number;
  barCount?: number;
}

export const JarvisWaveform: React.FC<Props> = ({
  state,
  height = 48,
  barCount = 28,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let phase = 0;

    const render = () => {
      phase += 0.08;
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const width = canvas.width;
      const h = canvas.height;
      const centerY = h / 2;
      const barWidth = Math.max(2, Math.floor(width / (barCount * 1.6)));
      const gap = Math.floor((width - barCount * barWidth) / (barCount - 1));

      // Get real audio frequency data if listening
      const freqData = jarvisVoice.getAudioFrequencyData();
      const hasRealAudio = state === "LISTENING" && freqData.some(v => v > 10);

      // Determine colors based on assistant state (NVIDIA Neon Green Aesthetic)
      let strokeColor = "#76b900";
      let glowColor = "rgba(118, 185, 0, 0.45)";
      if (state === "SPEAKING") {
        strokeColor = "#00ff88";
        glowColor = "rgba(0, 255, 136, 0.65)";
      } else if (state === "PROCESSING") {
        strokeColor = "#84cc16";
        glowColor = "rgba(132, 204, 22, 0.55)";
      } else if (state === "ERROR") {
        strokeColor = "#ef4444";
        glowColor = "rgba(239, 68, 68, 0.6)";
      } else if (state === "LISTENING") {
        strokeColor = "#76b900";
        glowColor = "rgba(118, 185, 0, 0.75)";
      }

      ctx.shadowBlur = 10;
      ctx.shadowColor = glowColor;

      for (let i = 0; i < barCount; i++) {
        let barHeight = 4;

        if (state === "SPEAKING") {
          // Acoustic harmonic wave synthesis
          const sin1 = Math.sin(phase + i * 0.35);
          const sin2 = Math.cos(phase * 1.5 + i * 0.2);
          const envelope = Math.sin((i / barCount) * Math.PI); // tapering envelope
          barHeight = Math.max(4, Math.abs(sin1 * 0.7 + sin2 * 0.3) * (h * 0.85) * envelope);
        } else if (state === "LISTENING") {
          if (hasRealAudio) {
            const dataIdx = Math.floor((i / barCount) * freqData.length);
            const val = freqData[dataIdx] || 0;
            barHeight = Math.max(4, (val / 255) * h * 0.9);
          } else {
            // Simulated active listening waveform
            const sin = Math.sin(phase * 1.8 + i * 0.4);
            const envelope = Math.sin((i / barCount) * Math.PI);
            barHeight = Math.max(4, Math.abs(sin) * (h * 0.7) * envelope);
          }
        } else if (state === "PROCESSING") {
          // Quantum ripple sweep
          const sweep = (Math.sin(phase * 2 - i * 0.3) + 1) / 2;
          barHeight = Math.max(4, sweep * (h * 0.6));
        } else {
          // Subtle idle resting pulse
          const sin = Math.sin(phase * 0.5 + i * 0.2);
          barHeight = Math.max(3, Math.abs(sin) * (h * 0.25));
        }

        const x = i * (barWidth + gap);
        const y = centerY - barHeight / 2;

        const grad = ctx.createLinearGradient(0, y, 0, y + barHeight);
        grad.addColorStop(0, strokeColor);
        grad.addColorStop(0.3, "#00ff88");
        grad.addColorStop(0.5, "#ffffff");
        grad.addColorStop(1, strokeColor);

        ctx.fillStyle = grad;
        ctx.beginPath();
        // Rounded bars
        ctx.roundRect ? ctx.roundRect(x, y, barWidth, barHeight, 2) : ctx.rect(x, y, barWidth, barHeight);
        ctx.fill();
      }

      animId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animId);
  }, [state, barCount]);

  return (
    <div className="jarvis-waveform-wrapper" style={{ height }}>
      <canvas
        ref={canvasRef}
        width={340}
        height={height}
        className="jarvis-waveform-canvas"
        aria-hidden="true"
      />
    </div>
  );
};
