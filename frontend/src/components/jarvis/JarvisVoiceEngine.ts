// frontend/src/components/jarvis/JarvisVoiceEngine.ts
// Robust Web Speech API controller with Speech-To-Text, Text-To-Speech, and Web Audio synthesis

export type VoiceState = "IDLE" | "LISTENING" | "PROCESSING" | "SPEAKING" | "ERROR";

export interface SpeechRecognitionEvent extends Event {
  results: SpeechRecognitionResultList;
  resultIndex: number;
}

export interface SpeechRecognitionErrorEvent extends Event {
  error: string;
  message?: string;
}

export class JarvisVoiceEngine {
  private recognition: any = null;
  private isListening: boolean = false;
  private isMuted: boolean = false;
  private audioCtx: AudioContext | null = null;
  private analyser: AnalyserNode | null = null;
  private microphoneStream: MediaStream | null = null;
  private selectedVoice: SpeechSynthesisVoice | null = null;
  private speechRate: number = 1.05;
  private speechPitch: number = 1.0;
  private speechLang: string = "en-US";
  private soundEffectsEnabled: boolean = true;

  // Callbacks
  public onTranscriptChange: (text: string, isFinal: boolean) => void = () => {};
  public onStateChange: (state: VoiceState) => void = () => {};
  public onError: (message: string) => void = () => {};

  constructor() {
    this.initRecognition();
    this.initVoiceList();
  }

  public isSpeechRecognitionSupported(): boolean {
    return typeof window !== "undefined" && ("SpeechRecognition" in window || "webkitSpeechRecognition" in window);
  }

  public isSpeechSynthesisSupported(): boolean {
    return typeof window !== "undefined" && "speechSynthesis" in window;
  }

  private initRecognition() {
    if (!this.isSpeechRecognitionSupported()) return;

    try {
      const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
      this.recognition = new SpeechRecognition();
      this.recognition.continuous = false;
      this.recognition.interimResults = true;
      this.recognition.maxAlternatives = 1;
      this.recognition.lang = this.speechLang;

      this.recognition.onstart = () => {
        this.isListening = true;
        this.onStateChange("LISTENING");
        this.playActivationChime();
      };

      this.recognition.onresult = (event: SpeechRecognitionEvent) => {
        let interimTranscript = "";
        let finalTranscript = "";

        for (let i = event.resultIndex; i < event.results.length; ++i) {
          if (event.results[i].isFinal) {
            finalTranscript += event.results[i][0].transcript;
          } else {
            interimTranscript += event.results[i][0].transcript;
          }
        }

        const text = finalTranscript || interimTranscript;
        this.onTranscriptChange(text, Boolean(finalTranscript));
      };

      this.recognition.onerror = (event: SpeechRecognitionErrorEvent) => {
        this.isListening = false;
        let errMsg = "Microphone error";
        if (event.error === "not-allowed" || event.error === "permission-denied") {
          errMsg = "Microphone access denied. Please grant permission in browser settings.";
        } else if (event.error === "no-speech") {
          errMsg = "No speech detected. Listening timed out.";
        } else if (event.error === "network") {
          errMsg = "Network error during speech recognition.";
        } else {
          errMsg = `Speech recognition error: ${event.error}`;
        }
        this.onError(errMsg);
        this.onStateChange("IDLE");
      };

      this.recognition.onend = () => {
        this.isListening = false;
        this.stopMicrophoneStream();
        this.onStateChange("IDLE");
      };
    } catch (e) {
      console.warn("Failed to initialize speech recognition:", e);
    }
  }

  private initVoiceList() {
    if (!this.isSpeechSynthesisSupported()) return;
    const loadVoices = () => {
      const voices = window.speechSynthesis.getVoices();
      if (!voices || voices.length === 0) return;

      // Prefer high-quality English or Indian English / Jarvis-like voices
      const preferred = voices.find(v => 
        (v.name.includes("Google UK English Male") ||
         v.name.includes("Natural") ||
         v.name.includes("Daniel") ||
         v.name.includes("George") ||
         v.name.includes("Ravi") ||
         v.name.includes("English United Kingdom")) && !v.name.includes("Female")
      ) || voices.find(v => v.lang.startsWith("en-GB") || v.lang.startsWith("en-IN") || v.lang.startsWith("en-US")) || voices[0];

      this.selectedVoice = preferred || null;
    };

    loadVoices();
    if (window.speechSynthesis.onvoiceschanged !== undefined) {
      window.speechSynthesis.onvoiceschanged = loadVoices;
    }
  }

  public getAvailableVoices(): SpeechSynthesisVoice[] {
    if (!this.isSpeechSynthesisSupported()) return [];
    return window.speechSynthesis.getVoices();
  }

  public setVoice(voiceName: string) {
    const voices = this.getAvailableVoices();
    const match = voices.find(v => v.name === voiceName);
    if (match) this.selectedVoice = match;
  }

  public setLanguage(langCode: string) {
    if (langCode === "mr") {
      this.speechLang = "mr-IN";
    } else if (langCode === "hi") {
      this.speechLang = "hi-IN";
    } else if (langCode === "hinglish") {
      this.speechLang = "en-IN";
    } else {
      this.speechLang = "en-US";
    }

    if (this.recognition) {
      this.recognition.lang = this.speechLang;
    }

    // Attempt to pick a matching speech synthesis voice
    const voices = this.getAvailableVoices();
    if (langCode === "mr") {
      const mrVoice = voices.find(v => v.lang.startsWith("mr") || v.name.toLowerCase().includes("marathi"));
      if (mrVoice) this.selectedVoice = mrVoice;
    } else if (langCode === "hi") {
      const hiVoice = voices.find(v => v.lang.startsWith("hi") || v.name.toLowerCase().includes("hindi"));
      if (hiVoice) this.selectedVoice = hiVoice;
    }
  }

  // --- Local Audio Playback with Visualizer, Pause, Resume, Replay ---
  private audioElement: HTMLAudioElement | null = null;
  private lastAudioUrl: string | null = null;
  private isAudioPaused: boolean = false;

  public playLocalAudioBase64(base64Wav: string): Promise<void> {
    return new Promise((resolve) => {
      this.stopSpeaking();
      const cleanB64 = base64Wav.includes(",") ? base64Wav.split(",")[1] : base64Wav;
      const audioUrl = `data:audio/wav;base64,${cleanB64}`;
      this.lastAudioUrl = audioUrl;

      const audio = new Audio(audioUrl);
      this.audioElement = audio;
      audio.playbackRate = this.speechRate;

      // Connect to audio analyser for orb waveform animation
      try {
        const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
        if (AudioCtx) {
          if (!this.audioCtx || this.audioCtx.state === "closed") {
            this.audioCtx = new AudioCtx();
          }
          const source = this.audioCtx.createMediaElementSource(audio);
          this.analyser = this.audioCtx.createAnalyser();
          this.analyser.fftSize = 64;
          source.connect(this.analyser);
          this.analyser.connect(this.audioCtx.destination);
          if (this.audioCtx.state === "suspended") {
            this.audioCtx.resume();
          }
        }
      } catch (e) {
        // Fallback to direct element playback
      }

      audio.onplay = () => {
        this.isAudioPaused = false;
        this.onStateChange("SPEAKING");
      };

      audio.onended = () => {
        this.onStateChange("IDLE");
        this.audioElement = null;
        resolve();
      };

      audio.onerror = () => {
        this.onStateChange("IDLE");
        this.audioElement = null;
        resolve();
      };

      audio.play().catch(() => {
        this.onStateChange("IDLE");
        this.audioElement = null;
        resolve();
      });
    });
  }

  public pauseSpeaking() {
    if (this.audioElement && !this.audioElement.paused) {
      this.audioElement.pause();
      this.isAudioPaused = true;
      this.onStateChange("IDLE");
    } else if (this.isSpeechSynthesisSupported() && window.speechSynthesis.speaking) {
      window.speechSynthesis.pause();
      this.isAudioPaused = true;
      this.onStateChange("IDLE");
    }
  }

  public resumeSpeaking() {
    if (this.audioElement && this.isAudioPaused) {
      this.audioElement.play();
      this.isAudioPaused = false;
      this.onStateChange("SPEAKING");
    } else if (this.isSpeechSynthesisSupported() && window.speechSynthesis.paused) {
      window.speechSynthesis.resume();
      this.isAudioPaused = false;
      this.onStateChange("SPEAKING");
    }
  }

  public replayLastSpeech() {
    if (this.lastAudioUrl) {
      const b64 = this.lastAudioUrl.replace("data:audio/wav;base64,", "");
      this.playLocalAudioBase64(b64);
    }
  }

  public isPlaybackPaused(): boolean {
    return this.isAudioPaused;
  }

  public setSpeechSettings(rate: number, pitch: number, isMuted: boolean, soundEffects: boolean) {
    this.speechRate = Math.max(0.5, Math.min(2.0, rate));
    this.speechPitch = Math.max(0.5, Math.min(2.0, pitch));
    this.isMuted = isMuted;
    this.soundEffectsEnabled = soundEffects;
  }

  public async startListening(): Promise<boolean> {
    if (!this.isSpeechRecognitionSupported()) {
      this.onError("Speech recognition is not supported in this browser. Please use Google Chrome, Edge, or text input.");
      return false;
    }

    // Cancel any active speech output
    this.stopSpeaking();

    try {
      // Request microphone stream for audio visualizer if available
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        try {
          this.microphoneStream = await navigator.mediaDevices.getUserMedia({ audio: true });
          this.initAudioAnalyser(this.microphoneStream);
        } catch {
          // Microphone visualizer permission denied, speech recognition still works via native prompt
        }
      }

      this.recognition.start();
      return true;
    } catch (err: any) {
      if (err.name !== "InvalidStateError") {
        this.onError(`Could not start listening: ${err.message || err}`);
      }
      return false;
    }
  }

  public stopListening() {
    if (this.recognition && this.isListening) {
      try {
        this.recognition.stop();
      } catch {}
    }
    this.isListening = false;
    this.stopMicrophoneStream();
    this.onStateChange("IDLE");
  }

  public speak(text: string): Promise<void> {
    return new Promise((resolve) => {
      if (!this.isSpeechSynthesisSupported() || this.isMuted || !text.trim()) {
        resolve();
        return;
      }

      // Stop any existing speech
      window.speechSynthesis.cancel();

      // Clean markdown tags, emojis, and code formatting from speech
      const cleanSpeech = text
        .replace(/[*_#`~>\[\]\(\)]/g, "")
        .replace(/https?:\/\/\S+/g, "link")
        .replace(/[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu, "")
        .trim();

      if (!cleanSpeech) {
        resolve();
        return;
      }

      const utterance = new SpeechSynthesisUtterance(cleanSpeech);
      if (this.selectedVoice) {
        utterance.voice = this.selectedVoice;
      }
      utterance.rate = this.speechRate;
      utterance.pitch = this.speechPitch;
      utterance.lang = this.speechLang;

      utterance.onstart = () => {
        this.onStateChange("SPEAKING");
      };

      utterance.onend = () => {
        this.onStateChange("IDLE");
        resolve();
      };

      utterance.onerror = () => {
        this.onStateChange("IDLE");
        resolve();
      };

      window.speechSynthesis.speak(utterance);
    });
  }

  public stopSpeaking() {
    if (this.isSpeechSynthesisSupported()) {
      window.speechSynthesis.cancel();
      this.onStateChange("IDLE");
    }
  }

  private initAudioAnalyser(stream: MediaStream) {
    try {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioCtx) return;
      this.audioCtx = new AudioCtx();
      const source = this.audioCtx.createMediaStreamSource(stream);
      this.analyser = this.audioCtx.createAnalyser();
      this.analyser.fftSize = 64;
      source.connect(this.analyser);
    } catch (e) {
      console.warn("Web Audio Analyser not available:", e);
    }
  }

  public getAudioFrequencyData(): Uint8Array {
    if (this.analyser) {
      const data = new Uint8Array(this.analyser.frequencyBinCount);
      this.analyser.getByteFrequencyData(data);
      return data;
    }
    // Fallback: return simulated idle or harmonic frequency array
    return new Uint8Array(32);
  }

  private stopMicrophoneStream() {
    if (this.microphoneStream) {
      this.microphoneStream.getTracks().forEach(t => t.stop());
      this.microphoneStream = null;
    }
    if (this.audioCtx && this.audioCtx.state !== "closed") {
      try {
        this.audioCtx.close();
      } catch {}
      this.audioCtx = null;
      this.analyser = null;
    }
  }

  // --- Futuristic High-Tech Audio Cues ---
  private playTone(freq1: number, freq2: number, type: OscillatorType = "sine", durationMs = 120) {
    if (!this.soundEffectsEnabled || typeof window === "undefined") return;
    try {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = type;
      osc.frequency.setValueAtTime(freq1, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(freq2, ctx.currentTime + durationMs / 1000);

      gain.gain.setValueAtTime(0.04, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + durationMs / 1000);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start();
      osc.stop(ctx.currentTime + durationMs / 1000);
      setTimeout(() => {
        try { ctx.close(); } catch {}
      }, durationMs + 50);
    } catch {}
  }

  public playActivationChime() {
    this.playTone(440, 880, "sine", 140);
  }

  public playAcknowledgeChime() {
    this.playTone(660, 1100, "sine", 160);
  }

  public playAlertChime() {
    this.playTone(750, 320, "triangle", 240);
  }
}

// Global singleton instance for app-wide continuity
export const jarvisVoice = new JarvisVoiceEngine();
