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
  private isSpeakerMuted: boolean = false;
  private isMicMuted: boolean = false;
  private isContinuousMode: boolean = false;
  private isWakeWordEnabled: boolean = false;
  private isPushToTalkActive: boolean = false;
  private continuousTimer: any = null;
  private activeState: VoiceState = "IDLE";
  private audioCtx: AudioContext | null = null;
  private analyser: AnalyserNode | null = null;
  private microphoneStream: MediaStream | null = null;
  private selectedVoice: SpeechSynthesisVoice | null = null;
  private speechRate: number = 1.05;
  private speechPitch: number = 1.05;
  private speechLang: string = "en-US";
  private soundEffectsEnabled: boolean = true;
  private recordingStartTime: number | null = null;
  private micPermissionStatus: "granted" | "denied" | "prompt" | "unsupported" = "prompt";

  // Wake-word signature regex patterns (English, Hindi, Marathi, Romanized)
  private static readonly WAKE_WORD_PATTERN = /^(?:hey\s+)?(?:amoja|amoza|jarvis|अमोजा|अमोझा|जार्विस)\b[\s,:\-!]*/i;
  private static readonly ANY_WAKE_WORD_PATTERN = /\b(?:hey\s+amoja|hey\s+amoza|hey\s+jarvis|अमोजा|हे\s+अमोजा|अमोजा\s+ऐक|अमोजा\s+सुनो)\b/i;

  // Callbacks
  public onTranscriptChange: (text: string, isFinal: boolean) => void = () => {};
  public onStateChange: (state: VoiceState) => void = () => {};
  public onError: (message: string) => void = () => {};
  public onWakeWordDetected: (wakePhrase: string) => void = () => {};
  public onPermissionStatusChange: (status: "granted" | "denied" | "prompt" | "unsupported") => void = () => {};

  constructor() {
    this.initRecognition();
    this.initVoiceList();
    this.checkMicrophonePermission();
  }

  // Backward compatibility alias for isSpeakerMuted
  public get isMuted(): boolean {
    return this.isSpeakerMuted;
  }
  public set isMuted(val: boolean) {
    this.isSpeakerMuted = val;
  }

  public isSpeechRecognitionSupported(): boolean {
    return typeof window !== "undefined" && ("SpeechRecognition" in window || "webkitSpeechRecognition" in window);
  }

  public isSpeechSynthesisSupported(): boolean {
    return typeof window !== "undefined" && "speechSynthesis" in window;
  }

  // --- Push-to-Talk (PTT) Controls ---
  public getPushToTalkActive(): boolean {
    return this.isPushToTalkActive;
  }

  public async startPushToTalk(): Promise<boolean> {
    if (this.isMicMuted) {
      this.onError("Microphone is currently muted. Unmute the microphone to speak.");
      return false;
    }
    this.isPushToTalkActive = true;
    this.interruptPlayback();
    return this.startListening();
  }

  public stopPushToTalk(): void {
    this.isPushToTalkActive = false;
    this.stopListening();
  }

  // --- Wake-Word ("Hey Amoja") Controls ---
  public setWakeWordEnabled(enabled: boolean) {
    this.isWakeWordEnabled = enabled;
    if (enabled && !this.isListening && !this.isMicMuted && this.activeState === "IDLE") {
      this.scheduleContinuousListen(300);
    }
  }

  public getWakeWordEnabled(): boolean {
    return this.isWakeWordEnabled;
  }

  // --- Microphone Mute vs Speaker Mute Controls ---
  public setMicrophoneMuted(muted: boolean) {
    this.isMicMuted = muted;
    if (muted) {
      this.stopListening();
    } else if (this.isContinuousMode || this.isWakeWordEnabled) {
      this.scheduleContinuousListen(300);
    }
  }

  public isMicrophoneMuted(): boolean {
    return this.isMicMuted;
  }

  public setSpeakerMuted(muted: boolean) {
    this.isSpeakerMuted = muted;
    if (muted) {
      this.stopSpeaking();
    }
  }

  public isSpeakerMutedState(): boolean {
    return this.isSpeakerMuted;
  }

  // --- Permission Controls ---
  public async checkMicrophonePermission(): Promise<"granted" | "denied" | "prompt" | "unsupported"> {
    if (typeof navigator === "undefined" || !navigator.permissions || !navigator.permissions.query) {
      this.micPermissionStatus = "unsupported";
      return "unsupported";
    }
    try {
      const status = await navigator.permissions.query({ name: "microphone" as any });
      this.micPermissionStatus = status.state as any;
      status.onchange = () => {
        this.micPermissionStatus = status.state as any;
        this.onPermissionStatusChange(this.micPermissionStatus);
      };
      return this.micPermissionStatus;
    } catch {
      this.micPermissionStatus = "prompt";
      return "prompt";
    }
  }

  public getMicrophonePermissionStatus(): "granted" | "denied" | "prompt" | "unsupported" {
    return this.micPermissionStatus;
  }

  public async requestMicrophonePermission(): Promise<boolean> {
    if (typeof navigator === "undefined" || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      this.onError("Microphone hardware access is not supported in this browser environment.");
      return false;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      this.micPermissionStatus = "granted";
      this.onPermissionStatusChange("granted");
      stream.getTracks().forEach(t => t.stop());
      return true;
    } catch (err: any) {
      this.micPermissionStatus = "denied";
      this.onPermissionStatusChange("denied");
      this.onError("Microphone permission was denied. Please allow microphone access in your browser site settings.");
      return false;
    }
  }

  // --- Recording Metrics ---
  public getRecordingDurationSeconds(): number {
    if (!this.isListening || !this.recordingStartTime) return 0;
    return Math.max(0, Math.floor((Date.now() - this.recordingStartTime) / 1000));
  }

  public getAudioRMSLevel(): number {
    if (!this.analyser) return 0;
    const data = new Uint8Array(this.analyser.frequencyBinCount);
    this.analyser.getByteFrequencyData(data);
    if (data.length === 0) return 0;
    let sum = 0;
    for (let i = 0; i < data.length; i++) {
      sum += data[i] * data[i];
    }
    const rms = Math.sqrt(sum / data.length);
    return Math.min(100, Math.round((rms / 255) * 100));
  }

  public setContinuousMode(enabled: boolean) {
    this.isContinuousMode = enabled;
    if (!enabled && this.continuousTimer) {
      clearTimeout(this.continuousTimer);
      this.continuousTimer = null;
    }
  }

  public getContinuousMode(): boolean {
    return this.isContinuousMode;
  }

  public scheduleContinuousListen(delayMs = 350) {
    if ((!this.isContinuousMode && !this.isWakeWordEnabled) || this.isMicMuted) return;
    if (this.continuousTimer) clearTimeout(this.continuousTimer);
    this.continuousTimer = setTimeout(() => {
      this.continuousTimer = null;
      if (
        (this.isContinuousMode || this.isWakeWordEnabled) &&
        !this.isMicMuted &&
        !this.isListening &&
        this.activeState !== "PROCESSING" &&
        this.activeState !== "SPEAKING"
      ) {
        this.startListening();
      }
    }, delayMs);
  }

  public interruptPlayback() {
    if (this.continuousTimer) {
      clearTimeout(this.continuousTimer);
      this.continuousTimer = null;
    }
    if (this.audioElement) {
      try {
        this.audioElement.pause();
        this.audioElement.currentTime = 0;
        this.audioElement.src = "";
      } catch {}
      this.audioElement = null;
    }
    if (this.isSpeechSynthesisSupported()) {
      try {
        window.speechSynthesis.cancel();
      } catch {}
    }
    this.isAudioPaused = false;
    this.notifyState("LISTENING");
  }

  private notifyState(state: VoiceState) {
    this.activeState = state;
    this.onStateChange(state);
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
        this.recordingStartTime = Date.now();
        this.notifyState("LISTENING");
        this.playActivationChime();
      };

      this.recognition.onspeechstart = () => {
        // Only allow explicit interruption if activeState is SPEAKING and an interruption is triggered
        if (this.activeState === "SPEAKING") {
          // Do not interrupt automatically on minor mic noise during speech
          return;
        }
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

        const rawText = (finalTranscript || interimTranscript).trim();
        if (!rawText) return;

        // Prevent self-transcription: If assistant is currently speaking, only allow interruption on explicit stop words
        if (this.activeState === "SPEAKING") {
          const lower = rawText.toLowerCase();
          const isInterruptPhrase = /(?:hey\s+amoja|stop|थांबा|रुको|chup|pause|wait)\b/i.test(lower);
          if (isInterruptPhrase) {
            this.interruptPlayback();
            this.onTranscriptChange(rawText, Boolean(finalTranscript));
          }
          // Discard self-hearing from speakers while assistant speaks
          return;
        }
        // Check for optional "Hey Amoja" wake-word activation
        if (this.isWakeWordEnabled) {
          const match = rawText.match(JarvisVoiceEngine.WAKE_WORD_PATTERN) || rawText.match(JarvisVoiceEngine.ANY_WAKE_WORD_PATTERN);
          if (match) {
            this.playAcknowledgeChime();
            this.onWakeWordDetected(match[0].trim());
            const cleanedDirective = rawText.replace(JarvisVoiceEngine.WAKE_WORD_PATTERN, "").trim();
            if (cleanedDirective) {
              this.onTranscriptChange(cleanedDirective, Boolean(finalTranscript));
            } else {
              // User only summoned Amoja by wake word: keep listening for command
              this.onTranscriptChange("AMOJA listening...", false);
            }
            return;
          }
        }

        this.onTranscriptChange(rawText, Boolean(finalTranscript));
      };

      this.recognition.onerror = (event: SpeechRecognitionErrorEvent) => {
        this.isListening = false;
        this.recordingStartTime = null;
        let errMsg = "Microphone error";
        if (event.error === "not-allowed" || event.error === "permission-denied") {
          this.micPermissionStatus = "denied";
          this.onPermissionStatusChange("denied");
          errMsg = "Microphone access denied. Please grant microphone permission in your browser.";
        } else if (event.error === "no-speech") {
          errMsg = "No speech detected. Listening timed out.";
        } else if (event.error === "network") {
          errMsg = "Network error during speech recognition.";
        } else {
          errMsg = `Speech recognition error: ${event.error}`;
        }
        this.onError(errMsg);
        this.notifyState("IDLE");
      };

      this.recognition.onend = () => {
        this.isListening = false;
        this.recordingStartTime = null;
        this.stopMicrophoneStream();
        this.notifyState("IDLE");

        // Re-arm in continuous mode or wake-word standby mode
        if (
          (this.isContinuousMode || this.isWakeWordEnabled) &&
          !this.isMicMuted &&
          !this.isPushToTalkActive &&
          this.activeState === "IDLE" &&
          !this.audioElement &&
          !(this.isSpeechSynthesisSupported() && window.speechSynthesis.speaking)
        ) {
          this.scheduleContinuousListen(450);
        }
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

      // Prefer warm, natural Female voices for AMOJA AI persona across Indic & English
      const preferred = voices.find(v => 
        (v.name.includes("Female") ||
         v.name.includes("Google UK English Female") ||
         v.name.includes("Google US English Female") ||
         v.name.includes("Zira") ||
         v.name.includes("Samantha") ||
         v.name.includes("Victoria") ||
         v.name.includes("Kavya") ||
         v.name.includes("Ananya") ||
         v.name.includes("Kalpana") ||
         v.name.includes("Neerja") ||
         v.name.includes("Swara") ||
         v.name.includes("Heera") ||
         v.name.includes("Anya"))
      ) || voices.find(v => v.lang.startsWith("en-IN") || v.lang.startsWith("en-GB") || v.lang.startsWith("en-US")) || voices[0];

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

    // Attempt to pick a matching female speech synthesis voice for AMOJA AI
    const voices = this.getAvailableVoices();
    if (langCode === "mr") {
      const mrVoice = voices.find(v => (v.lang.startsWith("mr") || v.name.toLowerCase().includes("marathi")) && (v.name.includes("Female") || v.name.includes("Ananya") || v.name.includes("Aarohi"))) ||
                      voices.find(v => v.lang.startsWith("mr") || v.name.toLowerCase().includes("marathi"));
      if (mrVoice) this.selectedVoice = mrVoice;
    } else if (langCode === "hi") {
      const hiVoice = voices.find(v => (v.lang.startsWith("hi") || v.name.toLowerCase().includes("hindi")) && (v.name.includes("Female") || v.name.includes("Kalpana") || v.name.includes("Kavya") || v.name.includes("Swara"))) ||
                      voices.find(v => v.lang.startsWith("hi") || v.name.toLowerCase().includes("hindi"));
      if (hiVoice) this.selectedVoice = hiVoice;
    } else {
      const enVoice = voices.find(v => v.lang.startsWith("en") && (v.name.includes("Female") || v.name.includes("Zira") || v.name.includes("Samantha")));
      if (enVoice) this.selectedVoice = enVoice;
    }
  }

  // --- Local Audio Playback with Visualizer, Pause, Resume, Replay ---
  private audioElement: HTMLAudioElement | null = null;
  private lastAudioUrl: string | null = null;
  private isAudioPaused: boolean = false;

  public playLocalAudioBase64(base64Wav: string): Promise<void> {
    return new Promise((resolve) => {
      this.stopSpeaking();
      if (this.recognition && this.isListening) {
        try {
          this.recognition.abort();
        } catch {}
        this.isListening = false;
      }
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
        this.notifyState("SPEAKING");
      };

      audio.onended = () => {
        this.notifyState("IDLE");
        this.audioElement = null;
        resolve();
        // Continuous hands-free voice loop: automatically re-arm listening after acoustic cooldown
        if (this.isContinuousMode && !this.isMicMuted && !this.isMuted) {
          this.scheduleContinuousListen(400);
        }
      };

      audio.onerror = () => {
        this.notifyState("IDLE");
        this.audioElement = null;
        resolve();
      };

      audio.play().catch(() => {
        this.notifyState("IDLE");
        this.audioElement = null;
        resolve();
      });
    });
  }

  public pauseSpeaking() {
    if (this.audioElement && !this.audioElement.paused) {
      this.audioElement.pause();
      this.isAudioPaused = true;
      this.notifyState("IDLE");
    } else if (this.isSpeechSynthesisSupported() && window.speechSynthesis.speaking) {
      window.speechSynthesis.pause();
      this.isAudioPaused = true;
      this.notifyState("IDLE");
    }
  }

  public resumeSpeaking() {
    if (this.audioElement && this.isAudioPaused) {
      this.audioElement.play();
      this.isAudioPaused = false;
      this.notifyState("SPEAKING");
    } else if (this.isSpeechSynthesisSupported() && window.speechSynthesis.paused) {
      window.speechSynthesis.resume();
      this.isAudioPaused = false;
      this.notifyState("SPEAKING");
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
    if (this.isMicMuted) {
      return false;
    }
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
    this.notifyState("IDLE");
  }

  public speak(text: string): Promise<void> {
    return new Promise((resolve) => {
      if (!this.isSpeechSynthesisSupported() || this.isMuted || !text.trim()) {
        resolve();
        return;
      }

      // Stop any existing speech and pause recognition during speaking to prevent feedback
      window.speechSynthesis.cancel();
      if (this.recognition && this.isListening) {
        try {
          this.recognition.abort();
        } catch {}
        this.isListening = false;
      }

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
        this.notifyState("SPEAKING");
      };

      utterance.onend = () => {
        this.notifyState("IDLE");
        resolve();
        // Continuous hands-free voice loop: automatically re-arm listening after acoustic cooldown
        if (this.isContinuousMode && !this.isMicMuted && !this.isMuted) {
          this.scheduleContinuousListen(400);
        }
      };

      utterance.onerror = () => {
        this.notifyState("IDLE");
        resolve();
      };

      window.speechSynthesis.speak(utterance);
    });
  }

  public stopSpeaking() {
    if (this.continuousTimer) {
      clearTimeout(this.continuousTimer);
      this.continuousTimer = null;
    }
    if (this.audioElement) {
      try {
        this.audioElement.pause();
        this.audioElement.currentTime = 0;
        this.audioElement.src = "";
      } catch {}
      this.audioElement = null;
    }
    if (this.isSpeechSynthesisSupported()) {
      window.speechSynthesis.cancel();
    }
    this.isAudioPaused = false;
    this.notifyState("IDLE");
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
