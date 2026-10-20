// frontend/src/components/jarvis/JarvisVoiceEngine.ts
// Robust Multilingual Voice Engine supporting Push-To-Talk, Hands-free continuous loop,
// Web Audio API VAD (Voice Activity Detection), MediaRecorder local STT, and SpeechSynthesis.

import { transcribeAudio } from "../../api";
import { JarvisLanguage } from "../../types";

export type VoiceState = "IDLE" | "LISTENING" | "PROCESSING" | "SPEAKING" | "ERROR";

export interface SpeechRecognitionEvent extends Event {
  results: SpeechRecognitionResultList;
  resultIndex: number;
}

export interface SpeechRecognitionErrorEvent extends Event {
  error: string;
  message?: string;
}

export interface VoiceDiagnostics {
  microphoneStatus: "READY" | "DENIED" | "ERROR" | "MUTED";
  recognitionEngine: "MediaRecorder + Local STT" | "Web Speech API" | "Dual Engine";
  recognitionStatus: "IDLE" | "LISTENING" | "TRANSCRIBING" | "ERROR";
  activeState: VoiceState;
  transcript: string;
  audioLevelRms: number;
  isElectron: boolean;
  isMicMuted: boolean;
  isSpeakerMuted: boolean;
  lastError: string;
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
  private targetLanguage: JarvisLanguage = "auto";
  private soundEffectsEnabled: boolean = true;
  private recordingStartTime: number | null = null;
  private micPermissionStatus: "granted" | "denied" | "prompt" | "unsupported" = "prompt";
  private lastErrorMessage: string = "";
  private lastRecognizedText: string = "";

  // MediaRecorder for guaranteed Electron / offline local STT capture
  private mediaRecorder: MediaRecorder | null = null;
  private audioChunks: Blob[] = [];
  private vadSilenceTimer: any = null;
  private vadHasSpeech: boolean = false;
  private webSpeechFailed: boolean = false;
  private isTranscribingBackend: boolean = false;

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

  public isElectronEnv(): boolean {
    return typeof window !== "undefined" && Boolean((window as any).agentShieldDesktop?.isDesktop);
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
    // If running inside Electron, check desktop bridge
    if (this.isElectronEnv() && (window as any).agentShieldDesktop?.checkMicrophonePermission) {
      try {
        const res = await (window as any).agentShieldDesktop.checkMicrophonePermission();
        if (res?.status === "granted") {
          this.micPermissionStatus = "granted";
          this.onPermissionStatusChange("granted");
          return "granted";
        }
      } catch {}
    }

    if (typeof navigator === "undefined" || !navigator.permissions || !navigator.permissions.query) {
      this.micPermissionStatus = "granted";
      return "granted";
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
    if (this.isElectronEnv() && (window as any).agentShieldDesktop?.requestMicrophonePermission) {
      try {
        await (window as any).agentShieldDesktop.requestMicrophonePermission();
      } catch {}
    }

    if (typeof navigator === "undefined" || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      this.onError("Microphone hardware access is not supported in this browser environment.");
      return false;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true
        }
      });
      this.micPermissionStatus = "granted";
      this.onPermissionStatusChange("granted");
      stream.getTracks().forEach(t => t.stop());
      return true;
    } catch (err: any) {
      this.micPermissionStatus = "denied";
      this.onPermissionStatusChange("denied");
      this.onError("Microphone permission was denied. Please allow microphone access in your system or browser settings.");
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

  public scheduleContinuousListen(delayMs = 400) {
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
    this.notifyState("IDLE");
  }

  private notifyState(state: VoiceState) {
    this.activeState = state;
    this.onStateChange(state);
  }

  // --- Recognition Initializer (Web Speech API) ---
  private initRecognition() {
    if (!this.isSpeechRecognitionSupported()) {
      this.webSpeechFailed = true;
      return;
    }

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

        // Discard self-transcription if assistant is currently speaking
        if (this.activeState === "SPEAKING") {
          const lower = rawText.toLowerCase();
          const isInterruptPhrase = /(?:hey\s+amoja|stop|थांबा|रुको|chup|pause|wait)\b/i.test(lower);
          if (isInterruptPhrase) {
            this.interruptPlayback();
            this.onTranscriptChange(rawText, Boolean(finalTranscript));
          }
          return;
        }

        this.lastRecognizedText = rawText;

        // Check for optional "Hey Amoja" wake-word
        if (this.isWakeWordEnabled) {
          const match = rawText.match(JarvisVoiceEngine.WAKE_WORD_PATTERN) || rawText.match(JarvisVoiceEngine.ANY_WAKE_WORD_PATTERN);
          if (match) {
            this.playAcknowledgeChime();
            this.onWakeWordDetected(match[0].trim());
            const cleanedDirective = rawText.replace(JarvisVoiceEngine.WAKE_WORD_PATTERN, "").trim();
            if (cleanedDirective) {
              this.onTranscriptChange(cleanedDirective, Boolean(finalTranscript));
            } else {
              this.onTranscriptChange("AMOJA listening...", false);
            }
            return;
          }
        }

        this.onTranscriptChange(rawText, Boolean(finalTranscript));
      };

      this.recognition.onerror = (event: SpeechRecognitionErrorEvent) => {
        if (event.error === "network") {
          // In Electron, Google Web Speech API throws 'network' error due to missing API keys.
          // Gracefully flag webSpeechFailed so MediaRecorder handles STT transparently.
          this.webSpeechFailed = true;
          return;
        }

        if (event.error === "not-allowed" || event.error === "permission-denied") {
          this.micPermissionStatus = "denied";
          this.onPermissionStatusChange("denied");
          this.lastErrorMessage = "Microphone access denied.";
          this.onError(this.lastErrorMessage);
        } else if (event.error !== "no-speech") {
          this.lastErrorMessage = `Recognition notice: ${event.error}`;
        }
      };

      this.recognition.onend = () => {
        // If not using MediaRecorder, wrap up listening
        if (!this.mediaRecorder || this.mediaRecorder.state === "inactive") {
          this.isListening = false;
          this.recordingStartTime = null;
          this.stopMicrophoneStream();
          if (this.activeState === "LISTENING") {
            this.notifyState("IDLE");
          }
        }
      };
    } catch {
      this.webSpeechFailed = true;
    }
  }

  // --- MediaRecorder Hardware Capture Engine ---
  private async startMediaRecorderCapture(): Promise<boolean> {
    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        return false;
      }

      this.microphoneStream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true
        }
      });

      this.initAudioAnalyser(this.microphoneStream);
      this.audioChunks = [];
      this.vadHasSpeech = false;

      // Choose supported MIME type
      let mimeType = "audio/webm;codecs=opus";
      if (typeof MediaRecorder !== "undefined" && !MediaRecorder.isTypeSupported(mimeType)) {
        mimeType = "audio/webm";
      }

      this.mediaRecorder = new MediaRecorder(this.microphoneStream, { mimeType });
      this.mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) {
          this.audioChunks.push(e.data);
        }
      };

      this.mediaRecorder.onstop = async () => {
        const audioBlob = new Blob(this.audioChunks, { type: mimeType });
        this.audioChunks = [];
        this.stopMicrophoneStream();

        // Process audio if speech was detected or duration > 0.4s
        if (audioBlob.size > 800) {
          await this.processRecordedAudioBlob(audioBlob);
        } else {
          if (this.activeState === "LISTENING") {
            this.notifyState("IDLE");
          }
        }
      };

      this.mediaRecorder.start(200); // 200ms slice
      this.isListening = true;
      this.recordingStartTime = Date.now();
      this.notifyState("LISTENING");
      this.startVoiceActivityDetection();
      return true;
    } catch (err: any) {
      this.micPermissionStatus = "denied";
      this.onPermissionStatusChange("denied");
      this.lastErrorMessage = "Microphone hardware access failed.";
      this.onError(this.lastErrorMessage);
      this.notifyState("ERROR");
      return false;
    }
  }

  private startVoiceActivityDetection() {
    if (this.vadSilenceTimer) clearInterval(this.vadSilenceTimer);
    let consecutiveSilentFrames = 0;

    this.vadSilenceTimer = setInterval(() => {
      if (!this.isListening || this.isPushToTalkActive) return;
      const level = this.getAudioRMSLevel();

      if (level > 12) {
        this.vadHasSpeech = true;
        consecutiveSilentFrames = 0;
      } else if (this.vadHasSpeech) {
        consecutiveSilentFrames++;
        // If silence persists for 1.8 seconds after speech, auto-commit utterance
        if (consecutiveSilentFrames >= 9) {
          clearInterval(this.vadSilenceTimer);
          this.vadSilenceTimer = null;
          this.stopListening();
        }
      }
    }, 200);
  }

  private async processRecordedAudioBlob(blob: Blob) {
    try {
      this.isTranscribingBackend = true;
      this.notifyState("PROCESSING");

      // Convert Blob to Base64
      const reader = new FileReader();
      const base64Promise = new Promise<string>((resolve, reject) => {
        reader.onloadend = () => resolve(reader.result as string);
        reader.onerror = reject;
      });
      reader.readAsDataURL(blob);
      const dataUri = await base64Promise;

      // Call backend local speech recognition endpoint
      const result = await transcribeAudio(dataUri, this.targetLanguage);
      if (result && result.text && result.text.trim()) {
        const text = result.text.trim();
        this.lastRecognizedText = text;
        this.onTranscriptChange(text, true);
      } else {
        this.notifyState("IDLE");
      }
    } catch (e: any) {
      this.lastErrorMessage = "Local STT transcription error: " + (e.message || e);
      this.notifyState("IDLE");
    } finally {
      this.isTranscribingBackend = false;
    }
  }

  // --- Voice Engine Controls ---
  public async startListening(): Promise<boolean> {
    if (this.isMicMuted) {
      this.onError("Microphone is currently muted.");
      return false;
    }

    // Cancel active speech playback to prevent self-hearing
    this.stopSpeaking();

    // In Electron or when Web Speech is unsupported/broken, use MediaRecorder
    if (this.isElectronEnv() || this.webSpeechFailed || !this.isSpeechRecognitionSupported()) {
      return this.startMediaRecorderCapture();
    }

    try {
      // Start both: MediaRecorder for audio visualizer/fallback, WebSpeech for instant text
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        this.microphoneStream = await navigator.mediaDevices.getUserMedia({
          audio: { echoCancellation: true, noiseSuppression: true }
        });
        this.initAudioAnalyser(this.microphoneStream);
      }
      this.recognition.start();
      this.isListening = true;
      return true;
    } catch {
      // Fallback to MediaRecorder
      return this.startMediaRecorderCapture();
    }
  }

  public stopListening() {
    if (this.vadSilenceTimer) {
      clearInterval(this.vadSilenceTimer);
      this.vadSilenceTimer = null;
    }

    if (this.mediaRecorder && this.mediaRecorder.state === "recording") {
      try {
        this.mediaRecorder.stop();
      } catch {}
    }

    if (this.recognition && this.isListening) {
      try {
        this.recognition.stop();
      } catch {}
    }

    this.isListening = false;
    this.recordingStartTime = null;
    this.stopMicrophoneStream();

    if (!this.isTranscribingBackend && this.activeState === "LISTENING") {
      this.notifyState("IDLE");
    }
  }

  private initVoiceList() {
    if (!this.isSpeechSynthesisSupported()) return;
    const loadVoices = () => {
      const voices = window.speechSynthesis.getVoices();
      if (!voices || voices.length === 0) return;

      const preferred = voices.find(v =>
        v.name.includes("Female") ||
        v.name.includes("Google UK English Female") ||
        v.name.includes("Google US English Female") ||
        v.name.includes("Zira") ||
        v.name.includes("Samantha") ||
        v.name.includes("Kavya") ||
        v.name.includes("Ananya")
      ) || voices[0];

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

  public setLanguage(langCode: JarvisLanguage | string) {
    this.targetLanguage = (langCode as JarvisLanguage) || "auto";
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
  }

  // --- Local Audio Playback with Watchdog & Autoplay Safety ---
  private audioElement: HTMLAudioElement | null = null;
  private lastAudioUrl: string | null = null;
  private isAudioPaused: boolean = false;

  public playLocalAudioBase64(base64Wav: string): Promise<void> {
    return new Promise((resolve) => {
      this.stopSpeaking();
      this.stopListening(); // Mute mic while playing

      const cleanB64 = base64Wav.includes(",") ? base64Wav.split(",")[1] : base64Wav;
      const audioUrl = `data:audio/wav;base64,${cleanB64}`;
      this.lastAudioUrl = audioUrl;

      const audio = new Audio(audioUrl);
      this.audioElement = audio;
      audio.playbackRate = this.speechRate;

      // Watchdog timer (max 20 seconds) to prevent permanent stuck SPEAKING state
      const watchdog = setTimeout(() => {
        this.notifyState("IDLE");
        this.audioElement = null;
        resolve();
      }, 20000);

      // Connect to audio analyser for orb waveform
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
      } catch {}

      audio.onplay = () => {
        this.isAudioPaused = false;
        this.notifyState("SPEAKING");
      };

      audio.onended = () => {
        clearTimeout(watchdog);
        this.notifyState("IDLE");
        this.audioElement = null;
        resolve();

        // Continuous mode re-arm
        if (this.isContinuousMode && !this.isMicMuted && !this.isSpeakerMuted) {
          this.scheduleContinuousListen(500);
        }
      };

      audio.onerror = () => {
        clearTimeout(watchdog);
        this.notifyState("IDLE");
        this.audioElement = null;
        resolve();
      };

      audio.play().catch(() => {
        clearTimeout(watchdog);
        this.notifyState("IDLE");
        this.audioElement = null;
        resolve();
      });
    });
  }

  public speak(text: string, langOverride?: string): Promise<void> {
    return new Promise((resolve) => {
      if (!this.isSpeechSynthesisSupported() || this.isSpeakerMuted || !text.trim()) {
        resolve();
        return;
      }

      window.speechSynthesis.cancel();
      this.stopListening(); // Mute mic while speaking

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

      // Resolve BCP-47 tag and compatible voice
      let targetLocale = this.speechLang;
      if (langOverride) {
        if (langOverride === "mr" || langOverride.startsWith("mr")) {
          targetLocale = "mr-IN";
        } else if (langOverride === "hi" || langOverride.startsWith("hi")) {
          targetLocale = "hi-IN";
        } else if (langOverride === "hinglish") {
          targetLocale = "en-IN";
        } else if (langOverride === "en" || langOverride.startsWith("en")) {
          targetLocale = "en-US";
        }
      }

      utterance.lang = targetLocale;

      // Select voice compatible with the target locale
      const voices = this.getAvailableVoices();
      let matchedVoice: SpeechSynthesisVoice | null = null;
      if (voices && voices.length > 0) {
        const langPrefix = targetLocale.split("-")[0].toLowerCase();
        matchedVoice = voices.find(v => v.lang.toLowerCase() === targetLocale.toLowerCase()) ||
          voices.find(v => v.lang.toLowerCase().startsWith(langPrefix)) ||
          voices.find(v => {
            const name = v.name.toLowerCase();
            if (langPrefix === "mr") return name.includes("marathi");
            if (langPrefix === "hi") return name.includes("hindi") || name.includes("kavya") || name.includes("kalpana");
            return false;
          }) || null;

        if (!matchedVoice && (langOverride === "mr" || langOverride === "hi")) {
          // If browser speech synthesis has no Hindi/Marathi voices installed, notify user
          console.warn(`Browser SpeechSynthesis has no voice installed for locale ${targetLocale}.`);
        }
      }

      if (matchedVoice) {
        utterance.voice = matchedVoice;
      } else if (this.selectedVoice && (!langOverride || langOverride === "en" || langOverride === "hinglish")) {
        utterance.voice = this.selectedVoice;
      }

      utterance.rate = this.speechRate;
      utterance.pitch = this.speechPitch;

      // Watchdog timer: forces resolve if Chromium drops the onend event
      const maxMs = Math.max(4000, cleanSpeech.length * 90);
      const watchdog = setTimeout(() => {
        this.notifyState("IDLE");
        resolve();
      }, maxMs);

      utterance.onstart = () => {
        this.notifyState("SPEAKING");
      };

      utterance.onend = () => {
        clearTimeout(watchdog);
        this.notifyState("IDLE");
        resolve();
        if (this.isContinuousMode && !this.isMicMuted && !this.isSpeakerMuted) {
          this.scheduleContinuousListen(500);
        }
      };

      utterance.onerror = () => {
        clearTimeout(watchdog);
        this.notifyState("IDLE");
        resolve();
      };

      window.speechSynthesis.speak(utterance);
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
    this.isSpeakerMuted = isMuted;
    this.soundEffectsEnabled = soundEffects;
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

  // --- Diagnostics Status Snapshot ---
  public getDiagnostics(): VoiceDiagnostics {
    let micStatus: "READY" | "DENIED" | "ERROR" | "MUTED" = "READY";
    if (this.isMicMuted) {
      micStatus = "MUTED";
    } else if (this.micPermissionStatus === "denied") {
      micStatus = "DENIED";
    } else if (this.micPermissionStatus === "unsupported") {
      micStatus = "ERROR";
    }

    let recStatus: "IDLE" | "LISTENING" | "TRANSCRIBING" | "ERROR" = "IDLE";
    if (this.isTranscribingBackend) {
      recStatus = "TRANSCRIBING";
    } else if (this.isListening) {
      recStatus = "LISTENING";
    } else if (this.activeState === "ERROR") {
      recStatus = "ERROR";
    }

    let recEngine: "MediaRecorder + Local STT" | "Web Speech API" | "Dual Engine" = "Dual Engine";
    if (this.isElectronEnv() || this.webSpeechFailed) {
      recEngine = "MediaRecorder + Local STT";
    } else if (this.isSpeechRecognitionSupported()) {
      recEngine = "Dual Engine";
    }

    return {
      microphoneStatus: micStatus,
      recognitionEngine: recEngine,
      recognitionStatus: recStatus,
      activeState: this.activeState,
      transcript: this.lastRecognizedText,
      audioLevelRms: this.getAudioRMSLevel(),
      isElectron: this.isElectronEnv(),
      isMicMuted: this.isMicMuted,
      isSpeakerMuted: this.isSpeakerMuted,
      lastError: this.lastErrorMessage
    };
  }

  // --- Audio Cues ---
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
