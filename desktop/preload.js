// desktop/preload.js
// Secure context bridge for AgentShield Desktop Application
// Strict isolation: nodeIntegration = false, contextIsolation = true

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('agentShieldDesktop', {
  appVersion: '1.2.0',
  platform: process.platform,
  isDesktop: true,
  
  // Query status from background agent
  getAgentStatus: () => ipcRenderer.invoke('get-agent-status'),
  
  // Submit enrollment with token
  enrollDevice: (token, deviceName, consent) => ipcRenderer.invoke('enroll-device', { token, deviceName, consent }),
  
  // Request pause or resume of local monitoring
  setMonitoringState: (active) => ipcRenderer.invoke('set-monitoring-state', { active }),
  
  // Inspect local device cache
  getDeviceIdentity: () => ipcRenderer.invoke('get-device-identity'),
  
  // Open diagnostic log folder
  openLogFolder: () => ipcRenderer.invoke('open-log-folder'),

  // Native microphone access check and request
  checkMicrophonePermission: () => ipcRenderer.invoke('check-microphone-permission'),
  requestMicrophonePermission: () => ipcRenderer.invoke('request-microphone-permission')
});
