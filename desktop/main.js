// desktop/main.js
// AgentShield Installable Desktop Application Main Process
// Electron-based application shell with zero-trust local agent integration.

const { app, BrowserWindow, ipcMain, Tray, Menu, shell, dialog, session, systemPreferences } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const { spawn, exec } = require('child_process');

let mainWindow = null;
let tray = null;
let agentProcess = null;

const CACHE_DIR = path.join(os.homedir(), '.agentshield');
const IDENTITY_FILE = path.join(CACHE_DIR, 'device_identity.json');

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 880,
    minWidth: 1024,
    minHeight: 700,
    title: 'AMOJA AI — Windows Personal Assistant & AgentShield Cybersecurity Platform',
    backgroundColor: '#0a0f1d',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true
    }
  });

  // Load local frontend (Vite dev server or built bundle)
  const devUrl = 'http://localhost:5173';
  mainWindow.loadURL(devUrl).catch(() => {
    // Fallback to static distribution if built
    const distPath = path.join(__dirname, '..', 'frontend', 'dist', 'index.html');
    if (fs.existsSync(distPath)) {
      mainWindow.loadFile(distPath);
    } else {
      mainWindow.loadURL('http://127.0.0.1:8000/docs');
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createTray() {
  // Setup system tray for continuous status indicator
  try {
    tray = new Tray(path.join(__dirname, 'tray_icon.png'));
  } catch (e) {
    // If icon file doesn't exist, skip tray initialization gracefully
    return;
  }

  const contextMenu = Menu.buildFromTemplate([
    { label: 'AMOJA AI: Assistant & Defense Active', enabled: false },
    { type: 'separator' },
    {
      label: 'Open AMOJA AI',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        } else {
          createWindow();
        }
      }
    },
    {
      label: 'Personal Assistant & Notes',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      }
    },
    {
      label: 'AgentShield Security HUD',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Quit AMOJA AI',
      click: () => {
        app.isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setToolTip('AMOJA AI — Windows Personal Assistant & AgentShield Platform');
  tray.setContextMenu(contextMenu);
}

// ============================================================================
// IPC HANDLERS
// ============================================================================

ipcMain.handle('get-agent-status', async () => {
  let identity = null;
  if (fs.existsSync(IDENTITY_FILE)) {
    try {
      identity = JSON.parse(fs.readFileSync(IDENTITY_FILE, 'utf8'));
    } catch (e) {
      identity = null;
    }
  }

  return {
    appVersion: '1.2.0',
    platform: process.platform,
    hostname: os.hostname(),
    arch: os.arch(),
    totalMemoryMb: Math.round(os.totalmem() / (1024 * 1024)),
    cacheDir: CACHE_DIR,
    identity: identity,
    isEnrolled: !!(identity && identity.device_id)
  };
});

ipcMain.handle('get-device-identity', async () => {
  if (fs.existsSync(IDENTITY_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(IDENTITY_FILE, 'utf8'));
    } catch (e) {
      return null;
    }
  }
  return null;
});

ipcMain.handle('open-log-folder', async () => {
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  }
  shell.openPath(CACHE_DIR);
  return { opened: true, path: CACHE_DIR };
});

// Explicit IPC Handler to query/request native microphone permissions in Electron
ipcMain.handle('check-microphone-permission', async () => {
  if (process.platform === 'darwin') {
    try {
      const status = systemPreferences.getMediaAccessStatus('microphone');
      return { status, platform: process.platform };
    } catch {
      return { status: 'granted', platform: process.platform };
    }
  }
  return { status: 'granted', platform: process.platform };
});

ipcMain.handle('request-microphone-permission', async () => {
  if (process.platform === 'darwin') {
    try {
      const granted = await systemPreferences.askForMediaAccess('microphone');
      return { granted, status: granted ? 'granted' : 'denied' };
    } catch {
      return { granted: true, status: 'granted' };
    }
  }
  return { granted: true, status: 'granted' };
});

// IPC Handler: Check FastAPI Backend Status
ipcMain.handle('get-backend-status', async () => {
  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:8000/health', (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ online: res.statusCode === 200, status: JSON.parse(data), statusCode: res.statusCode });
        } catch {
          resolve({ online: res.statusCode === 200, status: data, statusCode: res.statusCode });
        }
      });
    });
    req.on('error', (err) => {
      resolve({ online: false, error: err.message });
    });
    req.setTimeout(2500, () => {
      req.destroy();
      resolve({ online: false, error: 'Request timed out' });
    });
  });
});

// IPC Handler: Check Ollama Local AI Status
ipcMain.handle('get-ollama-status', async () => {
  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:11434/api/tags', (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const models = (parsed.models || []).map(m => m.name || m.model);
          const hasTargetModel = models.some(m => 
            m.includes('dolphinlabs/qwen3.5-uncensored') || 
            m.includes('qwen') || 
            models.length > 0
          );
          resolve({
            online: res.statusCode === 200,
            models: models,
            hasDefaultModel: hasTargetModel,
            activeModel: models.find(m => m.includes('dolphinlabs/qwen3.5-uncensored')) || models[0] || null,
            statusCode: res.statusCode
          });
        } catch (err) {
          resolve({ online: false, error: err.message });
        }
      });
    });
    req.on('error', (err) => {
      resolve({ online: false, error: err.message });
    });
    req.setTimeout(2500, () => {
      req.destroy();
      resolve({ online: false, error: 'Request timed out' });
    });
  });
});

// IPC Handler: Device Enrollment via Desktop UI
ipcMain.handle('enroll-device', async (event, { token, deviceName, consent }) => {
  return new Promise((resolve) => {
    const postData = JSON.stringify({
      token: token,
      device_name: deviceName || os.hostname(),
      consent_map: consent || {}
    });

    const req = http.request({
      hostname: '127.0.0.1',
      port: 8000,
      path: '/api/endpoint/enroll',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve({ status: 'OK', raw: data });
        }
      });
    });

    req.on('error', (err) => {
      resolve({ status: 'ERROR', message: `Backend connection failed: ${err.message}` });
    });
    req.write(postData);
    req.end();
  });
});

// IPC Handler: Toggle Monitoring State (Pause/Resume)
ipcMain.handle('set-monitoring-state', async (event, { active }) => {
  return new Promise((resolve) => {
    let identity = null;
    if (fs.existsSync(IDENTITY_FILE)) {
      try {
        identity = JSON.parse(fs.readFileSync(IDENTITY_FILE, 'utf8'));
      } catch (e) {
        identity = null;
      }
    }
    const devId = identity ? identity.device_id : 'dev-primary-desktop';
    const action = active ? 'RESUME' : 'PAUSE';

    const postData = JSON.stringify({ action: action });
    const req = http.request({
      hostname: '127.0.0.1',
      port: 8000,
      path: `/api/endpoint/devices/${devId}/control`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve({ status: 'OK', active: active });
        }
      });
    });

    req.on('error', (err) => {
      resolve({ status: 'ERROR', message: `Backend connection failed: ${err.message}` });
    });
    req.write(postData);
    req.end();
  });
});

app.whenReady().then(() => {
  // Explicitly permit microphone/media device access for AMOJA Voice Engine
  if (session && session.defaultSession) {
    const ALLOWED_PERMISSIONS = new Set(['media', 'microphone', 'audio-capture', 'mediaKeySystem', 'notifications']);

    session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
      if (ALLOWED_PERMISSIONS.has(permission)) {
        callback(true);
      } else {
        callback(false);
      }
    });

    session.defaultSession.setPermissionCheckHandler((webContents, permission) => {
      return ALLOWED_PERMISSIONS.has(permission);
    });
  }

  createWindow();
  createTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  // On Windows/Linux, keep running in background tray unless explicitly quit
  if (process.platform !== 'darwin' && !tray) {
    app.quit();
  }
});
