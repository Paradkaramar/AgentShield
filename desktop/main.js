// desktop/main.js
// AgentShield Installable Desktop Application Main Process
// Electron-based application shell with zero-trust local agent integration.

const { app, BrowserWindow, ipcMain, Tray, Menu, shell, dialog, session } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
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
    title: 'AgentShield — Personal Device Security Platform (v1.2.0)',
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
    { label: 'AgentShield: Active Protection', enabled: false },
    { type: 'separator' },
    {
      label: 'Open Dashboard',
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
      label: 'Pause Monitoring',
      click: () => {
        // Toggle pause via local agent
      }
    },
    {
      label: 'Device Permissions...',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Quit AgentShield',
      click: () => {
        app.isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setToolTip('AgentShield Personal Device Security');
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

app.whenReady().then(() => {
  // Explicitly permit microphone/media device access for AMOJA Voice Engine
  if (session && session.defaultSession) {
    session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
      if (permission === 'media') {
        callback(true);
      } else {
        callback(false);
      }
    });

    session.defaultSession.setPermissionCheckHandler((webContents, permission) => {
      return permission === 'media';
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
