// desktop/run_desktop.js
// AgentShield Desktop Application Launcher
// Launches desktop interface with zero-trust local agent checks.

const { spawn, exec } = require('child_process');
const path = require('path');
const os = require('os');
const http = require('http');

console.log('=======================================================');
console.log('  AMOJA AI Windows Personal Assistant & AgentShield SOC');
console.log('  Version: 1.2.0 | Architecture: ' + os.arch() + ' | Platform: ' + process.platform);
console.log('=======================================================');

// Check if Electron is installed locally or globally
function tryLaunchElectron() {
  try {
    const electron = require('electron');
    const child = spawn(electron, [path.join(__dirname, 'main.js')], {
      stdio: 'inherit',
      windowsHide: false
    });
    child.on('close', (code) => {
      console.log(`AMOJA AI desktop exited with code ${code}`);
      process.exit(code);
    });
    return true;
  } catch (err) {
    return false;
  }
}

// Fallback: Launch default browser to AMOJA AI control plane
function launchBrowserApp() {
  const targetUrl = 'http://localhost:5173/jarvis';
  console.log(`Launching AMOJA AI Unified Assistant Portal at: ${targetUrl}`);
  
  const startCmd = process.platform === 'win32' ? 'start' : (process.platform === 'darwin' ? 'open' : 'xdg-open');
  exec(`${startCmd} ${targetUrl}`, (err) => {
    if (err) {
      console.error('Failed to launch browser:', err);
    } else {
      console.log('AMOJA AI Windows Personal Assistant & AgentShield Platform launched successfully.');
    }
  });
}

if (!tryLaunchElectron()) {
  console.log('Notice: Running in native desktop browser shell mode.');
  launchBrowserApp();
}
