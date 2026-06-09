/* ============================================================
   FlashBack GUI — Electron 主进程
   - 启动 Python FastAPI 后端子进程
   - 创建 frameless 窗口（自定义标题栏可拖动）
   - 窗口控制（最小化 / 最大化 / 关闭）
   ============================================================ */

const { app, BrowserWindow, ipcMain } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');

// ── 配置 ──────────────────────────────────────────────────
const BACKEND_PORT = 18920;
const BACKEND_HOST = '127.0.0.1';
const BACKEND_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}`;

let mainWindow = null;
let pythonProcess = null;

// ── 启动 Python 后端 ─────────────────────────────────────
function startBackend() {
  const pythonExe = 'python';
  const scriptPath = path.join(__dirname, '..', 'main.py');

  console.log(`[Electron] Starting backend: ${pythonExe} ${scriptPath} --server-only --port ${BACKEND_PORT}`);

  pythonProcess = spawn(pythonExe, [scriptPath, '--server-only', '--port', String(BACKEND_PORT)], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONUNBUFFERED: '1' },
  });

  pythonProcess.stdout.on('data', (data) => {
    console.log(`[Python] ${data.toString().trim()}`);
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`[Python:err] ${data.toString().trim()}`);
  });

  pythonProcess.on('close', (code) => {
    console.log(`[Electron] Python process exited (code=${code})`);
    pythonProcess = null;
  });

  pythonProcess.on('error', (err) => {
    console.error(`[Electron] Failed to start Python: ${err.message}`);
  });
}

// ── 等待后端就绪 ─────────────────────────────────────────
function waitForBackend(retries = 30, interval = 500) {
  return new Promise((resolve, reject) => {
    let attempts = 0;
    const check = () => {
      attempts++;
      http.get(`${BACKEND_URL}/api/settings`, (res) => {
        resolve(true);
      }).on('error', () => {
        if (attempts >= retries) {
          reject(new Error(`Backend not ready after ${retries} attempts`));
        } else {
          setTimeout(check, interval);
        }
      });
    };
    check();
  });
}

// ── 创建窗口 ─────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 768,
    frame: false,                    // frameless — 自定义标题栏
    titleBarStyle: 'hidden',         // 隐藏原生标题栏
    backgroundColor: '#08080f',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  mainWindow.loadURL(BACKEND_URL);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ── IPC：窗口控制 ────────────────────────────────────────
function setupIPC() {
  ipcMain.on('window:minimize', () => {
    if (mainWindow) mainWindow.minimize();
  });
  ipcMain.on('window:maximize', () => {
    if (mainWindow) {
      mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
    }
  });
  ipcMain.on('window:close', () => {
    if (mainWindow) mainWindow.close();
  });
}

// ── 清理 ─────────────────────────────────────────────────
function cleanup() {
  if (pythonProcess) {
    console.log('[Electron] Killing Python backend...');
    pythonProcess.kill();
    pythonProcess = null;
  }
}

// ── App 生命周期 ─────────────────────────────────────────
app.whenReady().then(async () => {
  setupIPC();
  startBackend();

  try {
    await waitForBackend();
    console.log('[Electron] Backend is ready');
  } catch (err) {
    console.error('[Electron]', err.message);
    // 即使后端检查失败也继续，让用户看到错误页面
  }

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  cleanup();
  app.quit();
});

app.on('before-quit', cleanup);
