/* ============================================================
   FlashBack GUI — Electron 主进程
   - 启动 Python FastAPI 后端子进程
   - 创建 frameless 窗口（自定义标题栏可拖动）
   - 窗口控制（最小化 / 最大化 / 关闭）
   ============================================================ */

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

// ── GPU 渲染优化（修复 Electron Chromium 文字合成）──────
app.commandLine.appendSwitch('enable-gpu-rasterization');
app.commandLine.appendSwitch('disable-software-rasterizer');
app.commandLine.appendSwitch('enable-zero-copy');
app.commandLine.appendSwitch('disable-http-cache');

// ── 配置 ──────────────────────────────────────────────────
const BACKEND_PORT = 18920;
const BACKEND_HOST = '127.0.0.1';
const BACKEND_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}`;
const AUTH_TOKEN = crypto.randomBytes(32).toString('hex');

let mainWindow = null;
let pythonProcess = null;

// ── 启动 Python 后端 ─────────────────────────────────────
function startBackend() {
  let exe, args;

  if (app.isPackaged) {
    // 生产环境：使用 PyInstaller 编译的 flashback-server.exe
    exe = path.join(process.resourcesPath, 'flashback-server', 'flashback-server.exe');
    args = ['--server-only', '--port', String(BACKEND_PORT)];
  } else {
    // 开发环境：直接用 python 运行 main.py
    exe = 'python';
    args = [path.join(__dirname, '..', 'main.py'), '--server-only', '--port', String(BACKEND_PORT)];
  }

  console.log(`[Electron] Starting backend: ${exe} ${args.join(' ')}`);

  pythonProcess = spawn(exe, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      PYTHONUNBUFFERED: '1',
      FLASHBACK_TOKEN: AUTH_TOKEN,
      FLASHBACK_ALLOWED_ORIGIN: BACKEND_URL,
    },
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
      const req = http.get(`${BACKEND_URL}/api/settings`, {
        headers: { 'X-FlashBack-Token': AUTH_TOKEN },
      }, (res) => {
        res.resume();
        resolve(true);
      });
      req.on('error', () => {
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
async function createWindow() {
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

  // 页面加载失败时显示错误信息（避免黑屏无提示）
  mainWindow.webContents.on('did-fail-load', (_event, errorCode, errorDesc, validatedURL) => {
    console.error(`[Electron] Page load failed: ${errorDesc} (code=${errorCode}) url=${validatedURL}`);
    mainWindow.webContents.loadURL(`data:text/html;charset=utf-8,
      <html><body style="background:#1a1a2e;color:#e0e0e0;font-family:monospace;padding:40px;">
      <h2>FlashBack 启动失败</h2>
      <p>无法连接到后端服务：${errorDesc}</p>
      <p>请确认端口 18920 未被占用，然后重启应用。</p>
      </body></html>`);
  });

  // 打开 DevTools 方便调试（Ctrl+Shift+I 也可手动打开）
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }

  // 禁用磁盘缓存 — 确保每次加载最新的 CSS/JS
  await mainWindow.webContents.session.clearCache();
  mainWindow.loadURL(`${BACKEND_URL}/#token=${AUTH_TOKEN}`);

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

  ipcMain.handle('dialog:select-directory', async (_event, title) => {
    if (!mainWindow) return null;
    const result = await dialog.showOpenDialog(mainWindow, {
      title: title || '选择目录',
      properties: ['openDirectory', 'createDirectory'],
    });
    if (result.canceled || !result.filePaths.length) return null;
    return result.filePaths[0];
  });

  ipcMain.handle('dialog:select-file', async (_event, title) => {
    if (!mainWindow) return null;
    const result = await dialog.showOpenDialog(mainWindow, {
      title: title || '选择固件二进制文件',
      properties: ['openFile'],
    });
    if (result.canceled || !result.filePaths.length) return null;
    return result.filePaths[0];
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
