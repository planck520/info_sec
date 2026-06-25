/* ============================================================
   FlashBack GUI — Electron 主进程
   - 启动 Python FastAPI 后端子进程（端口递增恢复）
   - 后端崩溃自动重试（最多 3 次）
   - 无边框窗口 + 自定义标题栏
   - loadURL 失败时显示错误页（不再黑屏）
   - 快捷键：Ctrl+W 关窗 / Ctrl+Shift+Q 强制退出
   ============================================================ */

const { app, BrowserWindow, ipcMain, dialog, globalShortcut } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');
const fs = require('fs');

// ── GPU 渲染（仅保留安全标志，不禁用软件回退）──────────────
app.commandLine.appendSwitch('enable-gpu-rasterization');
app.commandLine.appendSwitch('enable-zero-copy');

// ── 配置 ──────────────────────────────────────────────────
const BACKEND_HOST = '127.0.0.1';
const BASE_PORT = 18920;
const MAX_PORT_TRY = 10;
const MAX_RESTARTS = 3;

let backendPort = BASE_PORT;
let backendUrl = `http://${BACKEND_HOST}:${backendPort}`;
let mainWindow = null;
let pythonProcess = null;
let backendRestarts = 0;
let isShuttingDown = false;

// ── 错误页（内联 HTML，不依赖任何外部资源）─────────────────
function _buildErrorHtml(message) {
  const safeMsg = (message || 'Unable to start FlashBack analysis engine.')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>FlashBack — Error</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
       background:#08080f;color:#e0e0e0;display:flex;align-items:center;
       justify-content:center;height:100vh;user-select:none}
  .box{text-align:center;max-width:500px;padding:2rem}
  h1{color:#ff6b6b;font-size:1.4rem;margin:1rem 0 .75rem}
  p{color:#888;font-size:.88rem;line-height:1.6;margin-bottom:.4rem}
  button{margin-top:1.5rem;padding:.6rem 1.6rem;background:#2d6ff7;color:#fff;
         border:none;border-radius:6px;cursor:pointer;font-size:.95rem}
  button:hover{background:#1a5ad9}
  .hint{margin-top:2rem;font-size:.72rem;color:#444}
  .icon{font-size:2.5rem}
</style></head><body>
<div class="box">
  <div class="icon">&#x26A1;</div>
  <h1>Backend Connection Failed</h1>
  <p>${safeMsg}</p>
  <p>Please ensure no other program is using port ${backendPort},<br>
     and that the FlashBack installation is not corrupted.</p>
  <button onclick="location.reload()">&#x1F504; Retry</button>
  <button onclick="window.close()" style="margin-left:.5rem;background:#555">&#x2715; Close</button>
  <div class="hint">Keyboard: Ctrl+Shift+Q to force quit &middot; Ctrl+W to close window</div>
</div>
</body></html>`;
}

function showErrorPage(message) {
  if (!mainWindow) {
    mainWindow = _createBrowserWindow();
  }
  const html = _buildErrorHtml(message);
  mainWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
}

// ── 启动 Python 后端 ─────────────────────────────────────
function startBackend(port) {
  backendPort = port;
  backendUrl = `http://${BACKEND_HOST}:${port}`;

  const bundledExe = path.join(process.resourcesPath, 'flashback-server', 'flashback-server.exe');

  let cmd, args;
  if (fs.existsSync(bundledExe)) {
    cmd = bundledExe;
    args = ['--server-only', '--port', String(port)];
    console.log(`[Electron] Starting bundled backend: ${cmd} (port ${port})`);
  } else {
    cmd = 'python';
    args = [path.join(__dirname, '..', 'main.py'), '--server-only', '--port', String(port)];
    console.log(`[Electron] Starting dev backend: ${cmd} ${args.join(' ')}`);
  }

  pythonProcess = spawn(cmd, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONUNBUFFERED: '1' },
  });

  pythonProcess.stdout.on('data', (data) => {
    console.log(`[Python] ${data.toString().trim()}`);
  });

  pythonProcess.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    console.error(`[Python:err] ${msg}`);
  });

  pythonProcess.on('close', (code) => {
    console.log(`[Electron] Python process exited (code=${code}, port=${port})`);
    pythonProcess = null;
    if (!isShuttingDown) {
      _handleBackendCrash(code, port);
    }
  });

  pythonProcess.on('error', (err) => {
    console.error(`[Electron] Failed to start Python: ${err.message}`);
    pythonProcess = null;
  });
}

// ── 后端崩溃 / 端口恢复 ──────────────────────────────────
async function _handleBackendCrash(code, port) {
  if (isShuttingDown) return;

  // During initial startup (no window yet), let the port-scan loop handle recovery
  if (!mainWindow || mainWindow.isDestroyed()) {
    console.log(`[Electron] Backend crashed during startup (code=${code}), deferring to port scan`);
    return;
  }

  // Try next port
  const nextPort = port + 1;
  if (nextPort < BASE_PORT + MAX_PORT_TRY) {
    console.log(`[Electron] Backend exited code=${code}. Trying port ${nextPort}...`);
    startBackend(nextPort);
    try {
      await waitForBackend(15, 500);
      console.log(`[Electron] Backend recovered on port ${nextPort}`);
      backendRestarts = 0;
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.loadURL(backendUrl);
      } else {
        mainWindow = _createBrowserWindow();
        mainWindow.loadURL(backendUrl);
      }
      return;
    } catch (e) {
      console.error(`[Electron] Port ${nextPort} also failed:`, e.message);
    }
  }

  // All ports exhausted — try restart with same port (up to MAX_RESTARTS)
  backendRestarts++;
  if (backendRestarts < MAX_RESTARTS) {
    console.log(`[Electron] Restarting backend (attempt ${backendRestarts + 1}/${MAX_RESTARTS})...`);
    startBackend(port);
    try {
      await waitForBackend(30, 500);
      console.log('[Electron] Backend restarted successfully');
      backendRestarts = 0;
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.loadURL(backendUrl);
      } else {
        mainWindow = _createBrowserWindow();
        mainWindow.loadURL(backendUrl);
      }
      return;
    } catch (e) {
      console.error('[Electron] Restart failed:', e.message);
    }
  }

  // Give up
  showErrorPage(
    `FlashBack backend exited unexpectedly (code ${code}). ` +
    `Restarted ${backendRestarts} time(s) without success. ` +
    `Please check your antivirus, firewall, or reinstall FlashBack.`
  );
}

// ── 等待后端就绪 ─────────────────────────────────────────
function waitForBackend(retries, interval) {
  retries = retries || 30;
  interval = interval || 500;
  const url = `${backendUrl}/api/settings`;
  return new Promise((resolve, reject) => {
    let attempts = 0;
    const check = () => {
      attempts++;
      const req = http.get(url, (res) => {
        res.resume(); // consume data
        if (res.statusCode < 500) {
          resolve(true);
        } else {
          _retryOrReject();
        }
      });
      req.on('error', () => _retryOrReject());
      req.setTimeout(2000, () => { req.destroy(); _retryOrReject(); });

      function _retryOrReject() {
        if (attempts >= retries) {
          reject(new Error(`Backend not ready after ${retries} attempts on port ${backendPort}`));
        } else {
          setTimeout(check, interval);
        }
      }
    };
    check();
  });
}

// ── 创建 BrowserWindow ───────────────────────────────────
function _createBrowserWindow() {
  const iconPath = path.join(process.resourcesPath, 'frontend', 'logo.png');
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 768,
    frame: false,
    backgroundColor: '#08080f',
    icon: iconPath,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // ── loadURL 失败时显示错误页 ──────────────────────────
  win.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL) => {
    console.error(`[Electron] Page load failed: ${errorDescription} (code=${errorCode})`);
    if (validatedURL === backendUrl || validatedURL.startsWith(backendUrl)) {
      showErrorPage(`Failed to load application page: ${errorDescription} (code ${errorCode}).`);
    }
  });

  win.webContents.on('crashed', () => {
    console.error('[Electron] Renderer process crashed');
    showErrorPage('Application renderer crashed. Please restart FlashBack.');
  });

  win.webContents.on('unresponsive', () => {
    console.error('[Electron] Renderer process unresponsive');
  });

  win.on('closed', () => {
    mainWindow = null;
  });

  return win;
}

function createWindow(isError) {
  mainWindow = _createBrowserWindow();
  if (!isError) {
    mainWindow.loadURL(backendUrl);
  }
}

// ── 全局快捷键 ───────────────────────────────────────────
function registerShortcuts() {
  try {
    globalShortcut.register('CommandOrControl+Shift+Q', () => {
      console.log('[Electron] Force quit via shortcut');
      isShuttingDown = true;
      cleanup();
      app.quit();
    });
  } catch (e) {
    console.error('[Electron] Failed to register Ctrl+Shift+Q:', e.message);
  }

  try {
    globalShortcut.register('CommandOrControl+W', () => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.close();
      }
    });
  } catch (e) {
    console.error('[Electron] Failed to register Ctrl+W:', e.message);
  }
}

// ── IPC：窗口控制 + 文件对话框 ───────────────────────────
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
  globalShortcut.unregisterAll();
  if (pythonProcess) {
    console.log('[Electron] Killing Python backend...');
    pythonProcess.kill();
    pythonProcess = null;
  }
}

// ── App 生命周期 ─────────────────────────────────────────
app.whenReady().then(async () => {
  setupIPC();
  registerShortcuts();
  startBackend(BASE_PORT);

  let started = false;

  // 尝试 BASE_PORT 到 BASE_PORT+MAX_PORT_TRY
  for (let portTry = BASE_PORT; portTry < BASE_PORT + MAX_PORT_TRY; portTry++) {
    if (portTry !== BASE_PORT) {
      console.log(`[Electron] Port ${portTry - 1} failed, trying ${portTry}...`);
      if (pythonProcess) { pythonProcess.kill(); pythonProcess = null; }
      startBackend(portTry);
    }
    try {
      await waitForBackend(portTry === BASE_PORT ? 30 : 15, 500);
      console.log(`[Electron] Backend is ready on port ${backendPort}`);
      createWindow(false);
      backendRestarts = 0;
      started = true;
      break;
    } catch (err) {
      console.error(`[Electron] Port ${portTry}: ${err.message}`);
    }
  }

  if (!started) {
    const portRange = `${BASE_PORT}-${BASE_PORT + MAX_PORT_TRY - 1}`;
    console.error(`[Electron] All ports ${portRange} exhausted. Backend could not start.`);
    createWindow(true);
    showErrorPage(
      `FlashBack backend could not start on any port (${portRange}). ` +
      `Please check your firewall settings, antivirus, or reinstall FlashBack.`
    );
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      startBackend(BASE_PORT);
      waitForBackend(30, 500).then(() => {
        createWindow(false);
        backendRestarts = 0;
      }).catch(() => {
        createWindow(true);
        showErrorPage('Backend failed to start.');
      });
    }
  });
});

app.on('window-all-closed', () => {
  isShuttingDown = true;
  cleanup();
  app.quit();
});

app.on('before-quit', () => {
  isShuttingDown = true;
  cleanup();
});
