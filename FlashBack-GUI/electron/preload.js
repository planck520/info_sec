/* ============================================================
   FlashBack GUI — Electron Preload
   安全暴露窗口控制 API 给渲染进程
   ============================================================ */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  minimize: () => ipcRenderer.send('window:minimize'),
  maximize: () => ipcRenderer.send('window:maximize'),
  close: () => ipcRenderer.send('window:close'),
  selectDirectory: (title) => ipcRenderer.invoke('dialog:select-directory', title),
  selectFile: (title) => ipcRenderer.invoke('dialog:select-file', title),
});
