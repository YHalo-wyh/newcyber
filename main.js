const { app, BrowserWindow, dialog, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs/promises');
const { scanWorkspace, inspectFile, buildMarkdownReport } = require('./src/core/analyzer');

let win = null;
const approvedRoots = new Set();

function createWindow() {
  win = new BrowserWindow({
    width: 1400,
    height: 860,
    minWidth: 1000,
    minHeight: 640,
    backgroundColor: '#17181C',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event) => event.preventDefault());
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

function registerIpc() {
  ipcMain.handle('workspace:choose', async () => {
    const result = await dialog.showOpenDialog(win, {
      title: '选择赛题目录',
      properties: ['openDirectory']
    });
    if (result.canceled) return null;
    const selectedPath = path.resolve(result.filePaths[0]);
    approvedRoots.add(selectedPath);
    return selectedPath;
  });

  ipcMain.handle('workspace:scan', async (_event, rootPath) => {
    const resolved = path.resolve(rootPath);
    if (!approvedRoots.has(resolved)) throw new Error('请通过目录选择器打开赛题');
    return scanWorkspace(resolved);
  });
  ipcMain.handle('workspace:inspect', async (_event, rootPath, relativePath) => {
    const resolved = path.resolve(rootPath);
    if (!approvedRoots.has(resolved)) throw new Error('赛题目录未授权');
    return inspectFile(resolved, relativePath);
  });
  ipcMain.handle('report:save', async (_event, payload) => {
    const result = await dialog.showSaveDialog(win, {
      title: '导出分析报告',
      defaultPath: `newcyber-${payload.analysis.workspaceName || 'report'}.md`,
      filters: [{ name: 'Markdown', extensions: ['md'] }]
    });
    if (result.canceled || !result.filePath) return null;
    await fs.writeFile(result.filePath, buildMarkdownReport(payload.analysis, payload.notes || ''), 'utf8');
    return result.filePath;
  });
}

app.whenReady().then(() => {
  registerIpc();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
