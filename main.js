const { app, BrowserWindow, dialog, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs/promises');
const { scanWorkspace, inspectFile, buildMarkdownReport } = require('./src/core/finals_analyzer_batch5');
const { runTool } = require('./src/core/tool_router');
const { bufferFromArtifact } = require('./src/core/artifacts');

let win = null;
const approvedRoots = new Set();

function createWindow() {
  win = new BrowserWindow({
    width: 1480,
    height: 900,
    minWidth: 1080,
    minHeight: 700,
    backgroundColor: '#0d1015',
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
  win.loadFile(path.join(__dirname, 'renderer', 'toolbox.html'));
}

function registerIpc() {
  ipcMain.handle('workspace:choose', async () => {
    const result = await dialog.showOpenDialog(win, { title: '选择赛题目录', properties: ['openDirectory'] });
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

  ipcMain.handle('artifact:save', async (_event, artifact) => {
    const decoded = bufferFromArtifact(artifact, { requireComplete: true });
    const result = await dialog.showSaveDialog(win, {
      title: '导出二进制产物',
      defaultPath: decoded.name,
      filters: [{ name: 'Binary artifact', extensions: [path.extname(decoded.name).replace(/^\./, '') || 'bin'] }]
    });
    if (result.canceled || !result.filePath) return null;
    await fs.writeFile(result.filePath, decoded.buffer);
    return { filePath: result.filePath, size: decoded.buffer.length, sha256: decoded.sha256 };
  });

  ipcMain.handle('toolbox:run', async (_event, tool, payload) => runTool(tool, payload || {}));
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
