'use strict';

const { BrowserWindow, dialog, ipcMain } = require('electron');
const fs = require('fs/promises');
const path = require('path');
const { analyzeIdaSnapshot } = require('../core/ida_snapshot_graph');

const MAX_SNAPSHOT_BYTES = 48 * 1024 * 1024;

function activeWindow() {
  return BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0] || null;
}

async function analyzeIdaSnapshotPath(filePath) {
  const resolved = path.resolve(String(filePath || ''));
  const stat = await fs.stat(resolved);
  if (!stat.isFile()) throw new Error('IDA Snapshot 输入不是文件');
  if (stat.size <= 0) throw new Error('IDA Snapshot 文件为空');
  if (stat.size > MAX_SNAPSHOT_BYTES) throw new Error(`IDA Snapshot 超过 ${MAX_SNAPSHOT_BYTES} bytes 上限`);
  const raw = await fs.readFile(resolved, 'utf8');
  let snapshot;
  try { snapshot = JSON.parse(raw); } catch { throw new Error('IDA Snapshot JSON 解析失败'); }
  const analysis = analyzeIdaSnapshot(snapshot);
  return { filePath:resolved, fileName:path.basename(resolved), size:stat.size, analysis };
}

function registerIdaSnapshotIpc() {
  if (ipcMain.listenerCount('ida:choose-analyze') || ipcMain.listenerCount('ida:analyze-dropped')) return;
  ipcMain.handle('ida:choose-analyze', async () => {
    const result = await dialog.showOpenDialog(activeWindow(), {
      title:'导入 NewCyber IDA Snapshot',
      properties:['openFile'],
      filters:[{ name:'NewCyber IDA Snapshot', extensions:['json'] },{ name:'All files', extensions:['*'] }]
    });
    if (result.canceled || !result.filePaths[0]) return null;
    return analyzeIdaSnapshotPath(result.filePaths[0]);
  });
  ipcMain.handle('ida:analyze-dropped', async (_event, filePath) => analyzeIdaSnapshotPath(filePath));
}

module.exports = { MAX_SNAPSHOT_BYTES, registerIdaSnapshotIpc, analyzeIdaSnapshotPath };
