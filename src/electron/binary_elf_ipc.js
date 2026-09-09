'use strict';

const { BrowserWindow, dialog, ipcMain } = require('electron');
const fs = require('fs/promises');
const path = require('path');
const { analyzeElfBinary, MAX_ELF_BYTES } = require('../core/binary_elf_loader');

function activeWindow() {
  return BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0] || null;
}

async function analyzeElfPath(filePath) {
  const resolved = path.resolve(String(filePath || ''));
  if (!resolved || resolved === path.parse(resolved).root) throw new Error('未获得有效 ELF 文件路径');
  const stat = await fs.stat(resolved);
  if (!stat.isFile()) throw new Error('拖入对象不是文件');
  if (stat.size <= 0) throw new Error('ELF 文件为空');
  if (stat.size > MAX_ELF_BYTES) throw new Error(`ELF 文件超过 ${MAX_ELF_BYTES} bytes 分析上限`);
  const handle = await fs.open(resolved, 'r');
  try {
    const magic = Buffer.alloc(4);
    const { bytesRead } = await handle.read(magic, 0, 4, 0);
    if (bytesRead !== 4 || !(magic[0] === 0x7f && magic[1] === 0x45 && magic[2] === 0x4c && magic[3] === 0x46)) {
      throw new Error('选择的文件不是 ELF（Magic 不匹配）');
    }
  } finally {
    await handle.close();
  }
  const buffer = await fs.readFile(resolved);
  return {
    filePath:resolved,
    fileName:path.basename(resolved),
    size:stat.size,
    analysis:analyzeElfBinary(buffer, path.basename(resolved))
  };
}

function registerBinaryElfIpc() {
  if (ipcMain.listenerCount('binary:choose-analyze') || ipcMain.listenerCount('binary:analyze-dropped')) return;
  ipcMain.handle('binary:choose-analyze', async () => {
    const result = await dialog.showOpenDialog(activeWindow(), {
      title:'选择 ELF 二进制',
      properties:['openFile'],
      filters:[
        { name:'ELF / Linux binary', extensions:['elf','bin','out','so'] },
        { name:'All files', extensions:['*'] }
      ]
    });
    if (result.canceled || !result.filePaths[0]) return null;
    return analyzeElfPath(result.filePaths[0]);
  });
  ipcMain.handle('binary:analyze-dropped', async (_event, filePath) => analyzeElfPath(filePath));
}

module.exports = { registerBinaryElfIpc, analyzeElfPath };
