'use strict';

const { BrowserWindow, dialog, ipcMain } = require('electron');
const fs = require('fs/promises');
const path = require('path');
const { analyzePowerTracePath, extractWindowFeatures } = require('../core/power_side_channel');
const { runtimeStatus, inspectOnnxModel, runOnnxModel } = require('../core/local_ml_runtime');

const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_ONNX_BYTES = 4 * 1024 * 1024 * 1024;
const approvedTraceFiles = new Set();
const approvedOnnxFiles = new Set();

function openDialog(options) {
  const parent = BrowserWindow.getFocusedWindow();
  return parent ? dialog.showOpenDialog(parent, options) : dialog.showOpenDialog(options);
}

function resolvedPath(value) {
  const resolved = path.resolve(String(value || ''));
  if (!resolved || resolved === path.parse(resolved).root) throw new Error('未获得有效文件路径');
  return resolved;
}

async function checkedFile(value) {
  const filePath = resolvedPath(value);
  const stat = await fs.stat(filePath);
  if (!stat.isFile()) throw new Error(`${path.basename(filePath)} 不是普通文件`);
  if (stat.size <= 0) throw new Error(`${path.basename(filePath)} 为空`);
  return { filePath, stat };
}

async function sourceTextFromPaths(paths) {
  const chunks = [];
  let total = 0;
  for (const candidate of paths) {
    const ext = path.extname(candidate).toLowerCase();
    if (!['.py', '.pyw', '.txt', '.md', '.json', '.toml', '.yaml', '.yml'].includes(ext)) continue;
    const { filePath, stat } = await checkedFile(candidate);
    if (stat.size > MAX_SOURCE_BYTES) continue;
    total += stat.size;
    if (total > MAX_SOURCE_BYTES) break;
    chunks.push(`\n# --- ${path.basename(filePath)} ---\n${await fs.readFile(filePath, 'utf8')}`);
  }
  return chunks.join('\n').slice(0, MAX_SOURCE_BYTES);
}

async function analyzeScaPaths(filePaths) {
  const paths = Array.isArray(filePaths) ? filePaths.map(resolvedPath) : [resolvedPath(filePaths)];
  if (!paths.length) throw new Error('没有选择 SCA 文件');
  const npy = [];
  for (const candidate of paths) {
    if (path.extname(candidate).toLowerCase() !== '.npy') continue;
    const checked = await checkedFile(candidate);
    npy.push(checked);
  }
  if (!npy.length) throw new Error('SCA 工作台至少需要一个 .npy trace');
  npy.sort((left, right) => right.stat.size - left.stat.size || left.filePath.localeCompare(right.filePath));
  const trace = npy[0];
  approvedTraceFiles.add(trace.filePath);
  const sourceText = await sourceTextFromPaths(paths);
  const analysis = await analyzePowerTracePath(trace.filePath, { sourceText });
  return {
    filePath: trace.filePath,
    fileName: path.basename(trace.filePath),
    sourceFiles: paths.filter((candidate) => ['.py', '.pyw', '.txt', '.md', '.json', '.toml', '.yaml', '.yml'].includes(path.extname(candidate).toLowerCase())).map((candidate) => path.basename(candidate)).slice(0, 32),
    analysis
  };
}

async function inspectOnnxPath(filePath, provider = 'cpu') {
  const checked = await checkedFile(filePath);
  if (path.extname(checked.filePath).toLowerCase() !== '.onnx') throw new Error('本地 ML runtime 当前只接受 .onnx 执行工件');
  if (checked.stat.size > MAX_ONNX_BYTES) throw new Error(`ONNX 超过 ${MAX_ONNX_BYTES} bytes 上限`);
  approvedOnnxFiles.add(checked.filePath);
  const status = runtimeStatus();
  if (!status.available) return {
    filePath: checked.filePath,
    fileName: path.basename(checked.filePath),
    size: checked.stat.size,
    runtime: status,
    model: null
  };
  const model = await inspectOnnxModel(checked.filePath, { provider });
  return {
    filePath: checked.filePath,
    fileName: path.basename(checked.filePath),
    size: checked.stat.size,
    runtime: status,
    model
  };
}

function registerAiScaIpc() {
  ipcMain.handle('ai:sca-choose-analyze', async () => {
    const result = await openDialog({
      title: '选择功耗侧信道题目工件',
      properties: ['openFile', 'multiSelections'],
      filters: [
        { name: 'SCA challenge files', extensions: ['npy', 'py', 'pyw', 'txt', 'json', 'toml', 'yaml', 'yml', 'md'] },
        { name: 'All files', extensions: ['*'] }
      ]
    });
    if (result.canceled || !result.filePaths.length) return null;
    return analyzeScaPaths(result.filePaths);
  });

  ipcMain.handle('ai:sca-analyze-dropped', async (_event, filePaths) => analyzeScaPaths(filePaths));

  ipcMain.handle('ai:sca-extract-windows', async (_event, payload) => {
    const filePath = resolvedPath(payload?.filePath);
    if (!approvedTraceFiles.has(filePath)) throw new Error('请先通过 SCA 选择器或拖放打开 trace');
    return extractWindowFeatures(filePath, {
      samplesPerRow: Number(payload?.samplesPerRow),
      windows: Array.isArray(payload?.windows) ? payload.windows : undefined
    });
  });

  ipcMain.handle('ai:local-ml-status', async () => runtimeStatus());

  ipcMain.handle('ai:onnx-choose-inspect', async (_event, provider = 'cpu') => {
    const result = await openDialog({
      title: '选择 ONNX oracle',
      properties: ['openFile'],
      filters: [{ name: 'ONNX model', extensions: ['onnx'] }, { name: 'All files', extensions: ['*'] }]
    });
    if (result.canceled || !result.filePaths[0]) return null;
    return inspectOnnxPath(result.filePaths[0], provider);
  });

  ipcMain.handle('ai:onnx-inspect-dropped', async (_event, filePath, provider = 'cpu') => inspectOnnxPath(filePath, provider));

  ipcMain.handle('ai:onnx-run', async (_event, payload) => {
    const filePath = resolvedPath(payload?.filePath);
    if (!approvedOnnxFiles.has(filePath)) throw new Error('请先通过 ONNX 选择器打开模型');
    return runOnnxModel(filePath, payload?.request || {}, {
      provider: payload?.provider || 'cpu',
      intraOpNumThreads: payload?.intraOpNumThreads,
      interOpNumThreads: payload?.interOpNumThreads
    });
  });
}

module.exports = { registerAiScaIpc, analyzeScaPaths, inspectOnnxPath };
