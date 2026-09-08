const { app, BrowserWindow, dialog, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs/promises');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { scanWorkspace, inspectFile, buildMarkdownReport } = require('./src/core/finals_analyzer_batch14');
const { runTool } = require('./src/core/tool_router');
const { bufferFromArtifact } = require('./src/core/artifacts');
const { analyzeFirmwareBuffer, MAX_FIRMWARE_BYTES } = require('./src/core/firmware_workbench');
const { exportVerifiedFirmwareArtifacts } = require('./src/core/firmware_export');
const { inspectModelInternally, normalizeExternalResult, mergeModelScanEvidence, toolingCatalog } = require('./src/core/ai_tooling');

const execFileAsync = promisify(execFile);
const MAX_INTERNAL_MODEL_BYTES = 256 * 1024 * 1024;
let win = null;
const approvedRoots = new Set();
const approvedFirmwareFiles = new Set();
const approvedAiModelFiles = new Set();

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

async function readFirmware(filePath) {
  const stat = await fs.stat(filePath);
  if (stat.size <= 0) throw new Error('固件文件为空');
  if (stat.size > MAX_FIRMWARE_BYTES) throw new Error(`固件文件超过分析上限 ${MAX_FIRMWARE_BYTES} bytes`);
  return fs.readFile(filePath);
}

async function analyzeFirmwarePath(filePath) {
  const resolved = path.resolve(String(filePath || ''));
  if (!resolved || resolved === path.parse(resolved).root) throw new Error('未获得有效固件文件路径');
  const stat = await fs.stat(resolved);
  if (!stat.isFile()) throw new Error('拖入对象不是文件');
  approvedFirmwareFiles.add(resolved);
  const buffer = await readFirmware(resolved);
  return { filePath: resolved, fileName: path.basename(resolved), analysis: analyzeFirmwareBuffer(buffer) };
}

async function execCaptured(command, args, options = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      windowsHide: true,
      timeout: options.timeout || 120000,
      maxBuffer: options.maxBuffer || 8 * 1024 * 1024,
      shell: false,
      cwd: options.cwd
    });
    return { ok: true, code: 0, stdout: String(stdout || ''), stderr: String(stderr || '') };
  } catch (error) {
    if (error?.code === 'ENOENT') return { ok: false, missing: true, code: null, stdout: '', stderr: '', error: `${command} not found` };
    return {
      ok: false,
      missing: false,
      code: Number.isInteger(error?.code) ? error.code : null,
      stdout: String(error?.stdout || ''),
      stderr: String(error?.stderr || ''),
      error: error?.message || String(error)
    };
  }
}

async function probeAiBackends() {
  const [modelscan, picklescan] = await Promise.all([
    execCaptured('modelscan', ['-v'], { timeout: 10000, maxBuffer: 512 * 1024 }),
    execCaptured('picklescan', ['--help'], { timeout: 10000, maxBuffer: 512 * 1024 })
  ]);
  return {
    catalog: toolingCatalog(),
    cli: {
      modelscan: { available: !modelscan.missing, detail: (modelscan.stdout || modelscan.stderr || modelscan.error || '').trim().slice(0, 500) },
      picklescan: { available: !picklescan.missing, detail: picklescan.missing ? picklescan.error : 'picklescan CLI available' }
    }
  };
}

async function runAiModelScan(filePath) {
  const resolved = path.resolve(String(filePath || ''));
  if (!approvedAiModelFiles.has(resolved)) throw new Error('请先通过模型选择器打开文件');
  const stat = await fs.stat(resolved);
  if (stat.size <= 0) throw new Error('模型文件为空');
  const fileName = path.basename(resolved);
  let internal;
  if (stat.size <= MAX_INTERNAL_MODEL_BYTES) {
    const buffer = await fs.readFile(resolved);
    internal = inspectModelInternally(buffer, fileName);
  } else {
    internal = { engine:'newcyber', format:path.extname(fileName).toLowerCase() || 'unknown', result:null, skipped:`文件超过内置整文件解析上限 ${MAX_INTERNAL_MODEL_BYTES} bytes` };
  }

  const modelscanExec = await execCaptured('modelscan', ['-p', resolved, '-r', 'json'], { timeout: 180000, maxBuffer: 16 * 1024 * 1024 });
  const ext = path.extname(fileName).toLowerCase();
  const pickleLike = ['.pt','.pth','.pkl','.pickle','.joblib','.bin','.npy'].includes(ext);
  const picklescanExec = pickleLike
    ? await execCaptured('picklescan', ['--path', resolved], { timeout: 180000, maxBuffer: 16 * 1024 * 1024 })
    : { missing:true, code:null, stdout:'', stderr:'', error:'not-applicable' };

  const external = [];
  if (!modelscanExec.missing) external.push(normalizeExternalResult('modelscan', modelscanExec));
  if (!picklescanExec.missing) external.push(normalizeExternalResult('picklescan', picklescanExec));
  const merged = mergeModelScanEvidence(internal, external);
  return {
    filePath: resolved,
    fileName,
    size: stat.size,
    ...merged,
    backendAvailability: {
      modelscan: !modelscanExec.missing,
      picklescan: pickleLike && !picklescanExec.missing
    }
  };
}

function compactRecursiveAnalysis(analysis) {
  const captureFiles = (analysis.files || []).filter((file) => file.metadata?.captureIntelligence);
  const credentialCount = captureFiles.reduce((sum,file)=>sum+(file.metadata.captureIntelligence.network?.credentials?.length||0),0);
  const rtspCount = captureFiles.reduce((sum,file)=>sum+(file.metadata.captureIntelligence.network?.rtspEndpoints?.length||0),0);
  const mavlinkFrames = captureFiles.reduce((sum,file)=>sum+(file.metadata.captureIntelligence.network?.mavlink?.parsedFrames||0),0);
  const canFrames = captureFiles.reduce((sum,file)=>sum+(file.metadata.captureIntelligence.can?.parsedFrames||0),0);
  return {
    workspaceName:analysis.workspaceName,
    fileCount:analysis.files?.length || 0,
    findingCount:analysis.findings?.length || 0,
    captureFiles:captureFiles.map((file)=>({
      path:file.path,
      format:file.metadata.captureIntelligence.format,
      packetCount:file.metadata.captureIntelligence.packetCount,
      highlights:(file.metadata.captureIntelligence.highlights||[]).slice(0,12)
    })).slice(0,80),
    credentialCount,
    rtspCount,
    mavlinkFrames,
    canFrames,
    examDirectionCounts:analysis.examDirectionCounts || null,
    recommendations:(analysis.recommendations||[]).slice(0,20),
    topFindings:(analysis.findings||[]).slice(0,40).map((finding)=>({ severity:finding.severity, title:finding.title, file:finding.file, evidence:finding.evidence }))
  };
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

  ipcMain.handle('firmware:choose-analyze', async () => {
    const result = await dialog.showOpenDialog(win, {
      title: '选择固件文件',
      properties: ['openFile'],
      filters: [{ name: 'Firmware / Binary', extensions: ['bin','img','fw','rom','trx','chk','ubi','squashfs','zip'] }, { name: 'All files', extensions: ['*'] }]
    });
    if (result.canceled || !result.filePaths[0]) return null;
    return analyzeFirmwarePath(result.filePaths[0]);
  });

  ipcMain.handle('firmware:analyze-dropped', async (_event, filePath) => analyzeFirmwarePath(filePath));

  ipcMain.handle('firmware:export-recovered', async (_event, filePath) => {
    const resolved = path.resolve(String(filePath || ''));
    if (!approvedFirmwareFiles.has(resolved)) throw new Error('请先通过固件选择器或拖放打开文件');
    const buffer = await readFirmware(resolved);
    const analysis = analyzeFirmwareBuffer(buffer);
    if (!analysis.artifacts?.length) return { ok: false, error: '当前没有可直接导出的完整恢复段；可改用 Binwalk 解包到目录。' };
    const out = await dialog.showOpenDialog(win, { title: '选择固件恢复结果导出位置', properties: ['openDirectory', 'createDirectory'] });
    if (out.canceled || !out.filePaths[0]) return null;
    const exported = await exportVerifiedFirmwareArtifacts({
      artifacts: analysis.artifacts,
      parentDir: path.resolve(out.filePaths[0]),
      sourceName: path.basename(resolved)
    });
    return { ok: true, ...exported };
  });

  ipcMain.handle('firmware:extract-binwalk', async (_event, filePath) => {
    const resolved = path.resolve(String(filePath || ''));
    if (!approvedFirmwareFiles.has(resolved)) throw new Error('请先通过固件选择器或拖放打开文件');
    const out = await dialog.showOpenDialog(win, { title: '选择 Binwalk 解包输出目录', properties: ['openDirectory', 'createDirectory'] });
    if (out.canceled || !out.filePaths[0]) return null;
    const outputDir = path.resolve(out.filePaths[0]);
    try {
      const { stdout, stderr } = await execFileAsync('binwalk', ['-eM', '--directory', outputDir, resolved], {
        windowsHide: true,
        timeout: 120000,
        maxBuffer: 4 * 1024 * 1024,
        shell: false
      });
      approvedRoots.add(outputDir);
      let recursive = null;
      try {
        const analysis = await scanWorkspace(outputDir);
        recursive = compactRecursiveAnalysis(analysis);
      } catch (error) {
        recursive = { error:error?.message || String(error) };
      }
      return { ok: true, outputDir, stdout: String(stdout || '').slice(-12000), stderr: String(stderr || '').slice(-4000), recursive };
    } catch (error) {
      if (error?.code === 'ENOENT') return { ok: false, missingTool: 'binwalk', outputDir, error: '未找到 binwalk；仍可导出内置解析器恢复出的完整段。' };
      return { ok: false, outputDir, error: error?.message || String(error), stdout: String(error?.stdout || '').slice(-12000), stderr: String(error?.stderr || '').slice(-4000) };
    }
  });

  ipcMain.handle('ai:backend-status', async () => probeAiBackends());

  ipcMain.handle('ai:model-choose-scan', async () => {
    const result = await dialog.showOpenDialog(win, {
      title: '选择模型 / Checkpoint',
      properties: ['openFile'],
      filters: [
        { name:'AI model / checkpoint', extensions:['pt','pth','pkl','pickle','joblib','bin','npy','safetensors','h5','keras'] },
        { name:'All files', extensions:['*'] }
      ]
    });
    if (result.canceled || !result.filePaths[0]) return null;
    const filePath = path.resolve(result.filePaths[0]);
    approvedAiModelFiles.add(filePath);
    return runAiModelScan(filePath);
  });

  ipcMain.handle('ai:model-rescan', async (_event, filePath) => runAiModelScan(filePath));

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
