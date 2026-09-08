const { app, BrowserWindow, dialog, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs/promises');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { scanWorkspace, inspectFile, buildMarkdownReport } = require('./src/core/finals_analyzer_batch15');
const { runTool } = require('./src/core/tool_router');
const { bufferFromArtifact } = require('./src/core/artifacts');
const { analyzeFirmwareBuffer, MAX_FIRMWARE_BYTES } = require('./src/core/firmware_workbench');
const { exportVerifiedFirmwareArtifacts } = require('./src/core/firmware_export');
const { inspectModelInternally, normalizeExternalResult, mergeModelScanEvidence, toolingCatalog } = require('./src/core/ai_tooling');
const { buildPocIndexFromDirectory, loadPocIndexFile, INDEX_SCHEMA } = require('./src/core/poc_reference_index');

const execFileAsync = promisify(execFile);
const MAX_INTERNAL_MODEL_BYTES = 256 * 1024 * 1024;
let win = null;
let pocIndexCache = null;
let pocIndexError = null;
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

function pocIndexFilePath() {
  return path.join(app.getPath('userData'), 'poc-in-github-index-v1.json');
}

function pocIndexStatus() {
  return {
    available:Boolean(pocIndexCache?.schema === INDEX_SCHEMA),
    generatedAt:pocIndexCache?.generatedAt || null,
    stats:pocIndexCache?.stats || null,
    source:pocIndexCache?.source || null,
    cachePath:pocIndexCache ? pocIndexFilePath() : null,
    error:pocIndexError
  };
}

async function loadCachedPocIndex() {
  try {
    pocIndexCache = await loadPocIndexFile(pocIndexFilePath());
    pocIndexError = null;
  } catch (error) {
    pocIndexCache = null;
    pocIndexError = error?.code === 'ENOENT' ? null : (error?.message || String(error));
  }
  return pocIndexCache;
}

async function importPocIndex() {
  const result = await dialog.showOpenDialog(win, {
    title:'选择 nomi-sec/PoC-in-GitHub 本地仓库根目录',
    properties:['openDirectory']
  });
  if (result.canceled || !result.filePaths[0]) return null;
  const sourceRoot = path.resolve(result.filePaths[0]);
  const index = await buildPocIndexFromDirectory(sourceRoot, { maxReposPerCve:6, concurrency:24 });
  const target = pocIndexFilePath();
  const temp = `${target}.tmp-${process.pid}-${Date.now()}`;
  await fs.mkdir(path.dirname(target), { recursive:true });
  await fs.writeFile(temp, JSON.stringify(index), 'utf8');
  await fs.rename(temp, target);
  pocIndexCache = index;
  pocIndexError = null;
  return { ...pocIndexStatus(), importedFrom:sourceRoot };
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
  const videoSessions = captureFiles.reduce((sum,file)=>sum+(file.metadata.captureIntelligence.video?.sessions?.length||0),0);
  const datalinkFiles = captureFiles.filter((file)=>file.metadata.captureIntelligence.datalink).length;
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
    videoSessions,
    datalinkFiles,
    pocMatches:analysis.pocReferences?.matches?.length || 0,
    examDirectionCounts:analysis.examDirectionCounts || null,
    batch15Counts:analysis.batch15Counts || null,
    batch17Counts:analysis.batch17Counts || null,
    recommendations:(analysis.recommendations||[]).slice(0,24),
    topFindings:(analysis.findings||[]).slice(0,40).map((finding)=>({ severity:finding.severity, title:finding.title, file:finding.file, evidence:finding.evidence }))
  };
}

function safeBundleName(value,fallback='item') {
  const base=path.basename(String(value||fallback)).replace(/[<>:"/\\|?*\x00-\x1f]/g,'_').replace(/[. ]+$/g,'').trim();
  return (base||fallback).slice(0,140);
}

async function createBundleDirectory(parentDir,workspaceName) {
  const stamp=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z').replace('T','-');
  const stem=`newcyber-${safeBundleName(workspaceName,'workspace')}-${stamp}`;
  for (let i=0;i<100;i+=1) {
    const candidate=path.join(parentDir,i?`${stem}-${i}`:stem);
    try { await fs.mkdir(candidate); return candidate; }
    catch (error) { if (error?.code!=='EEXIST') throw error; }
  }
  throw new Error('无法创建唯一结果包目录');
}

function uniqueArtifactName(name,index,used) {
  const safe=safeBundleName(name,`artifact-${index+1}.bin`);
  const ext=path.extname(safe);
  const stem=ext?safe.slice(0,-ext.length):safe;
  let candidate=safe; let suffix=1;
  while (used.has(candidate.toLowerCase())) candidate=`${stem}-${suffix++}${ext}`;
  used.add(candidate.toLowerCase());
  return candidate;
}

async function exportAutopilotBundle(parentDir,analysis,notes='') {
  const outputDir=await createBundleDirectory(parentDir,analysis.workspaceName||'workspace');
  const artifactsDir=path.join(outputDir,'artifacts');
  await fs.mkdir(artifactsDir);
  const exported=[]; const skipped=[]; const used=new Set();
  const entries=analysis.autopilot?.artifacts||[];
  for (let index=0;index<entries.length;index+=1) {
    const entry=entries[index];
    if (!entry?.artifact) continue;
    try {
      const decoded=bufferFromArtifact(entry.artifact,{requireComplete:true});
      const fileName=uniqueArtifactName(decoded.name||entry.name,index,used);
      const filePath=path.join(artifactsDir,fileName);
      await fs.writeFile(filePath,decoded.buffer);
      exported.push({name:fileName,kind:entry.kind||'artifact',sourceFile:entry.file||null,size:decoded.buffer.length,sha256:decoded.sha256});
    } catch (error) {
      skipped.push({name:entry.name||entry.artifact?.name||`artifact-${index+1}`,reason:error?.message||String(error)});
    }
  }
  const flags=(analysis.autopilot?.flags||[]).map((item)=>({value:item.value||item.flag||String(item),file:item.file||null})).filter((item)=>item.value);
  const report=buildMarkdownReport(analysis,notes||'');
  await fs.writeFile(path.join(outputDir,'report.md'),report,'utf8');
  if (flags.length) await fs.writeFile(path.join(outputDir,'flags.txt'),flags.map((item)=>`${item.value}${item.file?`\t${item.file}`:''}`).join('\n')+'\n','utf8');
  const manifest={
    schema:'newcyber.autopilot-bundle.v1',
    generatedAt:new Date().toISOString(),
    workspace:{name:analysis.workspaceName||null,path:analysis.workspacePath||null},
    track:analysis.autopilot?.track||null,
    summary:analysis.autopilot?.summary||null,
    flags,
    actions:analysis.autopilot?.actions||[],
    pocReferences:(analysis.pocReferences?.matches||[]).slice(0,12).map((item)=>({cve:item.cve,score:item.score,summary:item.summary||null,sourceUrl:item.sourceUrl,reasons:item.reasons||[]})),
    findings:(analysis.autopilot?.findings||analysis.findings||[]).slice(0,40).map((item)=>({id:item.id||null,severity:item.severity||null,title:item.title||null,file:item.file||null,evidence:item.evidence||null})),
    artifacts:exported,
    skippedArtifacts:skipped
  };
  await fs.writeFile(path.join(outputDir,'manifest.json'),JSON.stringify(manifest,null,2)+'\n','utf8');
  return {ok:true,outputDir,artifacts:exported.length,flags:flags.length,skipped:skipped.length};
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
    return scanWorkspace(resolved, { pocIndex:pocIndexCache });
  });

  ipcMain.handle('workspace:inspect', async (_event, rootPath, relativePath) => {
    const resolved = path.resolve(rootPath);
    if (!approvedRoots.has(resolved)) throw new Error('赛题目录未授权');
    return inspectFile(resolved, relativePath);
  });

  ipcMain.handle('poc:index-status', async () => pocIndexStatus());

  ipcMain.handle('poc:index-import', async () => importPocIndex());

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

  ipcMain.handle('autopilot:export-bundle', async (_event, payload) => {
    const analysis=payload?.analysis;
    if (!analysis||typeof analysis!=='object') throw new Error('没有可导出的分析结果');
    const workspacePath=analysis.workspacePath?path.resolve(String(analysis.workspacePath)):null;
    if (workspacePath&&!approvedRoots.has(workspacePath)) throw new Error('赛题目录未授权，请重新打开工作区');
    const result=await dialog.showOpenDialog(win,{title:'选择一键结果包保存位置',properties:['openDirectory','createDirectory']});
    if (result.canceled||!result.filePaths[0]) return null;
    return exportAutopilotBundle(path.resolve(result.filePaths[0]),analysis,payload?.notes||'');
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
        const analysis = await scanWorkspace(outputDir, { pocIndex:pocIndexCache });
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

app.whenReady().then(async () => {
  await loadCachedPocIndex();
  registerIpc();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});