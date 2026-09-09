'use strict';

const { BrowserWindow, dialog, ipcMain } = require('electron');
const fs = require('fs/promises');
const path = require('path');
const { analyzePowerTracePath, extractWindowFeatures } = require('../core/power_side_channel');
const { runtimeStatus, inspectOnnxModel, runOnnxModel, setRuntimeBundleRoot } = require('../core/local_ml_runtime');
const { inspectTransformerModel, runTransformerDecode } = require('../core/transformer_oracle');
const { createGpt2Bpe } = require('../core/gpt2_bpe');
const { fitLeakageProfile, recoverProbeCandidates } = require('../core/side_channel_probe');
const { runScaAutopilotPaths } = require('../core/sca_autopilot');
const { planHfOnnxExport } = require('../core/hf_onnx_export');
const { inspectTrustedConverter, executeTrustedHfOnnxPlan } = require('../core/trusted_hf_converter');
const { validateTrustedConverterLocation } = require('../core/trusted_converter_location');
const { convertAndResumeSca, isSafeTensorOracleGap } = require('../core/hf_sca_bridge');

const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_ONNX_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_VOCAB_BYTES = 32 * 1024 * 1024;
const MAX_MERGES_BYTES = 16 * 1024 * 1024;
const MAX_AUTOPILOT_FILES = 256;
const MAX_AUTOPILOT_DEPTH = 8;
const AUTOPILOT_EXT = new Set(['.npy','.onnx','.safetensors','.py','.pyw','.json','.txt','.md','.toml','.yaml','.yml']);
const SKIP_DIRS = new Set(['.git','node_modules','.venv','venv','__pycache__','.idea','.vscode','dist','build']);
const approvedTraceFiles = new Set();
const approvedOnnxFiles = new Set();
const approvedHfRoots = new Set();
const approvedAutopilotRoots = new Set();
const approvedScaConversionRoots = new Set();
let trustedHfConverter = null;

function openDialog(options) {
  const parent = BrowserWindow.getFocusedWindow();
  return parent ? dialog.showOpenDialog(parent, options) : dialog.showOpenDialog(options);
}

function saveDialog(options) {
  const parent = BrowserWindow.getFocusedWindow();
  return parent ? dialog.showSaveDialog(parent, options) : dialog.showSaveDialog(options);
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

async function collectAutopilotFiles(rootPath) {
  const root = resolvedPath(rootPath);
  const stat = await fs.lstat(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('SCA Autopilot 入口必须是非符号链接目录');
  const out = [];
  async function walk(current, depth) {
    if (depth > MAX_AUTOPILOT_DEPTH || out.length >= MAX_AUTOPILOT_FILES) return;
    let entries = await fs.readdir(current, { withFileTypes: true });
    entries = entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (out.length >= MAX_AUTOPILOT_FILES) break;
      if (entry.isSymbolicLink()) continue;
      const target = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name.toLowerCase())) await walk(target, depth + 1);
        continue;
      }
      if (!entry.isFile() || !AUTOPILOT_EXT.has(path.extname(entry.name).toLowerCase())) continue;
      out.push(target);
    }
  }
  await walk(root, 0);
  if (!out.length) throw new Error('目录内没有可识别的 SCA 工件');
  return out;
}

function approveResultArtifacts(result) {
  const discovery = result?.result?.discovery || result?.discovery;
  const model = discovery?.roles?.model?.file?.filePath;
  if (model) approvedOnnxFiles.add(path.resolve(model));
  for (const key of ['profileTrace','targetTrace']) {
    const trace = discovery?.roles?.[key]?.file?.filePath;
    if (trace) approvedTraceFiles.add(path.resolve(trace));
  }
  const converted = result?.conversion?.selected?.filePath;
  if (converted) approvedOnnxFiles.add(path.resolve(converted));
}

async function runScaAutopilotDirectory(rootPath, options = {}) {
  const root = resolvedPath(rootPath);
  const paths = await collectAutopilotFiles(root);
  approvedAutopilotRoots.add(root);
  const result = await runScaAutopilotPaths(paths, { provider: options.provider || 'cpu' });
  if (isSafeTensorOracleGap(result)) approvedScaConversionRoots.add(root);
  else approvedScaConversionRoots.delete(root);
  approveResultArtifacts(result);
  return { ...result, workspaceRoot: root };
}

async function optionalSibling(filePath,name,maxBytes) {
  const candidate=path.join(path.dirname(filePath),name);
  try {
    const stat=await fs.stat(candidate);
    if(!stat.isFile()||stat.size<=0||stat.size>maxBytes)return null;
    return {filePath:candidate,fileName:name,size:stat.size,text:await fs.readFile(candidate,'utf8')};
  } catch(error) {
    if(error?.code==='ENOENT')return null;
    throw error;
  }
}

async function tokenizerSibling(filePath,includeText=false) {
  const vocab=await optionalSibling(filePath,'vocab.json',MAX_VOCAB_BYTES);
  if(!vocab)return {available:false,kind:null,vocab:null,merges:null};
  const merges=await optionalSibling(filePath,'merges.txt',MAX_MERGES_BYTES);
  let parsed;
  try { parsed=createGpt2Bpe(vocab.text,merges?.text||''); }
  catch(error) { return {available:false,kind:'gpt2-bpe',error:error?.message||String(error),vocab:vocab.fileName,merges:merges?.fileName||null}; }
  const result={available:true,kind:'gpt2-bpe',vocab:vocab.fileName,merges:merges?.fileName||null,vocabSize:parsed.vocabSize,mergeCount:parsed.mergeCount};
  if(includeText){result.vocabText=vocab.text;result.mergesText=merges?.text||'';}
  return result;
}

async function inspectOnnxPath(filePath, provider = 'cpu') {
  const checked = await checkedFile(filePath);
  if (path.extname(checked.filePath).toLowerCase() !== '.onnx') throw new Error('本地 ML runtime 当前只接受 .onnx 执行工件');
  if (checked.stat.size > MAX_ONNX_BYTES) throw new Error(`ONNX 超过 ${MAX_ONNX_BYTES} bytes 上限`);
  approvedOnnxFiles.add(checked.filePath);
  const status = runtimeStatus();
  const tokenizer=await tokenizerSibling(checked.filePath,false);
  if (!status.available) return {
    filePath: checked.filePath,
    fileName: path.basename(checked.filePath),
    size: checked.stat.size,
    runtime: status,
    tokenizer,
    model: null,
    transformer: null
  };
  const [model,transformer] = await Promise.all([
    inspectOnnxModel(checked.filePath, { provider }),
    inspectTransformerModel(checked.filePath,{provider})
  ]);
  return {
    filePath: checked.filePath,
    fileName: path.basename(checked.filePath),
    size: checked.stat.size,
    runtime: status,
    tokenizer,
    model,
    transformer
  };
}

async function runTransformerPath(payload={}) {
  const filePath=resolvedPath(payload.filePath);
  if(!approvedOnnxFiles.has(filePath))throw new Error('请先通过 ONNX 选择器打开模型');
  const request={...(payload.request||{})};
  if(typeof request.promptText==='string'&&!request.tokenizer){
    const tokenizer=await tokenizerSibling(filePath,true);
    if(!tokenizer.available)throw new Error('promptText 需要模型同目录的 vocab.json；也可以直接提供 promptTokenIds');
    request.tokenizer={vocabText:tokenizer.vocabText,mergesText:tokenizer.mergesText};
  }
  return runTransformerDecode(filePath,request,{
    provider:payload.provider||'cpu',
    intraOpNumThreads:payload.intraOpNumThreads,
    interOpNumThreads:payload.interOpNumThreads
  });
}

async function planHfDirectory(rootPath, options = {}) {
  const root = resolvedPath(rootPath);
  const stat = await fs.lstat(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('请选择非符号链接的本地 HuggingFace 模型目录');
  const plan = await planHfOnnxExport(root, options);
  approvedHfRoots.add(root);
  return plan;
}

async function saveHfPlan(rootPath, options = {}) {
  const root = resolvedPath(rootPath);
  if (!approvedHfRoots.has(root)) throw new Error('请先通过 HF / SafeTensors 选择器检查模型目录');
  const plan = await planHfOnnxExport(root, options);
  const result = await saveDialog({
    title: '保存 NewCyber ONNX 转换清单',
    defaultPath: path.join(root, 'newcyber_hf_onnx_plan.json'),
    filters: [{ name: 'JSON', extensions: ['json'] }]
  });
  if (result.canceled || !result.filePath) return null;
  await fs.writeFile(result.filePath, `${JSON.stringify(plan, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' }).catch(async (error) => {
    if (error?.code !== 'EEXIST') throw error;
    throw new Error('目标转换清单已存在；NewCyber 不会静默覆盖已有文件');
  });
  return { filePath: result.filePath, status: plan.status, gap: plan.gap || null };
}

async function executeApprovedHfConversion(rootPath, options = {}) {
  const root = resolvedPath(rootPath);
  if (!approvedHfRoots.has(root)) throw new Error('请先通过 HF / SafeTensors 选择器检查模型目录');
  if (!trustedHfConverter) throw new Error('请先显式选择并审计 optimum-cli');
  const converterLocation = await validateTrustedConverterLocation(trustedHfConverter, [{ path:root, label:'HF model root' }]);
  if (!converterLocation.ok) return { schema:'newcyber.hf-onnx-conversion.v1', status:'gap', gap:{ code:converterLocation.code, detail:converterLocation.detail, stage:'converter-location' }, converterLocation };
  const runtime = runtimeStatus();
  if (!runtime.available) return { schema:'newcyber.hf-onnx-conversion.v1', status:'gap', gap:{ code:'MODEL_RUNTIME_GAP', detail:runtime.installHint, stage:'preflight' }, runtime, converterLocation };
  const plan = await planHfOnnxExport(root, { task: options.task || null, outputDir: options.outputDir || null });
  const conversion = await executeTrustedHfOnnxPlan(plan, trustedHfConverter, { provider: options.provider || 'cpu', purpose: options.purpose || 'general', timeoutMs: options.timeoutMs, maxOutputBytes: options.maxOutputBytes });
  approveResultArtifacts({ conversion });
  return { ...conversion, converterLocation };
}

async function continueScaAutopilotDirectory(rootPath, options = {}) {
  const root = resolvedPath(rootPath);
  if (!approvedAutopilotRoots.has(root)) throw new Error('请先通过 Power SCA Autopilot 选择器打开赛题目录');
  if (!approvedScaConversionRoots.has(root)) throw new Error('当前赛题未获得 SafeTensors ORACLE_ARTIFACT_GAP 转换许可');
  if (!trustedHfConverter) throw new Error('请先显式选择并审计 optimum-cli');
  const runtime = runtimeStatus();
  if (!runtime.available) return { schema:'newcyber.sca-autopilot-conversion.v1', status:'gap', gap:{ code:'MODEL_RUNTIME_GAP', detail:runtime.installHint, stage:'preflight' }, runtime, workspaceRoot:root };
  const paths = await collectAutopilotFiles(root);
  const bridged = await convertAndResumeSca(paths, trustedHfConverter, { workspaceRoot:root, provider: options.provider || 'cpu', timeoutMs: options.timeoutMs, maxOutputBytes: options.maxOutputBytes });
  if (bridged?.conversion?.status === 'converted') approvedScaConversionRoots.delete(root);
  approveResultArtifacts(bridged);
  return { ...bridged, workspaceRoot: root, runtime };
}

function trustedConverterStatus() {
  return trustedHfConverter ? { ...trustedHfConverter, selected:true } : { schema:'newcyber.trusted-hf-converter.v1', selected:false };
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

  ipcMain.handle('ai:sca-autopilot-choose', async () => {
    const result = await openDialog({ title: '选择 Power SCA / Transformer 赛题目录', properties: ['openDirectory'] });
    if (result.canceled || !result.filePaths[0]) return null;
    return runScaAutopilotDirectory(result.filePaths[0], { provider: 'cpu' });
  });

  ipcMain.handle('ai:sca-autopilot-convert-resume', async (_event, payload) => continueScaAutopilotDirectory(payload?.root, { provider: payload?.provider || 'cpu', timeoutMs: payload?.timeoutMs, maxOutputBytes: payload?.maxOutputBytes }));

  ipcMain.handle('ai:sca-analyze-dropped', async (_event, filePaths) => analyzeScaPaths(filePaths));

  ipcMain.handle('ai:sca-extract-windows', async (_event, payload) => {
    const filePath = resolvedPath(payload?.filePath);
    if (!approvedTraceFiles.has(filePath)) throw new Error('请先通过 SCA 选择器或拖放打开 trace');
    return extractWindowFeatures(filePath, {
      samplesPerRow: Number(payload?.samplesPerRow),
      windows: Array.isArray(payload?.windows) ? payload.windows : undefined
    });
  });

  ipcMain.handle('ai:sca-fit-leakage-profile', async (_event,payload) => fitLeakageProfile(payload?.hiddenStates,payload?.leakageFeatures,payload?.options||{}));
  ipcMain.handle('ai:sca-recover-probe', async (_event,payload) => recoverProbeCandidates(payload?.profile,payload?.targetLeakage,payload?.probeMatrix,payload?.options||{}));
  ipcMain.handle('ai:local-ml-status', async () => runtimeStatus());

  ipcMain.handle('ai:local-ml-select-runtime', async () => {
    const result = await openDialog({ title: '选择 NewCyber ONNX Runtime Bundle', properties: ['openDirectory'] });
    if (result.canceled || !result.filePaths[0]) return null;
    setRuntimeBundleRoot(result.filePaths[0]);
    return runtimeStatus();
  });

  ipcMain.handle('ai:hf-converter-status', async () => trustedConverterStatus());

  ipcMain.handle('ai:hf-converter-select', async () => {
    const result = await openDialog({
      title: '选择 Trusted Optimum Converter',
      properties: ['openFile'],
      filters: [{ name:'optimum-cli', extensions:['exe'] }, { name:'All files', extensions:['*'] }]
    });
    if (result.canceled || !result.filePaths[0]) return null;
    trustedHfConverter = await inspectTrustedConverter(result.filePaths[0]);
    return trustedConverterStatus();
  });

  ipcMain.handle('ai:hf-onnx-choose-plan', async () => {
    const result = await openDialog({ title: '选择本地 HuggingFace / SafeTensors 模型目录', properties: ['openDirectory'] });
    if (result.canceled || !result.filePaths[0]) return null;
    return planHfDirectory(result.filePaths[0]);
  });

  ipcMain.handle('ai:hf-onnx-save-plan', async (_event, payload) => saveHfPlan(payload?.root, { task: payload?.task || null, outputDir: payload?.outputDir || null }));
  ipcMain.handle('ai:hf-onnx-execute', async (_event, payload) => executeApprovedHfConversion(payload?.root, { task: payload?.task || null, outputDir: payload?.outputDir || null, provider: payload?.provider || 'cpu', purpose: payload?.purpose || 'general', timeoutMs: payload?.timeoutMs, maxOutputBytes: payload?.maxOutputBytes }));

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

  ipcMain.handle('ai:transformer-run', async (_event,payload) => runTransformerPath(payload||{}));
}

module.exports = {
  registerAiScaIpc,
  analyzeScaPaths,
  collectAutopilotFiles,
  runScaAutopilotDirectory,
  continueScaAutopilotDirectory,
  inspectOnnxPath,
  tokenizerSibling,
  runTransformerPath,
  planHfDirectory,
  saveHfPlan,
  executeApprovedHfConversion,
  trustedConverterStatus
};