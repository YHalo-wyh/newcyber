'use strict';

const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { inspectOnnxModel } = require('./local_ml_runtime');
const { inspectTransformerModel } = require('./transformer_oracle');

const CONVERTER_SCHEMA = 'newcyber.trusted-hf-converter.v1';
const CONVERSION_SCHEMA = 'newcyber.hf-onnx-conversion.v1';
const MAX_CONVERTER_BYTES = 64 * 1024 * 1024;
const MAX_PROCESS_OUTPUT_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_TIMEOUT_MS = 60 * 60 * 1000;
const MAX_ONNX_FILES = 32;
const MAX_ONNX_DEPTH = 4;
const MAX_ONNX_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_MODEL_TREE_ENTRIES = 4096;
const CODE_EXTENSIONS = new Set(['.py', '.pyc', '.pyo', '.pyd', '.so', '.dll', '.dylib', '.exe', '.sh', '.bat', '.cmd', '.ps1']);
const UNSAFE_WEIGHT_EXTENSIONS = new Set(['.bin', '.pt', '.pth', '.pkl', '.pickle', '.ckpt']);
const TOKENIZER_COPY_LIMITS = new Map([
  ['vocab.json', 32 * 1024 * 1024],
  ['merges.txt', 16 * 1024 * 1024],
  ['tokenizer.json', 64 * 1024 * 1024],
  ['tokenizer_config.json', 4 * 1024 * 1024],
  ['special_tokens_map.json', 4 * 1024 * 1024]
]);

function resolved(value) {
  const result = path.resolve(String(value || ''));
  if (!result || result === path.parse(result).root) throw new Error('路径无效');
  return result;
}

function sameOrInside(root, target) {
  const base = resolved(root);
  const value = resolved(target);
  return value === base || value.startsWith(`${base}${path.sep}`);
}

function gap(code, detail, stage, extra = {}) {
  return { schema: CONVERSION_SCHEMA, status: 'gap', gap: { code, detail, stage }, ...extra };
}

async function sha256Path(filePath) {
  const handle = await fs.open(filePath, 'r');
  const hash = crypto.createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    let position = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (!bytesRead) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
  } finally {
    await handle.close();
  }
  return hash.digest('hex');
}

async function inspectTrustedConverter(filePath) {
  const target = resolved(filePath);
  const stat = await fs.lstat(target);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('converter 必须是非符号链接普通文件');
  if (stat.size <= 0 || stat.size > MAX_CONVERTER_BYTES) throw new Error(`converter 大小必须在 1..${MAX_CONVERTER_BYTES} bytes`);
  const fileName = path.basename(target);
  if (!/^optimum-cli(?:\.exe)?$/i.test(fileName)) throw new Error('只允许显式选择 optimum-cli / optimum-cli.exe');
  if (process.platform !== 'win32' && (stat.mode & 0o111) === 0) throw new Error('optimum-cli 没有可执行权限');
  return {
    schema: CONVERTER_SCHEMA,
    filePath: target,
    fileName,
    bytes: stat.size,
    sha256: await sha256Path(target),
    platform: process.platform,
    arch: process.arch,
    trust: 'explicit-user-selection'
  };
}

async function revalidateTrustedConverter(descriptor) {
  if (!descriptor || descriptor.schema !== CONVERTER_SCHEMA) throw new Error('缺少已审计 trusted converter');
  const current = await inspectTrustedConverter(descriptor.filePath);
  if (current.bytes !== Number(descriptor.bytes) || current.sha256 !== String(descriptor.sha256 || '').toLowerCase()) {
    throw new Error('trusted converter 在选择后发生变化；拒绝执行');
  }
  return current;
}

function buildOfflineEnv(baseEnv = process.env) {
  const keys = process.platform === 'win32'
    ? ['PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'LANG']
    : ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR'];
  const env = {};
  for (const key of keys) if (typeof baseEnv[key] === 'string' && baseEnv[key]) env[key] = baseEnv[key];
  Object.assign(env, {
    HF_HUB_OFFLINE: '1',
    TRANSFORMERS_OFFLINE: '1',
    HF_DATASETS_OFFLINE: '1',
    HF_HUB_DISABLE_TELEMETRY: '1',
    DO_NOT_TRACK: '1',
    PYTHONSAFEPATH: '1',
    NO_PROXY: '*',
    no_proxy: '*',
    HTTP_PROXY: '',
    HTTPS_PROXY: '',
    ALL_PROXY: '',
    http_proxy: '',
    https_proxy: '',
    all_proxy: ''
  });
  return env;
}

async function auditModelTree(rootPath) {
  const root = resolved(rootPath);
  const rootStat = await fs.lstat(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) return { ok: false, code: 'MODEL_ROOT_GAP', detail: '模型根目录必须是非符号链接目录' };
  let entriesSeen = 0;
  const findings = [];
  async function walk(current, depth) {
    if (depth > 4 || findings.length) return;
    const entries = (await fs.readdir(current, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      entriesSeen += 1;
      if (entriesSeen > MAX_MODEL_TREE_ENTRIES) {
        findings.push({ code: 'MODEL_TREE_BUDGET_GAP', detail: `模型目录条目超过 ${MAX_MODEL_TREE_ENTRIES}` });
        return;
      }
      const target = path.join(current, entry.name);
      if (entry.isSymbolicLink()) {
        findings.push({ code: 'MODEL_SYMLINK_GAP', detail: `模型目录包含符号链接: ${path.relative(root, target)}` });
        return;
      }
      if (entry.isDirectory()) {
        await walk(target, depth + 1);
        if (findings.length) return;
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = path.extname(entry.name).toLowerCase();
      if (UNSAFE_WEIGHT_EXTENSIONS.has(ext)) {
        findings.push({ code: 'UNSAFE_WEIGHT_ARTIFACT_GAP', detail: `SafeTensors 转换目录同时包含不安全权重格式: ${path.relative(root, target)}` });
        return;
      }
      if (CODE_EXTENSIONS.has(ext)) {
        findings.push({ code: 'MODEL_CODE_ARTIFACT_GAP', detail: `trusted converter 不执行模型目录代码工件: ${path.relative(root, target)}` });
        return;
      }
    }
  }
  await walk(root, 0);
  return findings.length ? { ok: false, ...findings[0], entriesSeen } : { ok: true, entriesSeen };
}

function validatePlan(plan) {
  if (!plan || plan.schema !== 'newcyber.hf-onnx-plan.v1' || plan.status !== 'ready') throw new Error('HF → ONNX plan 尚未 ready');
  if (!plan.bundle?.root || !plan.output?.directory) throw new Error('plan 缺少模型根目录或输出目录');
  if (plan.converter?.executable !== 'optimum-cli' || plan.converter?.shell !== false) throw new Error('plan converter 不满足 optimum-cli + shell:false');
  if (plan.converter?.networkPolicy !== 'offline-only' || plan.converter?.trustRemoteCode !== false) throw new Error('plan 不是 offline / no-remote-code 策略');
  const args = Array.isArray(plan.converter?.args) ? plan.converter.args : [];
  if (!args.length || args.length > 64 || args.some((item) => typeof item !== 'string' || item.length > 16 * 1024)) throw new Error('plan argv 非法');
  if (args.some((item) => /trust[-_]remote[-_]code/i.test(item))) throw new Error('plan argv 包含 trust_remote_code');
  const root = resolved(plan.bundle.root);
  const output = resolved(plan.output.directory);
  if (output === root || !sameOrInside(root, output)) throw new Error('转换输出必须位于模型目录的独立子目录');
  if (!args.includes('--model') || !args.includes(root) || args[args.length - 1] !== output) throw new Error('plan argv 与模型/输出目录不一致');
  return { root, output, args };
}

async function ensureOutputAbsent(outputDir) {
  try {
    await fs.lstat(outputDir);
    return false;
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    throw error;
  }
}

function boundedTimeout(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return DEFAULT_TIMEOUT_MS;
  return Math.max(100, Math.min(MAX_TIMEOUT_MS, Math.floor(number)));
}

function boundedOutput(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return MAX_PROCESS_OUTPUT_BYTES;
  return Math.max(1024, Math.min(MAX_PROCESS_OUTPUT_BYTES, Math.floor(number)));
}

function killChild(child) {
  try { child.kill('SIGTERM'); } catch {}
  const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1500);
  if (typeof timer.unref === 'function') timer.unref();
}

function runBoundedProcess(executable, args, options = {}) {
  const spawnImpl = options.spawnImpl || spawn;
  const timeoutMs = boundedTimeout(options.timeoutMs);
  const maxOutputBytes = boundedOutput(options.maxOutputBytes);
  return new Promise((resolve) => {
    let child;
    try {
      child = spawnImpl(executable, args, {
        cwd: options.cwd,
        env: options.env,
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch (error) {
      resolve({ status: 'spawn-error', error: error?.message || String(error), stdout: '', stderr: '' });
      return;
    }
    let stdout = '';
    let stderr = '';
    let outputBytes = 0;
    let timeout = false;
    let outputLimit = false;
    let settled = false;
    const append = (kind, chunk) => {
      if (outputLimit) return;
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      const remaining = maxOutputBytes - outputBytes;
      if (buffer.length > remaining) {
        const slice = buffer.subarray(0, Math.max(0, remaining)).toString('utf8');
        if (kind === 'stdout') stdout += slice; else stderr += slice;
        outputBytes = maxOutputBytes;
        outputLimit = true;
        killChild(child);
        return;
      }
      outputBytes += buffer.length;
      if (kind === 'stdout') stdout += buffer.toString('utf8'); else stderr += buffer.toString('utf8');
    };
    child.stdout?.on('data', (chunk) => append('stdout', chunk));
    child.stderr?.on('data', (chunk) => append('stderr', chunk));
    const timer = setTimeout(() => {
      timeout = true;
      killChild(child);
    }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ...payload, stdout, stderr, outputBytes, timeoutMs, maxOutputBytes });
    };
    child.once('error', (error) => finish({ status: 'spawn-error', error: error?.message || String(error) }));
    child.once('close', (code, signal) => {
      if (timeout) finish({ status: 'timeout', code, signal });
      else if (outputLimit) finish({ status: 'output-limit', code, signal });
      else finish({ status: code === 0 ? 'ok' : 'exit-error', code, signal });
    });
  });
}

async function collectOnnxFiles(outputDir) {
  const root = resolved(outputDir);
  const files = [];
  async function walk(current, depth) {
    if (depth > MAX_ONNX_DEPTH || files.length > MAX_ONNX_FILES) return;
    const entries = (await fs.readdir(current, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const target = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        await walk(target, depth + 1);
        continue;
      }
      if (!entry.isFile() || path.extname(entry.name).toLowerCase() !== '.onnx') continue;
      const stat = await fs.stat(target);
      if (stat.size <= 0 || stat.size > MAX_ONNX_BYTES) continue;
      files.push({ filePath: target, fileName: entry.name, size: stat.size });
      if (files.length > MAX_ONNX_FILES) return;
    }
  }
  await walk(root, 0);
  if (files.length > MAX_ONNX_FILES) throw new Error(`ONNX 输出数量超过 ${MAX_ONNX_FILES}`);
  return files;
}

function candidateScore(candidate) {
  let score = candidate.model ? 10 : 0;
  const recipe = candidate.transformer;
  if (recipe?.supported) score += 100;
  if (recipe?.roles?.hidden) score += 30;
  if (recipe?.unknownInputs?.length === 0) score += 10;
  if (recipe?.cache?.mode === 'paired') score += 20;
  else if (recipe?.cache?.mode === 'none') score += 5;
  if (/decoder_model_merged|model/i.test(candidate.fileName)) score += 5;
  return score;
}

async function validateConvertedOnnx(outputDir, options = {}) {
  const files = await collectOnnxFiles(outputDir);
  if (!files.length) return { status: 'gap', gap: { code: 'ONNX_OUTPUT_GAP', detail: 'converter 成功退出但输出目录没有可验证 .onnx' }, candidates: [] };
  const candidates = [];
  for (const file of files) {
    try {
      const model = await inspectOnnxModel(file.filePath, { provider: options.provider || 'cpu', ort: options.ort });
      let transformer = null;
      try { transformer = await inspectTransformerModel(file.filePath, { provider: options.provider || 'cpu', ort: options.ort }); }
      catch (error) { transformer = { supported: false, error: error?.message || String(error) }; }
      const candidate = { ...file, valid: true, model, transformer };
      candidate.score = candidateScore(candidate);
      candidates.push(candidate);
    } catch (error) {
      candidates.push({ ...file, valid: false, error: error?.message || String(error), score: -1 });
    }
  }
  const valid = candidates.filter((item) => item.valid);
  if (!valid.length) return { status: 'gap', gap: { code: 'ONNX_VALIDATION_GAP', detail: '生成的 ONNX 均无法由当前 ORT 建立 session' }, candidates };
  const purpose = options.purpose === 'sca' ? 'sca' : 'general';
  const eligible = purpose === 'sca'
    ? valid.filter((item) => item.transformer?.supported && item.transformer?.roles?.hidden && item.transformer?.unknownInputs?.length === 0 && item.transformer?.cache?.mode !== 'unpaired')
    : valid;
  if (!eligible.length) return { status: 'gap', gap: { code: 'ONNX_RECIPE_GAP', detail: purpose === 'sca' ? 'ONNX 可加载，但没有满足 SCA 所需 input_ids/logits/hidden-state 的唯一 Transformer recipe' : 'ONNX 可加载但没有可用候选' }, candidates };
  eligible.sort((a, b) => b.score - a.score || a.filePath.localeCompare(b.filePath));
  const bestScore = eligible[0].score;
  const top = eligible.filter((item) => item.score === bestScore);
  if (purpose === 'sca' && top.length !== 1) return { status: 'gap', gap: { code: 'ONNX_SELECTION_GAP', detail: `存在 ${top.length} 个同分 SCA ONNX 候选；不会按文件名猜 oracle` }, candidates };
  return { status: 'ok', purpose, selected: top[0], candidates };
}

async function mirrorTokenizerArtifacts(modelRoot, outputDir) {
  const copied = [];
  for (const [name, maxBytes] of TOKENIZER_COPY_LIMITS.entries()) {
    const source = path.join(modelRoot, name);
    const destination = path.join(outputDir, name);
    try {
      const sourceStat = await fs.lstat(source);
      if (!sourceStat.isFile() || sourceStat.isSymbolicLink() || sourceStat.size <= 0 || sourceStat.size > maxBytes) continue;
      try { await fs.lstat(destination); continue; }
      catch (error) { if (error?.code !== 'ENOENT') throw error; }
      await fs.copyFile(source, destination);
      copied.push({ name, bytes: sourceStat.size, sha256: await sha256Path(destination) });
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
  return copied;
}

async function writeConversionManifest(outputDir, payload) {
  const filePath = path.join(outputDir, 'newcyber_conversion.json');
  await fs.writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  return filePath;
}

async function executeTrustedHfOnnxPlan(plan, converterDescriptor, options = {}) {
  let planState;
  try { planState = validatePlan(plan); }
  catch (error) { return gap('PLAN_POLICY_GAP', error?.message || String(error), 'preflight', { plan }); }
  let converter;
  try { converter = await revalidateTrustedConverter(converterDescriptor); }
  catch (error) { return gap('CONVERTER_TRUST_GAP', error?.message || String(error), 'preflight', { plan }); }
  const treeAudit = await auditModelTree(planState.root);
  if (!treeAudit.ok) return gap(treeAudit.code, treeAudit.detail, 'model-audit', { plan, converter, treeAudit });
  if (!(await ensureOutputAbsent(planState.output))) return gap('OUTPUT_EXISTS_GAP', `输出目录已存在：${planState.output}；NewCyber 不会覆盖或混入旧产物`, 'preflight', { plan, converter, treeAudit });

  const env = buildOfflineEnv(options.baseEnv || process.env);
  const processResult = await runBoundedProcess(converter.filePath, planState.args, {
    spawnImpl: options.spawnImpl,
    timeoutMs: options.timeoutMs,
    maxOutputBytes: options.maxOutputBytes,
    cwd: path.dirname(converter.filePath),
    env
  });
  const processView = {
    status: processResult.status,
    code: processResult.code ?? null,
    signal: processResult.signal ?? null,
    stdout: processResult.stdout,
    stderr: processResult.stderr,
    outputBytes: processResult.outputBytes || 0,
    timeoutMs: processResult.timeoutMs,
    maxOutputBytes: processResult.maxOutputBytes,
    shell: false,
    cwd: path.dirname(converter.filePath),
    networkIsolation: 'offline-environment-only'
  };
  if (processResult.status === 'timeout') return gap('CONVERTER_TIMEOUT_GAP', `converter 超过 ${processResult.timeoutMs}ms，已终止；部分输出目录保留供检查`, 'convert', { plan, converter, process: processView });
  if (processResult.status === 'output-limit') return gap('CONVERTER_OUTPUT_LIMIT_GAP', `converter 输出超过 ${processResult.maxOutputBytes} bytes，已终止；部分输出目录保留供检查`, 'convert', { plan, converter, process: processView });
  if (processResult.status === 'spawn-error') return gap('CONVERTER_SPAWN_GAP', processResult.error || 'converter 启动失败', 'convert', { plan, converter, process: processView });
  if (processResult.status !== 'ok') return gap('CONVERTER_EXIT_GAP', `converter exit=${processResult.code ?? 'unknown'} signal=${processResult.signal || 'none'}`, 'convert', { plan, converter, process: processView });

  let validation;
  try { validation = await validateConvertedOnnx(planState.output, { provider: options.provider || 'cpu', ort: options.ort, purpose: options.purpose || 'general' }); }
  catch (error) { return gap('ONNX_VALIDATION_GAP', error?.message || String(error), 'onnx-validate', { plan, converter, process: processView }); }
  if (validation.status !== 'ok') return gap(validation.gap.code, validation.gap.detail, 'onnx-validate', { plan, converter, process: processView, validation });

  const tokenizerArtifacts = await mirrorTokenizerArtifacts(planState.root, planState.output);
  const selected = validation.selected ? {
    filePath: validation.selected.filePath,
    fileName: validation.selected.fileName,
    size: validation.selected.size,
    sha256: await sha256Path(validation.selected.filePath),
    transformer: validation.selected.transformer,
    model: validation.selected.model,
    score: validation.selected.score
  } : null;
  const provenance = {
    schema: 'newcyber.hf-onnx-conversion-manifest.v1',
    source: {
      root: planState.root,
      configSha256: plan.bundle?.config?.sha256 || null,
      safetensorsHeaders: (plan.bundle?.safetensors || []).map((item) => ({ fileName: item.fileName, headerSha256: item.headerSha256 || null, bytes: item.bytes || null })).slice(0, 256)
    },
    converter: { fileName: converter.fileName, bytes: converter.bytes, sha256: converter.sha256 },
    policy: {
      shell: false,
      remoteCodeAllowed: false,
      challengePythonAllowed: false,
      unsafeWeightFormatsAllowed: false,
      modelDirectoryCodeAllowed: false,
      networkIsolation: 'offline-environment-only'
    },
    output: {
      directory: planState.output,
      selectedOnnx: selected ? { fileName: selected.fileName, bytes: selected.size, sha256: selected.sha256 } : null,
      tokenizerArtifacts
    }
  };
  let manifestPath = null;
  try { manifestPath = await writeConversionManifest(planState.output, provenance); }
  catch (error) { return gap('PROVENANCE_WRITE_GAP', `ONNX 已验证，但 provenance manifest 写入失败：${error?.message || String(error)}`, 'provenance', { plan, converter, process: processView, validation, selected, tokenizerArtifacts }); }
  return {
    schema: CONVERSION_SCHEMA,
    status: 'converted',
    gap: null,
    plan,
    converter,
    treeAudit,
    process: processView,
    validation,
    selected,
    tokenizerArtifacts,
    manifestPath,
    provenance
  };
}

module.exports = {
  CONVERTER_SCHEMA,
  CONVERSION_SCHEMA,
  MAX_CONVERTER_BYTES,
  MAX_PROCESS_OUTPUT_BYTES,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  inspectTrustedConverter,
  revalidateTrustedConverter,
  buildOfflineEnv,
  auditModelTree,
  validatePlan,
  runBoundedProcess,
  collectOnnxFiles,
  validateConvertedOnnx,
  mirrorTokenizerArtifacts,
  executeTrustedHfOnnxPlan
};
