'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createRequire } = require('module');

const MAX_FEED_ELEMENTS = 8_000_000;
const MAX_OUTPUT_ELEMENTS = 8_000_000;
const MAX_BATCH_REQUESTS = 2048;
const PREVIEW_ELEMENTS = 4096;
const RUNTIME_BUNDLE_SCHEMA = 'newcyber.onnx-runtime-bundle.v1';
const PINNED_ORT_VERSION = '1.29.0';
const MAX_CRITICAL_FILES = 128;
const ALLOWED_PROVIDERS = new Set(['cpu', 'dml', 'cuda', 'webgpu', 'coreml']);
const TYPE_INFO = {
  float32: { ctor: Float32Array, bytes: 4 },
  float64: { ctor: Float64Array, bytes: 8 },
  int8: { ctor: Int8Array, bytes: 1 },
  uint8: { ctor: Uint8Array, bytes: 1 },
  int16: { ctor: Int16Array, bytes: 2 },
  uint16: { ctor: Uint16Array, bytes: 2 },
  int32: { ctor: Int32Array, bytes: 4 },
  uint32: { ctor: Uint32Array, bytes: 4 },
  int64: { ctor: BigInt64Array, bytes: 8, bigInt: true },
  uint64: { ctor: BigUint64Array, bytes: 8, bigInt: true },
  bool: { ctor: Uint8Array, bytes: 1, bool: true }
};

let runtimeBundleOverride = null;

function product(values) {
  let total = 1;
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('tensor dims 必须是非负安全整数');
    total *= value;
    if (!Number.isSafeInteger(total) || total > MAX_FEED_ELEMENTS) throw new Error(`tensor 元素数超过 ${MAX_FEED_ELEMENTS} 上限`);
  }
  return total;
}

function providerCatalog(platform = process.platform) {
  const providers = ['cpu'];
  if (platform === 'win32') providers.push('dml', 'webgpu');
  else if (platform === 'linux') providers.push('cuda', 'webgpu');
  else if (platform === 'darwin') providers.push('coreml', 'webgpu');
  return providers;
}

function sha256FileSync(filePath) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    while (true) {
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!bytes) break;
      hash.update(buffer.subarray(0, bytes));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

function safeRuntimeRoot(value) {
  const resolved = path.resolve(String(value || ''));
  if (!resolved || resolved === path.parse(resolved).root) throw new Error('runtime bundle 路径无效');
  return resolved;
}

function packageRootFromBundle(root) {
  return path.join(root, 'node_modules', 'onnxruntime-node');
}

function readJsonSync(filePath) {
  const stat = fs.statSync(filePath);
  if (!stat.isFile() || stat.size <= 0 || stat.size > 4 * 1024 * 1024) throw new Error(`${path.basename(filePath)} 大小异常`);
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function criticalRuntimeFiles(packageRoot, packageJson) {
  const files = new Set(['package.json']);
  const main = typeof packageJson.main === 'string' && packageJson.main ? packageJson.main : 'dist/index.js';
  files.add(main.replace(/\\/g, '/'));
  const binRoot = path.join(packageRoot, 'bin');
  if (fs.existsSync(binRoot)) {
    const walk = (dir) => {
      if (files.size >= MAX_CRITICAL_FILES) return;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
        if (files.size >= MAX_CRITICAL_FILES) break;
        const target = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(target);
        else if (entry.isFile() && /\.(?:node|dll|so|dylib)$/i.test(entry.name)) files.add(path.relative(packageRoot, target).split(path.sep).join('/'));
      }
    };
    walk(binRoot);
  }
  return [...files];
}

function createRuntimeBundleManifest(rootPath) {
  const root = safeRuntimeRoot(rootPath);
  const packageRoot = packageRootFromBundle(root);
  const packageJsonPath = path.join(packageRoot, 'package.json');
  const packageJson = readJsonSync(packageJsonPath);
  if (packageJson.name !== 'onnxruntime-node') throw new Error('runtime bundle 内不是 onnxruntime-node');
  if (packageJson.version !== PINNED_ORT_VERSION) throw new Error(`runtime 版本 ${packageJson.version || 'unknown'} 与固定版本 ${PINNED_ORT_VERSION} 不一致`);
  const criticalFiles = criticalRuntimeFiles(packageRoot, packageJson).map((relativePath) => {
    const target = path.resolve(packageRoot, relativePath);
    if (!target.startsWith(`${path.resolve(packageRoot)}${path.sep}`) && target !== packageJsonPath) throw new Error('runtime critical file 路径越界');
    const stat = fs.statSync(target);
    if (!stat.isFile()) throw new Error(`runtime critical file 缺失: ${relativePath}`);
    return { path: relativePath, bytes: stat.size, sha256: sha256FileSync(target) };
  });
  return {
    schema: RUNTIME_BUNDLE_SCHEMA,
    package: 'onnxruntime-node',
    version: PINNED_ORT_VERSION,
    platform: process.platform,
    arch: process.arch,
    installPolicy: { cudaAddon: 'skip', runtimeNetwork: 'disabled' },
    criticalFiles
  };
}

function verifyRuntimeBundle(rootPath, options = {}) {
  let root;
  try { root = safeRuntimeRoot(rootPath); }
  catch (error) { return { valid: false, error: error.message }; }
  try {
    const manifestPath = path.join(root, 'newcyber-runtime.json');
    const manifest = readJsonSync(manifestPath);
    if (manifest.schema !== RUNTIME_BUNDLE_SCHEMA) throw new Error(`runtime manifest schema 非 ${RUNTIME_BUNDLE_SCHEMA}`);
    if (manifest.package !== 'onnxruntime-node') throw new Error('runtime manifest package 非 onnxruntime-node');
    if (manifest.version !== PINNED_ORT_VERSION) throw new Error(`runtime manifest version=${manifest.version || 'unknown'}，期望 ${PINNED_ORT_VERSION}`);
    if (manifest.platform !== process.platform || manifest.arch !== process.arch) throw new Error(`runtime bundle 为 ${manifest.platform}/${manifest.arch}，当前是 ${process.platform}/${process.arch}`);
    const packageRoot = packageRootFromBundle(root);
    const packageJson = readJsonSync(path.join(packageRoot, 'package.json'));
    if (packageJson.name !== 'onnxruntime-node' || packageJson.version !== manifest.version) throw new Error('runtime package.json 与 manifest 不一致');
    const criticalFiles = Array.isArray(manifest.criticalFiles) ? manifest.criticalFiles : [];
    if (!criticalFiles.length || criticalFiles.length > MAX_CRITICAL_FILES) throw new Error('runtime manifest criticalFiles 数量异常');
    if (options.verifyHashes !== false) {
      const base = path.resolve(packageRoot);
      for (const item of criticalFiles) {
        if (!item || typeof item.path !== 'string' || !/^[a-f0-9]{64}$/i.test(String(item.sha256 || ''))) throw new Error('runtime critical file 记录非法');
        const target = path.resolve(packageRoot, item.path);
        if (target !== base && !target.startsWith(`${base}${path.sep}`)) throw new Error('runtime critical file 路径越界');
        const stat = fs.statSync(target);
        if (!stat.isFile() || stat.size !== Number(item.bytes)) throw new Error(`runtime critical file 大小不一致: ${item.path}`);
        if (sha256FileSync(target) !== String(item.sha256).toLowerCase()) throw new Error(`runtime critical file hash 不一致: ${item.path}`);
      }
    }
    return { valid: true, root, packageRoot, manifest, version: manifest.version, source: 'bundle' };
  } catch (error) {
    return { valid: false, root, error: error?.message || String(error) };
  }
}

function runtimeBundleCandidates() {
  const tag = `${process.platform}-${process.arch}`;
  const out = [];
  if (runtimeBundleOverride) out.push({ root: runtimeBundleOverride, source: 'selected-bundle' });
  if (process.env.NEWCYBER_ORT_ROOT) out.push({ root: process.env.NEWCYBER_ORT_ROOT, source: 'env-bundle' });
  if (typeof process.resourcesPath === 'string' && process.resourcesPath) out.push({ root: path.join(process.resourcesPath, 'runtime', tag), source: 'app-bundle' });
  out.push({ root: path.resolve(__dirname, '..', '..', '.newcyber-runtime', tag), source: 'project-bundle' });
  const seen = new Set();
  return out.filter((item) => {
    const root = path.resolve(String(item.root || ''));
    if (seen.has(root)) return false;
    seen.add(root);
    item.root = root;
    return true;
  });
}

function loadBundleOrt(candidate) {
  const verification = verifyRuntimeBundle(candidate.root);
  if (!verification.valid) return { ort: null, error: verification.error, source: candidate.source, bundle: verification };
  try {
    const packageRequire = createRequire(path.join(verification.packageRoot, 'package.json'));
    const ort = packageRequire(verification.packageRoot);
    return { ort, error: null, source: candidate.source, version: verification.version, bundle: verification };
  } catch (error) {
    return { ort: null, error: `runtime bundle 加载失败: ${error?.message || String(error)}`, source: candidate.source, bundle: verification };
  }
}

function loadOrt(moduleLoader = require) {
  if (moduleLoader !== require) {
    try { return { ort: moduleLoader('onnxruntime-node'), error: null, source: 'injected' }; }
    catch (error) { return { ort: null, error: error?.message || String(error), source: 'injected' }; }
  }
  const bundleErrors = [];
  for (const candidate of runtimeBundleCandidates()) {
    if (!fs.existsSync(candidate.root)) continue;
    const loaded = loadBundleOrt(candidate);
    if (loaded.ort) return loaded;
    bundleErrors.push(`${candidate.source}: ${loaded.error}`);
  }
  try {
    const ort = moduleLoader('onnxruntime-node');
    let version = null;
    try { version = moduleLoader('onnxruntime-node/package.json').version || null; } catch {}
    return { ort, error: null, source: 'node_modules', version };
  } catch (error) {
    const detail = [error?.message || String(error), ...bundleErrors].filter(Boolean).join(' | ');
    return { ort: null, error: detail, source: 'unavailable' };
  }
}

function setRuntimeBundleRoot(rootPath) {
  const verification = verifyRuntimeBundle(rootPath);
  if (!verification.valid) throw new Error(verification.error || 'runtime bundle 验证失败');
  runtimeBundleOverride = verification.root;
  return verification;
}

function clearRuntimeBundleRoot() {
  runtimeBundleOverride = null;
}

function runtimeStatus(options = {}) {
  const loaded = options.ort ? { ort: options.ort, error: null, source: 'injected', version: options.version || null } : loadOrt(options.moduleLoader || require);
  let version = options.version || loaded.version || null;
  if (loaded.ort && !version && loaded.source === 'node_modules') {
    try { version = (options.moduleLoader || require)('onnxruntime-node/package.json').version || null; } catch {}
  }
  return {
    schema: 'newcyber.local-ml-runtime.v2',
    available: Boolean(loaded.ort?.InferenceSession && loaded.ort?.Tensor),
    package: 'onnxruntime-node',
    pinnedVersion: PINNED_ORT_VERSION,
    version,
    source: loaded.source || null,
    bundleRoot: loaded.bundle?.root || null,
    bundleVerified: Boolean(loaded.bundle?.valid),
    platform: process.platform,
    arch: process.arch,
    providers: providerCatalog(),
    defaultProvider: 'cpu',
    error: loaded.ort ? null : loaded.error,
    installHint: `Run npm run runtime:prepare before going offline. NewCyber will load ${PINNED_ORT_VERSION} from .newcyber-runtime/${process.platform}-${process.arch} or packaged app resources; renderer never loads native runtime code.`
  };
}

function normalizeProvider(provider) {
  const value = String(provider || 'cpu').toLowerCase();
  if (!ALLOWED_PROVIDERS.has(value)) throw new Error(`不支持的 execution provider: ${value}`);
  if (!providerCatalog().includes(value)) throw new Error(`${value} 不在当前平台的 NewCyber provider allowlist 中`);
  return value;
}

function bytesToTypedArray(buffer, info, count) {
  if (buffer.byteLength !== count * info.bytes) throw new Error(`tensor base64 长度 ${buffer.byteLength} 与 dims/type 期望 ${count * info.bytes} 不一致`);
  const copy = Uint8Array.from(buffer);
  return new info.ctor(copy.buffer, copy.byteOffset, count);
}

function valuesToTypedArray(values, info, count) {
  if (!Array.isArray(values) && !ArrayBuffer.isView(values)) throw new Error('tensor values 必须是数组或 TypedArray');
  if (values.length !== count) throw new Error(`tensor values 数量 ${values.length} 与 dims 元素数 ${count} 不一致`);
  if (info.bigInt) return new info.ctor(Array.from(values, (value) => BigInt(value)));
  if (info.bool) return new info.ctor(Array.from(values, (value) => value ? 1 : 0));
  return new info.ctor(Array.from(values, Number));
}

function tensorFromSpec(ort, spec) {
  if (!spec || typeof spec !== 'object') throw new Error('tensor spec 缺失');
  const type = String(spec.type || 'float32').toLowerCase();
  const info = TYPE_INFO[type];
  if (!info) throw new Error(`当前不支持 tensor type ${type}`);
  const dims = Array.isArray(spec.dims) ? spec.dims.map(Number) : [];
  if (!dims.length) throw new Error('tensor dims 不能为空');
  const count = product(dims);
  let data;
  if (typeof spec.base64 === 'string') data = bytesToTypedArray(Buffer.from(spec.base64, 'base64'), info, count);
  else data = valuesToTypedArray(spec.values, info, count);
  return new ort.Tensor(type, data, dims);
}

function metadataView(metadata) {
  if (!metadata) return null;
  return {
    type: metadata.type || null,
    dimensions: Array.isArray(metadata.dimensions) ? metadata.dimensions.slice(0, 32) : null,
    symbolicDimensions: Array.isArray(metadata.symbolicDimensions) ? metadata.symbolicDimensions.slice(0, 32) : null
  };
}

function numericSummary(data) {
  let min = Infinity;
  let max = -Infinity;
  let sum = 0;
  let finite = 0;
  const length = Math.min(data.length, MAX_OUTPUT_ELEMENTS);
  for (let index = 0; index < length; index += 1) {
    const value = Number(data[index]);
    if (!Number.isFinite(value)) continue;
    if (value < min) min = value;
    if (value > max) max = value;
    sum += value;
    finite += 1;
  }
  return {
    finite,
    min: finite ? min : null,
    max: finite ? max : null,
    mean: finite ? sum / finite : null
  };
}

function outputView(value) {
  if (!value || !Array.isArray(value.dims) || !value.data) return { kind: typeof value };
  const count = value.data.length;
  const previewCount = Math.min(count, PREVIEW_ELEMENTS);
  const preview = Array.from(value.data.slice(0, previewCount), (item) => typeof item === 'bigint' ? item.toString() : Number(item));
  return {
    type: value.type || null,
    dims: value.dims.slice(0, 32),
    elements: count,
    preview,
    truncated: count > previewCount,
    summary: numericSummary(value.data)
  };
}

function sessionOptions(provider, options = {}) {
  const normalized = normalizeProvider(provider);
  const result = {
    executionProviders: [normalized],
    graphOptimizationLevel: options.graphOptimizationLevel || 'all',
    enableCpuMemArena: options.enableCpuMemArena !== false,
    enableMemPattern: options.enableMemPattern !== false
  };
  if (Number.isInteger(options.intraOpNumThreads) && options.intraOpNumThreads > 0 && options.intraOpNumThreads <= 64) result.intraOpNumThreads = options.intraOpNumThreads;
  if (Number.isInteger(options.interOpNumThreads) && options.interOpNumThreads > 0 && options.interOpNumThreads <= 64) result.interOpNumThreads = options.interOpNumThreads;
  return result;
}

async function withSession(model, options, callback) {
  const loaded = options?.ort ? { ort: options.ort, error: null } : loadOrt(options?.moduleLoader || require);
  if (!loaded.ort) throw new Error(`onnxruntime-node unavailable: ${loaded.error}`);
  const session = await loaded.ort.InferenceSession.create(model, sessionOptions(options?.provider || 'cpu', options || {}));
  try { return await callback(session, loaded.ort); }
  finally { if (typeof session.release === 'function') await session.release(); }
}

async function inspectOnnxModel(model, options = {}) {
  return withSession(model, options, async (session) => ({
    schema: 'newcyber.onnx-model.v1',
    provider: normalizeProvider(options.provider || 'cpu'),
    inputs: session.inputNames.map((name, index) => ({ name, metadata: metadataView(session.inputMetadata?.[index]) })),
    outputs: session.outputNames.map((name, index) => ({ name, metadata: metadataView(session.outputMetadata?.[index]) }))
  }));
}

async function runWithOpenSession(session, ort, request = {}, options = {}) {
  const feeds = {};
  const input = request.feeds || {};
  for (const name of session.inputNames) {
    if (!Object.prototype.hasOwnProperty.call(input, name)) throw new Error(`缺少 ONNX 输入 ${name}`);
    feeds[name] = tensorFromSpec(ort, input[name]);
  }
  const requested = Array.isArray(request.outputs) && request.outputs.length
    ? request.outputs.filter((name) => session.outputNames.includes(name)).slice(0, 64)
    : session.outputNames.slice(0, 64);
  if (!requested.length) throw new Error('没有有效 ONNX 输出请求');
  const fetches = Object.fromEntries(requested.map((name) => [name, null]));
  const output = await session.run(feeds, fetches);
  return {
    schema: 'newcyber.onnx-run.v1',
    provider: normalizeProvider(options.provider || 'cpu'),
    inputs: session.inputNames.slice(),
    outputs: Object.fromEntries(requested.map((name) => [name, outputView(output[name])]))
  };
}

async function runOnnxModel(model, request = {}, options = {}) {
  return withSession(model, options, async (session, ort) => runWithOpenSession(session, ort, request, options));
}

async function runOnnxRequests(model, requests = [], options = {}) {
  if (!Array.isArray(requests) || !requests.length) throw new Error('ONNX batch requests 不能为空');
  if (requests.length > MAX_BATCH_REQUESTS) throw new Error(`ONNX batch requests 超过 ${MAX_BATCH_REQUESTS} 上限`);
  const started = Date.now();
  return withSession(model, options, async (session, ort) => {
    const results = [];
    for (let index = 0; index < requests.length; index += 1) {
      try {
        const result = await runWithOpenSession(session, ort, requests[index], options);
        results.push({ index, ok: true, result });
      } catch (error) {
        const failure = { index, ok: false, error: String(error?.message || error).slice(0, 500) };
        results.push(failure);
        if (options.failFast === true) break;
      }
    }
    const succeeded = results.filter((item) => item.ok).length;
    return {
      schema: 'newcyber.onnx-request-batch.v1',
      provider: normalizeProvider(options.provider || 'cpu'),
      requested: requests.length,
      completed: results.length,
      succeeded,
      failed: results.length - succeeded,
      sessionCreates: 1,
      elapsedMs: Date.now() - started,
      results
    };
  });
}

module.exports = {
  MAX_FEED_ELEMENTS,
  MAX_OUTPUT_ELEMENTS,
  MAX_BATCH_REQUESTS,
  RUNTIME_BUNDLE_SCHEMA,
  PINNED_ORT_VERSION,
  providerCatalog,
  createRuntimeBundleManifest,
  verifyRuntimeBundle,
  setRuntimeBundleRoot,
  clearRuntimeBundleRoot,
  runtimeStatus,
  normalizeProvider,
  sessionOptions,
  withSession,
  tensorFromSpec,
  metadataView,
  outputView,
  inspectOnnxModel,
  runWithOpenSession,
  runOnnxModel,
  runOnnxRequests
};
