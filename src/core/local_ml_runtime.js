'use strict';

const MAX_FEED_ELEMENTS = 8_000_000;
const MAX_OUTPUT_ELEMENTS = 8_000_000;
const PREVIEW_ELEMENTS = 4096;
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

function loadOrt(moduleLoader = require) {
  try {
    return { ort: moduleLoader('onnxruntime-node'), error: null };
  } catch (error) {
    return { ort: null, error: error?.message || String(error) };
  }
}

function runtimeStatus(options = {}) {
  const loaded = options.ort ? { ort: options.ort, error: null } : loadOrt(options.moduleLoader || require);
  let version = options.version || null;
  if (loaded.ort && !version) {
    try { version = (options.moduleLoader || require)('onnxruntime-node/package.json').version || null; } catch {}
  }
  return {
    schema: 'newcyber.local-ml-runtime.v1',
    available: Boolean(loaded.ort?.InferenceSession && loaded.ort?.Tensor),
    package: 'onnxruntime-node',
    version,
    platform: process.platform,
    arch: process.arch,
    providers: providerCatalog(),
    defaultProvider: 'cpu',
    error: loaded.ort ? null : loaded.error,
    installHint: 'Install or bundle onnxruntime-node in the Electron main-process environment; NewCyber never loads it in the renderer.'
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

async function runOnnxModel(model, request = {}, options = {}) {
  return withSession(model, options, async (session, ort) => {
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
  });
}

module.exports = {
  MAX_FEED_ELEMENTS,
  MAX_OUTPUT_ELEMENTS,
  providerCatalog,
  runtimeStatus,
  tensorFromSpec,
  inspectOnnxModel,
  runOnnxModel
};
