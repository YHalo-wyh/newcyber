'use strict';

const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { SAFETENSORS_DTYPE_BYTES } = require('./model_artifacts');

const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MAX_SAFETENSORS_HEADER = 16 * 1024 * 1024;
const MAX_SAFETENSORS_SHARDS = 256;
const MAX_TENSORS_PER_SHARD = 200_000;
const MAX_TENSOR_PREVIEW = 64;
const ALLOWED_TASKS = new Set([
  'text-generation-with-past',
  'text2text-generation-with-past',
  'text-classification',
  'token-classification',
  'question-answering',
  'fill-mask',
  'image-classification',
  'feature-extraction'
]);

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function resolved(value) {
  const result = path.resolve(String(value || ''));
  if (!result || result === path.parse(result).root) throw new Error('模型目录路径无效');
  return result;
}

function safeRelative(base, value) {
  if (typeof value !== 'string' || !value.trim() || path.isAbsolute(value)) return null;
  const target = path.resolve(base, value);
  const root = path.resolve(base);
  if (target === root || !target.startsWith(`${root}${path.sep}`)) return null;
  return target;
}

async function readBoundedJson(filePath, maxBytes = MAX_JSON_BYTES) {
  const stat = await fs.stat(filePath);
  if (!stat.isFile() || stat.size <= 0 || stat.size > maxBytes) throw new Error(`${path.basename(filePath)} 大小异常`);
  const raw = await fs.readFile(filePath);
  return { value: JSON.parse(raw.toString('utf8')), bytes: stat.size, sha256: sha256(raw) };
}

function tensorByteCount(shape, dtype) {
  const width = SAFETENSORS_DTYPE_BYTES.get(dtype || '');
  if (!width || !Array.isArray(shape) || !shape.every((value) => Number.isSafeInteger(value) && value >= 0)) return null;
  let total = BigInt(width);
  for (const value of shape) total *= BigInt(value);
  return total;
}

async function inspectSafetensorsPath(filePath) {
  const target = resolved(filePath);
  const stat = await fs.stat(target);
  if (!stat.isFile() || stat.size < 10) return { valid: false, filePath: target, fileName: path.basename(target), issues: ['文件过小，无法构成 SafeTensors'] };
  const handle = await fs.open(target, 'r');
  try {
    const prefix = Buffer.alloc(8);
    const first = await handle.read(prefix, 0, 8, 0);
    if (first.bytesRead !== 8) return { valid: false, filePath: target, fileName: path.basename(target), issues: ['无法读取 SafeTensors header length'] };
    const headerLengthBig = prefix.readBigUInt64LE(0);
    if (headerLengthBig < 2n || headerLengthBig > BigInt(MAX_SAFETENSORS_HEADER) || headerLengthBig > BigInt(Number.MAX_SAFE_INTEGER)) {
      return { valid: false, filePath: target, fileName: path.basename(target), issues: ['SafeTensors header length 越界'] };
    }
    const headerLength = Number(headerLengthBig);
    const dataStart = 8 + headerLength;
    if (dataStart > stat.size) return { valid: false, filePath: target, fileName: path.basename(target), issues: ['SafeTensors header 超出文件边界'] };
    const headerBuffer = Buffer.alloc(headerLength);
    const read = await handle.read(headerBuffer, 0, headerLength, 8);
    if (read.bytesRead !== headerLength) return { valid: false, filePath: target, fileName: path.basename(target), issues: ['SafeTensors header 读取不完整'] };
    let header;
    try { header = JSON.parse(headerBuffer.toString('utf8')); }
    catch { return { valid: false, filePath: target, fileName: path.basename(target), issues: ['SafeTensors header 不是合法 JSON'] }; }
    if (!header || typeof header !== 'object' || Array.isArray(header)) return { valid: false, filePath: target, fileName: path.basename(target), issues: ['SafeTensors header 必须是 object'] };
    const entries = Object.entries(header).filter(([name]) => name !== '__metadata__');
    if (entries.length > MAX_TENSORS_PER_SHARD) return { valid: false, filePath: target, fileName: path.basename(target), issues: [`tensor 数量超过 ${MAX_TENSORS_PER_SHARD} 上限`] };
    const dataBytes = stat.size - dataStart;
    const issues = [];
    const ranges = [];
    const dtypeCounts = {};
    const tensorPreview = [];
    for (const [name, spec] of entries) {
      if (!spec || typeof spec !== 'object' || Array.isArray(spec)) { issues.push(`${name}: tensor entry 非 object`); continue; }
      const dtype = typeof spec.dtype === 'string' ? spec.dtype : null;
      const shape = Array.isArray(spec.shape) ? spec.shape : null;
      const offsets = Array.isArray(spec.data_offsets) ? spec.data_offsets : null;
      const shapeValid = Boolean(shape) && shape.every((value) => Number.isSafeInteger(value) && value >= 0);
      const offsetsValid = Boolean(offsets) && offsets.length === 2 && offsets.every((value) => Number.isSafeInteger(value) && value >= 0) && offsets[1] >= offsets[0];
      if (!dtype) issues.push(`${name}: 缺少 dtype`);
      if (!shapeValid) issues.push(`${name}: shape 非非负安全整数数组`);
      if (!offsetsValid) issues.push(`${name}: data_offsets 非法`);
      if (offsetsValid && offsets[1] > dataBytes) issues.push(`${name}: data_offsets 超出 data 区`);
      const expected = shapeValid && dtype ? tensorByteCount(shape, dtype) : null;
      const actual = offsetsValid ? BigInt(offsets[1] - offsets[0]) : null;
      if (expected != null && actual != null && expected !== actual) issues.push(`${name}: shape/dtype 与 data_offsets 字节数不一致`);
      if (offsetsValid) ranges.push({ name, start: offsets[0], end: offsets[1] });
      if (dtype) dtypeCounts[dtype] = (dtypeCounts[dtype] || 0) + 1;
      if (tensorPreview.length < MAX_TENSOR_PREVIEW) tensorPreview.push({ name, dtype, shape, dataOffsets: offsetsValid ? offsets : null });
    }
    ranges.sort((a, b) => a.start - b.start || a.end - b.end || a.name.localeCompare(b.name));
    let cursor = 0;
    for (const range of ranges) {
      if (range.start < cursor) issues.push(`${range.name}: tensor data range 与前一 tensor 重叠`);
      cursor = Math.max(cursor, range.end);
    }
    return {
      schema: 'newcyber.safetensors-header.v1',
      valid: issues.length === 0,
      filePath: target,
      fileName: path.basename(target),
      bytes: stat.size,
      headerBytes: headerLength,
      headerSha256: sha256(headerBuffer),
      payloadBytes: dataBytes,
      payloadSha256: null,
      payloadHashPolicy: 'not-hashed-by-default',
      tensorCount: entries.length,
      dtypeCounts,
      tensorPreview,
      metadata: header.__metadata__ && typeof header.__metadata__ === 'object' ? header.__metadata__ : null,
      issues
    };
  } finally {
    await handle.close();
  }
}

function inferExportTask(config, explicitTask = null) {
  if (explicitTask != null) {
    const task = String(explicitTask).trim();
    return ALLOWED_TASKS.has(task) ? { task, source: 'explicit' } : { task: null, source: 'explicit', error: `不支持的 ONNX export task: ${task}` };
  }
  const architectures = Array.isArray(config?.architectures) ? config.architectures.filter((value) => typeof value === 'string').slice(0, 32) : [];
  const joined = architectures.join(' ');
  if (/(?:ForCausalLM|LMHeadModel)\b/.test(joined)) return { task: 'text-generation-with-past', source: 'config.architectures' };
  if (/(?:ForConditionalGeneration|ForSeq2SeqLM)\b/.test(joined) || (config?.is_encoder_decoder === true && /Generation/.test(joined))) return { task: 'text2text-generation-with-past', source: 'config.architectures' };
  if (/ForSequenceClassification\b/.test(joined)) return { task: 'text-classification', source: 'config.architectures' };
  if (/ForTokenClassification\b/.test(joined)) return { task: 'token-classification', source: 'config.architectures' };
  if (/ForQuestionAnswering\b/.test(joined)) return { task: 'question-answering', source: 'config.architectures' };
  if (/ForMaskedLM\b/.test(joined)) return { task: 'fill-mask', source: 'config.architectures' };
  if (/ForImageClassification\b/.test(joined)) return { task: 'image-classification', source: 'config.architectures' };
  if (/Model\b/.test(joined) && !/For\w+/.test(joined)) return { task: 'feature-extraction', source: 'config.architectures' };
  return { task: null, source: 'none' };
}

function remoteCodeEvidence(config) {
  const autoMap = config?.auto_map;
  if (!autoMap || typeof autoMap !== 'object' || Array.isArray(autoMap)) return [];
  return Object.keys(autoMap).filter((key) => typeof key === 'string').slice(0, 64);
}

async function inspectHfModelDirectory(rootPath) {
  const root = resolved(rootPath);
  const stat = await fs.lstat(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('HF 模型入口必须是非符号链接目录');
  const entries = (await fs.readdir(root, { withFileTypes: true })).filter((entry) => entry.isFile()).sort((a, b) => a.name.localeCompare(b.name));
  const names = new Set(entries.map((entry) => entry.name));
  let configState = null;
  if (names.has('config.json')) {
    try { configState = await readBoundedJson(path.join(root, 'config.json')); }
    catch (error) { return { schema: 'newcyber.hf-model-bundle.v1', status: 'gap', gap: { code: 'CONFIG_INVALID_GAP', detail: error?.message || String(error) }, root }; }
  }
  let indexState = null;
  const indexName = entries.map((entry) => entry.name).find((name) => /\.safetensors\.index\.json$/i.test(name));
  if (indexName) {
    try { indexState = { name: indexName, ...(await readBoundedJson(path.join(root, indexName))) }; }
    catch (error) { return { schema: 'newcyber.hf-model-bundle.v1', status: 'gap', gap: { code: 'INDEX_INVALID_GAP', detail: error?.message || String(error) }, root }; }
  }
  let shardNames = [];
  if (indexState) {
    const weightMap = indexState.value?.weight_map;
    if (!weightMap || typeof weightMap !== 'object' || Array.isArray(weightMap)) return { schema: 'newcyber.hf-model-bundle.v1', status: 'gap', gap: { code: 'INDEX_INVALID_GAP', detail: `${indexName}: 缺少 weight_map object` }, root };
    const set = new Set();
    for (const value of Object.values(weightMap)) {
      const target = safeRelative(root, value);
      if (!target || path.extname(target).toLowerCase() !== '.safetensors') return { schema: 'newcyber.hf-model-bundle.v1', status: 'gap', gap: { code: 'INDEX_PATH_GAP', detail: `${indexName}: weight_map 包含非法 shard 路径` }, root };
      set.add(path.relative(root, target));
    }
    shardNames = [...set].sort();
  } else {
    shardNames = entries.map((entry) => entry.name).filter((name) => name.toLowerCase().endsWith('.safetensors'));
  }
  if (shardNames.length > MAX_SAFETENSORS_SHARDS) return { schema: 'newcyber.hf-model-bundle.v1', status: 'gap', gap: { code: 'SHARD_BUDGET_GAP', detail: `SafeTensors shards=${shardNames.length} 超过 ${MAX_SAFETENSORS_SHARDS}` }, root };
  const shards = [];
  for (const name of shardNames) {
    const target = safeRelative(root, name);
    if (!target) return { schema: 'newcyber.hf-model-bundle.v1', status: 'gap', gap: { code: 'INDEX_PATH_GAP', detail: `非法 shard 路径 ${name}` }, root };
    try { shards.push(await inspectSafetensorsPath(target)); }
    catch (error) { shards.push({ valid: false, filePath: target, fileName: path.basename(target), issues: [error?.message || String(error)] }); }
  }
  const config = configState?.value || null;
  const architectures = Array.isArray(config?.architectures) ? config.architectures.filter((value) => typeof value === 'string').slice(0, 32) : [];
  const tokenizerFiles = entries.map((entry) => entry.name).filter((name) => ['tokenizer.json', 'tokenizer_config.json', 'vocab.json', 'merges.txt', 'special_tokens_map.json', 'sentencepiece.bpe.model', 'tokenizer.model'].includes(name));
  return {
    schema: 'newcyber.hf-model-bundle.v1',
    status: 'ok',
    root,
    config: config ? {
      file: 'config.json',
      sha256: configState.sha256,
      modelType: typeof config.model_type === 'string' ? config.model_type : null,
      architectures,
      torchDtype: typeof config.torch_dtype === 'string' ? config.torch_dtype : null,
      isEncoderDecoder: config.is_encoder_decoder === true,
      autoMapKeys: remoteCodeEvidence(config)
    } : null,
    rawConfig: config,
    index: indexState ? { file: indexState.name, sha256: indexState.sha256, bytes: indexState.bytes } : null,
    safetensors: shards,
    shardCount: shards.length,
    tensorCount: shards.reduce((sum, shard) => sum + Number(shard.tensorCount || 0), 0),
    modelBytes: shards.reduce((sum, shard) => sum + Number(shard.bytes || 0), 0),
    tokenizerFiles,
    notes: [
      'SafeTensors 仅流式读取 header，不加载 tensor payload，不执行模型代码。',
      '默认不对 GB 级权重 payload 做完整 SHA-256；header/config/index hash 用于结构 provenance。'
    ]
  };
}

async function planHfOnnxExport(rootPath, options = {}) {
  const bundle = await inspectHfModelDirectory(rootPath);
  const base = { schema: 'newcyber.hf-onnx-plan.v1', bundle, status: 'gap', execution: 'not-run' };
  if (bundle.status !== 'ok') return { ...base, gap: bundle.gap };
  if (!bundle.config) return { ...base, gap: { code: 'CONFIG_GAP', detail: '缺少 config.json；不会仅凭 SafeTensors tensor 名称猜模型架构和导出 task' } };
  if (!bundle.safetensors.length) return { ...base, gap: { code: 'WEIGHTS_GAP', detail: '目录中没有 SafeTensors 权重工件' } };
  const invalid = bundle.safetensors.filter((item) => !item.valid);
  if (invalid.length) return { ...base, gap: { code: 'ARTIFACT_INVALID_GAP', detail: `SafeTensors 结构校验失败：${invalid.slice(0, 4).map((item) => `${item.fileName}: ${(item.issues || []).slice(0, 2).join('; ')}`).join(' | ')}` } };
  const remote = bundle.config.autoMapKeys || [];
  if (remote.length) return { ...base, gap: { code: 'REMOTE_CODE_GAP', detail: `config.auto_map=${remote.join(', ')}；NewCyber 不会自动启用 trust_remote_code 或执行模型仓库 Python` } };
  const task = inferExportTask(bundle.rawConfig, options.task || null);
  if (!task.task) return { ...base, gap: { code: 'TASK_INFERENCE_GAP', detail: task.error || `无法从 config.architectures=${(bundle.config.architectures || []).join(', ') || '[]'} 唯一确定 Optimum ONNX task` } };
  const outputDir = options.outputDir ? resolved(options.outputDir) : path.join(bundle.root, 'newcyber_onnx');
  const args = ['export', 'onnx', '--model', bundle.root, '--task', task.task, '--framework', 'pt', outputDir];
  return {
    ...base,
    status: 'ready',
    gap: null,
    task,
    converter: {
      executable: 'optimum-cli',
      args,
      shell: false,
      cwd: bundle.root,
      env: { HF_HUB_OFFLINE: '1', TRANSFORMERS_OFFLINE: '1', HF_DATASETS_OFFLINE: '1' },
      networkPolicy: 'offline-only',
      trustRemoteCode: false
    },
    output: { directory: outputDir, format: 'ONNX', expectedFiles: 'converter-determined' },
    policy: {
      execution: 'manual-trusted-converter-only',
      challengePythonExecuted: false,
      remoteCodeAllowed: false,
      sourcePayloadFullyHashed: false
    },
    evidence: [
      `config.json sha256=${bundle.config.sha256}`,
      `architectures=${bundle.config.architectures.join(', ') || 'unknown'}`,
      `SafeTensors shards=${bundle.shardCount}, tensors=${bundle.tensorCount}`,
      `task=${task.task} from ${task.source}`
    ]
  };
}

module.exports = {
  MAX_SAFETENSORS_HEADER,
  MAX_SAFETENSORS_SHARDS,
  ALLOWED_TASKS,
  inspectSafetensorsPath,
  inspectHfModelDirectory,
  inferExportTask,
  planHfOnnxExport
};
