'use strict';

const { parseZipCentralDirectory, extractZipEntry } = require('./model');
const { parseNpyAdvanced } = require('./model_artifacts');
const { solveBoundedModular } = require('./bounded_modular');
const { recoverFlagFromSecret } = require('./secret_flag_recovery');

const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_EXTRACTED = 96 * 1024 * 1024;
const MAX_FILES = 256;
const MAX_NPY_ELEMENTS = 1_000_000;
const MAX_SOURCE_BYTES = 2 * 1024 * 1024;

function mod(value, q) {
  const result = value % q;
  return result < 0 ? result + q : result;
}

function basename(name) {
  return String(name || '').replace(/\\/g, '/').split('/').filter(Boolean).pop() || '';
}

function safeFileName(name) {
  return String(name || '').replace(/\\/g, '/').replace(/^\/+/, '').slice(0, 500);
}

function bundleFromZip(buffer) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) throw new Error('ZIP 输入为空');
  if (buffer.length > MAX_ARCHIVE_BYTES) throw new Error(`ZIP 超过 ${MAX_ARCHIVE_BYTES} bytes 上限`);
  const zip = parseZipCentralDirectory(buffer);
  if (!zip) throw new Error('不是可识别的 ZIP');
  const files = [];
  let totalExtracted = 0;
  for (const entry of zip.entries.slice(0, MAX_FILES)) {
    if (!entry?.name || /\/$/.test(entry.name)) continue;
    const data = extractZipEntry(buffer, entry);
    if (!data) continue;
    totalExtracted += data.length;
    if (totalExtracted > MAX_TOTAL_EXTRACTED) throw new Error(`ZIP 解压后超过 ${MAX_TOTAL_EXTRACTED} bytes 上限`);
    files.push({ name: safeFileName(entry.name), buffer: data });
  }
  return files;
}

function bundleFromFileList(items) {
  if (!Array.isArray(items)) return [];
  const files = [];
  let total = 0;
  for (const item of items.slice(0, MAX_FILES)) {
    if (!item || typeof item !== 'object') continue;
    const name = safeFileName(item.name || item.fileName || `file-${files.length}`);
    let buffer = null;
    if (typeof item.base64 === 'string') buffer = Buffer.from(item.base64, 'base64');
    else if (typeof item.text === 'string') buffer = Buffer.from(item.text, 'utf8');
    if (!buffer?.length) continue;
    total += buffer.length;
    if (total > MAX_TOTAL_EXTRACTED) throw new Error(`输入文件总量超过 ${MAX_TOTAL_EXTRACTED} bytes 上限`);
    files.push({ name, buffer });
  }
  return files;
}

function normalizeBundle(input) {
  if (!input || typeof input !== 'object') throw new Error('模型算术工作台需要 ZIP 或 files 输入');
  if (typeof input.base64 === 'string') return bundleFromZip(Buffer.from(input.base64, 'base64'));
  if (Array.isArray(input.files)) return bundleFromFileList(input.files);
  throw new Error('输入需要 {base64} ZIP 或 {files:[{name,base64/text}]}');
}

function npyNumericDescriptor(descr) {
  const match = String(descr || '').match(/^([<>=|])?([?bBiuf])([0-9]+)$/);
  if (!match) return null;
  return { endian: match[1] || '=', kind: match[2], bytes: Number(match[3]) };
}

function readNumericNpy(buffer, fileName = 'sample.npy') {
  const parsed = parseNpyAdvanced(buffer);
  if (!parsed) return null;
  if (!parsed.valid || parsed.objectDtype || parsed.fortranOrder) {
    return { fileName, parsed, supported: false, reason: parsed.objectDtype ? 'object-dtype' : parsed.fortranOrder ? 'fortran-order' : 'invalid-npy' };
  }
  const descriptor = npyNumericDescriptor(parsed.descr);
  if (!descriptor || !parsed.shape || parsed.itemBytes !== descriptor.bytes) return { fileName, parsed, supported: false, reason: 'numeric-dtype-unsupported' };
  const elementCount = parsed.shape.reduce((product, value) => product * value, 1);
  if (!Number.isSafeInteger(elementCount) || elementCount < 0 || elementCount > MAX_NPY_ELEMENTS) {
    return { fileName, parsed, supported: false, reason: 'element-count-limit' };
  }
  const expectedBytes = elementCount * descriptor.bytes;
  if (parsed.payloadOffset + expectedBytes !== buffer.length) return { fileName, parsed, supported: false, reason: 'payload-length-mismatch' };

  const little = descriptor.endian !== '>';
  const values = new Array(elementCount);
  for (let index = 0; index < elementCount; index += 1) {
    const offset = parsed.payloadOffset + index * descriptor.bytes;
    let value;
    if (descriptor.kind === 'i' || descriptor.kind === 'b') {
      if (descriptor.bytes === 1) value = buffer.readInt8(offset);
      else if (descriptor.bytes === 2) value = little ? buffer.readInt16LE(offset) : buffer.readInt16BE(offset);
      else if (descriptor.bytes === 4) value = little ? buffer.readInt32LE(offset) : buffer.readInt32BE(offset);
      else if (descriptor.bytes === 8) {
        const big = little ? buffer.readBigInt64LE(offset) : buffer.readBigInt64BE(offset);
        if (big < BigInt(Number.MIN_SAFE_INTEGER) || big > BigInt(Number.MAX_SAFE_INTEGER)) return { fileName, parsed, supported: false, reason: 'int64-outside-safe-range' };
        value = Number(big);
      } else return { fileName, parsed, supported: false, reason: 'signed-width-unsupported' };
    } else if (descriptor.kind === 'u' || descriptor.kind === 'B' || descriptor.kind === '?') {
      if (descriptor.bytes === 1) value = buffer.readUInt8(offset);
      else if (descriptor.bytes === 2) value = little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
      else if (descriptor.bytes === 4) value = little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
      else if (descriptor.bytes === 8) {
        const big = little ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
        if (big > BigInt(Number.MAX_SAFE_INTEGER)) return { fileName, parsed, supported: false, reason: 'uint64-outside-safe-range' };
        value = Number(big);
      } else return { fileName, parsed, supported: false, reason: 'unsigned-width-unsupported' };
    } else if (descriptor.kind === 'f') {
      if (descriptor.bytes === 4) value = little ? buffer.readFloatLE(offset) : buffer.readFloatBE(offset);
      else if (descriptor.bytes === 8) value = little ? buffer.readDoubleLE(offset) : buffer.readDoubleBE(offset);
      else return { fileName, parsed, supported: false, reason: 'float-width-unsupported' };
    } else return { fileName, parsed, supported: false, reason: 'dtype-kind-unsupported' };
    values[index] = value;
  }
  return { fileName, parsed, supported: true, shape: parsed.shape, descr: parsed.descr, values };
}

function reshape(values, shape) {
  if (shape.length === 1) return values.slice();
  if (shape.length === 2) {
    const [rows, cols] = shape;
    return Array.from({ length: rows }, (_, row) => values.slice(row * cols, (row + 1) * cols));
  }
  if (shape.length === 3) {
    const [batch, rows, cols] = shape;
    return Array.from({ length: batch }, (_, sample) => Array.from({ length: rows }, (_, row) => {
      const start = (sample * rows + row) * cols;
      return values.slice(start, start + cols);
    }));
  }
  return null;
}

function recursiveFirst(object, keys) {
  if (!object || typeof object !== 'object') return null;
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(object, key)) return object[key];
  }
  for (const value of Object.values(object)) {
    const found = recursiveFirst(value, keys);
    if (found != null) return found;
  }
  return null;
}

function numericMatrix(value) {
  return Array.isArray(value) && value.length > 0 && value.every((row) => Array.isArray(row) && row.length === value[0].length && row.every(Number.isFinite));
}

function sourceLineEvidence(source, pattern) {
  return String(source || '').split(/\r?\n/).map((line, index) => ({ line: index + 1, text: line.trim() })).filter((item) => pattern.test(item.text)).slice(0, 8);
}

function inspectArithmeticSource(source) {
  const text = String(source || '').slice(0, MAX_SOURCE_BYTES);
  const dotEvidence = sourceLineEvidence(text, /(?:np\.)?dot\s*\(/i);
  const boundedNoiseEvidence = sourceLineEvidence(text, /(?:random|np\.random)\.(?:randint|integers)\s*\(/i);
  const moduloEvidence = sourceLineEvidence(text, /%\s*[A-Za-z_]\w*/);
  const convEvidence = sourceLineEvidence(text, /conv\w*\s*\(/i);
  const reluEvidence = sourceLineEvidence(text, /relu\s*\(|maximum\s*\([^,]+,\s*0\s*\)/i);
  const poolEvidence = sourceLineEvidence(text, /avgpool|pool2x2|pool\w*\s*\(/i);
  const concatEvidence = sourceLineEvidence(text, /concatenate\s*\(/i);
  const matrixMixEvidence = sourceLineEvidence(text, /@\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*@/);
  return {
    boundedLinearHead: dotEvidence.length > 0 && boundedNoiseEvidence.length > 0 && moduloEvidence.length > 0,
    cnnFeatureFamily: convEvidence.length > 0 && reluEvidence.length > 0 && poolEvidence.length > 0 && concatEvidence.length > 0 && matrixMixEvidence.length > 0,
    evidence: { dot: dotEvidence, boundedNoise: boundedNoiseEvidence, modulo: moduloEvidence, conv: convEvidence, relu: reluEvidence, pool: poolEvidence, concat: concatEvidence, mix: matrixMixEvidence }
  };
}

function extractPublicConfig(jsonObjects) {
  const candidates = [];
  for (const item of jsonObjects) {
    const object = item.value;
    const modulus = Number(recursiveFirst(object, ['q', 'modulus', 'prime_modulus']));
    const noiseBound = Number(recursiveFirst(object, ['noise_bound', 'error_bound', 'noiseBound', 'bounded_error']));
    const mix = recursiveFirst(object, ['mix', 'MIX', 'transform', 'feature_mix']);
    const explicitA = recursiveFirst(object, ['A', 'a_matrix', 'feature_matrix', 'features']);
    const kernelObject = recursiveFirst(object, ['kernels', 'filters']);
    const kernels = [];
    if (kernelObject && typeof kernelObject === 'object' && !Array.isArray(kernelObject)) {
      for (const [name, value] of Object.entries(kernelObject)) if (numericMatrix(value)) kernels.push({ name, matrix: value });
    }
    let score = 0;
    if (Number.isSafeInteger(modulus) && modulus > 1) score += 4;
    if (Number.isSafeInteger(noiseBound) && noiseBound >= 0) score += 4;
    if (numericMatrix(mix)) score += 2;
    if (numericMatrix(explicitA)) score += 3;
    if (kernels.length) score += 2;
    candidates.push({ fileName: item.fileName, object, modulus, noiseBound, mix, explicitA, kernels, score });
  }
  candidates.sort((left, right) => right.score - left.score || left.fileName.localeCompare(right.fileName));
  return candidates[0] || { fileName: null, object: {}, modulus: NaN, noiseBound: NaN, mix: null, explicitA: null, kernels: [], score: 0 };
}

function convValid(input, kernel) {
  const rows = input.length;
  const cols = input[0].length;
  const kernelRows = kernel.length;
  const kernelCols = kernel[0].length;
  if (kernelRows > rows || kernelCols > cols) throw new Error('卷积核大于输入尺寸');
  const output = Array.from({ length: rows - kernelRows + 1 }, () => Array(cols - kernelCols + 1).fill(0));
  for (let row = 0; row < output.length; row += 1) {
    for (let col = 0; col < output[0].length; col += 1) {
      let sum = 0;
      for (let kr = 0; kr < kernelRows; kr += 1) {
        for (let kc = 0; kc < kernelCols; kc += 1) sum += input[row + kr][col + kc] * kernel[kr][kc];
      }
      output[row][col] = sum;
    }
  }
  return output;
}

function relu(matrix) {
  return matrix.map((row) => row.map((value) => Math.max(0, value)));
}

function avgPool2x2(matrix) {
  const rows = Math.floor(matrix.length / 2);
  const cols = Math.floor(matrix[0].length / 2);
  if (!rows || !cols) throw new Error('2x2 avgpool 后没有输出元素');
  const output = Array.from({ length: rows }, () => Array(cols).fill(0));
  for (let row = 0; row < rows; row += 1) {
    for (let col = 0; col < cols; col += 1) {
      let sum = 0;
      for (let dr = 0; dr < 2; dr += 1) for (let dc = 0; dc < 2; dc += 1) sum += matrix[row * 2 + dr][col * 2 + dc];
      output[row][col] = Math.floor(sum / 4);
    }
  }
  return output;
}

function matrixVectorMod(matrix, vector, q) {
  return matrix.map((row) => {
    if (row.length !== vector.length) throw new Error(`矩阵列数 ${row.length} 与 feature 维数 ${vector.length} 不一致`);
    let sum = 0;
    for (let index = 0; index < row.length; index += 1) sum = mod(sum + mod(row[index], q) * mod(vector[index], q), q);
    return sum;
  });
}

function buildFeatureSystem(inputArray, publicConfig, sourceInspection) {
  const q = publicConfig.modulus;
  if (!Number.isSafeInteger(q) || q < 2) throw new Error('没有可靠提取 modulus/q');

  if (numericMatrix(publicConfig.explicitA)) {
    return { method: 'public-feature-matrix', A: publicConfig.explicitA.map((row) => row.map((value) => mod(Number(value), q))), featureDimension: publicConfig.explicitA[0].length };
  }

  if (inputArray.shape.length === 2) {
    const matrix = reshape(inputArray.values, inputArray.shape);
    if (matrix.every((row) => row.every(Number.isSafeInteger))) {
      return { method: 'direct-matrix-input', A: matrix.map((row) => row.map((value) => mod(value, q))), featureDimension: matrix[0].length };
    }
  }

  if (!sourceInspection.cnnFeatureFamily) throw new Error('输入不是直接 A 矩阵，且源码未建立受支持的 CNN feature family');
  if (inputArray.shape.length !== 3) throw new Error('CNN feature recipe 当前需要 [samples,height,width] NPY');
  if (!publicConfig.kernels.length || !numericMatrix(publicConfig.mix)) throw new Error('CNN feature recipe 缺 kernels 或 mix 矩阵');

  const samples = reshape(inputArray.values, inputArray.shape);
  const A = [];
  for (const sample of samples) {
    const base = [];
    for (const kernel of publicConfig.kernels) {
      const pooled = avgPool2x2(relu(convValid(sample, kernel.matrix)));
      for (const row of pooled) base.push(...row);
    }
    A.push(matrixVectorMod(publicConfig.mix, base, q));
  }
  return { method: 'conv-relu-avgpool2x2-concat-mix', A, featureDimension: A[0]?.length || 0, kernelCount: publicConfig.kernels.length };
}

function chooseNpyPair(arrays) {
  let best = null;
  for (const output of arrays.filter((item) => item.supported && item.shape.length === 1)) {
    for (const input of arrays.filter((item) => item.supported && item !== output && item.shape.length >= 2 && item.shape[0] === output.shape[0])) {
      let score = 0;
      if (/output|label|target|response|\bb\b/i.test(basename(output.fileName))) score += 4;
      if (/input|sample|query|feature|\ba\b/i.test(basename(input.fileName))) score += 4;
      if (input.values.every(Number.isSafeInteger)) score += 2;
      if (output.values.every(Number.isSafeInteger)) score += 2;
      const candidate = { input, output, score };
      if (!best || candidate.score > best.score || (candidate.score === best.score && input.fileName.localeCompare(best.input.fileName) < 0)) best = candidate;
    }
  }
  return best;
}

function parseJsonFiles(files) {
  const rows = [];
  for (const file of files.filter((item) => /\.json$/i.test(item.name))) {
    try {
      rows.push({ fileName: file.name, value: JSON.parse(file.buffer.toString('utf8')) });
    } catch {}
  }
  return rows;
}

function sourceFiles(files) {
  return files.filter((item) => /\.(?:py|pyw)$/i.test(item.name) && item.buffer.length <= MAX_SOURCE_BYTES)
    .map((item) => ({ fileName: item.name, text: item.buffer.toString('utf8') }));
}

function analyzeModelArithmeticBundle(input, options = {}) {
  const files = normalizeBundle(input);
  const sources = sourceFiles(files);
  const source = sources.map((item) => `# FILE: ${item.fileName}\n${item.text}`).join('\n\n');
  const sourceInspection = inspectArithmeticSource(source);
  const jsonFiles = parseJsonFiles(files);
  const publicConfig = extractPublicConfig(jsonFiles);
  const arrays = files.filter((item) => /\.npy$/i.test(item.name)).map((item) => readNumericNpy(item.buffer, item.name)).filter(Boolean);
  const pair = chooseNpyPair(arrays);

  const artifactSummary = {
    files: files.map((file) => ({ name: file.name, bytes: file.buffer.length })),
    pythonFiles: sources.map((item) => item.fileName),
    jsonFiles: jsonFiles.map((item) => item.fileName),
    npyFiles: arrays.map((item) => ({ fileName: item.fileName, shape: item.parsed?.shape || null, dtype: item.parsed?.descr || null, supported: item.supported, reason: item.reason || null }))
  };

  if (!sourceInspection.boundedLinearHead && options.assumeBoundedLinear !== true) {
    return {
      schema: 'newcyber.ai-model-arithmetic.v1', status: 'identified-no-linear-proof', artifactSummary, sourceInspection,
      notes: ['没有从源码中同时找到 dot/线性头、bounded random noise、modulo 三类证据，因此不会把普通 NPY 自动解释成 LWE/小噪声线性系统。']
    };
  }
  if (!pair) {
    return {
      schema: 'newcyber.ai-model-arithmetic.v1', status: 'missing-sample-pair', artifactSummary, sourceInspection,
      publicConfig: { fileName: publicConfig.fileName, modulus: publicConfig.modulus, noiseBound: publicConfig.noiseBound },
      notes: ['没有找到同 sample 数量的 input NPY + 1D output NPY 组合。']
    };
  }
  if (!Number.isSafeInteger(publicConfig.modulus) || !Number.isSafeInteger(publicConfig.noiseBound)) {
    return {
      schema: 'newcyber.ai-model-arithmetic.v1', status: 'missing-public-parameters', artifactSummary, sourceInspection,
      notes: ['没有可靠提取 q/modulus 与 noise_bound/error_bound。']
    };
  }

  let featureSystem;
  try {
    featureSystem = buildFeatureSystem(pair.input, publicConfig, sourceInspection);
  } catch (error) {
    return {
      schema: 'newcyber.ai-model-arithmetic.v1', status: 'feature-recipe-gap', artifactSummary, sourceInspection,
      publicConfig: { fileName: publicConfig.fileName, modulus: publicConfig.modulus, noiseBound: publicConfig.noiseBound, kernelCount: publicConfig.kernels.length },
      samplePair: { input: pair.input.fileName, output: pair.output.fileName, inputShape: pair.input.shape, outputShape: pair.output.shape },
      gap: error?.message || String(error),
      notes: ['源码关系已经像 bounded modular head，但 feature frontend 不在当前 deterministic recipe 集合里；不会执行不可信 Python 来强行获得 A。']
    };
  }

  const b = pair.output.values;
  if (!b.every(Number.isSafeInteger)) throw new Error('output NPY 不是安全整数，当前 modular solver 不处理浮点目标');
  if (featureSystem.A.length !== b.length) throw new Error('feature A 行数与 output 样本数不一致');

  const solver = solveBoundedModular(featureSystem.A, b, publicConfig.modulus, publicConfig.noiseBound, {
    maxEnumerations: options.maxEnumerations
  });
  let flagRecovery = null;
  if (solver.status === 'unique' && solver.candidates[0]) {
    flagRecovery = recoverFlagFromSecret(solver.candidates[0].secretSigned, {
      modulus: publicConfig.modulus,
      files,
      publicConfig: publicConfig.object
    });
  }

  const status = flagRecovery?.status === 'flag-recovered'
    ? 'flag-recovered'
    : solver.status === 'unique'
      ? 'secret-recovered'
      : solver.status === 'search-too-large'
        ? 'solver-budget-gap'
        : 'solver-incomplete';

  return {
    schema: 'newcyber.ai-model-arithmetic.v1',
    status,
    artifactSummary,
    sourceInspection,
    publicConfig: {
      fileName: publicConfig.fileName,
      modulus: publicConfig.modulus,
      noiseBound: publicConfig.noiseBound,
      kernels: publicConfig.kernels.map((item) => ({ name: item.name, shape: [item.matrix.length, item.matrix[0].length] })),
      mixShape: numericMatrix(publicConfig.mix) ? [publicConfig.mix.length, publicConfig.mix[0].length] : null
    },
    samplePair: {
      input: pair.input.fileName,
      output: pair.output.fileName,
      inputShape: pair.input.shape,
      outputShape: pair.output.shape,
      samples: b.length
    },
    featureSystem: {
      method: featureSystem.method,
      rows: featureSystem.A.length,
      dimension: featureSystem.A[0]?.length || 0,
      kernelCount: featureSystem.kernelCount || 0
    },
    solver,
    flagRecovery,
    flag: flagRecovery?.flag || null,
    notes: [
      '不执行 task.py / NumPy pickle；Python 只作为静态证据，用受限 deterministic recipe 重建 feature matrix。',
      '没有写死题目文件名、固定 q、固定 secret 维数或 flag；solver 由样本 shape/public 参数动态决定。',
      '当 (2B+1)^n 超过预算时返回 solver-budget-gap，而不是无限枚举或伪造结果。'
    ]
  };
}

module.exports = {
  normalizeBundle,
  readNumericNpy,
  inspectArithmeticSource,
  extractPublicConfig,
  buildFeatureSystem,
  chooseNpyPair,
  analyzeModelArithmeticBundle
};