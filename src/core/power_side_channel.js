'use strict';

const fs = require('fs/promises');
const path = require('path');

const MAX_HEADER_BYTES = 1024 * 1024;
const MAX_TRACE_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_ROWS = 200_000;
const MAX_WINDOW_SAMPLES = 1_000_000;
const MAX_FEATURE_VALUES = 2_000_000;
const SOURCE_LIMIT = 2 * 1024 * 1024;

function safeProduct(values) {
  let result = 1;
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('NPY shape 包含非法维度');
    result *= value;
    if (!Number.isSafeInteger(result)) throw new Error('NPY shape 元素数超出安全整数范围');
  }
  return result;
}

function parseNpyHeaderText(text) {
  const descr = String(text).match(/['"]descr['"]\s*:\s*['"]([^'"]+)['"]/i)?.[1] || null;
  const fortranToken = String(text).match(/['"]fortran_order['"]\s*:\s*(True|False)/i)?.[1] || null;
  const shapeToken = String(text).match(/['"]shape['"]\s*:\s*\(([^)]*)\)/i)?.[1] || null;
  if (!descr || !fortranToken || shapeToken == null) throw new Error('NPY header 缺 descr/fortran_order/shape');
  const shape = shapeToken.split(',').map((item) => item.trim()).filter(Boolean).map(Number);
  if (!shape.length || shape.some((value) => !Number.isSafeInteger(value) || value < 0)) throw new Error('NPY shape 无法解析');
  return { descr, fortranOrder: /^true$/i.test(fortranToken), shape };
}

function numericDescriptor(descr) {
  const match = String(descr || '').match(/^([<>=|])?([fiu])([1248])$/i);
  if (!match) return null;
  const kind = match[2].toLowerCase();
  const bytes = Number(match[3]);
  if (kind === 'f' && ![4, 8].includes(bytes)) return null;
  if (kind !== 'f' && ![1, 2, 4, 8].includes(bytes)) return null;
  return { endian: match[1] || '=', kind, bytes };
}

async function readNpyHeaderPath(filePath) {
  const resolved = path.resolve(String(filePath || ''));
  const stat = await fs.stat(resolved);
  if (!stat.isFile()) throw new Error('NPY trace 不是普通文件');
  if (stat.size <= 0) throw new Error('NPY trace 为空');
  if (stat.size > MAX_TRACE_BYTES) throw new Error(`NPY trace 超过 ${MAX_TRACE_BYTES} bytes 上限`);
  const handle = await fs.open(resolved, 'r');
  try {
    const lead = Buffer.alloc(12);
    const first = await handle.read(lead, 0, lead.length, 0);
    if (first.bytesRead < 10 || lead[0] !== 0x93 || lead.subarray(1, 6).toString('ascii') !== 'NUMPY') throw new Error('不是可识别的 NPY');
    const major = lead[6];
    const minor = lead[7];
    let headerLength;
    let headerOffset;
    if (major === 1) {
      headerLength = lead.readUInt16LE(8);
      headerOffset = 10;
    } else if (major === 2 || major === 3) {
      if (first.bytesRead < 12) throw new Error('NPY v2/v3 header 截断');
      headerLength = lead.readUInt32LE(8);
      headerOffset = 12;
    } else throw new Error(`不支持 NPY version ${major}.${minor}`);
    if (!Number.isSafeInteger(headerLength) || headerLength <= 0 || headerLength > MAX_HEADER_BYTES) throw new Error('NPY header 长度异常');
    if (headerOffset + headerLength > stat.size) throw new Error('NPY header 越界');
    const headerBuffer = Buffer.alloc(headerLength);
    const read = await handle.read(headerBuffer, 0, headerLength, headerOffset);
    if (read.bytesRead !== headerLength) throw new Error('NPY header 读取不完整');
    const parsed = parseNpyHeaderText(headerBuffer.toString(major === 3 ? 'utf8' : 'latin1'));
    const descriptor = numericDescriptor(parsed.descr);
    if (!descriptor) throw new Error(`侧信道流式读取暂不支持 dtype ${parsed.descr}`);
    if (parsed.fortranOrder) throw new Error('侧信道流式读取暂不支持 Fortran-order NPY');
    const elements = safeProduct(parsed.shape);
    const payloadOffset = headerOffset + headerLength;
    const payloadBytes = elements * descriptor.bytes;
    if (!Number.isSafeInteger(payloadBytes) || payloadOffset + payloadBytes !== stat.size) throw new Error('NPY payload 长度与 shape/dtype 不一致');
    return {
      filePath: resolved,
      fileName: path.basename(resolved),
      size: stat.size,
      version: `${major}.${minor}`,
      descr: parsed.descr,
      shape: parsed.shape,
      elements,
      payloadOffset,
      payloadBytes,
      descriptor
    };
  } finally {
    await handle.close();
  }
}

function readNumber(buffer, offset, descriptor) {
  const little = descriptor.endian !== '>';
  if (descriptor.kind === 'f') return descriptor.bytes === 4
    ? (little ? buffer.readFloatLE(offset) : buffer.readFloatBE(offset))
    : (little ? buffer.readDoubleLE(offset) : buffer.readDoubleBE(offset));
  if (descriptor.kind === 'i') {
    if (descriptor.bytes === 1) return buffer.readInt8(offset);
    if (descriptor.bytes === 2) return little ? buffer.readInt16LE(offset) : buffer.readInt16BE(offset);
    if (descriptor.bytes === 4) return little ? buffer.readInt32LE(offset) : buffer.readInt32BE(offset);
    const value = little ? buffer.readBigInt64LE(offset) : buffer.readBigInt64BE(offset);
    if (value < BigInt(Number.MIN_SAFE_INTEGER) || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('int64 trace 超出 JS 安全整数范围');
    return Number(value);
  }
  if (descriptor.bytes === 1) return buffer.readUInt8(offset);
  if (descriptor.bytes === 2) return little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
  if (descriptor.bytes === 4) return little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
  const value = little ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('uint64 trace 超出 JS 安全整数范围');
  return Number(value);
}

function metricValue(buffer, descriptor, startSample, length, metric) {
  const byteWidth = descriptor.bytes;
  let sum = 0;
  let sumSquares = 0;
  let sumAbs = 0;
  let min = Infinity;
  let max = -Infinity;
  for (let index = 0; index < length; index += 1) {
    const value = readNumber(buffer, (startSample + index) * byteWidth, descriptor);
    if (!Number.isFinite(value)) continue;
    sum += value;
    sumSquares += value * value;
    sumAbs += Math.abs(value);
    if (value < min) min = value;
    if (value > max) max = value;
  }
  if (metric === 'sum') return sum;
  if (metric === 'mean') return sum / length;
  if (metric === 'sum-abs') return sumAbs;
  if (metric === 'mean-abs') return sumAbs / length;
  if (metric === 'mean-square') return sumSquares / length;
  if (metric === 'peak-to-peak') return Number.isFinite(min) && Number.isFinite(max) ? max - min : 0;
  return sumSquares;
}

function normalizeWindows(windows, samplesPerRow) {
  const source = Array.isArray(windows) && windows.length ? windows : [{ id: 'energy', offset: 0, length: samplesPerRow, metric: 'sum-squares' }];
  if (source.length > 128) throw new Error('窗口数量超过 128 上限');
  return source.map((item, index) => {
    const offset = Number(item.offset ?? 0);
    const length = Number(item.length ?? samplesPerRow);
    const metric = String(item.metric || 'sum-squares').toLowerCase();
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length <= 0) throw new Error(`窗口 ${index} offset/length 非法`);
    if (offset + length > samplesPerRow) throw new Error(`窗口 ${index} 超出每行 ${samplesPerRow} samples`);
    if (length > MAX_WINDOW_SAMPLES) throw new Error(`窗口 ${index} 超过 ${MAX_WINDOW_SAMPLES} samples 上限`);
    if (!['sum-squares', 'mean-square', 'sum', 'mean', 'sum-abs', 'mean-abs', 'peak-to-peak'].includes(metric)) throw new Error(`不支持窗口 metric ${metric}`);
    return { id: String(item.id || `window-${index}`), offset, length, metric };
  });
}

async function extractWindowFeatures(filePath, options = {}) {
  const header = options.header || await readNpyHeaderPath(filePath);
  let samplesPerRow = Number(options.samplesPerRow || 0);
  let rowCount;
  if (!samplesPerRow && header.shape.length === 2) samplesPerRow = header.shape[1];
  if (!Number.isSafeInteger(samplesPerRow) || samplesPerRow <= 0) throw new Error('需要 samplesPerRow，或输入必须是二维 NPY');
  if (header.elements % samplesPerRow !== 0) throw new Error(`NPY 元素数 ${header.elements} 不能整除 samplesPerRow=${samplesPerRow}`);
  rowCount = header.elements / samplesPerRow;
  if (!Number.isSafeInteger(rowCount) || rowCount <= 0 || rowCount > MAX_ROWS) throw new Error(`trace rows=${rowCount} 超过 ${MAX_ROWS} 上限`);
  const windows = normalizeWindows(options.windows, samplesPerRow);
  if (rowCount * windows.length > MAX_FEATURE_VALUES) throw new Error(`feature 数量超过 ${MAX_FEATURE_VALUES} 上限`);
  const minOffset = Math.min(...windows.map((item) => item.offset));
  const maxEnd = Math.max(...windows.map((item) => item.offset + item.length));
  const spanSamples = maxEnd - minOffset;
  if (spanSamples > MAX_WINDOW_SAMPLES) throw new Error('窗口联合跨度过大');
  const spanBytes = spanSamples * header.descriptor.bytes;
  const rowStrideBytes = samplesPerRow * header.descriptor.bytes;
  const buffer = Buffer.allocUnsafe(spanBytes);
  const features = Array.from({ length: rowCount }, () => Array(windows.length).fill(0));
  const handle = await fs.open(header.filePath, 'r');
  try {
    for (let row = 0; row < rowCount; row += 1) {
      const position = header.payloadOffset + row * rowStrideBytes + minOffset * header.descriptor.bytes;
      const read = await handle.read(buffer, 0, spanBytes, position);
      if (read.bytesRead !== spanBytes) throw new Error(`trace row ${row} 读取不完整`);
      for (let index = 0; index < windows.length; index += 1) {
        const window = windows[index];
        features[row][index] = metricValue(buffer, header.descriptor, window.offset - minOffset, window.length, window.metric);
      }
    }
  } finally {
    await handle.close();
  }
  return {
    schema: 'newcyber.sca-window-features.v1',
    filePath: header.filePath,
    rows: rowCount,
    samplesPerRow,
    windows,
    features
  };
}

function sourceEvidence(source, pattern, limit = 12) {
  return String(source || '').split(/\r?\n/).map((text, index) => ({ line: index + 1, text: text.trim() })).filter((item) => pattern.test(item.text)).slice(0, limit);
}

function inspectScaSource(source) {
  const text = String(source || '').slice(0, SOURCE_LIMIT);
  const constants = {};
  const assignments = [];
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const match = line.match(/^\s*([A-Z][A-Z0-9_]{1,63})\s*=\s*(-?\d+(?:\.\d+)?)\s*(?:#.*)?$/);
    if (!match) continue;
    const value = Number(match[2]);
    if (!Number.isFinite(value)) continue;
    constants[match[1]] = value;
    assignments.push({ line: index + 1, name: match[1], value });
  }
  const reshapeEvidence = sourceEvidence(text, /(?:reshape|view)\s*\([^\n]*-1\s*,\s*\d+/i);
  let reshapeWidth = null;
  for (const item of reshapeEvidence) {
    const match = item.text.match(/(?:reshape|view)\s*\([^\n]*-1\s*,\s*(\d+)/i);
    if (match) { reshapeWidth = Number(match[1]); break; }
  }
  const widthNames = ['SAMPLES_PER_ROW', 'SAMPLES_PER_TRACE', 'TRACE_SAMPLES', 'TRACE_WIDTH', 'ROW_SAMPLES', 'POWER_SAMPLES'];
  const explicitWidth = widthNames.map((name) => constants[name]).find((value) => Number.isSafeInteger(value) && value > 0) || null;
  const hiddenState = sourceEvidence(text, /output_hidden_states|hidden_states|last_hidden_state/i);
  const kvCache = sourceEvidence(text, /past_key_values|use_cache\s*=\s*True|kv[_-]?cache/i);
  const modelForward = sourceEvidence(text, /\bmodel\s*\(|\btransformer\s*\(|AutoModel|GPT2(?:Model|LMHeadModel)/i);
  const pinv = sourceEvidence(text, /\bpinv\s*\(|pseudo(?:verse)?|lstsq\s*\(|least[_ -]?squares/i);
  const regression = sourceEvidence(text, /ridge|normal[_ -]?equation|X\.T\s*@|\.T\s*@\s*X/i);
  const todo = sourceEvidence(text, /NotImplementedError|\bTODO\b|raise\s+NotImplemented/i);
  const probe = sourceEvidence(text, /probe|768\s*[x×]\s*768|768\s*,\s*768|matmul|einsum/i);
  return {
    constants,
    assignments: assignments.slice(0, 64),
    samplesPerRow: explicitWidth || reshapeWidth,
    requiresModelForward: hiddenState.length > 0 || kvCache.length > 0,
    usesKvCache: kvCache.length > 0,
    usesHiddenStates: hiddenState.length > 0,
    evidence: { reshape: reshapeEvidence, hiddenState, kvCache, modelForward, pinv, regression, todo, probe }
  };
}

function matrixShape(matrix) {
  if (!Array.isArray(matrix) || !matrix.length || !Array.isArray(matrix[0]) || !matrix[0].length) throw new Error('矩阵为空');
  const cols = matrix[0].length;
  for (const row of matrix) if (!Array.isArray(row) || row.length !== cols || row.some((value) => !Number.isFinite(Number(value)))) throw new Error('矩阵必须是规则有限数值矩阵');
  return [matrix.length, cols];
}

function transpose(matrix) {
  const [rows, cols] = matrixShape(matrix);
  return Array.from({ length: cols }, (_, col) => Array.from({ length: rows }, (_, row) => Number(matrix[row][col])));
}

function matMul(left, right) {
  const [lr, lc] = matrixShape(left);
  const [rr, rc] = matrixShape(right);
  if (lc !== rr) throw new Error(`矩阵维数不匹配 ${lr}x${lc} · ${rr}x${rc}`);
  const output = Array.from({ length: lr }, () => Array(rc).fill(0));
  for (let i = 0; i < lr; i += 1) for (let k = 0; k < lc; k += 1) {
    const value = Number(left[i][k]);
    for (let j = 0; j < rc; j += 1) output[i][j] += value * Number(right[k][j]);
  }
  return output;
}

function matVec(matrix, vector) {
  const [rows, cols] = matrixShape(matrix);
  if (!Array.isArray(vector) || vector.length !== cols || vector.some((value) => !Number.isFinite(Number(value)))) throw new Error('矩阵与向量维数不匹配');
  return Array.from({ length: rows }, (_, row) => matrix[row].reduce((sum, value, col) => sum + Number(value) * Number(vector[col]), 0));
}

function solveLinearSystem(matrix, vector, tolerance = 1e-12) {
  const [rows, cols] = matrixShape(matrix);
  if (rows !== cols) throw new Error('线性求解需要方阵');
  if (!Array.isArray(vector) || vector.length !== rows || vector.some((value) => !Number.isFinite(Number(value)))) throw new Error('线性方程右侧向量非法');
  const a = matrix.map((row) => row.map(Number));
  const b = vector.map(Number);
  const scale = Math.max(1, ...a.flat().map(Math.abs));
  const threshold = tolerance * scale;
  for (let col = 0; col < cols; col += 1) {
    let pivot = col;
    for (let row = col + 1; row < rows; row += 1) if (Math.abs(a[row][col]) > Math.abs(a[pivot][col])) pivot = row;
    if (Math.abs(a[pivot][col]) <= threshold) return { status: 'rank-deficient', solution: null, pivot: col };
    if (pivot !== col) { [a[pivot], a[col]] = [a[col], a[pivot]]; [b[pivot], b[col]] = [b[col], b[pivot]]; }
    const diagonal = a[col][col];
    for (let j = col; j < cols; j += 1) a[col][j] /= diagonal;
    b[col] /= diagonal;
    for (let row = 0; row < rows; row += 1) {
      if (row === col) continue;
      const factor = a[row][col];
      if (Math.abs(factor) <= threshold) continue;
      for (let j = col; j < cols; j += 1) a[row][j] -= factor * a[col][j];
      b[row] -= factor * b[col];
    }
  }
  return { status: 'ok', solution: b };
}

function gramWithRidge(matrix, lambda, skipFirst = false) {
  const transposed = transpose(matrix);
  const gram = matMul(transposed, matrix);
  for (let index = 0; index < gram.length; index += 1) if (!(skipFirst && index === 0)) gram[index][index] += lambda;
  return { transposed, gram };
}

function ridgeRegression(features, target, options = {}) {
  const [rows] = matrixShape(features);
  if (!Array.isArray(target) || target.length !== rows || target.some((value) => !Number.isFinite(Number(value)))) throw new Error('ridge target 与 feature rows 不匹配');
  const interceptEnabled = options.intercept !== false;
  const design = interceptEnabled ? features.map((row) => [1, ...row.map(Number)]) : features.map((row) => row.map(Number));
  const lambda = Number.isFinite(Number(options.lambda)) && Number(options.lambda) >= 0 ? Number(options.lambda) : 1e-8;
  const { transposed, gram } = gramWithRidge(design, lambda, interceptEnabled);
  const rhs = matVec(transposed, target.map(Number));
  const solved = solveLinearSystem(gram, rhs, options.tolerance || 1e-12);
  if (solved.status !== 'ok') return { schema: 'newcyber.sca-regression.v1', status: solved.status, lambda, interceptEnabled };
  const params = solved.solution;
  const predictions = matVec(design, params);
  const mean = target.reduce((sum, value) => sum + Number(value), 0) / target.length;
  let ssResidual = 0;
  let ssTotal = 0;
  for (let index = 0; index < target.length; index += 1) {
    const residual = Number(target[index]) - predictions[index];
    ssResidual += residual * residual;
    const centered = Number(target[index]) - mean;
    ssTotal += centered * centered;
  }
  return {
    schema: 'newcyber.sca-regression.v1',
    status: 'ok',
    lambda,
    intercept: interceptEnabled ? params[0] : 0,
    coefficients: interceptEnabled ? params.slice(1) : params,
    rmse: Math.sqrt(ssResidual / target.length),
    r2: ssTotal > 0 ? 1 - ssResidual / ssTotal : (ssResidual === 0 ? 1 : null),
    rows,
    dimension: features[0].length
  };
}

function pseudoinverseSolve(matrix, vector, options = {}) {
  const [rows, cols] = matrixShape(matrix);
  if (!Array.isArray(vector) || vector.length !== rows || vector.some((value) => !Number.isFinite(Number(value)))) throw new Error('pinv target 与矩阵 rows 不匹配');
  const lambda = Number.isFinite(Number(options.lambda)) && Number(options.lambda) >= 0 ? Number(options.lambda) : 1e-10;
  const transposed = transpose(matrix);
  if (rows >= cols) {
    const gram = matMul(transposed, matrix);
    for (let index = 0; index < cols; index += 1) gram[index][index] += lambda;
    const rhs = matVec(transposed, vector.map(Number));
    const solved = solveLinearSystem(gram, rhs, options.tolerance || 1e-12);
    return { schema: 'newcyber.sca-pinv.v1', status: solved.status, method: 'left-pseudoinverse', lambda, rows, cols, solution: solved.solution };
  }
  const gram = matMul(matrix, transposed);
  for (let index = 0; index < rows; index += 1) gram[index][index] += lambda;
  const y = solveLinearSystem(gram, vector.map(Number), options.tolerance || 1e-12);
  if (y.status !== 'ok') return { schema: 'newcyber.sca-pinv.v1', status: y.status, method: 'right-pseudoinverse', lambda, rows, cols, solution: null };
  return { schema: 'newcyber.sca-pinv.v1', status: 'ok', method: 'right-pseudoinverse', lambda, rows, cols, solution: matVec(transposed, y.solution) };
}

async function analyzePowerTracePath(filePath, options = {}) {
  const header = await readNpyHeaderPath(filePath);
  const sourceInspection = inspectScaSource(options.sourceText || '');
  const samplesPerRow = Number(options.samplesPerRow || sourceInspection.samplesPerRow || (header.shape.length === 2 ? header.shape[1] : 0)) || null;
  let rowCount = null;
  let layoutStatus = 'needs-row-width';
  if (samplesPerRow && Number.isSafeInteger(samplesPerRow) && samplesPerRow > 0 && header.elements % samplesPerRow === 0) {
    rowCount = header.elements / samplesPerRow;
    layoutStatus = rowCount <= MAX_ROWS ? 'resolved' : 'row-limit';
  }
  let windowFeatures = null;
  if (options.extractFeatures === true && layoutStatus === 'resolved') {
    windowFeatures = await extractWindowFeatures(header.filePath, { header, samplesPerRow, windows: options.windows });
  }
  const nextActions = [];
  if (layoutStatus !== 'resolved') nextActions.push('从模板常量或 reshape/view 关系确认 samplesPerRow；工具不会按因数分解猜布局。');
  if (layoutStatus === 'resolved' && !windowFeatures) nextActions.push('配置功耗窗口并提取 energy/mean-square/peak-to-peak 特征。');
  if (sourceInspection.requiresModelForward) nextActions.push('题目需要 hidden state / KV-cache 前向；挂载受限 ONNX oracle 后再做 profiling/逐位验证。');
  if (sourceInspection.evidence.pinv.length || sourceInspection.evidence.regression.length) nextActions.push('模板已暴露线性反演证据，可用 ridgeRegression / pseudoinverseSolve 复现回归与反演。');
  return {
    schema: 'newcyber.power-side-channel.v1',
    trace: {
      filePath: header.filePath,
      fileName: header.fileName,
      bytes: header.size,
      dtype: header.descr,
      shape: header.shape,
      elements: header.elements,
      payloadOffset: header.payloadOffset
    },
    layout: { status: layoutStatus, samplesPerRow, rows: rowCount },
    sourceInspection,
    windowFeatures,
    nextActions
  };
}

module.exports = {
  MAX_TRACE_BYTES,
  readNpyHeaderPath,
  inspectScaSource,
  extractWindowFeatures,
  solveLinearSystem,
  ridgeRegression,
  pseudoinverseSolve,
  analyzePowerTracePath
};
