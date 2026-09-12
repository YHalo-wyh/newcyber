'use strict';

const fs = require('fs/promises');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { parseNpyAdvanced } = require('./model_artifacts');

const execFileAsync = promisify(execFile);

const MAX_FILES = 512;
const MAX_BYTES = 8 * 1024 * 1024;

function readNpyInt64(buffer) {
  const parsed = parseNpyAdvanced(buffer);
  if (!parsed || parsed.objectDtype || !Array.isArray(parsed.shape) || !/i8$/.test(String(parsed.descr || ''))) return null;
  const count = Number(parsed.elementCount);
  if (!Number.isSafeInteger(count) || count < 1 || count > 2_000_000) return null;
  const little = !String(parsed.descr).startsWith('>');
  const values = new Array(count);
  for (let i = 0; i < count; i += 1) {
    const offset = parsed.payloadOffset + i * 8;
    if (offset + 8 > buffer.length) return null;
    values[i] = Number(little ? buffer.readBigInt64LE(offset) : buffer.readBigInt64BE(offset));
  }
  return { parsed, values };
}

function modularInverse(value, modulus) {
  let a = ((value % modulus) + modulus) % modulus;
  let b = modulus; let x0 = 1; let x1 = 0;
  while (b) { const q = Math.floor(a / b); [a, b] = [b, a - q * b]; [x0, x1] = [x1, x0 - q * x1]; }
  return a === 1 ? ((x0 % modulus) + modulus) % modulus : null;
}

function solveModularSystem(rows, target, modulus) {
  const a = rows.map((row, index) => [...row.map((v) => ((v % modulus) + modulus) % modulus), ((target[index] % modulus) + modulus) % modulus]);
  const columns = rows[0]?.length || 0; let pivot = 0;
  for (let col = 0; col < columns && pivot < a.length; col += 1) {
    let selected = pivot;
    while (selected < a.length && !modularInverse(a[selected][col], modulus)) selected += 1;
    if (selected >= a.length) continue;
    [a[pivot], a[selected]] = [a[selected], a[pivot]];
    const inv = modularInverse(a[pivot][col], modulus);
    for (let j = col; j <= columns; j += 1) a[pivot][j] = (a[pivot][j] * inv) % modulus;
    for (let row = 0; row < a.length; row += 1) {
      if (row === pivot || a[row][col] === 0) continue;
      const factor = a[row][col];
      for (let j = col; j <= columns; j += 1) a[row][j] = (a[row][j] - factor * a[pivot][j]) % modulus;
    }
    pivot += 1;
  }
  if (pivot < columns) return null;
  const solution = new Array(columns).fill(0);
  for (let row = 0; row < a.length; row += 1) {
    const first = a[row].findIndex((value, index) => index < columns && value !== 0);
    if (first < 0 && a[row][columns] !== 0) return null;
    if (first >= 0) solution[first] = ((a[row][columns] % modulus) + modulus) % modulus;
  }
  return solution;
}

function fitQuantizedAffine(samples, outputs, modulus, scale = 1) {
  if (!samples?.parsed?.shape || !outputs?.parsed?.shape || samples.parsed.shape.length !== 2 || outputs.parsed.shape.length !== 2) return null;
  const rows = samples.parsed.shape[0]; const width = samples.parsed.shape[1]; const outWidth = outputs.parsed.shape[1];
  const matrix = [];
  for (let i = 0; i < rows; i += 1) matrix.push([...samples.values.slice(i * width, (i + 1) * width), 1]);
  const basis = matrix.slice(0, Math.min(rows, width + 1)); const matches = [];
  for (let col = 0; col < outWidth; col += 1) {
    const target = [];
    for (let i = 0; i < basis.length; i += 1) target.push(Math.floor(outputs.values[i * outWidth + col] / scale) % modulus);
    matches.push(solveModularSystem(basis, target, modulus));
  }
  let matched = 0;
  for (let i = 0; i < rows; i += 1) {
    const row = matrix[i]; let ok = true;
    for (let col = 0; col < outWidth; col += 1) {
      const coeff = matches[col];
      if (!coeff) { ok = false; break; }
      let predicted = 0; for (let j = 0; j < coeff.length; j += 1) predicted = (predicted + row[j] * coeff[j]) % modulus;
      const actual = ((Math.floor(outputs.values[i * outWidth + col] / scale) % modulus) + modulus) % modulus;
      if (((predicted % modulus) + modulus) % modulus !== actual) { ok = false; break; }
    }
    if (ok) matched += 1;
  }
  return { rows, width, outWidth, modulus, basisRows: basis.length, matched, consistent: matched === rows };
}

async function probeTensealRuntime(root) {
  const script = String.raw`import json, os, sys
try:
    import tenseal as ts
except Exception as exc:
    print(json.dumps({'available': False, 'error': type(exc).__name__ + ': ' + str(exc)}))
    raise SystemExit(0)
root = sys.argv[1]
out = {'available': True, 'version': getattr(ts, '__version__', None)}
try:
    with open(os.path.join(root, 'context.seal'), 'rb') as handle:
        context = ts.context_from(handle.read())
    out.update({'hasSecretKey': bool(context.has_secret_key()), 'isPublic': bool(context.is_public()), 'hasPublicKey': bool(context.has_public_key()), 'hasRelinKeys': bool(context.has_relin_keys()), 'hasGaloisKeys': bool(context.has_galois_keys())})
except Exception as exc:
    out.update({'contextError': type(exc).__name__ + ': ' + str(exc)})
try:
    with open(os.path.join(root, 'flag.enc'), 'rb') as handle:
        blob = handle.read()
    out['flagBytes'] = len(blob)
    try:
        ts.CKKSVector.load(context, blob)
        out['flagCiphertext'] = 'ckks-vector'
    except Exception as exc:
        out['flagCiphertext'] = 'not-ckks-vector'
        out['flagParseError'] = type(exc).__name__ + ': ' + str(exc)
except Exception as exc:
    out['flagReadError'] = type(exc).__name__ + ': ' + str(exc)
try:
    sample_path = os.path.join(root, 'encrypted_inputs', 'sample_000.ct')
    with open(sample_path, 'rb') as handle:
        sample = ts.CKKSVector.load(context, handle.read())
    out['sampleCiphertext'] = 'ckks-vector'
    out['sampleVectorSize'] = sample.size()
except Exception as exc:
    out['sampleCiphertext'] = 'unreadable'
    out['sampleParseError'] = type(exc).__name__ + ': ' + str(exc)
print(json.dumps(out, ensure_ascii=False))`;
  for (const executable of ['python', 'py']) {
    try {
      const result = await execFileAsync(executable, ['-c', script, root], { timeout: 15000, maxBuffer: 1024 * 1024, windowsHide: true });
      const line = String(result.stdout || '').trim().split(/\r?\n/).filter(Boolean).pop();
      return line ? JSON.parse(line) : { available: false, error: 'TenSEAL 探针没有输出 JSON' };
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      const line = String(error?.stdout || '').trim().split(/\r?\n/).filter(Boolean).pop();
      if (line) { try { return JSON.parse(line); } catch { /* keep structured fallback */ } }
      return { available: false, error: error?.message || String(error) };
    }
  }
  return { available: false, error: '未找到 python/py，跳过 TenSEAL 运行时探针' };
}

function round(value, digits = 6) {
  return Number.isFinite(value) ? Number(value.toFixed(digits)) : null;
}

function classify(name) {
  const lower = name.toLowerCase();
  if (lower === 'model.py') return 'model-source';
  if (lower === 'flag.enc') return 'encrypted-flag';
  if (lower === 'context.json' || lower === 'context.seal') return 'he-context';
  if (lower === 'samples.npy') return 'plaintext-samples';
  if (lower === 'outputs.npy') return 'quantized-outputs';
  if (lower.endsWith('.ct')) return 'encrypted-input';
  if (lower.includes('题目描述') || lower === 'readme.md') return 'challenge-description';
  return null;
}

function numericSummary(buffer, parsed) {
  if (!parsed || parsed.objectDtype || !parsed.shape?.length) return null;
  const descr = String(parsed.descr || '');
  const match = descr.match(/[<>=|]([fiu])([1248])/i);
  if (!match) return null;
  const kind = match[1].toLowerCase();
  const bytes = Number(match[2]);
  const count = Number(parsed.elementCount);
  if (!Number.isSafeInteger(count) || count <= 0 || count > 10_000_000) return null;
  const little = !descr.startsWith('>');
  const read = (index) => {
    const offset = parsed.payloadOffset + index * bytes;
    if (offset + bytes > buffer.length) return null;
    if (kind === 'f' && bytes === 8) return little ? buffer.readDoubleLE(offset) : buffer.readDoubleBE(offset);
    if (kind === 'f' && bytes === 4) return little ? buffer.readFloatLE(offset) : buffer.readFloatBE(offset);
    if (kind === 'i' && bytes === 8) return Number(little ? buffer.readBigInt64LE(offset) : buffer.readBigInt64BE(offset));
    if (kind === 'i' && bytes === 4) return little ? buffer.readInt32LE(offset) : buffer.readInt32BE(offset);
    if (kind === 'u' && bytes === 8) return Number(little ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset));
    if (kind === 'u' && bytes === 4) return little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
    if (kind === 'i' && bytes === 2) return little ? buffer.readInt16LE(offset) : buffer.readInt16BE(offset);
    if (kind === 'u' && bytes === 2) return little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
    return kind === 'i' ? buffer.readInt8(offset) : kind === 'u' ? buffer[offset] : null;
  };
  const step = Math.max(1, Math.ceil(count / 10000));
  const values = [];
  for (let i = 0; i < count; i += step) { const value = read(i); if (Number.isFinite(value)) values.push(value); }
  if (!values.length) return { sampled: 0, samplingStep: step };
  const sorted = [...values].sort((a, b) => a - b);
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
  return { sampled: values.length, samplingStep: step, min: round(sorted[0]), median: round(sorted[Math.floor(sorted.length / 2)]), max: round(sorted[sorted.length - 1]), mean: round(mean), std: round(Math.sqrt(variance)) };
}

function sourceEvidence(text) {
  const pick = (re) => { const match = text.match(re); return match ? match[1] : null; };
  return {
    library: /import\s+tenseal|from\s+tenseal/i.test(text) ? 'TenSEAL' : null,
    polyModulusDegree: Number(pick(/POLY_MODULUS_DEGREE\s*=\s*(\d+)/)) || null,
    coeffModBitSizes: pick(/COEFF_MOD_BIT_SIZES\s*=\s*\[([^\]]+)\]/),
    globalScale: Number(pick(/GLOBAL_SCALE\s*=\s*([0-9]+)/)) || null,
    moduloQ: Number(pick(/(?:^|\n)Q\s*=\s*([0-9]+)/)) || null,
    quantizer: /output_from_plain_model[\s\S]{0,180}round\s*\(/i.test(text) ? 'round(scale * y_plain) % Q' : null,
    unsafeExecution: /(?:exec|eval|subprocess|os\.system)\s*\(/.test(text)
  };
}

async function walk(root, out = []) {
  if (out.length >= MAX_FILES) return out;
  for (const entry of (await fs.readdir(root, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    if (out.length >= MAX_FILES || entry.isSymbolicLink()) continue;
    const target = path.join(root, entry.name);
    if (entry.isDirectory()) await walk(target, out);
    else if (entry.isFile()) out.push(target);
  }
  return out;
}

async function auditHeTrainingDirectory(rootPath) {
  const root = path.resolve(String(rootPath || ''));
  const stat = await fs.stat(root);
  if (!stat.isDirectory()) throw new Error('HE training 审计入口必须是目录');
  const files = await walk(root);
  const roles = {};
  const all = [];
  for (const filePath of files) {
    const stat = await fs.stat(filePath);
    const relative = path.relative(root, filePath);
    const role = classify(path.basename(filePath));
    const item = { path: relative, size: stat.size, role };
    if (role) roles[role] = roles[role] || [];
    if (role) roles[role].push(item);
    all.push(item);
    if (role === 'model-source' && stat.size <= MAX_BYTES) {
      const text = await fs.readFile(filePath, 'utf8');
      item.evidence = sourceEvidence(text);
    }
    if ((role === 'plaintext-samples' || role === 'quantized-outputs') && stat.size <= MAX_BYTES) {
      const buffer = await fs.readFile(filePath);
      const parsed = parseNpyAdvanced(buffer);
      item.npy = parsed ? { shape: parsed.shape, descr: parsed.descr, fortranOrder: parsed.fortranOrder, elementCount: parsed.elementCount } : null;
      item.numeric = numericSummary(buffer, parsed);
    }
  }
  const model = roles['model-source']?.[0]?.evidence || {};
  const samples = roles['plaintext-samples']?.[0];
  const outputs = roles['quantized-outputs']?.[0];
  const ct = roles['encrypted-input'] || [];
  const findings = [];
  if (model.library === 'TenSEAL') findings.push({ id: 'tenseal-ckks', severity: 'info', title: '识别到 TenSEAL CKKS 参数', evidence: model });
  if (model.quantizer) findings.push({ id: 'scaled-modulo-output', severity: 'high', title: '输出包含 scale + modulo 量化', evidence: { scale: model.globalScale, modulo: model.moduloQ } });
  if (ct.length) findings.push({ id: 'encrypted-input-batch', severity: 'info', title: '发现密态输入批次', evidence: { count: ct.length, totalBytes: ct.reduce((sum, x) => sum + x.size, 0) } });
  const next = [
    '用 context.json / context.seal 在隔离环境恢复 CKKS context，仅验证参数一致性。',
    '对 samples.npy 与 outputs.npy 做明文模型拟合和量化差分，确认 round(scale*y) % Q。',
    '逐个回放 encrypted_inputs/*.ct 的密态推理链；不要执行未知 Python 或把 flag.enc 写入训练语料。',
    '最后再根据已验证的解密条件处理 flag.enc，并保留原始工件与派生结果分离。'
  ];
  return {
    schema: 'newcyber.ai-he-training-audit.v1', status: model.library && samples && outputs ? 'evidence-present' : 'candidate',
    workspaceRoot: root, roles, files: all, findings, chain: ['encrypted input', 'TenSEAL CKKS inference', 'scaled modulo output', 'plaintext fit / differential', 'flag.enc decrypt condition'], nextActions: next,
    notes: ['仅做静态元数据与 NPY 数值摘要，不执行题目 Python，不复制 flag 或个人敏感数据。']
  };
}

async function solveHeTrainingDirectory(rootPath) {
  const audit = await auditHeTrainingDirectory(rootPath);
  const root = audit.workspaceRoot;
  const steps = [];
  const add = (id, title, state, detail, evidence = {}, output = null) => steps.push({ id, title, state, detail, evidence, output });
  add('ingest', '读取题目工件', 'done', '目录、角色和文件数量已固定；保留原始文件，不执行题目脚本。', { fileCount: audit.files.length, roles: Object.fromEntries(Object.entries(audit.roles).map(([key, value]) => [key, value.length])) });
  const context = audit.roles['he-context'] || [];
  const model = audit.roles['model-source']?.[0]?.evidence || {};
  let contextJson = null;
  const contextJsonPath = context.find((item) => path.basename(item.path).toLowerCase() === 'context.json')?.path;
  if (contextJsonPath) { try { contextJson = JSON.parse(await fs.readFile(path.join(root, contextJsonPath), 'utf8')); } catch { /* report missing context evidence */ } }
  const runtime = context.some((item) => path.basename(item.path).toLowerCase() === 'context.seal') ? await probeTensealRuntime(root) : { available: false, error: '缺少 context.seal' };
  const sourceBits = String(model.coeffModBitSizes || '').split(',').map((item) => Number(item.trim()));
  const paramsMatch = Boolean(contextJson && model.library === contextJson.library && model.polyModulusDegree === contextJson.poly_modulus_degree && model.globalScale === contextJson.global_scale && model.moduloQ === contextJson.wrapped_modulus && JSON.stringify(sourceBits) === JSON.stringify(contextJson.coeff_mod_bit_sizes));
  add('context', '核对 CKKS 参数与密钥状态', paramsMatch ? 'done' : 'gap', paramsMatch ? (runtime.available ? '模型常量与 context.json 一致，TenSEAL 已验证密钥状态。' : '模型常量与 context.json 一致；TenSEAL 运行时不可用，密钥状态待核实。') : '模型源码与 context.json 的关键参数不一致或缺失。', { contextFiles: context.map((item) => ({ path: item.path, size: item.size })), model, contextJson, paramsMatch, runtime });

  let samples = null; let outputs = null;
  const samplePath = audit.roles['plaintext-samples']?.[0]?.path;
  const outputPath = audit.roles['quantized-outputs']?.[0]?.path;
  if (samplePath) samples = readNpyInt64(await fs.readFile(path.join(root, samplePath)));
  if (outputPath) outputs = readNpyInt64(await fs.readFile(path.join(root, outputPath)));
  const scale = Number(model.globalScale) || 1;
  const q = Number(model.moduloQ) || 0;
  const modulus = q && scale ? Math.round(q / scale) : 0;
  const outputDivisible = Boolean(outputs?.values?.length) && outputs.values.every((value) => value % scale === 0);
  add('quantize', '还原输出量化层', outputDivisible ? 'done' : 'gap', outputDivisible ? 'outputs.npy 的每个值都可除以 global_scale，已得到明文量化域。' : '无法证明 outputs.npy 遵循 round(scale*y) 的量化规则。', { scale, wrappedModulus: q, outputDivisible, samplesShape: samples?.parsed?.shape || null, outputsShape: outputs?.parsed?.shape || null }, outputDivisible ? { modulus, domain: 'outputs / global_scale' } : null);

  const fit = outputDivisible && modulus ? fitQuantizedAffine(samples, outputs, modulus, scale) : null;
  add('fit', '用已知样本拟合明文模型', fit?.consistent ? 'done' : 'gap', fit?.consistent ? '样本到输出的模线性关系在全部行成立。' : '现有样本不能被一个可复核的模线性头解释，题目没有提供足够的模型权重/公式。', fit || { reason: 'missing-npy-or-modulus' });
  const ct = audit.roles['encrypted-input'] || [];
  const secretStatus = runtime.available ? (runtime.hasSecretKey ? 'present' : 'absent') : 'unknown';
  add('decrypt', '检查密态输入/flag 解密条件', 'gap', secretStatus === 'absent' ? '样本 .ct 可作为 CKKSVector 加载，但公开 context 不含 secret key；flag.enc 不是 CKKSVector 流，缺少其加密格式与密钥派生链。' : '没有可用的解密链：需确认 context.seal 是否含 secret key，并取得 flag.enc 的加密格式/密钥派生逻辑。', { encryptedInputs: ct.length, flagFiles: (audit.roles['encrypted-flag'] || []).map((item) => item.path), contextFiles: context.map((item) => item.path), secretStatus, sampleCiphertext: runtime.sampleCiphertext || 'unknown', sampleVectorSize: runtime.sampleVectorSize || null, flagBytes: runtime.flagBytes || null, flagCiphertext: runtime.flagCiphertext || 'unknown', flagParseError: runtime.flagParseError || null });
  const barrier = secretStatus === 'absent' ? '现有上下文没有 CKKS secret key' : secretStatus === 'present' ? '虽有 CKKS secret key，但 flag.enc 的非 CKKS 加密格式仍未知' : 'CKKS 密钥状态尚未核实';
  add('result', '输出最终答案', 'blocked', `未生成 flag。阻断点是实际模型/密钥派生链缺失；线性拟合不成立，且${barrier}。`, {}, null);
  return {
    schema: 'newcyber.ai-he-training-solve.v1', status: 'blocked', workspaceRoot: root, flag: null, result: null,
    steps, stages: steps, gap: { code: 'HE_MODEL_OR_SECRET_MISSING', message: `缺少实际模型/密钥派生链；${barrier}，flag.enc 不是可直接加载的 CKKSVector 流。` },
    evidence: { auditSchema: audit.schema, model, contextJson, runtime, sampleShape: samples?.parsed?.shape || null, outputShape: outputs?.parsed?.shape || null, affineFit: fit },
    nextActions: ['优先补题目生成端的模型权重/训练和推理代码，以及 flag.enc 的加密格式、密钥派生逻辑。', '若生成端另有 secret key，提供对应 context 后再验证 encrypted_inputs/*.ct 与 flag.enc。']
  };
}

module.exports = { auditHeTrainingDirectory, solveHeTrainingDirectory };
