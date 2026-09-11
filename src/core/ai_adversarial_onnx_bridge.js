'use strict';

const { rankAdversarialContestCandidates } = require('./ai_adversarial_ctf');

function finiteVector(values, label = 'scores') {
  if (!Array.isArray(values) || values.length < 2) throw new Error(`${label} 至少需要两个数值`);
  return values.map((value, index) => {
    const n = Number(value);
    if (!Number.isFinite(n)) throw new Error(`${label}[${index}] 不是有限数值`);
    return n;
  });
}

function product(dims) {
  return dims.reduce((total, value) => total * Number(value), 1);
}

function isAutoVectorShape(dims, elements) {
  if (!Array.isArray(dims) || !dims.length) return false;
  if (dims.some((value) => !Number.isInteger(Number(value)) || Number(value) <= 0)) return false;
  if (product(dims) !== elements) return false;
  if (dims.length === 1) return Number(dims[0]) === elements;
  if (dims.length === 2) return Number(dims[0]) === 1 && Number(dims[1]) === elements;
  return false;
}

function outputCandidates(run) {
  if (!run || typeof run !== 'object') throw new Error('缺少 ONNX run result');
  if (run.schema && run.schema !== 'newcyber.onnx-run.v1') throw new Error(`不支持的 ONNX run schema: ${run.schema}`);
  const outputs = run.outputs;
  if (!outputs || typeof outputs !== 'object' || Array.isArray(outputs)) throw new Error('ONNX run 缺少 outputs');
  return Object.entries(outputs).map(([name, view]) => ({ name, view }));
}

function scoreVectorFromView(name, view, options = {}) {
  if (!view || typeof view !== 'object') throw new Error(`ONNX 输出 ${name} 无效`);
  if (view.truncated) throw new Error(`ONNX 输出 ${name} 已截断，不能把 preview 当完整类别向量`);
  const preview = finiteVector(view.preview, `outputs.${name}.preview`);
  const elements = Number(view.elements ?? preview.length);
  if (!Number.isInteger(elements) || elements !== preview.length) throw new Error(`ONNX 输出 ${name} elements 与 preview 不一致`);
  const dims = Array.isArray(view.dims) ? view.dims.map(Number) : [];
  if (!isAutoVectorShape(dims, elements)) {
    if (!options.allowFlatten) throw new Error(`ONNX 输出 ${name} shape=${JSON.stringify(dims)} 不是自动允许的 [C] 或 [1,C] 分类向量`);
    if (!dims.length || product(dims) !== elements) throw new Error(`ONNX 输出 ${name} shape 无法安全 flatten`);
  }
  return { name, scores: preview, dims, type: view.type || null, elements };
}

function preferredOutput(items) {
  const preferred = items.filter((item) => /(?:logits?|scores?|probabilities|probs|class(?:ification)?_?output)/i.test(item.name));
  return preferred.length === 1 ? preferred[0] : null;
}
function chooseScoreOutput(run, options = {}) {
  const entries = outputCandidates(run);
  const requested = options.outputName == null ? null : String(options.outputName);
  if (requested) {
    const match = entries.find((entry) => entry.name === requested);
    if (!match) throw new Error(`ONNX 输出中不存在 ${requested}`);
    return scoreVectorFromView(match.name, match.view, options);
  }

  const safe = [];
  for (const entry of entries) {
    try { safe.push(scoreVectorFromView(entry.name, entry.view, options)); }
    catch {}
  }
  if (!safe.length) throw new Error('没有可自动识别的完整分类输出；请指定 outputName，且输出必须是未截断的 [C] 或 [1,C]');
  if (safe.length === 1) return safe[0];

  const expectedClasses = Number(options.expectedClasses);
  if (Number.isInteger(expectedClasses) && expectedClasses >= 2) {
    const matched = safe.filter((item) => item.elements === expectedClasses);
    if (matched.length === 1) return matched[0];
    if (matched.length > 1) {
      const named = preferredOutput(matched);if (named) return named;
      throw new Error(`有 ${matched.length} 个输出都匹配已恢复的 ${expectedClasses} 类 label space：${matched.map((item)=>item.name).join(', ')}；请显式指定 outputName`);
    }
  }

  const preferred = preferredOutput(safe);
  if (preferred) return preferred;
  throw new Error(`存在多个可用分类输出：${safe.map((item) => item.name).join(', ')}；请显式指定 outputName`);
}

function normalizeRunEntry(entry, index, defaults = {}) {
  if (!entry || typeof entry !== 'object') throw new Error(`runs[${index}] 格式无效`);
  const run = entry.run ?? entry.result ?? entry.onnxRun;
  const vector = chooseScoreOutput(run, {
    outputName: entry.outputName ?? defaults.outputName,
    allowFlatten: entry.allowFlatten ?? defaults.allowFlatten,
    expectedClasses: entry.expectedClasses ?? defaults.expectedClasses
  });
  const id = entry.id ?? entry.file ?? entry.name ?? `candidate-${index}`;
  const assignedLabel = entry.assignedLabel ?? entry.folderLabel ?? entry.bucketLabel ?? entry.classLabel;
  if (assignedLabel === undefined || assignedLabel === null) throw new Error(`runs[${index}] 缺少 assignedLabel/folderLabel`);
  return {
    id,
    assignedLabel,
    scores: vector.scores,
    onnx: {
      outputName: vector.name,
      dims: vector.dims,
      type: vector.type,
      provider: run?.provider || null
    }
  };
}

function adaptOnnxRunsToContestBundle(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('ONNX contest bridge 输入应为对象');
  const runs = input.runs ?? input.candidates ?? input.samples;
  if (!Array.isArray(runs) || !runs.length) throw new Error('需要 runs[]（每项包含 id、assignedLabel、run）');
  if (runs.length > 100000) throw new Error('ONNX run 数量超过 100000 上限');
  const hints = input.hints ?? input.hintPairs ?? input.transitions;
  if (!Array.isArray(hints) || !hints.length) throw new Error('需要 hints');
  const expectedClasses = Number(input.expectedClasses);
  const defaults = { outputName: input.outputName, allowFlatten: input.allowFlatten === true, expectedClasses:Number.isInteger(expectedClasses)&&expectedClasses>=2?expectedClasses:null };
  const candidates = runs.map((entry, index) => normalizeRunEntry(entry, index, defaults));
  return {
    schema: 'newcyber.ai-adversarial-onnx-contest-bundle.v2',
    hints,
    candidates,
    shortlistSize: input.shortlistSize,
    beamWidth: input.beamWidth,
    maxSets: input.maxSets,
    expectedClasses: defaults.expectedClasses,
    outputNames: [...new Set(candidates.map((item) => item.onnx.outputName))],
    providers: [...new Set(candidates.map((item) => item.onnx.provider).filter(Boolean))],
    notes: [
      '仅使用完整未截断 ONNX 输出向量；不会把 local_ml_runtime 的 preview 截断片段误当作全部类别。',
      '自动模式只接受 [C] 或 [1,C]。更高维输出默认拒绝，避免把 feature map/embedding 错当 logits。',
      '若题目材料恢复出完整连续 class_to_idx，可用类别总数消歧多个向量输出；不完整 label map 不参与猜测。'
    ]
  };
}

function rankAdversarialContestFromOnnxRuns(input = {}) {
  const bundle = adaptOnnxRunsToContestBundle(input);
  const ranking = rankAdversarialContestCandidates({
    hints: bundle.hints,
    candidates: bundle.candidates,
    shortlistSize: bundle.shortlistSize,
    beamWidth: bundle.beamWidth,
    maxSets: bundle.maxSets
  });
  return {
    schema: 'newcyber.ai-adversarial-onnx-contest-ranking.v2',
    bridge: {
      runs: bundle.candidates.length,
      outputNames: bundle.outputNames,
      providers: bundle.providers,
      expectedClasses: bundle.expectedClasses
    },
    bundle,
    ranking,
    findings: ranking.findings,
    notes: [
      ...bundle.notes,
      '这里复用 Batch45 的赛式候选排序；ONNX 推理结果仍只生成 candidate，最终需要题目 verifier/hash。'
    ]
  };
}

module.exports = {
  finiteVector,
  isAutoVectorShape,
  chooseScoreOutput,
  adaptOnnxRunsToContestBundle,
  rankAdversarialContestFromOnnxRuns
};
