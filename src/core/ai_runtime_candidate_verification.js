'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { withSession, tensorFromSpec, normalizeProvider } = require('./local_ml_runtime');
const { patchCandidateId, verifyBackdoorPatchCandidate } = require('./ai_candidate_verifier');

const MAX_RUNTIME_SAMPLES = 64;
const MAX_MODEL_BYTES = 512 * 1024 * 1024;
const TRUSTED_PREPROCESS_SOURCES = new Set(['challenge-source', 'model-config', 'official-writeup', 'explicit-user-verified']);

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function objectInput(input, label = 'input') {
  if (typeof input === 'string') {
    const text = input.trim();
    if (!text) return {};
    let parsed;
    try { parsed = JSON.parse(text); }
    catch { throw new Error(`${label} 需要 JSON 对象`); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${label} 需要 JSON 对象`);
    return parsed;
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error(`${label} 需要对象`);
  return input;
}

function normalizeRaster(value, label = 'raster') {
  if (!value || typeof value !== 'object') throw new Error(`${label} 缺失`);
  const width = Number(value.width);
  const height = Number(value.height);
  const channels = Number(value.channels || 4);
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0 || width > 4096 || height > 4096) {
    throw new Error(`${label} width/height 非法`);
  }
  if (![1,3,4].includes(channels)) throw new Error(`${label} channels 仅支持 1/3/4`);
  const data = ArrayBuffer.isView(value.data) ? Array.from(value.data) : value.data;
  if (!Array.isArray(data) || data.length !== width * height * channels) throw new Error(`${label} data 长度与尺寸不一致`);
  const normalized = data.map((item) => Number(item));
  if (normalized.some((item) => !Number.isFinite(item))) throw new Error(`${label} 包含非有限像素`);
  return { width, height, channels, data: normalized };
}

function pixel(raster, x, y, channel) {
  const sourceChannel = raster.channels === 1 ? 0 : Math.min(channel, raster.channels - 1);
  return raster.data[(y * raster.width + x) * raster.channels + sourceChannel];
}

function patchBounds(candidate, raster) {
  const patch = candidate?.patch || {};
  const x = Number(patch.x);
  const y = Number(patch.y);
  const width = Number(patch.width);
  const height = Number(patch.height);
  if (![x,y,width,height].every(Number.isInteger) || x < 0 || y < 0 || width <= 0 || height <= 0 || x + width > raster.width || y + height > raster.height) {
    throw new Error('candidate patch bbox 超出 raster 或格式非法');
  }
  return { x, y, width, height };
}

function extractPatch(rasterInput, candidate) {
  const raster = normalizeRaster(rasterInput, 'triggerSourceRaster');
  const bounds = patchBounds(candidate, raster);
  const data = [];
  for (let y = 0; y < bounds.height; y += 1) {
    for (let x = 0; x < bounds.width; x += 1) {
      for (let c = 0; c < raster.channels; c += 1) data.push(pixel(raster, bounds.x + x, bounds.y + y, c));
    }
  }
  return { ...bounds, channels:raster.channels, data };
}

function normalizeControlPatch(value, bounds, channels) {
  if (!value) return null;
  const patch = normalizeRaster(value, 'controlPatch');
  if (patch.width !== bounds.width || patch.height !== bounds.height) throw new Error('controlPatch 尺寸必须与 candidate bbox 一致');
  if (patch.channels !== channels) throw new Error('controlPatch channels 必须与 trigger patch 一致');
  return patch;
}

function pastePatch(baseInput, patch, bounds) {
  const base = normalizeRaster(baseInput, 'sample raster');
  if (base.channels !== patch.channels) throw new Error('sample channels 与 patch 不一致');
  if (bounds.x + bounds.width > base.width || bounds.y + bounds.height > base.height) throw new Error('candidate patch bbox 超出 sample raster');
  const data = base.data.slice();
  for (let y = 0; y < bounds.height; y += 1) {
    for (let x = 0; x < bounds.width; x += 1) {
      for (let c = 0; c < base.channels; c += 1) {
        const dst = ((bounds.y + y) * base.width + bounds.x + x) * base.channels + c;
        const src = (y * bounds.width + x) * patch.channels + c;
        data[dst] = patch.data[src];
      }
    }
  }
  return { width:base.width, height:base.height, channels:base.channels, data };
}

function normalizePreprocess(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('preprocess 需要对象');
  const layout = String(value.layout || '').toUpperCase();
  if (!['NCHW','NHWC'].includes(layout)) throw new Error('preprocess.layout 必须显式为 NCHW 或 NHWC');
  const channels = Number(value.channels || 3);
  if (![1,3,4].includes(channels)) throw new Error('preprocess.channels 仅支持 1/3/4');
  const scale = Number(value.scale);
  if (!Number.isFinite(scale) || scale === 0) throw new Error('preprocess.scale 必须显式提供非零有限数');
  const mean = Array.isArray(value.mean) ? value.mean.map(Number) : Array(channels).fill(0);
  const std = Array.isArray(value.std) ? value.std.map(Number) : Array(channels).fill(1);
  if (mean.length !== channels || std.length !== channels || mean.some((x)=>!Number.isFinite(x)) || std.some((x)=>!Number.isFinite(x) || x === 0)) {
    throw new Error('preprocess mean/std 必须与 channels 对齐且为有限值，std 不得为 0');
  }
  const source = String(value.source || '').trim();
  return {
    layout,
    channels,
    scale,
    mean,
    std,
    source,
    trusted: TRUSTED_PREPROCESS_SOURCES.has(source)
  };
}

function rasterTensorSpec(rasterInput, preprocess) {
  const raster = normalizeRaster(rasterInput, 'runtime raster');
  if (preprocess.channels > raster.channels && raster.channels !== 1) throw new Error('preprocess.channels 大于 raster channels');
  const values = [];
  const read = (x,y,c) => {
    const raw = pixel(raster,x,y,c);
    return (raw * preprocess.scale - preprocess.mean[c]) / preprocess.std[c];
  };
  if (preprocess.layout === 'NCHW') {
    for (let c=0;c<preprocess.channels;c+=1) for (let y=0;y<raster.height;y+=1) for (let x=0;x<raster.width;x+=1) values.push(read(x,y,c));
    return { type:'float32', dims:[1,preprocess.channels,raster.height,raster.width], values };
  }
  for (let y=0;y<raster.height;y+=1) for (let x=0;x<raster.width;x+=1) for (let c=0;c<preprocess.channels;c+=1) values.push(read(x,y,c));
  return { type:'float32', dims:[1,raster.height,raster.width,preprocess.channels], values };
}

function metadataDimensions(metadata) {
  const dims = metadata?.dimensions;
  return Array.isArray(dims) ? dims : null;
}

function validateInputShape(spec, metadata) {
  const dims = metadataDimensions(metadata);
  if (!dims || dims.length !== spec.dims.length) return;
  for (let i=0;i<dims.length;i+=1) {
    const expected = Number(dims[i]);
    if (Number.isFinite(expected) && expected > 0 && expected !== spec.dims[i]) {
      throw new Error(`ONNX 输入维度不匹配: metadata=${JSON.stringify(dims)} runtime=${JSON.stringify(spec.dims)}`);
    }
  }
}

function argmaxOutput(tensor) {
  if (!tensor || !tensor.data || !tensor.data.length) throw new Error('分类输出为空');
  const values = Array.from(tensor.data, Number);
  if (values.some((value) => !Number.isFinite(value))) throw new Error('分类输出包含非有限值');
  let best = 0;
  for (let i=1;i<values.length;i+=1) if (values[i] > values[best]) best = i;
  return { label:String(best), score:values[best], classes:values.length };
}

function resolveName(requested, names, label) {
  if (requested) {
    if (!names.includes(requested)) throw new Error(`${label} ${requested} 不存在`);
    return requested;
  }
  if (names.length !== 1) throw new Error(`${label} 存在歧义，必须显式指定`);
  return names[0];
}

function fileModel(modelPath) {
  const requested = path.resolve(String(modelPath || ''));
  if (!requested || path.extname(requested).toLowerCase() !== '.onnx') throw new Error('modelPath 必须指向 .onnx 文件');
  const stat = fs.lstatSync(requested);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('modelPath 必须是非符号链接普通文件');
  if (stat.size <= 0 || stat.size > MAX_MODEL_BYTES) throw new Error(`ONNX 模型大小必须在 1..${MAX_MODEL_BYTES} 字节`);
  const real = fs.realpathSync(requested);
  const buffer = fs.readFileSync(real);
  return { model:real, sha256:sha256(buffer), bytes:stat.size, source:'path', path:real };
}

function modelMaterial(input, options = {}) {
  if (options.model) {
    const buffer = Buffer.from(options.model);
    return { model:options.model, sha256:sha256(buffer), bytes:buffer.length, source:'injected', path:null };
  }
  if (input.model && (Buffer.isBuffer(input.model) || ArrayBuffer.isView(input.model))) {
    const buffer = Buffer.from(input.model);
    return { model:input.model, sha256:sha256(buffer), bytes:buffer.length, source:'buffer', path:null };
  }
  return fileModel(input.modelPath);
}

function runtimeBinding(candidateId, model, patch, preprocess) {
  const patchHash = sha256(Buffer.from(Float64Array.from(patch.data).buffer));
  const preprocessHash = sha256(stableJson({layout:preprocess.layout,channels:preprocess.channels,scale:preprocess.scale,mean:preprocess.mean,std:preprocess.std,source:preprocess.source}));
  const runtimeBindingId = `runtime-${sha256(`${candidateId}\n${model.sha256}\n${patchHash}\n${preprocessHash}`).slice(0,24)}`;
  return { runtimeBindingId, patchSha256:patchHash, preprocessSha256:preprocessHash };
}

function normalizeSamples(value) {
  if (!Array.isArray(value) || !value.length) throw new Error('samples 必须是非空数组');
  if (value.length > MAX_RUNTIME_SAMPLES) throw new Error(`samples 超过上限 ${MAX_RUNTIME_SAMPLES}`);
  return value.map((item,index) => {
    if (!item || typeof item !== 'object') throw new Error(`samples[${index}] 非对象`);
    if (item.trueLabel === null || item.trueLabel === undefined) throw new Error(`samples[${index}] 缺少 trueLabel`);
    return { trueLabel:String(item.trueLabel), raster:normalizeRaster(item.raster, `samples[${index}].raster`) };
  });
}

async function runBackdoorPatchRuntimeVerification(rawInput = {}, options = {}) {
  const input = objectInput(rawInput, 'runtime verifier input');
  const candidate = input.candidate || input.candidateObject;
  if (!candidate || candidate.kind !== 'localized-backdoor-trigger') throw new Error('需要 localized-backdoor-trigger candidate');
  const expectedCandidateId = patchCandidateId(candidate);
  const suppliedCandidateId = String(input.candidateId || candidate.candidateId || '').trim();
  if (!suppliedCandidateId || suppliedCandidateId !== expectedCandidateId) {
    return { schema:'newcyber.ai-backdoor-runtime-verifier.v1', verified:false, verdict:'candidate-binding-mismatch', candidateId:expectedCandidateId };
  }

  const preprocess = normalizePreprocess(input.preprocess || {});
  const samples = normalizeSamples(input.samples);
  const triggerSource = normalizeRaster(input.triggerSourceRaster || input.triggerRaster, 'triggerSourceRaster');
  const bounds = patchBounds(candidate, triggerSource);
  const triggerPatch = extractPatch(triggerSource, candidate);
  const controlPatch = normalizeControlPatch(input.controlPatch, bounds, triggerPatch.channels);
  if (!controlPatch) {
    return {
      schema:'newcyber.ai-backdoor-runtime-verifier.v1', verified:false, verdict:'runtime-gap', candidateId:expectedCandidateId,
      gap:{ code:'CONTROL_PATCH_REQUIRED', detail:'严格 runtime verification 需要显式 controlPatch；不会自动生成一个 control 来刷 specificity。' }
    };
  }
  const model = modelMaterial(input, options);
  const binding = runtimeBinding(expectedCandidateId, model, triggerPatch, preprocess);
  const provider = normalizeProvider(input.provider || options.provider || 'cpu');

  const execution = await withSession(model.model, { ...options, provider }, async (session, ort) => {
    const inputName = resolveName(input.inputName, session.inputNames || [], 'ONNX input');
    const outputName = resolveName(input.outputName, session.outputNames || [], 'ONNX output');
    if ((session.inputNames || []).length !== 1) throw new Error('Batch49 classifier runtime 当前只接受单输入模型，避免猜辅助输入语义');
    const rows = [];
    let classes = null;

    async function predict(raster) {
      const spec = rasterTensorSpec(raster, preprocess);
      const metaIndex = session.inputNames.indexOf(inputName);
      validateInputShape(spec, session.inputMetadata?.[metaIndex]);
      const feeds = { [inputName]: tensorFromSpec(ort, spec) };
      const output = await session.run(feeds, { [outputName]:null });
      const result = argmaxOutput(output[outputName]);
      if (classes === null) classes = result.classes;
      else if (classes !== result.classes) throw new Error('分类输出类别数在运行中发生变化');
      return result;
    }

    for (let index=0;index<samples.length;index+=1) {
      const sample = samples[index];
      if (sample.raster.width !== triggerSource.width || sample.raster.height !== triggerSource.height || sample.raster.channels !== triggerSource.channels) {
        throw new Error(`samples[${index}] 尺寸/channels 与 triggerSourceRaster 不一致`);
      }
      const triggered = pastePatch(sample.raster, triggerPatch, bounds);
      const controlled = pastePatch(sample.raster, { width:controlPatch.width,height:controlPatch.height,channels:controlPatch.channels,data:controlPatch.data }, bounds);
      const cleanPred = await predict(sample.raster);
      const triggerPred = await predict(triggered);
      const controlPred = await predict(controlled);
      rows.push({
        sample:index,
        true_label:sample.trueLabel,
        clean_pred:cleanPred.label,
        triggered_pred:triggerPred.label,
        control_pred:controlPred.label,
        target_label:String(candidate.targetLabel),
        candidateId:expectedCandidateId,
        runtimeBindingId:binding.runtimeBindingId
      });
    }
    return { inputName, outputName, classes, rows };
  });

  const observations = { targetLabel:String(candidate.targetLabel), candidateId:expectedCandidateId, rows:execution.rows };
  const verifier = verifyBackdoorPatchCandidate({ candidate, candidateId:expectedCandidateId, observations });
  const verificationEligible = Boolean(preprocess.trusted && model.sha256 && controlPatch);
  const verified = Boolean(verificationEligible && verifier.verified === true);
  return {
    schema:'newcyber.ai-backdoor-runtime-verifier.v1',
    candidateId:expectedCandidateId,
    runtimeBindingId:binding.runtimeBindingId,
    verified,
    verdict:verified?'runtime-verified':verifier.verified&&!verificationEligible?'runtime-evidence-not-eligible':'runtime-executed-not-verified',
    verificationEligible,
    provider,
    model:{ source:model.source, path:model.path, bytes:model.bytes, sha256:model.sha256 },
    triggerMaterial:{ bbox:bounds, sha256:binding.patchSha256 },
    preprocess:{ ...preprocess, sha256:binding.preprocessSha256 },
    execution:{ samples:samples.length, inputName:execution.inputName, outputName:execution.outputName, classes:execution.classes, complete:true },
    observations,
    verifier,
    notes:[
      '同一 ONNX session 对同一批 clean 样本生成 clean / triggered / control 三路预测，再交给 Batch48 candidate verifier。',
      'runtimeBindingId 同时绑定 candidateId、模型 SHA-256、trigger patch 内容 SHA-256 与 preprocessing SHA-256。',
      '只有 preprocessing 来源被显式标记为 challenge-source/model-config/official-writeup/explicit-user-verified 时，runtime 结果才有资格升级 Verified。',
      '本模块不搜索或优化 trigger；它只复验已经形成的具体 Candidate。'
    ]
  };
}

module.exports = {
  MAX_RUNTIME_SAMPLES,
  TRUSTED_PREPROCESS_SOURCES,
  normalizeRaster,
  normalizePreprocess,
  extractPatch,
  pastePatch,
  rasterTensorSpec,
  runBackdoorPatchRuntimeVerification
};
