'use strict';

const fs = require('fs/promises');
const path = require('path');
const { planHfOnnxExport } = require('./hf_onnx_export');
const { executeTrustedHfOnnxPlan } = require('./trusted_hf_converter');
const { validateTrustedConverterLocation } = require('./trusted_converter_location');
const { runScaAutopilotPaths } = require('./sca_autopilot');

const BRIDGE_SCHEMA = 'newcyber.sca-autopilot-conversion.v1';
const MAX_CANDIDATE_ROOTS = 16;

function resolved(value) {
  const result = path.resolve(String(value || ''));
  if (!result || result === path.parse(result).root) throw new Error('SCA/HF 路径无效');
  return result;
}

function bridgeGap(code, detail, stage, extra = {}) {
  return { schema: BRIDGE_SCHEMA, status: 'gap', gap: { code, detail, stage }, ...extra };
}

function isSafeTensorOracleGap(result) {
  return Boolean(
    result
    && result.status === 'gap'
    && result.gap?.code === 'ORACLE_ARTIFACT_GAP'
    && Array.isArray(result.discovery?.safetensors)
    && result.discovery.safetensors.length > 0
    && result.discovery?.roles?.model?.status !== 'ok'
  );
}

async function isRegularFile(filePath) {
  try {
    const stat = await fs.lstat(filePath);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function findHfModelRoots(filePaths) {
  const safetensorsDirs = new Set();
  for (const value of filePaths || []) {
    const filePath = resolved(value);
    if (path.extname(filePath).toLowerCase() === '.safetensors') safetensorsDirs.add(path.dirname(filePath));
  }
  const directories = [...safetensorsDirs].sort();
  if (directories.length > MAX_CANDIDATE_ROOTS) {
    return { status: 'gap', code: 'HF_ROOT_BUDGET_GAP', detail: `SafeTensors 候选目录=${directories.length} 超过 ${MAX_CANDIDATE_ROOTS}` };
  }
  const roots = [];
  for (const directory of directories) {
    if (await isRegularFile(path.join(directory, 'config.json'))) roots.push(directory);
  }
  if (!roots.length) return { status: 'gap', code: 'HF_ROOT_GAP', detail: '发现 SafeTensors，但没有同目录 config.json；不会跨目录猜 HuggingFace 模型根' };
  if (roots.length > 1) return { status: 'gap', code: 'HF_ROOT_AMBIGUITY_GAP', detail: `发现多个 HuggingFace 模型根：${roots.map((item) => path.basename(item)).join(', ')}`, roots };
  return { status: 'ok', root: roots[0], roots };
}

async function convertAndResumeSca(filePaths, converterDescriptor, options = {}) {
  const sourcePaths = [];
  const seen = new Set();
  for (const value of filePaths || []) {
    const filePath = resolved(value);
    if (seen.has(filePath)) continue;
    seen.add(filePath);
    sourcePaths.push(filePath);
  }
  if (!sourcePaths.length) return bridgeGap('ARTIFACT_ROLE_GAP', '没有 SCA 工件可继续', 'discover');

  const rootState = await findHfModelRoots(sourcePaths);
  if (rootState.status !== 'ok') return bridgeGap(rootState.code, rootState.detail, 'hf-root', { roots: rootState.roots || [] });

  const protectedRoots = [{ path:rootState.root, label:'HF model root' }];
  if (options.workspaceRoot) protectedRoots.push({ path:resolved(options.workspaceRoot), label:'challenge workspace' });
  const converterLocation = await validateTrustedConverterLocation(converterDescriptor, protectedRoots);
  if (!converterLocation.ok) {
    return bridgeGap(converterLocation.code, converterLocation.detail, 'converter-location', {
      modelRoot:rootState.root,
      converterLocation
    });
  }

  const planner = options.planHfOnnxExport || planHfOnnxExport;
  const executor = options.executeTrustedHfOnnxPlan || executeTrustedHfOnnxPlan;
  const autopilot = options.runScaAutopilotPaths || runScaAutopilotPaths;
  const plan = await planner(rootState.root, { task: options.task || null, outputDir: options.outputDir || null });
  if (plan?.status !== 'ready') {
    return bridgeGap(plan?.gap?.code || 'HF_PLAN_GAP', plan?.gap?.detail || 'HF → ONNX plan 未 ready', 'plan', { modelRoot: rootState.root, plan });
  }

  const conversion = await executor(plan, converterDescriptor, {
    provider: options.provider || 'cpu',
    purpose: 'sca',
    ort: options.ort,
    spawnImpl: options.spawnImpl,
    timeoutMs: options.timeoutMs,
    maxOutputBytes: options.maxOutputBytes,
    baseEnv: options.baseEnv
  });
  if (conversion?.status !== 'converted' || !conversion.selected?.filePath) {
    return bridgeGap(conversion?.gap?.code || 'CONVERSION_GAP', conversion?.gap?.detail || 'SafeTensors → ONNX 转换未完成', conversion?.gap?.stage || 'convert', {
      modelRoot: rootState.root,
      plan,
      conversion
    });
  }

  const selectedOnnx = resolved(conversion.selected.filePath);
  const rerunPaths = sourcePaths.filter((item) => path.extname(item).toLowerCase() !== '.onnx');
  rerunPaths.push(selectedOnnx);
  const result = await autopilot(rerunPaths, { provider: options.provider || 'cpu', ort: options.ort });
  return {
    schema: BRIDGE_SCHEMA,
    status: result?.status || 'gap',
    gap: result?.gap || null,
    modelRoot: rootState.root,
    plan,
    conversion,
    converterLocation,
    rerun: {
      selectedOnnx,
      originalFiles: sourcePaths.length,
      files: rerunPaths.length,
      existingOnnxExcluded: sourcePaths.filter((item) => path.extname(item).toLowerCase() === '.onnx').map((item) => path.basename(item))
    },
    result
  };
}

module.exports = {
  BRIDGE_SCHEMA,
  MAX_CANDIDATE_ROOTS,
  isSafeTensorOracleGap,
  findHfModelRoots,
  convertAndResumeSca
};
