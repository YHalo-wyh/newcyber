'use strict';

const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer_batch22');
const { analyzeModelArithmeticBundle } = require('./ai_model_arithmetic');

const MAX_ZIP_ATTEMPTS = 4;
const MAX_BUNDLE_FILES = 96;
const MAX_ZIP_BYTES = 64 * 1024 * 1024;
const MAX_BUNDLE_BYTES = 96 * 1024 * 1024;
const MAX_SINGLE_BUNDLE_FILE = 32 * 1024 * 1024;
const BUNDLE_EXTENSIONS = new Set(['.py','.pyw','.json','.npy','.bin','.enc','.dat']);

function inside(rootPath, relativePath) {
  const root = path.resolve(rootPath);
  const target = path.resolve(root, relativePath);
  if (target !== root && !target.startsWith(root + path.sep)) throw new Error('模型算术自动路由文件超出赛题目录');
  return target;
}

function statusPriority(status) {
  return {
    'flag-recovered':100,
    'secret-recovered':85,
    'solver-budget-gap':65,
    'feature-recipe-gap':55,
    'solver-incomplete':50,
    'missing-public-parameters':35,
    'missing-sample-pair':25,
    'identified-no-linear-proof':0
  }[status] ?? 10;
}

function likelyUnpackedBundle(files) {
  const extensions = files.map((file) => file.extension);
  const npy = extensions.filter((ext) => ext === '.npy').length;
  const source = extensions.some((ext) => ext === '.py' || ext === '.pyw');
  const config = extensions.includes('.json');
  return npy >= 2 && source && config;
}

async function readZipAttempt(rootPath, file) {
  if (!file || file.extension !== '.zip' || file.size <= 0 || file.size > MAX_ZIP_BYTES) return null;
  const buffer = await fsp.readFile(inside(rootPath, file.path));
  const result = analyzeModelArithmeticBundle({ base64:buffer.toString('base64'), fileName:file.name });
  return { sourceKind:'zip', source:file.path, result };
}

async function readUnpackedAttempt(rootPath, files) {
  if (!likelyUnpackedBundle(files)) return null;
  const selected = files.filter((file) => BUNDLE_EXTENSIONS.has(file.extension) && file.size > 0 && file.size <= MAX_SINGLE_BUNDLE_FILE).slice(0,MAX_BUNDLE_FILES);
  let total = 0;
  const packed = [];
  for (const file of selected) {
    if (total + file.size > MAX_BUNDLE_BYTES) break;
    const buffer = await fsp.readFile(inside(rootPath,file.path));
    total += buffer.length;
    packed.push({ name:file.path, base64:buffer.toString('base64') });
  }
  if (!packed.length) return null;
  const result = analyzeModelArithmeticBundle({ files:packed });
  return { sourceKind:'workspace-files', source:`${packed.length} workspace files`, result };
}

async function analyzeWorkspaceModelArithmetic(rootPath,analysis,options={}) {
  if (options.enabled === false) return { schema:'newcyber.workspace-model-arithmetic.v1', enabled:false, attempts:[], best:null };
  const attempts = [];
  const zips = (analysis.files||[]).filter((file) => file.extension === '.zip' && file.size > 0 && file.size <= MAX_ZIP_BYTES).sort((a,b) => a.size-b.size || a.path.localeCompare(b.path)).slice(0,MAX_ZIP_ATTEMPTS);
  for (const file of zips) {
    try {
      const attempt = await readZipAttempt(rootPath,file);
      if (attempt) attempts.push(attempt);
      if (attempt?.result?.status === 'flag-recovered') break;
    } catch (error) {
      attempts.push({ sourceKind:'zip', source:file.path, error:error?.message||String(error), result:null });
    }
  }
  if (!attempts.some((item) => item.result?.status === 'flag-recovered')) {
    try {
      const unpacked = await readUnpackedAttempt(rootPath,analysis.files||[]);
      if (unpacked) attempts.push(unpacked);
    } catch (error) {
      attempts.push({ sourceKind:'workspace-files', source:'workspace bundle', error:error?.message||String(error), result:null });
    }
  }
  const ranked = attempts.filter((item) => item.result).sort((a,b) => statusPriority(b.result.status)-statusPriority(a.result.status));
  return {
    schema:'newcyber.workspace-model-arithmetic.v1',
    enabled:true,
    attempts,
    best:ranked[0]||null,
    summary:{
      attempted:attempts.length,
      provenLinear:attempts.filter((item)=>item.result?.sourceInspection?.boundedLinearHead).length,
      systemsBuilt:attempts.filter((item)=>item.result?.featureSystem?.rows).length,
      uniqueSecrets:attempts.filter((item)=>item.result?.solver?.status==='unique').length,
      flagsRecovered:attempts.filter((item)=>item.result?.status==='flag-recovered').length
    }
  };
}

function promoteWorkspaceResult(analysis) {
  const routed = analysis.modelArithmeticAuto;
  const best = routed?.best;
  if (!best?.result) return;
  const result = best.result;
  analysis.autopilot ||= { automaticChecks:[], actions:[], summary:{} };
  analysis.autopilot.automaticChecks ||= [];
  if (!analysis.autopilot.automaticChecks.some((item)=>item.id==='model-arithmetic-auto')) {
    analysis.autopilot.automaticChecks.push({
      id:'model-arithmetic-auto',
      title:'模型算术 / Hidden Head 自动恢复',
      hits:(routed.summary?.systemsBuilt||0)+(routed.summary?.flagsRecovered||0)
    });
  }

  if (result.status === 'flag-recovered' && result.flag) {
    analysis.candidates ||= { flags:[], urls:[], ips:[] };
    analysis.candidates.flags ||= [];
    if (!analysis.candidates.flags.some((item)=>item.value===result.flag)) {
      analysis.candidates.flags.unshift({
        value:result.flag,
        file:best.source,
        source:'model-arithmetic-auto',
        confidence:'verified',
        evidence:`unique secret · ${result.solver?.rows||0}/${result.solver?.rows||0} residuals within ±${result.solver?.bound ?? '?'} · ${result.flagRecovery?.hits?.find((hit)=>hit.flags?.includes(result.flag))?.algorithm||'cipher oracle'}`
      });
    }
    analysis.stats ||= {};
    analysis.stats.flags=analysis.candidates.flags.length;
    analysis.insights ||= [];
    if (!analysis.insights.some((item)=>item.kind==='model-arithmetic-flag-recovery'&&item.flag===result.flag)) {
      analysis.insights.unshift({
        kind:'model-arithmetic-flag-recovery',
        title:'Hidden linear head 已确定性恢复并解出 Flag',
        file:best.source,
        flag:result.flag,
        evidence:`${result.featureSystem?.rows||0}×${result.featureSystem?.dimension||0} mod ${result.publicConfig?.modulus||'?'} · B=${result.publicConfig?.noiseBound??'?'} · solver=${result.solver?.method||'?'} · unique secret`
      });
    }
    analysis.autopilot.actions=(analysis.autopilot.actions||[]).filter((item)=>item.id!=='model-arithmetic-flag');
    analysis.autopilot.actions.unshift({
      id:'model-arithmetic-flag',
      priority:120,
      level:'win',
      title:'Flag 已自动恢复：Model Arithmetic',
      detail:`${result.flag} · ${best.source} · unique secret / all residuals within bound / reproducible decrypt`
    });
  } else if (result.solver?.status === 'unique') {
    analysis.autopilot.actions=(analysis.autopilot.actions||[]).filter((item)=>item.id!=='model-arithmetic-secret');
    analysis.autopilot.actions.unshift({
      id:'model-arithmetic-secret',
      priority:96,
      level:'hot',
      title:'Hidden Head 已恢复，继续确认 Flag 派生',
      detail:`${best.source} · secret=[${result.solver.candidates?.[0]?.secretSigned?.join(', ')||''}] · ${result.flagRecovery?.status||'no cipher hit'}`
    });
  } else if (result.status === 'solver-budget-gap') {
    analysis.autopilot.actions=(analysis.autopilot.actions||[]).filter((item)=>item.id!=='model-arithmetic-budget');
    analysis.autopilot.actions.unshift({
      id:'model-arithmetic-budget',
      priority:82,
      level:'normal',
      title:'模型算术结构已建立，但枚举预算不足',
      detail:`${best.source} · dimension=${result.featureSystem?.dimension||'?'} · B=${result.publicConfig?.noiseBound??'?'}；考虑 LLL/BKZ backend，而不是扩大无界枚举。`
    });
  }

  analysis.autopilot.actions=(analysis.autopilot.actions||[]).sort((a,b)=>(b.priority||0)-(a.priority||0)).slice(0,5);
  analysis.autopilot.summary ||= {};
  analysis.autopilot.summary.modelArithmeticSystems=routed.summary?.systemsBuilt||0;
  analysis.autopilot.summary.modelArithmeticFlags=routed.summary?.flagsRecovered||0;
  analysis.autopilot.summary.flagCandidates=analysis.candidates?.flags?.length||0;
  analysis.autopilot.summary.automaticCheckKinds=analysis.autopilot.automaticChecks.length;
  analysis.autopilot.summary.automaticCheckHits=analysis.autopilot.automaticChecks.reduce((sum,item)=>sum+(Number(item.hits)||0),0);
}

async function scanWorkspace(rootPath,options={}) {
  const analysis=await base.scanWorkspace(rootPath,options);
  analysis.modelArithmeticAuto=await analyzeWorkspaceModelArithmetic(rootPath,analysis,options.modelArithmetic||{});
  promoteWorkspaceResult(analysis);
  const result=analysis.modelArithmeticAuto?.best?.result;
  if (result?.status==='flag-recovered') {
    analysis.recommendations=(analysis.recommendations||[]).filter((item)=>!/^模型算术：/.test(String(item)));
    analysis.recommendations.unshift(`模型算术：已通过唯一 bounded-modular secret 与可复现密钥派生自动恢复 Flag ${result.flag}。`);
  } else if (result?.sourceInspection?.boundedLinearHead) {
    analysis.recommendations=(analysis.recommendations||[]).filter((item)=>!/^模型算术：/.test(String(item)));
    analysis.recommendations.unshift(`模型算术：检测到 bounded modular hidden-head 结构，当前状态 ${result.status}；查看 Model Arithmetic 工作台的证据/预算 gap。`);
  }
  analysis.version=Math.max(Number(analysis.version)||1,31);
  return analysis;
}

function buildBatch31Section(analysis) {
  const routed=analysis.modelArithmeticAuto;
  if (!routed?.attempts?.length) return '';
  const lines=['## Batch 31 · Model Arithmetic Auto Recovery',''];
  for (const attempt of routed.attempts.slice(0,8)) {
    if (!attempt.result) {
      lines.push(`- \`${attempt.source}\`：ERROR · ${attempt.error||'unknown'}`);
      continue;
    }
    const result=attempt.result;
    lines.push(`- \`${attempt.source}\`：${result.status} · samples=${result.featureSystem?.rows||0} · dim=${result.featureSystem?.dimension||0} · q=${result.publicConfig?.modulus||'?'} · B=${result.publicConfig?.noiseBound??'?'}`);
    if (result.solver?.status==='unique') lines.push(`  - secret=[${result.solver.candidates?.[0]?.secretSigned?.join(', ')||''}] · max residual=${result.solver.candidates?.[0]?.maxAbsResidual??'?'}`);
    if (result.flag) lines.push(`  - Flag：\`${result.flag}\``);
  }
  lines.push('','> 自动提升 Flag 必须经过源码 bounded-linear 证据、唯一 secret、全方程 residual 验证和严格解密 Flag oracle；普通 ZIP/NPY 不会因为文件共现而被强行解释成 LWE。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildBatch31Section(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={
  ...base,
  scanWorkspace,
  buildMarkdownReport,
  analyzeWorkspaceModelArithmetic,
  promoteWorkspaceResult,
  buildBatch31Section
};