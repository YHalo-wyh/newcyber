const path = require('path');
const { inspectModelArtifact, scanPickleOpcodes } = require('./model_artifacts');

const AI_TOOLING = Object.freeze([
  { id:'art', name:'Adversarial Robustness Toolbox (ART)', project:'Trusted-AI/adversarial-robustness-toolbox', license:'MIT', role:'evasion / poisoning / extraction / inference', mode:'harness' },
  { id:'foolbox', name:'Foolbox', project:'bethgelab/foolbox', license:'MIT', role:'gradient-based adversarial example evaluation', mode:'harness' },
  { id:'privacy-meter', name:'Privacy Meter', project:'privacytrustlab/ml_privacy_meter', license:'MIT', role:'membership / range-membership / data-usage privacy audit', mode:'harness' },
  { id:'cleanlab', name:'cleanlab', project:'cleanlab/cleanlab', license:'Apache-2.0', role:'label issues / data quality / outlier evidence', mode:'harness' },
  { id:'backdoorbench', name:'BackdoorBench', project:'SCLBD/BackdoorBench', license:'research-project', role:'backdoor attack/defense benchmark reference', mode:'reference' },
  { id:'modelscan', name:'ModelScan', project:'protectai/modelscan', license:'Apache-2.0', role:'static model serialization scan', mode:'cli' },
  { id:'picklescan', name:'PickleScan', project:'mmaitre314/picklescan', license:'MIT', role:'pickle / PyTorch dangerous global scan', mode:'cli' }
]);

function inspectModelInternally(buffer, fileName='model.bin') {
  const ext=path.extname(String(fileName||'')).toLowerCase();
  const advanced=inspectModelArtifact(buffer,ext);
  if (advanced) return { engine:'newcyber', format:advanced.format||ext, result:advanced };
  if (['.pkl','.pickle','.joblib','.bin'].includes(ext)) {
    const pickle=scanPickleOpcodes(buffer);
    if (pickle?.opcodeCount || pickle?.globals?.length || pickle?.complete) return { engine:'newcyber-pickle', format:'pickle-like', result:pickle };
  }
  return { engine:'newcyber', format:ext||'unknown', result:null };
}

function normalizeExternalResult(engine, execution={}) {
  const stdout=String(execution.stdout||'').trim();
  const stderr=String(execution.stderr||'').trim();
  let parsed=null;
  if (stdout && /^[\[{]/.test(stdout)) {
    try { parsed=JSON.parse(stdout); } catch {}
  }
  const code=Number.isInteger(execution.code) ? execution.code : null;
  let status='unknown';
  if (engine==='modelscan') {
    if (code===0) status='clean';
    else if (code===1) status='findings';
    else if (code===2 || code===3 || code===4) status='error';
  } else if (engine==='picklescan') {
    if (code===0) status='clean';
    else if (code===1) status='findings';
    else if (code===2) status='error';
  }
  return {
    engine,
    status,
    exitCode:code,
    parsed,
    stdout:stdout.slice(-24000),
    stderr:stderr.slice(-8000),
    findingsLikely:status==='findings' || /(?:dangerous globals|infected files|critical|unsafe|vulnerab)/i.test(`${stdout}\n${stderr}`)
  };
}

function mergeModelScanEvidence(internal, external=[]) {
  const findings=[];
  const internalFindings=internal?.result?.securityFindings||[];
  for (const item of internalFindings) findings.push({ source:'NewCyber', severity:item.severity||'info', id:item.id||'model-structure', evidence:item.message||JSON.stringify(item) });
  for (const result of external) {
    if (result.status==='findings') findings.push({ source:result.engine, severity:'high', id:`${result.engine}-findings`, evidence:(result.stdout||result.stderr||'scanner reported findings').slice(0,2000) });
    else if (result.status==='error') findings.push({ source:result.engine, severity:'info', id:`${result.engine}-error`, evidence:(result.stderr||result.stdout||'scanner failed').slice(0,1000) });
  }
  return {
    internal,
    external,
    findings,
    verdict: findings.some((x)=>x.severity==='high') ? 'review-required' : findings.some((x)=>x.severity==='medium') ? 'review' : 'no-high-risk-evidence',
    notes:['多个扫描器结果是交叉证据，不把任何单一扫描器的“clean”解释为模型可安全执行。']
  };
}

function toolingCatalog() {
  return AI_TOOLING.map((x)=>({...x}));
}

module.exports={ AI_TOOLING, toolingCatalog, inspectModelInternally, normalizeExternalResult, mergeModelScanEvidence };
