const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const fsp=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const vm=require('node:vm');

const { analyzeAdversarialPair, buildAdversarialHarness }=require('../src/core/ai_adversarial');
const { analyzePrivacyTranscript }=require('../src/core/ai_privacy');
const { analyzeDatasetSecurity }=require('../src/core/ai_dataset_security');
const { auditAiSupplyChain }=require('../src/core/ai_supply_chain');
const { normalizeExternalResult, toolingCatalog }=require('../src/core/ai_tooling');
const { runTool }=require('../src/core/tool_router');
const { scanWorkspace }=require('../src/core/finals_analyzer_batch9');

test('adversarial auditor validates norm budget and output goal independently',()=>{
  const result=analyzeAdversarialPair({
    original:[0,0.2,0.4],
    adversarial:[0.01,0.22,0.38],
    epsilon:0.03,
    norm:'linf',
    clip:[0,1],
    trueLabel:0,
    predictedOriginal:0,
    predictedAdversarial:1
  });
  assert.equal(result.withinBudget,true);
  assert.equal(result.outcome.success,true);
  assert.equal(result.verdict,'within-budget-success');
  assert.ok(result.norms.linf<=0.03+1e-12);
  assert.ok(result.findings.some((x)=>x.id==='adversarial-candidate-valid'));
});

test('adversarial auditor rejects over-budget candidate even if prediction changed',()=>{
  const result=analyzeAdversarialPair({ original:[0,0], adversarial:[0.2,0], epsilon:0.05, predictedOriginal:0, predictedAdversarial:1 });
  assert.equal(result.withinBudget,false);
  assert.equal(result.verdict,'over-budget');
  assert.ok(result.findings.some((x)=>x.id==='adversarial-budget-exceeded'));
});

test('adversarial harness exposes ART and Foolbox without inventing challenge model loader',()=>{
  const result=buildAdversarialHarness({ epsilon:8/255, attacks:['fgsm','pgd'] });
  assert.deepEqual(result.harnesses.map((x)=>x.backend),['ART','Foolbox']);
  assert.match(result.harnesses[0].script,/FastGradientMethod/);
  assert.match(result.harnesses[0].script,/ProjectedGradientDescent/);
  assert.match(result.harnesses[0].script,/NotImplementedError/);
  assert.match(result.harnesses[1].script,/LinfPGD/);
});

test('privacy auditor recovers a strong loss-based membership separation',()=>{
  const csv=[
    'member,loss,confidence',
    '1,0.10,0.98',
    '1,0.15,0.96',
    '1,0.20,0.93',
    '0,0.80,0.60',
    '0,0.90,0.55',
    '0,1.10,0.50'
  ].join('\n');
  const result=analyzePrivacyTranscript(csv);
  const loss=result.signals.find((x)=>x.id==='loss');
  assert.ok(loss);
  assert.equal(loss.auc,1);
  assert.ok(loss.threshold.balancedAccuracy>=0.99);
  assert.equal(result.privacyRisk,'high');
  assert.ok(result.findings.some((x)=>x.id==='membership-separation'));
});

test('dataset auditor finds conflicting labels and rare label-bound trigger candidates',()=>{
  const csv=[
    'text,feature,label',
    'normal alpha,1,0',
    'normal beta,2,0',
    'normal gamma,3,0',
    'rare_trigger red,9,1',
    'rare_trigger blue,8,1',
    'same sample,7,0',
    'same sample,7,1'
  ].join('\n');
  const result=analyzeDatasetSecurity(csv);
  assert.equal(result.labelColumn,'label');
  assert.ok(result.conflictingLabels.length>=1);
  assert.ok(result.triggerCandidates.some((x)=>x.token==='rare_trigger' && x.targetLabel==='1'));
  assert.ok(result.findings.some((x)=>x.id==='dataset-label-conflict'));
  assert.ok(result.findings.some((x)=>x.id==='dataset-trigger-candidate'));
});

test('supply-chain auditor connects source evidence to fix and regression guidance',()=>{
  const source=`
from transformers import AutoModel
model = AutoModel.from_pretrained(repo, trust_remote_code=True)
obj = torch.load(upload_path)
--extra-index-url https://mirror.example/simple
internal_pkg>=1.0
`;
  const result=auditAiSupplyChain(source);
  assert.ok(result.findings.some((x)=>x.id==='hf-trust-remote-code'));
  assert.ok(result.findings.some((x)=>x.id==='hf-revision-unpinned'));
  assert.ok(result.findings.some((x)=>x.id==='unsafe-model-deserialization-call'));
  assert.ok(result.findings.some((x)=>x.id==='python-extra-index'));
  const trust=result.findings.find((x)=>x.id==='hf-trust-remote-code');
  assert.ok(trust.fix?.action);
  assert.ok(trust.fix?.regression);
});

test('open-source backend normalization keeps scanner exit semantics explicit',()=>{
  const modelscan=normalizeExternalResult('modelscan',{ code:1,stdout:'{"issues":[{"severity":"HIGH"}]}',stderr:'' });
  const picklescan=normalizeExternalResult('picklescan',{ code:0,stdout:'Scanned files: 1\nInfected files: 0',stderr:'' });
  assert.equal(modelscan.status,'findings');
  assert.equal(modelscan.parsed.issues.length,1);
  assert.equal(picklescan.status,'clean');
  const names=toolingCatalog().map((x)=>x.id);
  for (const id of ['art','foolbox','privacy-meter','cleanlab','backdoorbench','modelscan','picklescan']) assert.ok(names.includes(id));
});

test('tool router exposes Batch 9 AI analyzers',()=>{
  assert.equal(runTool('ai-adversarial-audit',{input:JSON.stringify({original:[0],adversarial:[0.01],epsilon:0.1})}).withinBudget,true);
  assert.equal(runTool('ai-privacy-audit',{input:'member,loss\n1,0.1\n0,1.0'}).signals[0].auc,1);
  assert.equal(runTool('ai-dataset-security',{input:'text,label\na,0\nb,1'}).rows,2);
  assert.ok(runTool('ai-supply-chain',{input:'AutoModel.from_pretrained(repo, trust_remote_code=True)'}).findings.length>=1);
});

test('Batch 9 workspace enriches AI supply-chain and labeled dataset attachments',async()=>{
  const dir=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-ai9-'));
  try {
    await fsp.writeFile(path.join(dir,'service.py'),"model=AutoModel.from_pretrained(repo, trust_remote_code=True)\n");
    await fsp.writeFile(path.join(dir,'train.csv'),'text,label\nnormal,0\nrare_trigger a,1\nrare_trigger b,1\n');
    const analysis=await scanWorkspace(dir);
    const source=analysis.files.find((x)=>x.path==='service.py');
    const dataset=analysis.files.find((x)=>x.path==='train.csv');
    assert.ok(source?.metadata?.aiSupplyChain?.findings?.some((x)=>x.id==='hf-trust-remote-code'));
    assert.ok(dataset?.metadata?.aiDatasetSecurity);
    assert.ok(analysis.recommendations.some((x)=>/AI 供应链/.test(x)));
    assert.ok(analysis.recommendations.some((x)=>/AI 数据安全/.test(x)));
  } finally { await fsp.rm(dir,{recursive:true,force:true}); }
});

test('Batch 9 renderer compiles, loads after UAV Batch 8, and Electron exposes model scanners',()=>{
  const root=path.join(__dirname,'..');
  const source=fs.readFileSync(path.join(root,'renderer/ai_batch9_tools.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  const main=fs.readFileSync(path.join(root,'main.js'),'utf8');
  const preload=fs.readFileSync(path.join(root,'preload.js'),'utf8');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'renderer/ai_batch9_tools.js'}));
  assert.ok(html.indexOf('ai_batch9_tools.js')>html.indexOf('uav_batch8_tools.js'));
  assert.match(source,/ModelScan \/ PickleScan/);
  assert.match(source,/Privacy Meter/);
  assert.match(source,/BackdoorBench/);
  assert.match(main,/finals_analyzer_batch9/);
  assert.match(main,/modelscan/);
  assert.match(main,/picklescan/);
  assert.match(main,/shell:\s*false/);
  assert.match(preload,/chooseAndScanAiModel/);
});
