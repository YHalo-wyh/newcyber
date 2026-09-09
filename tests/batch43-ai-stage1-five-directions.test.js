'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {tprAtFpr,membershipAdvantage,analyzePrivacyTranscript}=require('../src/core/ai_privacy');
const {analyzeAdversarialBatch}=require('../src/core/ai_adversarial');
const {auditAiSupplyChain}=require('../src/core/ai_supply_chain');
const {STAGE1_DIRECTIONS,PUBLIC_TRAINING_SEEDS,runAiStage1TrainingRegression}=require('../src/core/ai_stage1_training_corpus');
const {runTool}=require('../src/core/tool_router');

function ids(items){return items.map((x)=>x.id);}

test('Batch43 corpus covers exactly the five latest stage-one directions with broad public provenance',()=>{
  assert.deepEqual(ids(STAGE1_DIRECTIONS),['prompt-llm-security','adversarial-example','privacy-leakage','backdoor-poisoning','infra-supply-chain']);
  assert.ok(PUBLIC_TRAINING_SEEDS.length>=25,`seedCount=${PUBLIC_TRAINING_SEEDS.length}`);
  for(const direction of STAGE1_DIRECTIONS){
    const subset=PUBLIC_TRAINING_SEEDS.filter((x)=>x.direction===direction.id);
    assert.ok(subset.length>=5,`${direction.id} seeds=${subset.length}`);
    assert.ok(new Set(subset.map((x)=>x.family)).size>=4,`${direction.id} family diversity`);
  }
  for(const seed of PUBLIC_TRAINING_SEEDS){
    assert.match(seed.provenance.url,/^https:\/\//);
    assert.ok(seed.provenance.title);
    assert.ok(seed.family);
  }
});

test('Batch43 public seed mutation produces at least 100 deterministic training cases',()=>{
  const first=runAiStage1TrainingRegression({variantsPerSeed:4});
  const second=runAiStage1TrainingRegression({variantsPerSeed:4});
  assert.ok(first.caseCount>=100,`cases=${first.caseCount}`);
  assert.deepEqual(first,second);
  assert.equal(first.directions.length,5);
  assert.ok(first.passRate>=0.95,`pass=${first.pass}/${first.caseCount} miss=${first.miss} error=${first.error}`);
  for(const direction of first.directions)assert.ok(direction.passRate>=0.9,`${direction.id} passRate=${direction.passRate}`);
});

test('Batch43 MICO-style scorer exposes TPR at 10 percent FPR and membership advantage',()=>{
  const items=[
    {member:true,value:0.99},{member:true,value:0.97},{member:true,value:0.95},{member:true,value:0.93},
    {member:false,value:0.61},{member:false,value:0.58},{member:false,value:0.55},{member:false,value:0.51}
  ];
  const low=tprAtFpr(items,true,0.1);
  assert.equal(low.tpr,1);
  assert.equal(low.fpr,0);
  const advantage=membershipAdvantage(items,true);
  assert.equal(advantage.advantage,1);
  const report=analyzePrivacyTranscript({rows:items.map((x)=>({member:x.member,confidence:x.value}))});
  assert.equal(report.competitionMetrics.tprAtFpr10,1);
  assert.equal(report.competitionMetrics.realizedFpr,0);
  assert.equal(report.competitionMetrics.membershipAdvantage,1);
  assert.equal(report.privacyRisk,'high');
});

test('Batch43 adversarial batch scorer separates attack success from invalid over-budget rows',()=>{
  const report=analyzeAdversarialBatch({norm:'linf',epsilon:0.05,clip:[0,1],samples:[
    {original:[0.1,0.2],adversarial:[0.12,0.21],trueLabel:0,predictedOriginal:0,predictedAdversarial:1},
    {original:[0.3,0.4],adversarial:[0.28,0.43],trueLabel:1,predictedOriginal:1,predictedAdversarial:0},
    {original:[0.5,0.6],adversarial:[0.52,0.58],trueLabel:2,predictedOriginal:2,predictedAdversarial:3},
    {original:[0.2,0.2],adversarial:[0.3,0.2],trueLabel:4,predictedOriginal:4,predictedAdversarial:5}
  ]});
  assert.equal(report.samples,4);
  assert.equal(report.budget.within,3);
  assert.equal(report.budget.over,1);
  assert.equal(report.budget.allWithin,false);
  assert.equal(report.attack.successful,3);
  assert.equal(report.attack.validSuccessRate,1);
  assert.equal(report.accuracy.clean,1);
  assert.equal(report.accuracy.adversarial,0);
  assert.ok(report.findings.some((x)=>x.id==='adversarial-batch-budget-violations'));
});

test('Batch43 supply-chain audit distinguishes unrestricted torch load from explicit weights-only load',()=>{
  const unsafe=auditAiSupplyChain('import torch\nmodel = torch.load(path, weights_only=False)');
  assert.ok(unsafe.findings.some((x)=>x.id==='torch-load-weights-only-false'&&x.severity==='high'));
  const restricted=auditAiSupplyChain('import torch\nstate = torch.load(path, weights_only=True)');
  assert.equal(restricted.findings.some((x)=>x.id==='torch-load-weights-only-false'||x.id==='torch-load-policy-implicit'),false);
});

test('Batch43 tool router exposes batch adversarial scoring and high-intensity training regression',()=>{
  const adversarial=runTool('ai-adversarial-batch',{input:{epsilon:0.1,norm:'linf',samples:[{original:[0],adversarial:[0.01],trueLabel:0,predictedAdversarial:1}]}});
  assert.equal(adversarial.schema,'newcyber.ai-adversarial-batch.v1');
  const regression=runTool('ai-stage1-training-regression',{options:{variantsPerSeed:4}});
  assert.equal(regression.schema,'newcyber.ai-stage1-training-regression.v1');
  assert.ok(regression.caseCount>=100);
  const corpus=runTool('ai-stage1-training-corpus',{});
  assert.equal(corpus.schema,'newcyber.ai-stage1-training-corpus.v1');
  assert.equal(corpus.cases.length,PUBLIC_TRAINING_SEEDS.length);
});
