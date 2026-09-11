'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  SG_AICTF_TRAINING_SEEDS,STRUCTURED_RULES,evaluateSgAiCtfStructuredReplay,
  getSgAiCtfTrainingCorpus,runSgAiCtfTrainingRegression
}=require('../src/core/ai_sg_aictf_training');
const {CORPORA,getTrainingCurriculum,runTrainingCurriculumRegression}=require('../src/core/ai_training_curriculum');
const {runTool}=require('../src/core/tool_router');

const EXPECTED=[
  'Don’t Chao Keng','MNIST 11-class Backdoor','Adversarial Attack (delta.npy)',
  'StrideSafe','Bring Your Own Guardrails','Kopitalk','Co-Pirate'
];

test('Batch71 imports seven distinct AICTF 2025 challenge mechanics',()=>{
  assert.equal(SG_AICTF_TRAINING_SEEDS.length,7);
  const names=new Set(SG_AICTF_TRAINING_SEEDS.map((item)=>item.challenge));
  for(const name of EXPECTED)assert.ok(names.has(name),name);
  assert.equal(names.size,7);
  assert.ok(new Set(SG_AICTF_TRAINING_SEEDS.map((item)=>item.family)).size>=7);
});

test('Batch71 keeps participant answers and exact winning parameters out of executable fixtures',()=>{
  const serialized=JSON.stringify(SG_AICTF_TRAINING_SEEDS);
  assert.equal(/AI2025\{/i.test(serialized),false);
  assert.equal(/Found sigma/i.test(serialized),false);
  assert.equal(/EPS\s*=/i.test(serialized),false);
  assert.equal(/flag\{/i.test(serialized),false);
  for(const item of SG_AICTF_TRAINING_SEEDS){
    assert.equal(item.trainingPolicy,'synthetic-fixture-only');
    assert.equal(item.caseType,'real-ctf');
    assert.match(item.provenance.url,/Lushfadeds\/SG-AI-CTF---Pre-U-Solutions/);
    assert.equal(item.provenance.evidenceLevel,'writeup-specific');
  }
});

test('Batch71 structured replay requires the complete evidence chain',()=>{
  assert.equal(Object.keys(STRUCTURED_RULES).length,4);
  for(const [riskType,keys] of Object.entries(STRUCTURED_RULES)){
    const hit={riskType};for(const key of keys)hit[key]=true;
    assert.equal(evaluateSgAiCtfStructuredReplay(hit).verdict,'candidate-failure',riskType);
    const miss={...hit,[keys.at(-1)]:false};
    assert.equal(evaluateSgAiCtfStructuredReplay(miss).verdict,'no-explicit-failure',`${riskType} negative`);
  }
});

test('Batch71 backdoor/adversarial/prompt seeds are executable against existing analyzers',()=>{
  const regression=runSgAiCtfTrainingRegression({variantsPerSeed:1});
  const backdoor=regression.results.find((x)=>x.seed==='sg-aictf-2025-mnist-backdoor');
  const adversarial=regression.results.find((x)=>x.seed==='sg-aictf-2025-adversarial-delta');
  const prompt=regression.results.find((x)=>x.seed==='sg-aictf-2025-co-pirate');
  assert.equal(backdoor.status,'pass');
  assert.ok(backdoor.findingIds.includes('backdoor-target-asr-candidate'));
  assert.equal(adversarial.status,'pass');
  assert.ok(adversarial.findingIds.includes('adversarial-candidate-valid'));
  assert.equal(prompt.status,'pass');
});

test('Batch71 regression is deterministic across synthetic variants',()=>{
  const first=runSgAiCtfTrainingRegression({variantsPerSeed:4});
  const second=runSgAiCtfTrainingRegression({variantsPerSeed:4});
  assert.deepEqual(first,second);
  assert.equal(first.schema,'newcyber.sg-aictf-training.v1');
  assert.equal(first.summary.challenges,7);
  assert.equal(first.summary.cases,28);
  assert.ok(first.summary.passRate>=0.95,`pass=${first.summary.pass} miss=${first.summary.miss} error=${first.summary.error}`);
});

test('Batch71 is wired into router and global curriculum without exposing fixtures',()=>{
  const corpus=runTool('ai-sg-aictf-training-corpus',{});
  assert.equal(corpus.schema,'newcyber.ai-sg-aictf-training-corpus.v1');
  assert.equal(corpus.cases.length,getSgAiCtfTrainingCorpus().length);
  assert.ok(corpus.cases.every((item)=>!Object.prototype.hasOwnProperty.call(item,'fixture')));
  const regression=runTool('ai-sg-aictf-training-regression',{options:{variantsPerSeed:2}});
  assert.equal(regression.schema,'newcyber.sg-aictf-training.v1');
  const curriculum=getTrainingCurriculum();
  assert.ok(CORPORA.some((row)=>row.id==='sg-aictf-2025'));
  assert.equal(curriculum.summary.byCorpus['sg-aictf-2025'],7);
  assert.ok(curriculum.cases.some((row)=>row.id.startsWith('sg-aictf-2025:')));
  const full=runTrainingCurriculumRegression({variantsPerSeed:1});
  assert.equal(full.summary.suites,CORPORA.length);
  assert.equal(full.summary.suiteErrors,0);
  assert.ok(full.suites.some((row)=>row.id==='sg-aictf-2025'&&row.ok));
});
