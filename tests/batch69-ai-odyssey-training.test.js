'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  ODYSSEY_TRAINING_SEEDS,
  STRUCTURED_RULES,
  evaluateOdysseyStructuredReplay,
  getOdysseyTrainingCorpus,
  runOdysseyTrainingRegression
}=require('../src/core/ai_odyssey_training');
const {runTool}=require('../src/core/tool_router');

const EXPECTED_CHALLENGES=[
  'Model Leakage Event','Mask of Injectus IX','Trojaned Model — Neural C2 Beacon','Catch Me If You Scan',
  'ShopFlow','Rogue Commit','Sealed Substation','Shipped With Malice','The Loan Arranger'
];

test('Batch69 covers all nine public AI Odyssey challenges with challenge-specific mechanics',()=>{
  const challenges=new Set(ODYSSEY_TRAINING_SEEDS.map((item)=>item.challenge));
  assert.equal(challenges.size,9);
  for(const name of EXPECTED_CHALLENGES)assert.ok(challenges.has(name),name);
  assert.ok(ODYSSEY_TRAINING_SEEDS.length>=15,`seeds=${ODYSSEY_TRAINING_SEEDS.length}`);
  assert.ok(new Set(ODYSSEY_TRAINING_SEEDS.map((item)=>item.family)).size>=14);
});

test('Batch69 never copies upstream flags, credentials, challenge IPs, secrets or original thresholds into fixtures',()=>{
  const serialized=JSON.stringify(ODYSSEY_TRAINING_SEEDS);
  assert.equal(/THM\{/i.test(serialized),false);
  assert.equal(/TryHaulMe123/i.test(serialized),false);
  assert.equal(/shopflow-internal/i.test(serialized),false);
  assert.equal(/10\.14\d\./.test(serialized),false);
  assert.equal(/0\.45/.test(serialized),false);
  for(const item of ODYSSEY_TRAINING_SEEDS){
    assert.equal(item.trainingPolicy,'synthetic-fixture-only');
    assert.match(item.provenance.url,/^https:\/\/github\.com\/the-byte-chef\/ctf-ai-odyssey-2026\/blob\/main\//);
    assert.equal(item.provenance.evidenceLevel,'writeup-specific');
  }
});

test('Batch69 adds extraction and inversion training on top of prompt/supply/structured replay',()=>{
  const evaluators=new Set(ODYSSEY_TRAINING_SEEDS.map((item)=>item.evaluator));
  for(const name of ['extraction','inversion','supply','prompt','structured'])assert.ok(evaluators.has(name),name);
  const regression=runOdysseyTrainingRegression({variantsPerSeed:1});
  const extraction=regression.results.find((row)=>row.seed==='ai-odyssey-2026-model-leakage-extraction');
  const inversion=regression.results.find((row)=>row.seed==='ai-odyssey-2026-mask-embedding-inversion');
  const supply=regression.results.find((row)=>row.seed==='ai-odyssey-2026-trojaned-model-deserialization');
  assert.equal(extraction.status,'pass');assert.ok(extraction.findingIds.some((id)=>id.startsWith('extraction-')));
  assert.equal(inversion.status,'pass');assert.ok(inversion.findingIds.some((id)=>id.startsWith('inversion-')));
  assert.equal(supply.status,'pass');assert.ok(supply.findingIds.some((id)=>/torch-load|deserialization/.test(id)));
});

test('Batch69 structured challenge graphs require the whole evidence chain',()=>{
  assert.ok(Object.keys(STRUCTURED_RULES).length>=11);
  for(const [riskType,keys] of Object.entries(STRUCTURED_RULES)){
    const hit={riskType};for(const key of keys)hit[key]=true;
    assert.equal(evaluateOdysseyStructuredReplay(hit).verdict,'candidate-failure',riskType);
    const miss={...hit,[keys[keys.length-1]]:false};
    assert.equal(evaluateOdysseyStructuredReplay(miss).verdict,'no-explicit-failure',`${riskType} negative control`);
  }
});

test('Batch69 regression stays deterministic across challenge-derived variants',()=>{
  const a=runOdysseyTrainingRegression({variantsPerSeed:4});
  const b=runOdysseyTrainingRegression({variantsPerSeed:4});
  assert.deepEqual(a,b);
  assert.equal(a.schema,'newcyber.ai-odyssey-training.v1');
  assert.equal(a.summary.seeds,ODYSSEY_TRAINING_SEEDS.length);
  assert.equal(a.summary.cases,ODYSSEY_TRAINING_SEEDS.length*4);
  assert.equal(a.summary.challenges,9);
  assert.ok(a.summary.directions>=5,`directions=${a.summary.directions}`);
  assert.ok(a.summary.passRate>=0.95,`pass=${a.summary.pass} miss=${a.summary.miss} error=${a.summary.error}`);
});

test('Batch69 router exposes corpus and regression without exposing synthetic fixtures',()=>{
  const corpus=runTool('ai-odyssey-training-corpus',{});
  assert.equal(corpus.schema,'newcyber.ai-odyssey-training-corpus.v1');
  assert.equal(corpus.cases.length,getOdysseyTrainingCorpus().length);
  assert.ok(corpus.cases.every((item)=>!Object.prototype.hasOwnProperty.call(item,'fixture')));
  const regression=runTool('ai-odyssey-training-regression',{options:{variantsPerSeed:2}});
  assert.equal(regression.schema,'newcyber.ai-odyssey-training.v1');
  assert.equal(regression.summary.cases,ODYSSEY_TRAINING_SEEDS.length*2);
});
