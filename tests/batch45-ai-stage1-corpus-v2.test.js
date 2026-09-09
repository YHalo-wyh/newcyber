'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  DIRECTIONS,AI_STAGE1_SOURCE_CATALOG,byDirection:baseByDirection,buildCorpusV2Plan,catalogHealth
}=require('../src/core/ai_stage1_source_catalog');
const {SOURCE_REGISTRY,byDirection,registryHealth}=require('../src/core/ai_stage1_source_registry');
const {auditCurrentCorpusCoverage,buildTrainingMix}=require('../src/core/ai_stage1_corpus_optimizer');

test('Batch45 source catalog covers all five official stage-one directions with real sources',()=>{
  assert.equal(DIRECTIONS.length,5);
  const health=catalogHealth();
  assert.equal(health.complete,true);
  assert.equal(health.duplicateIds.length,0);
  for(const direction of DIRECTIONS){
    const sources=baseByDirection(direction);
    assert.ok(sources.length>=5,`${direction} source coverage`);
    assert.ok(sources.some((x)=>x.tier==='A'),`${direction} needs a real competition/dataset source`);
    assert.ok(sources.every((x)=>/^https:\/\//.test(x.url)),`${direction} sources must preserve provenance URL`);
  }
});

test('Batch45 expanded registry includes the user-selected global corpora and domestic CTFs',()=>{
  const health=registryHealth();
  assert.equal(health.complete,true);
  assert.ok(health.domestic>=6);
  assert.deepEqual(health.requestedCoreMissing,[]);
  const ids=new Set(SOURCE_REGISTRY.map((x)=>x.id));
  for(const id of [
    'tensortrust-data','prompt-airlines','gandalf-ignore-instructions','agentdojo',
    'madry-mnist-challenge','madry-cifar10-challenge','nips17-adversarial','robustbench',
    'mico','nist-trojai','ccb-2025-ai-archive','ccb-2025-easy-poison','ccb-2025-llm-poison',
    'bayarea-2025-blind-whisper','ycb-2024-nlp-model-attack','ycb-2024-targeted-image-adv','ycb-2025-mini-modelscope'
  ])assert.ok(ids.has(id),id);
  for(const direction of DIRECTIONS){
    const sources=byDirection(direction);
    assert.ok(sources.length>=5,`${direction} expanded source coverage`);
    assert.ok(sources.every((x)=>/^https:\/\//.test(x.url)),`${direction} registry provenance`);
  }
});

test('Batch45 plan prefers real competitions and benchmarks over synthetic tooling',()=>{
  const plan=buildCorpusV2Plan({maxPerDirection:6});
  assert.equal(plan.schema,'newcyber.ai-stage1-corpus-plan.v2');
  assert.equal(plan.directions.length,5);
  for(const group of plan.directions){
    assert.ok(group.sources.length>0);
    assert.ok(group.realSources>=1);
    assert.ok(group.sourceDiversity>=2);
    const priorities=group.sources.map((x)=>Number(x.priority)||0);
    assert.deepEqual(priorities,priorities.slice().sort((a,b)=>b-a));
  }
});

test('Batch45 split policy prevents mutation leakage and answer/flag memorization',()=>{
  const policy=buildCorpusV2Plan().policy;
  assert.match(policy.split,/upstream source\/competition before mutation/i);
  assert.match(policy.ctf,/strip flags and final answers/i);
  assert.match(policy.artifacts,/never deserialize untrusted Pickle\/PyTorch/i);
  assert.match(policy.negatives,/hard negatives/i);
});

test('Batch45 base catalog contains competition-grade bulk corpora and real CTF bundles',()=>{
  const ids=new Set(AI_STAGE1_SOURCE_CATALOG.map((x)=>x.id));
  for(const id of [
    'defcon31-mosscap','agentdojo','injecagent','robustbench','tianchi-imagenet-attack',
    'mico','midst','mibench','nist-trojai','backdoorbench','ductf-2025-ai',
    'htb-business-2025-ai','htb-gcsb-2026-lotus','thm-model-leakage-2026','modelscan','shadowray'
  ])assert.ok(ids.has(id),id);
});

test('Batch45 audits the old mutated-seed corpus by upstream diversity instead of raw case count',()=>{
  const audit=auditCurrentCorpusCoverage();
  assert.equal(audit.schema,'newcyber.ai-stage1-corpus-audit.v2');
  assert.equal(audit.groups.length,5);
  assert.ok(audit.currentSeedCount>0);
  assert.ok(audit.queue.length>0,'the old corpus should expose real-source expansion work');
  for(const group of audit.groups){
    assert.ok(group.currentSeeds>0,`${group.direction} keeps existing Batch43 seed coverage`);
    assert.ok(group.distinctCurrentSources<=group.currentSeeds);
  }
  assert.ok(audit.queue.some((x)=>x.id==='tensortrust-data'));
  assert.ok(audit.queue.some((x)=>x.id==='madry-mnist-challenge'));
});

test('Batch45 training mix is dominated by real competitions and benchmarks with source-grouped split',()=>{
  const mix=buildTrainingMix();
  assert.equal(mix.schema,'newcyber.ai-stage1-training-mix.v2');
  assert.equal(mix.weights.A,0.45);
  assert.equal(mix.weights.B,0.35);
  assert.equal(mix.weights.synthetic,0.05);
  assert.equal(mix.split.groupKey,'upstream-source-or-competition');
  assert.equal(mix.requirements.stripFinalAnswers,true);
  assert.equal(mix.requirements.forbidUnsafeArtifactExecution,true);
});
