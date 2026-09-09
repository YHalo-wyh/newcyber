'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  DIRECTIONS,AI_STAGE1_SOURCE_CATALOG,byDirection,buildCorpusV2Plan,catalogHealth
}=require('../src/core/ai_stage1_source_catalog');

test('Batch45 source catalog covers all five official stage-one directions with real sources',()=>{
  assert.equal(DIRECTIONS.length,5);
  const health=catalogHealth();
  assert.equal(health.complete,true);
  assert.equal(health.duplicateIds.length,0);
  for(const direction of DIRECTIONS){
    const sources=byDirection(direction);
    assert.ok(sources.length>=5,`${direction} source coverage`);
    assert.ok(sources.some((x)=>x.tier==='A'),`${direction} needs a real competition/dataset source`);
    assert.ok(sources.every((x)=>/^https:\/\//.test(x.url)),`${direction} sources must preserve provenance URL`);
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

test('Batch45 catalog contains competition-grade bulk corpora and real CTF bundles',()=>{
  const ids=new Set(AI_STAGE1_SOURCE_CATALOG.map((x)=>x.id));
  for(const id of [
    'defcon31-mosscap','agentdojo','injecagent','robustbench','tianchi-imagenet-attack',
    'mico','midst','mibench','nist-trojai','backdoorbench','ductf-2025-ai',
    'htb-business-2025-ai','htb-gcsb-2026-lotus','thm-model-leakage-2026','modelscan','shadowray'
  ])assert.ok(ids.has(id),id);
});
