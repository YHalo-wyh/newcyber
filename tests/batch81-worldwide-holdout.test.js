'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {buildPromptAttackMegaPack,TRANSFORMS}=require('../src/core/ai_prompt_attack_mega');
const {SOURCES,CASES,runStage1WorldwideHoldout}=require('../src/core/ai_stage1_worldwide_holdout');

test('Batch81 Prompt MegaPack produces >1000 deduplicated safe competition templates',()=>{
  const pack=buildPromptAttackMegaPack();
  assert.ok(pack.total>=1000,`total=${pack.total}`);
  assert.equal(pack.total,new Set(pack.templates.map((x)=>x.payload)).size);
  assert.ok(pack.seeds>=30);
  assert.ok(pack.mutations>=8);
  assert.ok(TRANSFORMS.length>=6);
  for(const category of ['direct','indirect','rag','agent-tool','secret-boundary','multi-turn'])assert.ok(pack.coverage.byCategory[category]>0,category);
  assert.ok(pack.templates.every((x)=>x.failureSignals.some((s)=>/TRAINING_|training_noop/.test(s))));
});

test('Batch81 worldwide holdout is source-derived, five-direction and reaches the 7/10 proxy gate',()=>{
  const result=runStage1WorldwideHoldout();
  assert.ok(SOURCES.length>=10);
  assert.ok(CASES.length>=20);
  assert.equal(result.summary.cases,CASES.length);
  assert.ok(result.summary.solveProxyRate>=0.70,JSON.stringify(result.summary));
  assert.equal(result.summary.targetMet,true);
  assert.ok(result.summary.expectationMatches>=CASES.length-1,JSON.stringify(result.results.filter((x)=>x.status!==x.expected)));
  for(const direction of ['prompt-llm-security','adversarial-example','privacy-leakage','backdoor-poisoning','infra-supply-chain']){
    assert.ok(result.byDirection[direction]?.cases>=4,direction);
  }
  assert.ok(result.gaps.some((x)=>x.id==='adversarial-ml-blackbox-oracle'));
  assert.ok(result.gaps.some((x)=>x.id==='mirage-mcp-signature-cloaking'));
});

test('Batch81 holdout keeps public provenance and never embeds real challenge flags',()=>{
  for(const row of CASES){
    const src=SOURCES.find((x)=>x.id===row.source);
    assert.ok(src,`missing source ${row.source}`);
    assert.match(src.url,/^https:\/\/github\.com\//);
  }
  const source=fs.readFileSync(path.join(__dirname,'../src/core/ai_stage1_worldwide_holdout.js'),'utf8');
  assert.doesNotMatch(source,/flag\{[^}]{3,}\}/i);
  assert.doesNotMatch(source,/WRAITH\{[^}]{3,}\}/i);
  assert.match(source,/solveProxyRate 只表示/);
});

test('Batch81 compatibility analyzer surfaces MegaPack and worldwide holdout without deleting historical markers',()=>{
  const root=path.join(__dirname,'..');
  const compat=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  const wrapper=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch81.js'),'utf8');
  assert.match(compat,/finals_analyzer_batch49/);
  assert.match(compat,/finals_analyzer_batch81/);
  assert.match(wrapper,/promptAttackMegaPack/);
  assert.match(wrapper,/aiStage1WorldwideHoldout/);
  assert.match(wrapper,/solveProxyRate/);
});
