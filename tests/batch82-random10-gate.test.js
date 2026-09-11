'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {analyzeBlackboxAdversarialTranscript}=require('../src/core/ai_blackbox_adversarial');
const {analyzeMcpSupplyChain}=require('../src/core/ai_mcp_supply_chain');
const {runStage1WorldwideHoldoutBatch82,SOURCES}=require('../src/core/ai_stage1_worldwide_holdout_batch82');
const {choose,probabilityAtLeast,runRandom10Gate}=require('../src/core/ai_stage1_random10_gate');

test('Batch82 black-box transcript ranks an in-budget successful candidate without network access',()=>{
  const result=analyzeBlackboxAdversarialTranscript({norm:'linf',epsilon:0.08,queryBudget:100,targetLabel:'ok',rows:[
    {query:1,linf:0.02,target_score:0.1,predicted_label:'no'},
    {query:25,linf:0.07,target_score:0.91,predicted_label:'ok'},
    {query:30,linf:0.09,target_score:0.98,predicted_label:'ok'}
  ]});
  assert.equal(result.status,'candidate');
  assert.equal(result.summary.validSuccess,1);
  assert.equal(result.summary.overBudget,1);
  assert.equal(result.bestCandidate.query,25);
  assert.ok(result.findings.some((x)=>x.id==='blackbox-adversarial-valid-candidate'));
  assert.match(result.notes.join(' '),/不自行访问远端服务/);
});

test('Batch82 black-box transcript computes vector distance and enforces query budget',()=>{
  const result=analyzeBlackboxAdversarialTranscript({norm:'linf',epsilon:0.05,queryBudget:5,targetLabel:'target',rows:[
    {query:6,original:'[0.1,0.2]',candidate:'[0.12,0.18]',predicted_label:'target'}
  ]});
  assert.ok(Math.abs(result.shortlist[0].distance-0.02)<1e-12,result.shortlist[0].distance);
  assert.equal(result.queryBudgetExceeded,true);
  assert.equal(result.status,'partial');
  assert.ok(result.findings.some((x)=>x.id==='blackbox-query-budget-exceeded'));
});

test('Batch82 MCP supply-chain verifier rejects floating unsigned unpinned untrusted records',()=>{
  const result=analyzeMcpSupplyChain({baseline:{name:'mcp-a',source:'trusted.registry/a',ref:'v1.0.0',digest:`sha256:${'a'.repeat(64)}`},candidate:{name:'mcp-a',source:'attacker.invalid/a',ref:'latest',sourceAllowed:false,signed:false,provenanceVerified:false}});
  assert.equal(result.status,'rejected-record');
  for(const id of ['mcp-floating-reference','mcp-digest-missing','mcp-signature-unverified','mcp-provenance-unverified','mcp-source-not-allowlisted'])assert.ok(result.findings.some((x)=>x.id===id),id);
  assert.ok(result.drift.some((x)=>x.field==='source'));
});

test('Batch82 MCP supply-chain verifier only calls admission ready with independent verified evidence',()=>{
  const result=analyzeMcpSupplyChain({name:'mcp-safe',source:'trusted.registry/mcp-safe',ref:'v1.2.3',digest:`sha256:${'b'.repeat(64)}`,sourceAllowed:true,signed:true,signatureVerified:true,provenancePresent:true,provenanceVerified:true});
  assert.equal(result.status,'verified-record');
  assert.equal(result.admissionReady,true);
  assert.equal(result.findings.length,0);
});

test('Batch82 worldwide holdout expands source diversity and keeps hard partials visible',()=>{
  const result=runStage1WorldwideHoldoutBatch82();
  assert.ok(SOURCES.length>=16,`sources=${SOURCES.length}`);
  assert.ok(result.summary.cases>=26,JSON.stringify(result.summary));
  assert.ok(result.summary.solveProxyRate>=0.70,JSON.stringify(result.summary));
  assert.equal(result.summary.targetMet,true);
  assert.ok(result.results.some((x)=>x.id==='mirage-mcp-signature-cloaking'&&x.status==='closed'));
  assert.ok(result.results.some((x)=>x.id==='adversarial-ml-blackbox-oracle'&&x.status==='partial'));
  assert.ok(result.results.some((x)=>x.id==='satml-universal-trojan-detection'&&x.status==='partial'));
  assert.ok(result.summary.expectationMatches>=result.summary.cases-1,JSON.stringify(result.results.filter((x)=>x.status!==x.expected)));
});

test('Batch82 exact random-10 gate treats partial as unsolved and targets 7/10',()=>{
  assert.equal(choose(10,3),120);
  const result=runRandom10Gate();
  assert.equal(result.draws,10);
  assert.equal(result.target,7);
  assert.ok(result.solveProxyRate>=0.70,JSON.stringify(result));
  assert.ok(result.expectedSolved>=7,JSON.stringify(result));
  assert.ok(result.probabilityAtLeast7>=0.70,JSON.stringify(result));
  assert.equal(result.pass,true);
  assert.ok(result.median>=7);
  assert.equal(probabilityAtLeast(10,7,10,7),1);
  assert.match(result.notes.join(' '),/partial 一律按未出题处理/);
});

test('Batch82 compatibility analyzer routes Drop-to-Result through new analyzers and random-10 report',()=>{
  const root=path.join(__dirname,'..');
  const compat=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  const wrapper=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch82.js'),'utf8');
  assert.match(compat,/finals_analyzer_batch80/);
  assert.match(compat,/finals_analyzer_batch81/);
  assert.match(compat,/finals_analyzer_batch82/);
  assert.match(wrapper,/analyzeBlackboxAdversarialTranscript/);
  assert.match(wrapper,/analyzeMcpSupplyChain/);
  assert.match(wrapper,/aiStage1Random10Gate/);
  assert.match(wrapper,/P\(≥7\)/);
});
