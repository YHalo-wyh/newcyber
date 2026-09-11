'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const {digestsForIds,analyzeAiContestBundle,discoverDelimitedCandidates,discoverTextHints}=require('../src/core/ai_contest_bundle_autopilot');
const {buildChallengeSession}=require('../src/core/challenge_session_batch51');

const bundle={
  hints:[[0,1],[2,3]],
  candidates:[
    {id:11,assignedLabel:1,scores:[4.90,5.00,-1,-1]},
    {id:12,assignedLabel:1,scores:[2.0,5.00,4.50,-1]},
    {id:23,assignedLabel:3,scores:[-1,-1,4.95,5.00]},
    {id:24,assignedLabel:3,scores:[-1,4.80,4.70,5.00]}
  ]
};

test('bundle autopilot verifies ranked answer set against challenge digest',()=>{
  const digest=digestsForIds([11,23]);
  const sources=[
    {file:'scores.json',text:JSON.stringify(bundle)},
    {file:'verify.py',text:`expected_sha256 = '${digest.sha256}'\n# verify hash of sorted ids`}
  ];
  const result=analyzeAiContestBundle(sources,{files:[]},{status:'not-detected',executionReady:false});
  assert.equal(result.status,'verified');
  assert.equal(result.result.verified,true);assert.equal(result.result.value,'[11, 23]');
  assert.equal(result.verifierMatches[0].verifier.algorithm,'sha256');
  assert.ok(result.findings.some((item)=>item.id==='ai-contest-verifier-match'));
});

test('bundle autopilot keeps ranked result candidate when no verifier is present',()=>{
  const result=analyzeAiContestBundle([{file:'scores.json',text:JSON.stringify(bundle)}],{files:[]},{status:'not-detected',executionReady:false});
  assert.equal(result.status,'ranked');assert.equal(result.result.verified,false);assert.equal(result.result.value,'[11, 23]');
  assert.equal(result.next,'need-real-verifier-or-manual-check');
});

test('separate python hints and CSV logits are correlated automatically',()=>{
  const hintText='hint1 = [(0, 1), (2, 3)]\n';
  const csv='id,assignedLabel,logit_0,logit_1,logit_2,logit_3\n11,1,4.9,5.0,-1,-1\n23,3,-1,-1,4.95,5.0\n';
  assert.equal(discoverTextHints('hint.py',hintText)[0].rows.length,2);
  assert.equal(discoverDelimitedCandidates('scores.csv',csv)[0].rows.length,2);
  const result=analyzeAiContestBundle([{file:'hint.py',text:hintText},{file:'scores.csv',text:csv}],{files:[]},{status:'not-detected',executionReady:false});
  assert.equal(result.status,'ranked');assert.equal(result.ranking.hints,2);assert.equal(result.ranking.candidates,2);
});

test('model assets plus ready preprocessing become an executable ONNX bridge stage',()=>{
  const result=analyzeAiContestBundle([],{
    files:[{path:'model.onnx',extension:'.onnx'},{path:'images/1.png',extension:'.png'}]
  },{status:'ready',executionReady:true});
  assert.equal(result.status,'model-assets-ready');assert.equal(result.next,'onnx-inference-bridge');
});

test('Challenge Session exposes generic verifier-backed answer as solved result',()=>{
  const analysis={
    workspaceName:'synthetic-ai-challenge',files:[{path:'scores.json',extension:'.json',size:100,sha256:'a'.repeat(64),findings:[],flags:[]}],
    findings:[],candidates:{flags:[],urls:[],ips:[]},autopilot:{automaticChecks:[],track:{id:'ai',title:'人工智能安全',score:10}},
    aiContestAutopilot:{status:'verified',next:'verified-answer-ready',result:{value:'[11, 23]',verified:true,confidence:'verified',source:'sha256 verifier',ids:[11,23]},discovery:{},ranking:{candidateSets:[{ids:[11,23]}]}}
  };
  const session=buildChallengeSession(analysis);
  assert.equal(session.status,'solved');assert.equal(session.result.value,'[11, 23]');assert.equal(session.result.kind,'answer-set');
  assert.ok(session.solverLedger.some((item)=>item.id==='ai-contest-bundle-autopilot'&&item.status==='solved'));
});

test('dropped Challenge Session uses Batch51 generic result wrapper',()=>{
  const source=fs.readFileSync(path.join(__dirname,'..','src','electron','challenge_session_ipc.js'),'utf8');
  assert.match(source,/challenge_session_batch51/);assert.match(source,/aiContestAutopilot/);
});
