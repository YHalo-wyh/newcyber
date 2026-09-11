'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {analyzeModelFingerprintCandidates}=require('../src/core/ai_model_fingerprint_ranker');
const {buildChallengeSession}=require('../src/core/challenge_session_batch87');
const {buildChallengeSession:buildCompatibilitySession}=require('../src/core/challenge_session_batch51');

function baseAnalysis(){return{workspaceName:'fingerprint',workspacePath:'/tmp/fingerprint',files:[],findings:[],candidates:{flags:[],urls:[],ips:[]},autopilot:{automaticChecks:[],flags:[],artifacts:[],actions:[],summary:{}},autoSolve:{status:'review',gaps:[]},submissionAutopilot:{status:'not-detected'},aiUniversalTriggerAutopilot:{status:'not-detected'}};}

function fingerprintRows(){
  const rows=[];
  for(let i=0;i<12;i++){
    const victim=i%3===0?'cat':i%3===1?'dog':'bird';
    rows.push({candidate_model:'model-A',query_id:`q${i}`,victim_label:victim,candidate_label:victim,victim_probs:'[0.8,0.1,0.1]',candidate_probs:'[0.79,0.11,0.10]'});
    rows.push({candidate_model:'model-B',query_id:`q${i}`,victim_label:victim,candidate_label:i%4===0?'other':victim,victim_probs:'[0.8,0.1,0.1]',candidate_probs:'[0.55,0.25,0.20]'});
  }
  return rows;
}

test('Batch87 ranks the candidate model with highest holdout fidelity and soft-output similarity',()=>{
  const result=analyzeModelFingerprintCandidates({rows:fingerprintRows(),minQueries:6,minAgreement:.6});
  assert.equal(result.status,'candidate');
  assert.equal(result.result.value,'model-A');
  assert.equal(result.bestCandidate.labelAgreement,1);
  assert.ok(result.bestCandidate.vectorCosine>.99);
  assert.ok(result.bestCandidate.queries>=12);
});

test('Batch87 stops at ambiguous when two models have equal independent evidence',()=>{
  const rows=[];
  for(const model of ['m1','m2'])for(let i=0;i<8;i++)rows.push({candidate_model:model,query_id:`q${i}`,victim_label:'x',candidate_label:'x',victim_probs:'[0.7,0.3]',candidate_probs:'[0.7,0.3]'});
  const result=analyzeModelFingerprintCandidates({rows,minQueries:6,minAgreement:.6});
  assert.equal(result.status,'ambiguous');
  assert.equal(result.result,null);
});

test('Batch87 requires enough independent query coverage',()=>{
  const rows=[
    {candidate_model:'m1',query_id:'q1',victim_label:'x',candidate_label:'x'},
    {candidate_model:'m1',query_id:'q2',victim_label:'x',candidate_label:'x'},
    {candidate_model:'m1',query_id:'q3',victim_label:'x',candidate_label:'x'}
  ];
  const result=analyzeModelFingerprintCandidates({rows,minQueries:6,minAgreement:.6});
  assert.equal(result.status,'partial');
  assert.equal(result.eligible,0);
});

test('Batch87 challenge session exposes fingerprint only as candidate and asks for checker/holdout',()=>{
  const ranked=analyzeModelFingerprintCandidates({rows:fingerprintRows(),minQueries:6,minAgreement:.6});
  const analysis=baseAnalysis();analysis.aiModelFingerprintAutopilot={status:ranked.status,summary:{files:1,candidates:ranked.candidates,eligible:ranked.eligible,rows:ranked.rows},bestCandidate:ranked.bestCandidate,result:ranked.result,next:ranked.next};
  const session=buildChallengeSession(analysis);
  assert.equal(session.status,'candidate');
  assert.equal(session.result.kind,'model-fingerprint');
  assert.equal(session.result.value,'model-A');
  assert.equal(session.primaryNeed.code,'MODEL_FINGERPRINT_VERIFIER_OR_HOLDOUT');
  const compat=buildCompatibilitySession(analysis);
  assert.equal(compat.status,'candidate');
  assert.equal(compat.result.kind,'model-fingerprint');
});

test('Batch87 compatibility analyzer and clean renderer load newest fingerprint path',()=>{
  const root=path.join(__dirname,'..');
  const entry=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'renderer/challenge_session_batch87.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  assert.match(entry,/finals_analyzer_batch87/);
  assert.doesNotThrow(()=>new vm.Script(renderer,{filename:'challenge_session_batch87.js'}));
  assert.match(renderer,/fingerprint holdout/);
  assert.match(html,/challenge_session_batch87\.js/);
  assert.ok(html.indexOf('challenge_session_batch87.js')>html.indexOf('challenge_session_batch86.js'));
});
