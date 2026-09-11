'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {analyzeUniversalTriggerCandidates}=require('../src/core/ai_universal_trigger_ranker');
const {buildChallengeSession}=require('../src/core/challenge_session_batch86');

function baseAnalysis(){return{workspaceName:'trigger',workspacePath:'/tmp/trigger',files:[],findings:[],candidates:{flags:[],urls:[],ips:[]},autopilot:{automaticChecks:[],flags:[],artifacts:[],actions:[],summary:{}},autoSolve:{status:'review',gaps:[]},submissionAutopilot:{status:'not-detected'}};}

test('Batch86 ranks a cross-prompt universal trigger and penalizes control side effects',()=>{
  const rows=[];
  for(const prompt of ['p1','p2','p3','p4','p5'])rows.push({trigger:'alpha beta gamma',prompt_id:prompt,success:true,reward:.95,baseline_reward:.1,clean_failure:false});
  for(const prompt of ['p1','p2','p3','p4','p5'])rows.push({trigger:'noisy suffix',prompt_id:prompt,success:prompt!=='p5',reward:.9,baseline_reward:.1,clean_failure:true});
  const result=analyzeUniversalTriggerCandidates({rows,minPrompts:3,minAsr:.6,minTokens:2,maxTokens:5});
  assert.equal(result.status,'candidate');
  assert.equal(result.result.value,'alpha beta gamma');
  assert.equal(result.bestCandidate.asr,1);
  assert.equal(result.bestCandidate.cleanFailureRate,0);
});

test('Batch86 stops at ambiguous when two triggers have essentially equal holdout evidence',()=>{
  const rows=[];
  for(const trigger of ['one two','red blue'])for(const prompt of ['a','b','c','d'])rows.push({trigger,prompt_id:prompt,success:true,reward:.8,clean_failure:false});
  const result=analyzeUniversalTriggerCandidates({rows,minPrompts:3,minAsr:.6});
  assert.equal(result.status,'ambiguous');
  assert.equal(result.result,null);
});

test('Batch86 honors explicit token-length constraints instead of assuming challenge defaults',()=>{
  const rows=[];
  for(const prompt of ['a','b','c'])rows.push({trigger:'too short',prompt_id:prompt,success:true,reward:1});
  const result=analyzeUniversalTriggerCandidates({rows,minPrompts:3,minAsr:.6,minTokens:4,maxTokens:8});
  assert.equal(result.status,'partial');
  assert.equal(result.eligible,0);
});

test('Batch86 challenge session exposes only a candidate and asks for reward/checker evidence',()=>{
  const rows=[];for(const prompt of ['a','b','c','d'])rows.push({trigger:'stable trigger phrase',prompt_id:prompt,success:true,reward:.9,clean_failure:false});
  const ranked=analyzeUniversalTriggerCandidates({rows,minPrompts:3,minAsr:.6});
  const analysis=baseAnalysis();analysis.aiUniversalTriggerAutopilot={status:ranked.status,summary:{files:1,candidates:ranked.candidates,eligible:ranked.eligible,rows:ranked.rows},bestCandidate:ranked.bestCandidate,result:ranked.result,next:ranked.next};
  const session=buildChallengeSession(analysis);
  assert.equal(session.status,'candidate');
  assert.equal(session.result.kind,'universal-trigger');
  assert.equal(session.result.verified,false);
  assert.equal(session.primaryNeed.code,'TRIGGER_VERIFIER_OR_HOLDOUT');
});

test('Batch86 compatibility entry and clean UI load the trigger-aware path',()=>{
  const root=path.join(__dirname,'..');
  const entry=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'renderer/challenge_session_batch86.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  assert.match(entry,/finals_analyzer_batch86/);
  assert.doesNotThrow(()=>new vm.Script(renderer,{filename:'challenge_session_batch86.js'}));
  assert.match(renderer,/reward\/checker/);
  assert.match(html,/challenge_session_batch86\.js/);
  assert.ok(html.indexOf('challenge_session_batch86.js')>html.indexOf('challenge_session_batch85.js'));
});
