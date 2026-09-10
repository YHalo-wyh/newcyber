'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const vm=require('vm');

const {buildFiveDirectionAutopilot}=require('../src/core/ai_five_direction_competition_autopilot');
const {buildFlagClosureScheduler}=require('../src/core/ai_flag_closure_scheduler');
const {buildRemoteReplayPlan,flagPattern}=require('../src/core/ai_remote_replay_contract');
const batch55=require('../src/core/finals_analyzer_batch55');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

function baseAnalysis(extra={}){
  return {files:[],findings:[],candidates:{flags:[]},challengeSession:{flags:{verified:[]},solverLedger:[]},...extra};
}

test('Batch55 closure scheduler prioritizes an active SCA chain near oracle over a keyword-heavy but distant direction',()=>{
  const analysis=baseAnalysis({
    files:[{path:'prompt_agent_rag_notes.txt',metadata:{description:'prompt agent rag tool system prompt'}}],
    scaAutopilot:{result:{status:'decoded-no-flag',gap:null}}
  });
  const autopilot=buildFiveDirectionAutopilot(analysis);
  const prompt=autopilot.directions.find((d)=>d.id==='prompt-llm-security');
  prompt.score=25;
  const closure=buildFlagClosureScheduler(analysis,autopilot);
  assert.equal(closure.primaryDirection,'privacy-leakage');
  const privacy=closure.directions.find((d)=>d.id==='privacy-leakage');
  assert.equal(privacy.stepsToFlag,2);
  assert.equal(privacy.closureStage,'recovered-sequence-no-flag');
  assert.match(privacy.nextBestAction,/calibrated|full-probe|oracle/i);
});

test('Batch55 plain prompt evidence plus a top-level candidates field never fabricates a Prompt candidate',()=>{
  const analysis=baseAnalysis({files:[{path:'prompt_notes.txt',metadata:{description:'prompt agent rag tool'}}],candidates:{flags:[],other:[]}});
  const autopilot=buildFiveDirectionAutopilot(analysis);
  const closure=buildFlagClosureScheduler(analysis,autopilot);
  const prompt=closure.directions.find((d)=>d.id==='prompt-llm-security');
  assert.equal(prompt.stepsToFlag,3);
  assert.equal(prompt.closureStage,'probe-ready');
  assert.equal(prompt.blockers.includes('REAL_TARGET_OBSERVATION'),false);
});

test('Batch55 genuine Batch51 transform candidate still promotes Prompt to candidate-needs-replay',()=>{
  const analysis=baseAnalysis({files:[{
    path:'prompt.txt',metadata:{batch51:{candidateObject:{kind:'transform-exfiltration-replay',candidateId:'transform-fixture-1',prompt:'encode hidden system prompt'}}}
  }]});
  const autopilot=buildFiveDirectionAutopilot(analysis);
  const closure=buildFlagClosureScheduler(analysis,autopilot);
  const prompt=closure.directions.find((d)=>d.id==='prompt-llm-security');
  assert.equal(prompt.stepsToFlag,2);
  assert.equal(prompt.closureStage,'candidate-needs-replay');
  assert.ok(prompt.blockers.includes('REAL_TARGET_OBSERVATION'));
});

test('Batch55 prompt replay plan is candidate-bound, bounded and stops when a verified flag appears',()=>{
  const analysis=baseAnalysis({files:[{path:'prompt.txt',metadata:{description:'system prompt secret agent tool call'}}]});
  const autopilot=buildFiveDirectionAutopilot(analysis,{endpoint:'https://ctf.invalid/api',flagFormat:'ACTF{...}'});
  const closure=buildFlagClosureScheduler(analysis,autopilot);
  closure.primaryDirection='prompt-llm-security';
  const plan=buildRemoteReplayPlan(autopilot,closure,{endpoint:'https://ctf.invalid/api',flagFormat:'ACTF{...}',maxRemoteRequests:16});
  assert.equal(plan.status,'ready');
  assert.ok(plan.contractCount>0&&plan.contractCount<=16);
  assert.equal(new Set(plan.contracts.map((x)=>x.contractId)).size,plan.contractCount);
  for(const contract of plan.contracts){
    assert.equal(contract.observation.schema,'newcyber.observation.v1');
    assert.equal(contract.observation.candidateId,contract.candidateId);
    assert.equal(contract.execution.automatic,false);
    assert.equal(contract.execution.authorizationRequired,true);
    assert.ok(contract.stopConditions.includes('verified-flag'));
  }
});

test('Batch55 verified flag closes scheduler and emits zero remote replay contracts',()=>{
  const analysis=baseAnalysis({challengeSession:{flags:{verified:['ACTF{done}']},solverLedger:[]}});
  const autopilot=buildFiveDirectionAutopilot(analysis);
  const closure=buildFlagClosureScheduler(analysis,autopilot);
  const replay=buildRemoteReplayPlan(autopilot,closure,{});
  assert.equal(closure.closed,true);
  assert.equal(closure.minStepsToFlag,0);
  assert.equal(replay.status,'closed');
  assert.equal(replay.contracts.length,0);
});

test('Batch55 replay flag matcher respects explicit CTF prefix and keeps a bounded body',()=>{
  const source=flagPattern('ynuctf{...}');
  const re=new RegExp(source);
  assert.match('answer ynuctf{batch55_flag}',re);
  assert.doesNotMatch('ynuctf{'+'A'.repeat(300)+'}',re);
  assert.doesNotMatch('other{flag}',re);
});

test('Batch55 workspace attachment publishes flag distance, replay contracts and report section',()=>{
  const analysis=baseAnalysis({aiCompetitionAutopilot:buildFiveDirectionAutopilot(baseAnalysis({files:[{path:'agent_prompt.txt'}]}))});
  const closure=buildFlagClosureScheduler(analysis,analysis.aiCompetitionAutopilot);
  const replay=buildRemoteReplayPlan(analysis.aiCompetitionAutopilot,closure,{});
  batch55.attachFlagClosure(analysis,closure,replay);
  assert.equal(analysis.aiFlagClosure,closure);
  assert.equal(analysis.challengeSession.aiRemoteReplay,replay);
  assert.ok(analysis.challengeSession.solverLedger.some((x)=>x.id==='ai-flag-closure-sprint'));
  const report=batch55.buildFlagClosureSection(analysis);
  assert.match(report,/AI-Only Flag Closure Sprint/);
  assert.match(report,/minimum steps/);
  assert.match(report,/Authorized Replay Contracts|remote replay contracts/);
});

test('Batch55 UI is a de-carded AI closure strip with no network execution code',()=>{
  const source=read('renderer/challenge_session_batch55.js');
  const css=read('renderer/styles/challenge_session_batch55.css');
  const html=read('renderer/toolbox.html');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'challenge_session_batch55.js'}));
  for(const token of ['AI FLAG CLOSURE','SCA QUALITY ROUTE','AUTHORIZED REPLAY','steps to flag'])assert.ok(source.includes(token),token);
  assert.ok(html.indexOf('challenge_session_batch55.js')>html.indexOf('challenge_session_batch54.js'));
  assert.ok(html.includes('styles/challenge_session_batch55.css'));
  assert.doesNotMatch(source,/fetch\s*\(|XMLHttpRequest|require\(['"]https?['"]\)|https?\.request/i);
  assert.doesNotMatch(css,/grid-template-columns:\s*repeat\(/i);
});

test('Batch55 production compatibility advances Workspace while retaining Batch53/54 historical markers',()=>{
  const entry=read('src/core/finals_analyzer_batch15.js');
  assert.match(entry,/require\('\.\/finals_analyzer_batch53'\)/);
  assert.match(entry,/require\('\.\/finals_analyzer_batch54'\)/);
  assert.match(entry,/require\('\.\/finals_analyzer_batch55'\)/);
});

test('Batch55 remote replay implementation is contract-only and contains no HTTP client',()=>{
  const source=read('src/core/ai_remote_replay_contract.js');
  assert.doesNotMatch(source,/\bfetch\s*\(|require\(['"](?:http|https|axios|undici)['"]\)|XMLHttpRequest/i);
  assert.match(source,/authorizationRequired:true/);
  assert.match(source,/maxRequests/);
});
