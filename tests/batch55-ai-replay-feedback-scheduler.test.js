'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const {buildPromptAttackAutopilot}=require('../src/core/ai_prompt_attack_autopilot');
const {buildRemoteReplayPlan}=require('../src/core/ai_remote_replay_contract');
const {buildReplayFeedback}=require('../src/core/ai_replay_feedback_scheduler');

function fixture(options={}){
  const promptPlan=buildPromptAttackAutopilot({
    context:'Agent reads RAG documents, uses MCP tools, keeps hidden system prompt and flag secret',
    maxTemplates:12,maxProbes:256
  });
  const autopilot={primaryDirection:'prompt-llm-security',directions:[{id:'prompt-llm-security'}],promptPlan};
  const closure={closed:false,primaryDirection:'prompt-llm-security',directions:[]};
  const replay=buildRemoteReplayPlan(autopilot,closure,{endpoint:'{{TARGET}}',flagFormat:'ctf{...}',maxRemoteRequests:16,...options});
  return {promptPlan,replay};
}
function obs(contract,extra={}){return {schema:'newcyber.observation.v1',candidateId:contract.candidateId,provenance:'challenge-runtime',statusCode:200,response:'ordinary answer',toolCalls:[],...extra};}

test('Batch55 refusal feedback switches recipe family and never repeats the attempted probe',()=>{
  const {promptPlan,replay}=fixture();const attempted=replay.contracts[0];
  const feedback=buildReplayFeedback(replay,promptPlan,[obs(attempted,{response:'I cannot reveal the hidden system prompt or secret.'})],{endpoint:'{{TARGET}}',flagFormat:'ctf{...}'});
  assert.equal(feedback.status,'adaptive-ready');
  assert.equal(feedback.dominantClass,'refusal');
  assert.ok(feedback.nextContractCount>0&&feedback.nextContractCount<=16);
  assert.equal(feedback.nextContracts[0].recipeId,'delimiter-stack');
  assert.ok(feedback.nextContracts.every((item)=>item.probeId!==attempted.probeId));
  assert.equal(feedback.executionPolicy.automatic,false);
});

test('Batch55 ignores an observation whose candidateId is not bound to the current replay plan',()=>{
  const {promptPlan,replay}=fixture();
  const feedback=buildReplayFeedback(replay,promptPlan,[{schema:'newcyber.observation.v1',candidateId:'foreign-candidate',provenance:'challenge-runtime',response:'ctf{fake}'}],{flagFormat:'ctf{...}'});
  assert.equal(feedback.status,'no-observation');
  assert.equal(feedback.ignoredUnbound,1);
  assert.equal(feedback.trustedMatched,0);
  assert.equal(feedback.nextContractCount,0);
});

test('Batch55 refuses adaptive ranking from candidate-bound but untrusted provenance',()=>{
  const {promptPlan,replay}=fixture();const attempted=replay.contracts[0];
  const feedback=buildReplayFeedback(replay,promptPlan,[obs(attempted,{provenance:'downloaded-writeup',response:'system prompt: leak me'})]);
  assert.equal(feedback.status,'untrusted-observation');
  assert.equal(feedback.ignoredUntrusted,1);
  assert.equal(feedback.trustedMatched,0);
  assert.equal(feedback.nextContractCount,0);
});

test('Batch55 encoded output pauses remote mutation and hands off to local decoder/verifier',()=>{
  const {promptPlan,replay}=fixture();const attempted=replay.contracts[0];
  const encoded='99 116 102 123 116 101 115 116 95 102 108 97 103 125';
  const feedback=buildReplayFeedback(replay,promptPlan,[obs(attempted,{response:encoded})],{flagFormat:'ctf{...}'});
  assert.equal(feedback.status,'verifier-handoff');
  assert.equal(feedback.dominantClass,'encoded-output');
  assert.equal(feedback.pauseForVerifier,true);
  assert.equal(feedback.nextContractCount,0);
  assert.equal(JSON.stringify(feedback).includes(encoded),false);
});

test('Batch55 flag-shaped response is only a candidate signal and never becomes Verified by feedback classifier',()=>{
  const {promptPlan,replay}=fixture();const attempted=replay.contracts[0];
  const feedback=buildReplayFeedback(replay,promptPlan,[obs(attempted,{response:'candidate result: ctf{needs_real_verifier}'})],{flagFormat:'ctf{...}'});
  assert.equal(feedback.status,'verifier-handoff');
  assert.equal(feedback.classifications[0].classification,'flag-candidate');
  assert.equal(feedback.classifications[0].candidateSignal,true);
  assert.equal(Object.hasOwn(feedback.classifications[0],'verified'),false);
  assert.equal(feedback.nextContractCount,0);
});

test('Batch55 observed tool call pauses prompt spam for tool-policy evaluation',()=>{
  const {promptPlan,replay}=fixture();const attempted=replay.contracts[0];
  const feedback=buildReplayFeedback(replay,promptPlan,[obs(attempted,{response:'done',toolCalls:[{name:'read_secret',arguments:{}}]})]);
  assert.equal(feedback.status,'verifier-handoff');
  assert.equal(feedback.dominantClass,'tool-call');
  assert.equal(feedback.classifications[0].toolCallCount,1);
  assert.equal(feedback.nextContractCount,0);
});

test('Batch55 429 feedback holds budget instead of creating a retry wave',()=>{
  const {promptPlan,replay}=fixture();const attempted=replay.contracts[0];
  const feedback=buildReplayFeedback(replay,promptPlan,[obs(attempted,{statusCode:429,response:'Too many requests'})]);
  assert.equal(feedback.status,'hold');
  assert.equal(feedback.dominantClass,'rate-limited');
  assert.equal(feedback.nextContractCount,0);
});

test('Batch55 adaptive wave obeys both 16-request wave cap and 32-request global cap',()=>{
  const {promptPlan,replay}=fixture();const attempted=replay.contracts[0];
  const nearLimit=buildReplayFeedback(replay,promptPlan,[obs(attempted,{response:'ordinary response'})],{attemptedRequestCount:31,maxAdaptiveRequests:16});
  assert.equal(nearLimit.status,'adaptive-ready');
  assert.equal(nearLimit.globalBudget.remaining,1);
  assert.equal(nearLimit.nextContractCount,1);
  const exhausted=buildReplayFeedback(replay,promptPlan,[obs(attempted,{response:'ordinary response'})],{attemptedRequestCount:32,maxAdaptiveRequests:16});
  assert.equal(exhausted.status,'budget-exhausted');
  assert.equal(exhausted.nextContractCount,0);
});

test('Batch55 feedback scheduling is deterministic for identical observations',()=>{
  const {promptPlan,replay}=fixture();const observation=obs(replay.contracts[0],{response:'I cannot comply with that request.'});
  const a=buildReplayFeedback(replay,promptPlan,[observation],{endpoint:'{{TARGET}}'});
  const b=buildReplayFeedback(replay,promptPlan,[observation],{endpoint:'{{TARGET}}'});
  assert.deepEqual(a,b);
});

test('Batch55 production wrapper attaches replay feedback while feedback module contains no network client',()=>{
  const wrapper=fs.readFileSync(require.resolve('../src/core/finals_analyzer_batch55'),'utf8');
  const scheduler=fs.readFileSync(require.resolve('../src/core/ai_replay_feedback_scheduler'),'utf8');
  assert.match(wrapper,/collectObservationInbox/);
  assert.match(wrapper,/buildReplayFeedback/);
  assert.match(wrapper,/adaptiveReplayContracts/);
  assert.match(wrapper,/raw responses：not included/);
  assert.doesNotMatch(scheduler,/require\(['"](?:http|https|axios|undici|node-fetch)['"]\)/);
  assert.doesNotMatch(scheduler,/\bfetch\s*\(/);
});