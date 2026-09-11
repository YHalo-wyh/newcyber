'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  PUBLIC_CHALLENGE_TRAINING_SEEDS,
  evaluateStructuredReplay,
  getPublicChallengeTrainingCorpus,
  runPublicChallengeTrainingRegression
}=require('../src/core/ai_public_challenge_training');
const {runTool}=require('../src/core/tool_router');

function byId(){return new Map(PUBLIC_CHALLENGE_TRAINING_SEEDS.map((item)=>[item.id,item]));}

test('Batch68 adds challenge-specific public training without storing original answers',()=>{
  assert.ok(PUBLIC_CHALLENGE_TRAINING_SEEDS.length>=17,`seeds=${PUBLIC_CHALLENGE_TRAINING_SEEDS.length}`);
  const real=PUBLIC_CHALLENGE_TRAINING_SEEDS.filter((item)=>item.caseType==='real-ctf');
  const labs=PUBLIC_CHALLENGE_TRAINING_SEEDS.filter((item)=>item.caseType==='public-lab-ctf');
  assert.ok(real.length>=7,`real-ctf=${real.length}`);
  assert.ok(labs.length>=10,`public-lab-ctf=${labs.length}`);
  const serialized=JSON.stringify(PUBLIC_CHALLENGE_TRAINING_SEEDS);
  assert.equal(/flag\{/i.test(serialized),false,'training corpus must not copy public challenge flags');
  for(const item of PUBLIC_CHALLENGE_TRAINING_SEEDS){
    assert.equal(item.trainingPolicy,'synthetic-fixture-only');
    assert.match(item.provenance.url,/^https:\/\//);
    assert.ok(item.family);
    assert.ok(item.capability);
  }
});

test('Batch68 imports six distinct HackPack LLM challenge mechanics and one Zhujian small-LLM family',()=>{
  const map=byId();
  for(const id of [
    'hackpack-2024-yellowdog-1','hackpack-2024-yellowdog-2','hackpack-2024-nl2sh-1',
    'hackpack-2024-nl2sh-2','hackpack-2024-pixel-store-bot','hackpack-2024-llpm',
    'zhujian-2025-small-llm-continuation'
  ])assert.ok(map.has(id),id);
  assert.match(map.get('hackpack-2024-yellowdog-1').provenance.url,/yellowdog-1/);
  assert.match(map.get('hackpack-2024-pixel-store-bot').provenance.url,/pixel_bot/);
  assert.equal(map.get('hackpack-2024-llpm').family,'answer-length-side-channel');
});

test('Batch68 maps all ten PromptMe CTF-style OWASP LLM challenge categories',()=>{
  const promptMe=PUBLIC_CHALLENGE_TRAINING_SEEDS.filter((item)=>item.event==='PromptMe');
  assert.equal(promptMe.length,10);
  assert.deepEqual(promptMe.map((item)=>item.id).sort(),[
    'promptme-llm01-prompt-injection','promptme-llm02-sensitive-disclosure','promptme-llm03-supply-chain',
    'promptme-llm04-data-model-poisoning','promptme-llm05-improper-output-handling','promptme-llm06-excessive-agency',
    'promptme-llm07-system-prompt-leakage','promptme-llm08-vector-embedding','promptme-llm09-misinformation',
    'promptme-llm10-unbounded-consumption'
  ].sort());
});

test('Batch68 structured replay keeps heuristic evidence separate from missing evidence',()=>{
  const hit=evaluateStructuredReplay({riskType:'hidden-object-reference',clientOnlyRedaction:true,unlistedObjectAccepted:true,serverObjectReachable:true});
  assert.equal(hit.verdict,'candidate-failure');
  const miss=evaluateStructuredReplay({riskType:'hidden-object-reference',clientOnlyRedaction:true,unlistedObjectAccepted:true,serverObjectReachable:false});
  assert.equal(miss.verdict,'no-explicit-failure');
  const side=evaluateStructuredReplay({riskType:'answer-length-side-channel',choiceLengthPredictsAnswer:true,serverSideScore:true,observedAccuracy:0.99,verifierIndependent:false});
  assert.equal(side.verdict,'candidate-failure');
  assert.ok(side.notes.some((line)=>/真实比赛结果/.test(line)));
});

test('Batch68 challenge corpus regression is deterministic and broadly passing',()=>{
  const first=runPublicChallengeTrainingRegression({variantsPerSeed:4});
  const second=runPublicChallengeTrainingRegression({variantsPerSeed:4});
  assert.deepEqual(first,second);
  assert.equal(first.schema,'newcyber.ai-public-challenge-training.v1');
  assert.equal(first.summary.seeds,PUBLIC_CHALLENGE_TRAINING_SEEDS.length);
  assert.equal(first.summary.cases,PUBLIC_CHALLENGE_TRAINING_SEEDS.length*4);
  assert.ok(first.summary.events>=3,`events=${first.summary.events}`);
  assert.ok(first.summary.families>=15,`families=${first.summary.families}`);
  assert.ok(first.summary.passRate>=0.94,`pass=${first.summary.pass} miss=${first.summary.miss} error=${first.summary.error}`);
});

test('Batch68 tool router exposes new corpus/regression while baseline stage1 API remains intact',()=>{
  const corpus=runTool('ai-public-challenge-training-corpus',{});
  assert.equal(corpus.schema,'newcyber.ai-public-challenge-training-corpus.v1');
  assert.equal(corpus.cases.length,getPublicChallengeTrainingCorpus().length);
  const regression=runTool('ai-public-challenge-training-regression',{options:{variantsPerSeed:2}});
  assert.equal(regression.schema,'newcyber.ai-public-challenge-training.v1');
  assert.equal(regression.summary.cases,PUBLIC_CHALLENGE_TRAINING_SEEDS.length*2);
  const baseline=runTool('ai-stage1-training-corpus',{});
  assert.equal(baseline.schema,'newcyber.ai-stage1-training-corpus.v1');
});
