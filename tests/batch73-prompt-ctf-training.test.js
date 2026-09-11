'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  SOURCES,STRUCTURED_RULES,PROMPT_CTF_TRAINING_SEEDS,evaluatePromptCtfStructuredReplay,
  getPromptCtfTrainingCorpus,runPromptCtfTrainingRegression
}=require('../src/core/ai_prompt_ctf_training');
const {CORPORA,getTrainingCurriculum,runTrainingCurriculumRegression}=require('../src/core/ai_training_curriculum');
const {runTool}=require('../src/core/tool_router');

const EXPECTED=[
  'Challenge 1 — Assistant Identifier','Challenge 2 — System Prompt Extraction','Challenge 3 — Hidden Coupon Field',
  'Challenge 4 — AI Authentication','Challenge 5 — Chained Free Booking','Employee Wellness Companion',
  'Incremental Secret Extraction','Digital Doppelgänger'
];

test('Batch73 imports eight prompt/agent CTF challenge mechanics',()=>{
  assert.equal(PROMPT_CTF_TRAINING_SEEDS.length,8);
  const names=new Set(PROMPT_CTF_TRAINING_SEEDS.map((item)=>item.challenge));
  for(const name of EXPECTED)assert.ok(names.has(name),name);
  assert.equal(names.size,8);
  assert.equal(new Set(PROMPT_CTF_TRAINING_SEEDS.map((item)=>item.family)).size,8);
  assert.match(SOURCES.promptAirlines,/wiz-prompt-airlines-ctf-writeup/);
  assert.match(SOURCES.digitalDoppelganger,/AI-Security-Academy-Lab-CTF/);
});

test('Batch73 fixtures keep public answers, coupons and session secrets out',()=>{
  const serialized=JSON.stringify(PROMPT_CTF_TRAINING_SEEDS);
  assert.equal(/WIZ_CTF\{|secret\{|FLY_50|AIR_100|TRAVEL_25|68191/i.test(serialized),false);
  assert.equal(/challenge_1_welcome|spill_the_beans|free_flight/i.test(serialized),false);
  for(const item of PROMPT_CTF_TRAINING_SEEDS){
    assert.equal(item.trainingPolicy,'synthetic-fixture-only');
    assert.equal(item.caseType,'real-ctf');
    assert.equal(item.provenance.evidenceLevel,'writeup-specific');
    assert.match(item.provenance.url,/github\.com\//);
  }
});

test('Batch73 structured replays require the complete evidence chain',()=>{
  assert.equal(Object.keys(STRUCTURED_RULES).length,5);
  for(const [riskType,keys] of Object.entries(STRUCTURED_RULES)){
    const hit={riskType};for(const key of keys)hit[key]=true;
    const positive=evaluatePromptCtfStructuredReplay(hit);
    assert.equal(positive.verdict,'candidate-failure',riskType);
    assert.equal(positive.findings.length,1);
    const miss={...hit,[keys[0]]:false};
    const negative=evaluatePromptCtfStructuredReplay(miss);
    assert.equal(negative.verdict,'no-explicit-failure',`${riskType} negative`);
    assert.equal(negative.findings.length,0);
  }
});

test('Batch73 regression has passing positive and negative controls',()=>{
  const report=runPromptCtfTrainingRegression({variantsPerSeed:1});
  assert.equal(report.schema,'newcyber.prompt-ctf-training.v1');
  assert.equal(report.summary.seeds,8);
  assert.equal(report.summary.cases,16);
  assert.equal(report.summary.pass,16);
  assert.equal(report.summary.miss,0);
  assert.equal(report.summary.error,0);
  assert.equal(report.summary.passRate,1);
  for(const evaluator of ['prompt','structured']){
    const rows=report.results.filter((row)=>row.evaluator===evaluator);
    assert.ok(rows.length>0,evaluator);
    assert.ok(rows.some((row)=>row.control==='positive'&&row.status==='pass'),`${evaluator} positive`);
    assert.ok(rows.some((row)=>row.control==='negative'&&row.status==='pass'),`${evaluator} negative`);
  }
  const c1=report.results.find((row)=>row.seed==='prompt-airlines-c1-identifier-leak'&&row.control==='positive');
  assert.ok(c1.findingIds.includes('prompt-injection-canary-exposed'));
  const deputy=report.results.find((row)=>row.seed==='ai-security-academy-digital-doppelganger'&&row.control==='positive');
  assert.ok(deputy.findingIds.includes('prompt-ctf-multi-agent-confused-deputy'));
});

test('Batch73 regression is deterministic and public corpus is metadata-only',()=>{
  const first=runPromptCtfTrainingRegression({variantsPerSeed:3});
  const second=runPromptCtfTrainingRegression({variantsPerSeed:3});
  assert.deepEqual(first,second);
  const corpus=getPromptCtfTrainingCorpus();
  assert.equal(corpus.length,8);
  assert.ok(corpus.every((item)=>!Object.prototype.hasOwnProperty.call(item,'fixture')));
  assert.ok(corpus.every((item)=>item.capability&&item.family&&item.provenance?.url));
});

test('Batch73 is wired into router and global curriculum/full regression',()=>{
  const corpus=runTool('ai-prompt-ctf-training-corpus',{});
  assert.equal(corpus.schema,'newcyber.ai-prompt-ctf-training-corpus.v1');
  assert.equal(corpus.cases.length,8);
  const regression=runTool('ai-prompt-ctf-training-regression',{options:{variantsPerSeed:1}});
  assert.equal(regression.summary.passRate,1);
  const curriculum=getTrainingCurriculum();
  assert.ok(CORPORA.some((row)=>row.id==='prompt-agent-ctf'));
  assert.equal(curriculum.summary.byCorpus['prompt-agent-ctf'],8);
  assert.ok(curriculum.cases.some((row)=>row.id.startsWith('prompt-agent-ctf:')));
  const full=runTrainingCurriculumRegression({variantsPerSeed:1});
  assert.equal(full.summary.suites,CORPORA.length);
  assert.equal(full.summary.suiteErrors,0);
  assert.ok(full.suites.some((row)=>row.id==='prompt-agent-ctf'&&row.ok));
});
