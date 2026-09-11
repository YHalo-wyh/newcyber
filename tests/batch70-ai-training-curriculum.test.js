'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  TARGET_DIRECTIONS,CORPORA,inferDirection,normalizeCase,getTrainingCurriculum,runTrainingCurriculumRegression
}=require('../src/core/ai_training_curriculum');
const {runTool}=require('../src/core/tool_router');

test('Batch70 unifies every existing AI challenge corpus into one metadata-only curriculum',()=>{
  const curriculum=getTrainingCurriculum();
  assert.equal(curriculum.schema,'newcyber.ai-training-curriculum.v1');
  assert.equal(curriculum.generatedFrom.length,CORPORA.length);
  assert.equal(curriculum.summary.corpora,CORPORA.length);
  assert.equal(curriculum.sourceErrors.length,0,JSON.stringify(curriculum.sourceErrors));
  assert.ok(curriculum.summary.cases>=50,`cases=${curriculum.summary.cases}`);
  assert.ok(curriculum.summary.events>=8,`events=${curriculum.summary.events}`);
  assert.ok(curriculum.summary.challenges>=20,`challenges=${curriculum.summary.challenges}`);
  assert.ok(curriculum.summary.families>=20,`families=${curriculum.summary.families}`);
  assert.ok(curriculum.cases.every((row)=>!Object.prototype.hasOwnProperty.call(row,'fixture')));
  assert.equal(new Set(curriculum.cases.map((row)=>row.id)).size,curriculum.cases.length);
});

test('Batch70 coverage map keeps the seven competition directions visible',()=>{
  const curriculum=getTrainingCurriculum();
  assert.equal(curriculum.coverageDebt.length,TARGET_DIRECTIONS.length);
  for(const direction of TARGET_DIRECTIONS){
    assert.ok(curriculum.coverageDebt.some((row)=>row.direction===direction),direction);
  }
  assert.ok((curriculum.summary.byDirection['prompt-llm-security']||0)>0);
  assert.ok((curriculum.summary.byDirection['adversarial-example']||0)>0);
  assert.ok((curriculum.summary.byDirection['infra-supply-chain']||0)>0);
});

test('Batch70 direction inference is deterministic for legacy corpora without explicit direction',()=>{
  assert.equal(inferDirection({kind:'model extraction / black-box stealing'}),'model-extraction');
  assert.equal(inferDirection({kind:'CIFAR adversarial sample'}),'adversarial-example');
  assert.equal(inferDirection({kind:'PyTorch pickle supply chain'}),'infra-supply-chain');
  assert.equal(inferDirection({kind:'RAG prompt injection'}),'prompt-llm-security');
  const row=normalizeCase({id:'x',event:'Synthetic',challenge:'X',kind:'feature store manipulation',source:'https://example.invalid/x'},{id:'legacy',title:'Legacy',kind:'ctf-derived'},0);
  assert.equal(row.direction,'dataset-pipeline-security');
  assert.equal(row.id,'legacy:x');
});

test('Batch70 full regression executes every suite without suite-level exceptions',()=>{
  const result=runTrainingCurriculumRegression({variantsPerSeed:1});
  assert.equal(result.schema,'newcyber.ai-training-curriculum-regression.v1');
  assert.equal(result.summary.suites,CORPORA.length);
  assert.equal(result.summary.suiteErrors,0,JSON.stringify(result.suites.filter((x)=>!x.ok)));
  assert.ok(result.summary.curriculumCases>=50);
  const ids=new Set(result.suites.map((x)=>x.id));
  for(const corpus of CORPORA)assert.ok(ids.has(corpus.id),corpus.id);
});

test('Batch70 tool router exposes curriculum and full regression',()=>{
  const curriculum=runTool('ai-training-curriculum',{});
  assert.equal(curriculum.schema,'newcyber.ai-training-curriculum.v1');
  const regression=runTool('ai-training-full-regression',{options:{variantsPerSeed:1}});
  assert.equal(regression.schema,'newcyber.ai-training-curriculum-regression.v1');
  assert.equal(regression.summary.suiteErrors,0);
});
