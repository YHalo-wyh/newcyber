'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  DOMESTIC_BACKDOOR_TRAINING_SEEDS,
  getDomesticBackdoorTrainingCorpus,
  runDomesticBackdoorTrainingRegression
}=require('../src/core/ai_domestic_backdoor_training');
const {CORPORA,getTrainingCurriculum,runTrainingCurriculumRegression}=require('../src/core/ai_training_curriculum');

test('Batch94 domestic backdoor corpus keeps provenance and synthetic-only policy',()=>{
  const corpus=getDomesticBackdoorTrainingCorpus();
  assert.equal(corpus.length,3);
  assert.equal(DOMESTIC_BACKDOOR_TRAINING_SEEDS.length,3);
  assert.ok(corpus.every((item)=>item.direction==='backdoor-poisoning'));
  assert.ok(corpus.every((item)=>item.trainingPolicy==='synthetic-fixture-only'));
  assert.ok(corpus.some((item)=>item.id==='ccsssc-2026-cifar10-backdoor-activation'));
  assert.ok(corpus.some((item)=>item.id==='gyxxaqjnds-2025-loss-history-poison-ranking'));
  assert.ok(corpus.some((item)=>item.id==='ccb-2025-easy-poison-label-swap'));
  assert.ok(corpus.every((item)=>/^https:\/\//.test(item.provenance.url)));
});

test('Batch94 positive and negative controls both pass',()=>{
  const result=runDomesticBackdoorTrainingRegression();
  assert.equal(result.summary.challenges,3);
  assert.equal(result.summary.families,3);
  assert.equal(result.summary.total,6);
  assert.equal(result.summary.pass,result.summary.total);
  assert.equal(result.summary.miss,0);
  assert.equal(result.summary.positiveControls,3);
  assert.equal(result.summary.negativeControls,3);
  assert.ok(result.results.every((item)=>item.status==='pass'));
});

test('Batch94 CIFAR-10 replay requires target ASR plus neutral-control specificity',()=>{
  const result=runDomesticBackdoorTrainingRegression();
  const positive=result.results.find((item)=>item.caseId==='ccsssc-2026-cifar10-backdoor-activation'&&item.control==='positive');
  const negative=result.results.find((item)=>item.caseId==='ccsssc-2026-cifar10-backdoor-activation'&&item.control==='negative');
  assert.ok(positive.findingIds.includes('backdoor-target-asr-candidate'));
  assert.ok(positive.findingIds.includes('backdoor-control-specificity'));
  assert.ok(!negative.findingIds.includes('backdoor-target-asr-candidate'));
  assert.ok(!negative.findingIds.includes('backdoor-control-specificity'));
});

test('Batch94 corpus is part of the unified curriculum and full regression',()=>{
  const curriculum=getTrainingCurriculum();
  assert.equal(curriculum.summary.corpora,CORPORA.length);
  assert.equal(curriculum.summary.byCorpus['domestic-backdoor-poisoning-2025-2026'],3);
  assert.ok(curriculum.cases.some((row)=>row.id.startsWith('domestic-backdoor-poisoning-2025-2026:ccsssc-2026-cifar10')));
  const full=runTrainingCurriculumRegression({variantsPerSeed:1});
  assert.equal(full.summary.suites,CORPORA.length);
  assert.equal(full.summary.suiteErrors,0);
  assert.ok(full.suites.some((row)=>row.id==='domestic-backdoor-poisoning-2025-2026'&&row.ok));
});
