'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  provenanceWeight,
  effectiveCases,
  directionQuality,
  analyzeTrainingQuality
}=require('../src/core/ai_training_quality');
const {getTrainingCurriculum,runTrainingCurriculumRegression}=require('../src/core/ai_training_curriculum');

function row(overrides={}){
  return {
    direction:'privacy-leakage',
    event:'Event A',
    challenge:'Challenge A',
    family:'membership-inference',
    provenance:{kind:'official-challenge-archive',evidenceLevel:'challenge-source-specific',url:'https://example.com/a'},
    ...overrides
  };
}

test('Batch95 provenance weights prefer challenge-specific evidence over weak URL-only evidence',()=>{
  assert.equal(provenanceWeight(row()),1);
  assert.equal(provenanceWeight(row({provenance:{kind:'ctf-writeup',evidenceLevel:'writeup-specific',url:'https://example.com'}})),0.8);
  assert.equal(provenanceWeight(row({provenance:{url:'https://example.com'}})),0.5);
  assert.equal(provenanceWeight(row({provenance:{}})),0.25);
});

test('Batch95 repeated variants do not inflate effective coverage',()=>{
  const repeated=Array.from({length:8},(_,i)=>row({id:`variant-${i}`}));
  assert.equal(effectiveCases(repeated),1);
  const quality=directionQuality(repeated,'privacy-leakage');
  assert.equal(quality.rawCases,8);
  assert.equal(quality.uniqueSignatures,1);
  assert.equal(quality.uniqueFamilies,1);
  assert.equal(quality.uniqueEvents,1);
  assert.equal(quality.duplicateRatio,0.875);
  assert.notEqual(quality.readiness,'ready');
  assert.ok(quality.recommendations.includes('reduce-duplicate-case-inflation'));
  assert.ok(quality.recommendations.includes('build-cross-event-holdout'));
});

test('Batch95 ready requires family/event diversity and cross-event holdout conditions',()=>{
  const rows=[
    row({event:'Event A',challenge:'MIA A',family:'membership-inference'}),
    row({event:'Event B',challenge:'Inversion B',family:'model-inversion'}),
    row({event:'Event C',challenge:'Leak C',family:'sensitive-output-leakage'}),
    row({event:'Event D',challenge:'MIA D',family:'membership-inference'}),
    row({event:'Event E',challenge:'Extract E',family:'model-extraction'})
  ];
  const quality=directionQuality(rows,'privacy-leakage');
  assert.equal(quality.crossEventHoldoutReady,true);
  assert.ok(quality.uniqueFamilies>=3);
  assert.ok(quality.uniqueEvents>=3);
  assert.equal(quality.readiness,'ready');
});

test('Batch95 unified curriculum exposes quality health without breaking v1 schema consumers',()=>{
  const curriculum=getTrainingCurriculum();
  assert.equal(curriculum.schema,'newcyber.ai-training-curriculum.v1');
  assert.equal(curriculum.quality.schema,'newcyber.ai-training-quality.v1');
  assert.equal(curriculum.summary.quality.directions,curriculum.quality.byDirection.length);
  assert.ok(curriculum.quality.byDirection.some((item)=>item.direction==='privacy-leakage'));
  assert.ok(curriculum.quality.byDirection.every((item)=>['seed','developing','ready'].includes(item.readiness)));

  const regression=runTrainingCurriculumRegression({variantsPerSeed:1});
  assert.equal(regression.schema,'newcyber.ai-training-curriculum-regression.v1');
  assert.deepEqual(regression.summary.quality,regression.quality.summary);
  assert.equal(regression.summary.suiteErrors,0);
});

test('Batch95 quality analyzer reports all requested directions',()=>{
  const result=analyzeTrainingQuality([row()],{directions:['privacy-leakage','infra-supply-chain']});
  assert.equal(result.summary.directions,2);
  assert.equal(result.byDirection.length,2);
  assert.equal(result.byDirection.find((x)=>x.direction==='infra-supply-chain').rawCases,0);
});
