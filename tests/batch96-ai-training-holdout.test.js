'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {splitForEvent,buildDirectionHoldouts,analyzeCrossEventHoldout}=require('../src/core/ai_training_holdout');
const {getTrainingCurriculum}=require('../src/core/ai_training_curriculum');

function row(event,challenge,family,direction='privacy-leakage'){
  return {event,challenge,family,direction};
}

const SAMPLE=[
  row('Event A','MIA A','membership-inference'),
  row('Event A','Leak A','sensitive-output-leakage'),
  row('Event B','MIA B','membership-inference'),
  row('Event B','Inversion B','model-inversion'),
  row('Event C','Extract C','model-extraction'),
  row('Event D','Leak D','sensitive-output-leakage')
];

test('Batch96 leave-one-event-out split excludes held-out event from training',()=>{
  const split=splitForEvent(SAMPLE,'Event C');
  assert.deepEqual(split.testEvents,['Event C']);
  assert.ok(!split.trainEvents.includes('Event C'));
  assert.equal(split.leakage.clean,true);
  assert.deepEqual(split.leakage.event,[]);
  assert.deepEqual(split.leakage.challenge,[]);
});

test('Batch96 distinguishes unseen-family from known-family cross-event plans',()=>{
  const unseen=splitForEvent(SAMPLE,'Event C');
  assert.equal(unseen.mode,'cross-event-unseen-family');
  assert.deepEqual(unseen.unseenFamilies,['model-extraction']);

  const known=splitForEvent(SAMPLE,'Event D');
  assert.equal(known.mode,'cross-event-known-family');
  assert.deepEqual(known.unseenFamilies,[]);
  assert.ok(known.knownFamilies.includes('sensitive-output-leakage'));
});

test('Batch96 direction planner is deterministic and requires enough training events',()=>{
  const first=buildDirectionHoldouts(SAMPLE,'privacy-leakage');
  const second=buildDirectionHoldouts([...SAMPLE].reverse(),'privacy-leakage');
  assert.equal(first.eligible,true);
  assert.deepEqual(first.plans.map((x)=>x.heldOutEvent),second.plans.map((x)=>x.heldOutEvent));
  assert.ok(first.plans.every((plan)=>plan.trainEvents.length>=2));
  assert.ok(first.plans.every((plan)=>plan.leakage.clean));

  const tooSmall=buildDirectionHoldouts([row('Only Event','Only Challenge','membership-inference')],'privacy-leakage');
  assert.equal(tooSmall.eligible,false);
  assert.equal(tooSmall.reason,'insufficient-events');
});

test('Batch96 analyzer covers requested directions and exposes clean-plan summary',()=>{
  const result=analyzeCrossEventHoldout(SAMPLE,{directions:['privacy-leakage','infra-supply-chain']});
  assert.equal(result.schema,'newcyber.ai-training-holdout.v1');
  assert.equal(result.byDirection.length,2);
  assert.equal(result.summary.plans,result.summary.cleanPlans);
  assert.equal(result.byDirection.find((x)=>x.direction==='infra-supply-chain').eligible,false);
  assert.ok(result.summary.unseenFamilyPlans>=1);
});

test('Batch96 unified curriculum exposes executable holdout plans without changing v1 schema',()=>{
  const curriculum=getTrainingCurriculum();
  assert.equal(curriculum.schema,'newcyber.ai-training-curriculum.v1');
  assert.equal(curriculum.holdout.schema,'newcyber.ai-training-holdout.v1');
  assert.deepEqual(curriculum.summary.holdout,curriculum.holdout.summary);
  assert.equal(curriculum.holdout.summary.plans,curriculum.holdout.summary.cleanPlans);
});
