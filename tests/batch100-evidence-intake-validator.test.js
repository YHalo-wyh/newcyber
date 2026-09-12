'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');

const {checkCandidate,buildIntakeTemplate}=require('../src/core/ai_training_evidence_intake');
const {getTrainingCurriculum}=require('../src/core/ai_training_curriculum');
const {runTool}=require('../src/core/tool_router');

function context(){
  return {
    cases:[
      {id:'existing:1',event:'Event A',challenge:'Challenge A',direction:'privacy-leakage',family:'membership-inference'},
      {id:'existing:2',event:'Event B',challenge:'Challenge B',direction:'privacy-leakage',family:'sensitive-output-leakage'}
    ],
    workOrders:{orders:[{
      id:'wo-01-privacy-leakage',direction:'privacy-leakage',priority:'high',score:72,
      objective:{nextAction:'add-distinct-families',targets:{newEvents:1,newFamilies:1}},
      acquisition:{familyThemes:['model-inversion','memorization-canary']},
      regressionDesign:{verifier:['balanced synthetic positive/negative rows']}
    }]}
  };
}

function validCandidate(){
  return {
    workOrderId:'wo-01-privacy-leakage',
    event:'Event C',challenge:'Privacy New',direction:'privacy-leakage',family:'model-inversion',
    mechanicsSummary:'Public task describes recovering a coarse property from model outputs under a stated query interface.',
    source:{url:'https://example.org/public/privacy-new',title:'Privacy New',kind:'official challenge archive',evidenceLevel:'official-challenge-archive'},
    evidence:{facts:['The public task exposes model outputs.','The stated goal is to recover a property from those outputs.'],successCondition:'Public statement defines recovery of the target property as success.',negativeControl:'A held-out synthetic control should not meet the recovery predicate.'},
    verifier:{synthetic:true,plan:['build deterministic synthetic victim outputs','evaluate recovery predicate'],positive:'Synthetic outputs that satisfy the recovery predicate.',negative:'Synthetic outputs below the recovery threshold.',control:'Held-out outputs that should not expose the target property.'}
  };
}

test('Batch100 accepts a complete public-evidence package and emits corpus draft',()=>{
  const result=checkCandidate(validCandidate(),context());
  assert.equal(result.schema,'newcyber.ai-training-evidence-intake.v1');
  assert.equal(result.verdict,'accept');
  assert.equal(result.blockers.length,0);
  assert.equal(result.missingEvidence.length,0);
  assert.equal(result.checks.provenance.pass,true);
  assert.equal(result.checks.signature.pass,true);
  assert.equal(result.checks.novelty.eventNew,true);
  assert.equal(result.checks.novelty.familyNew,true);
  assert.equal(result.checks.novelty.workOrderFamilyTheme,true);
  assert.equal(result.checks.verifier.pass,true);
  assert.equal(result.corpusDraft.direction,'privacy-leakage');
  assert.equal(result.nextStep,'build-synthetic-regression-and-rerun-quality-holdout-schedule');
});

test('Batch100 returns needs-evidence for incomplete but non-blocked package',()=>{
  const candidate=validCandidate();
  candidate.source.url='';
  candidate.evidence.negativeControl='';
  candidate.verifier.control='';
  const result=checkCandidate(candidate,context());
  assert.equal(result.verdict,'needs-evidence');
  assert.ok(result.missingEvidence.includes('public-source-url'));
  assert.ok(result.missingEvidence.includes('negative-control-evidence'));
  assert.ok(result.missingEvidence.includes('synthetic-control-case'));
  assert.equal(result.corpusDraft,null);
});

test('Batch100 rejects duplicate signatures',()=>{
  const candidate=validCandidate();
  candidate.event='Event A';candidate.challenge='Challenge A';candidate.family='membership-inference';
  const result=checkCandidate(candidate,context());
  assert.equal(result.verdict,'reject');
  assert.ok(result.blockers.includes('duplicate-event-challenge-family-signature'));
  assert.equal(result.checks.signature.pass,false);
});

test('Batch100 rejects secret-bearing evidence packages',()=>{
  const candidate=validCandidate();
  candidate.notes='FLAG{real-secret-must-not-enter-training}';
  const result=checkCandidate(candidate,context());
  assert.equal(result.verdict,'reject');
  assert.ok(result.blockers.includes('forbidden-secret-material'));
  assert.ok(result.checks.policy.forbiddenHits.length>0);
});

test('Batch100 intake template is derived from work order without inventing evidence',()=>{
  const order=context().workOrders.orders[0];
  const template=buildIntakeTemplate(order);
  assert.equal(template.schema,'newcyber.ai-training-evidence-intake-template.v1');
  assert.equal(template.workOrderId,order.id);
  assert.equal(template.direction,'privacy-leakage');
  assert.equal(template.family,'model-inversion');
  assert.equal(template.source.url,'');
  assert.deepEqual(template.evidence.facts,[]);
  assert.equal(template.verifier.synthetic,true);
});

test('Batch100 router exposes template and intake validation against live curriculum',()=>{
  const curriculum=getTrainingCurriculum();
  const order=curriculum.workOrders.orders[0];
  assert.ok(order);
  const template=runTool('ai-training-evidence-template',{options:{workOrderId:order.id}});
  assert.equal(template.workOrderId,order.id);
  const result=runTool('ai-training-evidence-intake',{input:{...template,mechanicsSummary:'Publicly documented behavior.',source:{...template.source,url:'https://example.org/challenge'},evidence:{facts:['fact one','fact two'],successCondition:'public success',negativeControl:'public control'},verifier:{...template.verifier,positive:'synthetic positive',negative:'synthetic negative',control:'synthetic control'}}});
  assert.ok(['accept','needs-evidence'].includes(result.verdict));
  assert.notEqual(result.verdict,'reject');
});
