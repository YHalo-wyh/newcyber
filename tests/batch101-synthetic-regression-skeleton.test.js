'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {evaluatorFor,buildRegressionSkeleton}=require('../src/core/ai_training_regression_skeleton');
const {runTool}=require('../src/core/tool_router');

function accepted(direction='privacy-leakage',family='membership-inference'){
  return{
    schema:'newcyber.ai-training-evidence-intake.v1',verdict:'accept',
    candidate:{
      event:'Synthetic Public Event',challenge:'Public Challenge A',direction,family,
      mechanicsSummary:'Public evidence describes a deterministic challenge criterion.',
      source:{url:'https://example.org/challenge',title:'Challenge page',kind:'official challenge archive',evidenceLevel:'official-challenge-archive'},
      evidence:{facts:['fact one','fact two'],successCondition:'positive crosses threshold',negativeControl:'control stays below threshold'},
      verifier:{synthetic:true,plan:['build deterministic rows'],positive:'synthetic positive',negative:'synthetic negative',control:'synthetic held-out control'}
    },
    workOrder:{id:'wo-01-privacy-leakage',direction,priority:'high',score:80,nextAction:'add-distinct-families'},
    corpusDraft:{provenance:{title:'Challenge page',url:'https://example.org/challenge',kind:'official challenge archive',evidenceLevel:'official-challenge-archive'}}
  };
}

test('Batch101 maps directions and family-specific cases to existing evaluators',()=>{
  assert.equal(evaluatorFor({direction:'privacy-leakage',family:'membership-inference'}).tool,'ai-privacy-audit');
  assert.equal(evaluatorFor({direction:'privacy-leakage',family:'model-inversion'}).tool,'ai-model-inversion');
  assert.equal(evaluatorFor({direction:'backdoor-poisoning',family:'label-swap-poisoning'}).tool,'ai-poisoning-impact');
  assert.equal(evaluatorFor({direction:'backdoor-poisoning',family:'image-trigger-backdoor'}).tool,'ai-backdoor-behavior');
});

test('Batch101 builds a safe synthetic skeleton from accepted evidence',()=>{
  const result=buildRegressionSkeleton(accepted());
  assert.equal(result.schema,'newcyber.ai-training-regression-skeleton.v1');
  assert.equal(result.status,'ready');
  assert.equal(result.skeleton.fixtures.length,3);
  assert.deepEqual(result.skeleton.fixtures.map((row)=>row.role),['positive','negative','control']);
  assert.ok(result.skeleton.fixtures.every((row)=>row.synthetic===true&&row.payload===null));
  assert.equal(result.skeleton.corpusEntry.evaluator,'ai-privacy-audit');
  assert.match(result.skeleton.testCode,/test\.skip/);
  assert.match(result.skeleton.testCode,/TODO: assert/);
  assert.match(result.skeleton.corpusEntry.limitation,/no original challenge secret/i);
});

test('Batch101 refuses to scaffold rejected or incomplete intake results',()=>{
  const needs={schema:'newcyber.ai-training-evidence-intake.v1',verdict:'needs-evidence',missingEvidence:['public-source-url'],blockers:[]};
  const rejected={schema:'newcyber.ai-training-evidence-intake.v1',verdict:'reject',missingEvidence:[],blockers:['forbidden-secret-material']};
  assert.equal(buildRegressionSkeleton(needs).status,'blocked');
  assert.equal(buildRegressionSkeleton(needs).reason,'intake-needs-evidence');
  assert.equal(buildRegressionSkeleton(rejected).reason,'intake-reject');
});

test('Batch101 artifact names and IDs are deterministic',()=>{
  const left=buildRegressionSkeleton(accepted());
  const right=buildRegressionSkeleton(accepted());
  assert.equal(left.skeleton.id,right.skeleton.id);
  assert.deepEqual(left.skeleton.artifactPlan,right.skeleton.artifactPlan);
  assert.deepEqual(left.skeleton.fixtures.map((row)=>row.id),right.skeleton.fixtures.map((row)=>row.id));
});

test('Batch101 tool router exposes regression skeleton generation',()=>{
  const result=runTool('ai-training-regression-skeleton',accepted());
  assert.equal(result.schema,'newcyber.ai-training-regression-skeleton.v1');
  assert.equal(result.status,'ready');
  assert.equal(result.skeleton.evaluator.tool,'ai-privacy-audit');
});
