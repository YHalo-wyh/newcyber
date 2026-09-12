'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  evaluateAssertion,validateFixture,materializeRegression,scanSecrets
}=require('../src/core/ai_training_regression_materializer');

function skeleton(){
  return{
    schema:'newcyber.ai-training-regression-skeleton.v1',status:'ready',
    skeleton:{
      id:'sk-demo-event-demo-challenge-demo-family',
      candidate:{event:'Demo Event',challenge:'Demo Challenge',direction:'privacy-leakage',family:'membership-inference'},
      evaluator:{tool:'demo-evaluator',module:'demo',entrypoint:'evaluate',contract:['synthetic only']},
      corpusEntry:{id:'demo-case',event:'Demo Event',challenge:'Demo Challenge',direction:'privacy-leakage',family:'membership-inference',provenance:{url:'https://example.org/public-challenge',evidenceLevel:'public-challenge'}},
      fixtures:[
        {id:'demo-positive',role:'positive',synthetic:true,payload:{score:.91,label:'member'},expected:{status:'finding',predicate:'score separates member sample',assertions:[{path:'score',op:'gte',value:.8},{path:'finding',op:'truthy'}]}},
        {id:'demo-negative',role:'negative',synthetic:true,payload:{score:.21,label:'non-member'},expected:{status:'non-finding',predicate:'non-member stays below threshold',assertions:[{path:'score',op:'lt',value:.8},{path:'finding',op:'falsy'}]}},
        {id:'demo-control',role:'control',synthetic:true,payload:{score:.35,label:'held-out-control'},expected:{status:'non-finding',predicate:'held-out control stays below threshold',assertions:[{path:'score',op:'lt',value:.8},{path:'finding',op:'falsy'}]}}
      ],
      artifactPlan:{suggestedCorpusFile:'src/core/ai_training_demo.js',suggestedTestFile:'tests/demo.test.js',suggestedDocFile:'docs/demo.md'}
    }
  };
}

function executor(tool,{input}){
  assert.equal(tool,'demo-evaluator');
  return{score:input.score,finding:input.score>=.8,label:input.label};
}

test('materializer emits ready-to-commit artifacts only after all fixture assertions pass',()=>{
  const result=materializeRegression(skeleton(),executor);
  assert.equal(result.status,'ready-to-commit');
  assert.equal(result.readyToCommit,true);
  assert.equal(result.checks.dryRuns.length,3);
  assert.ok(result.checks.dryRuns.every((row)=>row.pass));
  assert.match(result.artifacts.test.content,/test\('/);
  assert.doesNotMatch(result.artifacts.test.content,/test\.skip/);
  assert.match(result.artifacts.corpus.content,/public-evidence|Demo Event/);
  assert.match(result.artifacts.doc.content,/Dry-run/);
});

test('null fixture payload and TODO predicate block materialization before evaluator execution',()=>{
  const input=skeleton();
  input.skeleton.fixtures[0].payload=null;
  input.skeleton.fixtures[0].expected.predicate='TODO: later';
  let called=false;
  const result=materializeRegression(input,()=>{called=true;return{};});
  assert.equal(result.status,'blocked');
  assert.equal(called,false);
  assert.ok(result.errors.includes('positive:fixture-payload-missing'));
  assert.ok(result.errors.includes('positive:fixture-predicate-still-todo'));
});

test('secret scanner rejects flag-like or credential-like fixture values',()=>{
  assert.equal(scanSecrets({value:'FLAG{real-looking-answer}'}).some((x)=>x.id==='ctf-flag'),true);
  const input=skeleton();
  input.skeleton.fixtures[1].payload={message:'FLAG{real-looking-answer}'};
  const check=validateFixture(input.skeleton.fixtures[1]);
  assert.equal(check.pass,false);
  assert.ok(check.errors.includes('secret-pattern-detected'));
});

test('dry-run assertion failure never emits artifacts',()=>{
  const result=materializeRegression(skeleton(),(_tool,{input})=>({score:input.score,finding:false}));
  assert.equal(result.status,'dry-run-failed');
  assert.equal(result.readyToCommit,false);
  assert.equal(result.artifacts,null);
  assert.ok(result.errors.includes('positive:dry-run-failed'));
});

test('declarative assertion evaluator supports numeric, existence and inclusion checks',()=>{
  const result={metrics:{auc:.91},tags:['synthetic','member'],finding:true};
  assert.equal(evaluateAssertion(result,{path:'metrics.auc',op:'gte',value:.9}).pass,true);
  assert.equal(evaluateAssertion(result,{path:'finding',op:'truthy'}).pass,true);
  assert.equal(evaluateAssertion(result,{path:'tags',op:'includes',value:'synthetic'}).pass,true);
  assert.equal(evaluateAssertion(result,{path:'missing',op:'not-exists'}).pass,true);
});

test('materializer rejects malformed skeletons and missing executors deterministically',()=>{
  const malformed=materializeRegression({schema:'wrong',status:'ready'},executor);
  assert.equal(malformed.status,'blocked');
  assert.ok(malformed.errors.includes('regression-skeleton-required'));
  const noExecutor=materializeRegression(skeleton());
  assert.equal(noExecutor.status,'blocked');
  assert.ok(noExecutor.errors.includes('evaluator-executor-required'));
});
