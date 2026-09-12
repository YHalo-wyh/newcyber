'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {planIntegration}=require('../src/core/ai_training_integration_gate');
const {buildIntegrationWritePlan,applyRegistryPatch,verifyIntegratedResult,stableKey}=require('../src/core/ai_training_integration_writer');
const {analyzeTrainingQuality}=require('../src/core/ai_training_quality');
const {analyzeCrossEventHoldout}=require('../src/core/ai_training_holdout');
const {buildTrainingSchedule}=require('../src/core/ai_training_scheduler');

function baseCases(){
  return[
    {id:'a',event:'Event A',challenge:'C1',direction:'privacy-leakage',family:'membership-inference',provenance:{evidenceLevel:'official'}},
    {id:'b',event:'Event B',challenge:'C2',direction:'privacy-leakage',family:'sensitive-output-leakage',provenance:{evidenceLevel:'writeup-specific'}},
    {id:'c',event:'Event C',challenge:'C3',direction:'privacy-leakage',family:'membership-inference',provenance:{evidenceLevel:'public-challenge'}}
  ];
}
function materialized(entry={}){
  const corpusEntry={id:'candidate-demo',event:'Event D',challenge:'C4',direction:'privacy-leakage',family:'memorization-canary',evaluator:'ai-privacy-audit',provenance:{url:'https://example.org/challenge',evidenceLevel:'official-challenge-archive'},...entry};
  return{schema:'newcyber.ai-training-regression-materializer.v1',status:'ready-to-commit',readyToCommit:true,corpusEntry,artifacts:{corpus:{path:'src/core/ai_training_event_d_c4.js',operation:'create',content:"'use strict';\nconst CORPUS_ENTRY={};\nfunction getTrainingCorpus(){return [CORPUS_ENTRY];}\nmodule.exports={getTrainingCorpus};\n"},test:{path:'tests/event-d-c4.test.js',operation:'create',content:"'use strict';\n"},doc:{path:'docs/event-d-c4.md',operation:'create',content:'# regression\n'}}};
}
function gate(){return planIntegration({materialized:materialized(),cases:baseCases()});}
function curriculumSource(){return "'use strict';\n\nconst {foo}=require('./foo');\n\nconst TARGET_DIRECTIONS=Object.freeze([\n  'privacy-leakage'\n]);\n\nconst CORPORA=Object.freeze([\n  {id:'base',title:'Base',kind:'baseline',get:()=>[]}\n]);\n\nmodule.exports={TARGET_DIRECTIONS,CORPORA};\n";}

test('writer creates deterministic artifacts plus exact registry patch',()=>{
  const g=gate();
  assert.equal(g.readyToIntegrate,true);
  const plan=buildIntegrationWritePlan({gate:g,curriculumSource:curriculumSource(),existingPaths:[]});
  assert.equal(plan.status,'ready-to-write');
  assert.equal(plan.readyToWrite,true);
  assert.equal(plan.writes.length,4);
  assert.ok(plan.descriptor.registryId.startsWith('integration-'));
  assert.equal(plan.descriptor.key,stableKey(g.candidate));
  const registryWrite=plan.writes.find((row)=>row.path==='src/core/ai_training_curriculum.js');
  assert.ok(registryWrite.content.includes(plan.descriptor.importSymbol));
  assert.ok(registryWrite.content.includes(plan.descriptor.registryId));
  assert.ok(registryWrite.content.includes("require('./ai_training_event_d_c4')"));
});

test('writer rejects existing artifact path collisions',()=>{
  const g=gate();
  const plan=buildIntegrationWritePlan({gate:g,curriculumSource:curriculumSource(),existingPaths:['tests/event-d-c4.test.js']});
  assert.equal(plan.readyToWrite,false);
  assert.equal(plan.status,'blocked');
  assert.ok(plan.errors.includes('artifact-path-already-exists:tests/event-d-c4.test.js'));
});

test('registry patch refuses duplicate module or malformed source anchors',()=>{
  const g=gate();
  const ready=buildIntegrationWritePlan({gate:g,curriculumSource:curriculumSource()});
  assert.equal(ready.readyToWrite,true);
  const patched=ready.writes.find((row)=>row.path==='src/core/ai_training_curriculum.js').content;
  const again=applyRegistryPatch(patched,ready.descriptor);
  assert.equal(again.pass,false);
  assert.ok(again.errors.some((x)=>x.includes('already-present')));
  const malformed=applyRegistryPatch("'use strict';\n",ready.descriptor);
  assert.equal(malformed.pass,false);
  assert.ok(malformed.errors.includes('curriculum-import-anchor-missing'));
});

test('registry patch blocks unsafe corpus paths',()=>{
  const g=gate();
  g.patch.files[0].path='src/core/../evil.js';
  const plan=buildIntegrationWritePlan({gate:g,curriculumSource:curriculumSource()});
  assert.equal(plan.readyToWrite,false);
  assert.ok(plan.errors.includes('unsafe-corpus-artifact-path'));
});

function fullRegressionFor(cases){
  const directions=['privacy-leakage'];
  const quality=analyzeTrainingQuality(cases,{directions});
  const holdout=analyzeCrossEventHoldout(cases,{directions,minTrainEvents:2});
  const schedule=buildTrainingSchedule({cases,quality,holdout},{directions});
  return{schema:'newcyber.ai-training-curriculum-regression.v1',summary:{suiteErrors:0,curriculumCases:cases.length},quality,holdout,schedule};
}

test('post-write verification accepts only exact simulated delta and clean tests',()=>{
  const before=baseCases();const g=gate();
  const after=[...before,{...g.candidate,id:'integration:candidate'}];
  const result=verifyIntegratedResult({gate:g,beforeCases:before,afterCurriculum:{schema:'newcyber.ai-training-curriculum.v1',cases:after,sourceErrors:[]},fullRegression:fullRegressionFor(after),repositoryTests:{passed:true}});
  assert.equal(result.status,'verified-integrated');
  assert.equal(result.verified,true);
  assert.equal(result.checks.deltaMatchesSimulation,true);
});

test('post-write verification detects actual curriculum drift',()=>{
  const before=baseCases();const g=gate();
  const after=[...before,{...g.candidate,id:'integration:candidate'},{id:'extra',event:'Event X',challenge:'CX',direction:'privacy-leakage',family:'extra-family',provenance:{evidenceLevel:'official'}}];
  const result=verifyIntegratedResult({gate:g,beforeCases:before,afterCurriculum:{schema:'newcyber.ai-training-curriculum.v1',cases:after,sourceErrors:[]},fullRegression:fullRegressionFor(after),repositoryTests:{passed:true}});
  assert.equal(result.verified,false);
  assert.ok(result.errors.some((x)=>x.startsWith('curriculum-case-count-drift:')));
  assert.ok(result.errors.includes('simulated-vs-actual-delta-mismatch'));
});

test('post-write verification requires repository and full regression success',()=>{
  const before=baseCases();const g=gate();const after=[...before,{...g.candidate,id:'integration:candidate'}];
  const result=verifyIntegratedResult({gate:g,beforeCases:before,afterCurriculum:{schema:'newcyber.ai-training-curriculum.v1',cases:after,sourceErrors:[]},fullRegression:{schema:'newcyber.ai-training-curriculum-regression.v1',summary:{suiteErrors:1,curriculumCases:after.length}},repositoryTests:{passed:false}});
  assert.equal(result.verified,false);
  assert.ok(result.errors.includes('full-regression-suite-errors'));
  assert.ok(result.errors.includes('repository-tests-not-passed'));
});
