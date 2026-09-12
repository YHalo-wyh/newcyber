'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {planIntegration}=require('../src/core/ai_training_integration_gate');
const {analyzeTrainingQuality}=require('../src/core/ai_training_quality');
const {analyzeCrossEventHoldout}=require('../src/core/ai_training_holdout');
const {buildTrainingSchedule}=require('../src/core/ai_training_scheduler');
const {buildTransactionManifest,digestCases,isolatedBranchName,executeTransactionalIntegration}=require('../src/core/ai_training_transactional_integration');

function baseCases(){return[
  {id:'a',event:'Event A',challenge:'C1',direction:'privacy-leakage',family:'membership-inference',provenance:{evidenceLevel:'official'}},
  {id:'b',event:'Event B',challenge:'C2',direction:'privacy-leakage',family:'sensitive-output-leakage',provenance:{evidenceLevel:'writeup-specific'}},
  {id:'c',event:'Event C',challenge:'C3',direction:'privacy-leakage',family:'membership-inference',provenance:{evidenceLevel:'public-challenge'}}
];}
function materialized(){
  const corpusEntry={id:'candidate-demo',event:'Event D',challenge:'C4',direction:'privacy-leakage',family:'memorization-canary',evaluator:'ai-privacy-audit',provenance:{url:'https://example.org/challenge',evidenceLevel:'official-challenge-archive'}};
  return{schema:'newcyber.ai-training-regression-materializer.v1',status:'ready-to-commit',readyToCommit:true,corpusEntry,artifacts:{corpus:{path:'src/core/ai_training_event_d_c4.js',operation:'create',content:"'use strict';\nconst CORPUS_ENTRY={};\nfunction getTrainingCorpus(){return [CORPUS_ENTRY];}\nmodule.exports={getTrainingCorpus};\n"},test:{path:'tests/event-d-c4.test.js',operation:'create',content:"'use strict';\n"},doc:{path:'docs/event-d-c4.md',operation:'create',content:'# regression\n'}}};
}
function gate(){return planIntegration({materialized:materialized(),cases:baseCases()});}
function curriculumSource(){return "'use strict';\n\nconst {foo}=require('./foo');\n\nconst TARGET_DIRECTIONS=Object.freeze([\n  'privacy-leakage'\n]);\n\nconst CORPORA=Object.freeze([\n  {id:'base',title:'Base',kind:'baseline',get:()=>[]}\n]);\n\nmodule.exports={TARGET_DIRECTIONS,CORPORA};\n";}
function fullRegressionFor(cases){
  const directions=['privacy-leakage'];
  const quality=analyzeTrainingQuality(cases,{directions});
  const holdout=analyzeCrossEventHoldout(cases,{directions,minTrainEvents:2});
  const schedule=buildTrainingSchedule({cases,quality,holdout},{directions});
  return{schema:'newcyber.ai-training-curriculum-regression.v1',summary:{suiteErrors:0,curriculumCases:cases.length},quality,holdout,schedule};
}
function makeAdapter({manifest,g,driftCases=false,testsPass=true,extraAfter=false}={}){
  const files=new Map([['src/core/ai_training_curriculum.js',curriculumSource()]]);
  let branch='main';let head='base-sha';let integrated=false;
  const before=baseCases();
  return{
    state:{files,get branch(){return branch;},get integrated(){return integrated;}},
    getCurrentBranch:()=>branch,
    getHeadSha:()=>head,
    readText:(path)=>files.get(path),
    pathExists:(path)=>files.has(path),
    createBranch:(name,sha)=>{assert.equal(sha,'base-sha');branch=name;head='txn-sha';},
    checkoutBranch:(name)=>{branch=name;},
    createText:(path,content)=>{if(files.has(path))throw new Error('exists');files.set(path,content);integrated=true;},
    updateText:(path,content)=>{files.set(path,content);integrated=true;},
    runRepositoryTests:()=>({passed:testsPass}),
    loadCurriculum:()=>{
      if(!integrated)return{schema:'newcyber.ai-training-curriculum.v1',cases:driftCases?[...before,{id:'drift',event:'Drift',challenge:'D',direction:'privacy-leakage',family:'drift',provenance:{evidenceLevel:'official'}}]:before,sourceErrors:[]};
      const cases=[...before,{...g.candidate,id:'integrated'}];
      if(extraAfter)cases.push({id:'extra',event:'Extra',challenge:'E',direction:'privacy-leakage',family:'extra',provenance:{evidenceLevel:'official'}});
      return{schema:'newcyber.ai-training-curriculum.v1',cases,sourceErrors:[]};
    },
    runFullRegression:()=>{
      const cases=[...before,{...g.candidate,id:'integrated'}];
      if(extraAfter)cases.push({id:'extra',event:'Extra',challenge:'E',direction:'privacy-leakage',family:'extra',provenance:{evidenceLevel:'official'}});
      return fullRegressionFor(cases);
    }
  };
}

test('manifest locks base SHA, source hash, case digest and isolated branch',()=>{
  const g=gate();
  const manifest=buildTransactionManifest({gate:g,curriculumSource:curriculumSource(),beforeCases:baseCases(),baseBranch:'main',baseHeadSha:'base-sha'});
  assert.equal(manifest.status,'ready-to-execute');
  assert.equal(manifest.base.headSha,'base-sha');
  assert.equal(manifest.base.casesDigest,digestCases(baseCases()));
  assert.ok(manifest.isolation.branch.startsWith('training-integration/'));
  assert.equal(manifest.isolation.branch,isolatedBranchName(g.candidate,manifest.writer.descriptor.key));
  assert.equal(manifest.writer.writes.length,4);
});

test('transaction executes only on isolated branch and reaches verified state',async()=>{
  const g=gate();
  const manifest=buildTransactionManifest({gate:g,curriculumSource:curriculumSource(),beforeCases:baseCases(),baseBranch:'main',baseHeadSha:'base-sha'});
  const adapter=makeAdapter({manifest,g});
  const result=await executeTransactionalIntegration({manifest,gate:g,adapter});
  assert.equal(result.status,'verified-on-isolated-branch');
  assert.equal(result.verified,true);
  assert.equal(result.finalization.allowed,true);
  assert.equal(result.finalization.action,'open-integration-pr');
  assert.equal(result.applied.length,4);
  assert.equal(adapter.state.branch,manifest.isolation.branch);
});

test('preflight blocks when curriculum cases drift even if registry source is unchanged',async()=>{
  const g=gate();
  const manifest=buildTransactionManifest({gate:g,curriculumSource:curriculumSource(),beforeCases:baseCases(),baseBranch:'main',baseHeadSha:'base-sha'});
  const adapter=makeAdapter({manifest,g,driftCases:true});
  const result=await executeTransactionalIntegration({manifest,gate:g,adapter});
  assert.equal(result.status,'preflight-failed');
  assert.ok(result.errors.includes('curriculum-cases-digest-drift'));
  assert.equal(result.executed,false);
});

test('repository test failure never authorizes finalization',async()=>{
  const g=gate();
  const manifest=buildTransactionManifest({gate:g,curriculumSource:curriculumSource(),beforeCases:baseCases(),baseBranch:'main',baseHeadSha:'base-sha'});
  const result=await executeTransactionalIntegration({manifest,gate:g,adapter:makeAdapter({manifest,g,testsPass:false})});
  assert.equal(result.status,'tests-failed');
  assert.equal(result.executed,true);
  assert.equal(result.finalization,undefined);
  assert.ok(result.errors.includes('repository-tests-not-passed'));
});

test('post-write curriculum drift blocks integration PR authorization',async()=>{
  const g=gate();
  const manifest=buildTransactionManifest({gate:g,curriculumSource:curriculumSource(),beforeCases:baseCases(),baseBranch:'main',baseHeadSha:'base-sha'});
  const result=await executeTransactionalIntegration({manifest,gate:g,adapter:makeAdapter({manifest,g,extraAfter:true})});
  assert.equal(result.status,'verification-failed');
  assert.equal(result.verified,undefined);
  assert.equal(result.finalization,undefined);
  assert.ok(result.errors.includes('simulated-vs-actual-delta-mismatch'));
});

test('missing repository adapter capabilities block before execution',async()=>{
  const g=gate();
  const manifest=buildTransactionManifest({gate:g,curriculumSource:curriculumSource(),beforeCases:baseCases(),baseBranch:'main',baseHeadSha:'base-sha'});
  const result=await executeTransactionalIntegration({manifest,gate:g,adapter:{}});
  assert.equal(result.status,'blocked');
  assert.equal(result.executed,false);
  assert.ok(result.errors.some((x)=>x.startsWith('adapter-missing:')));
});

test('case digest is order-independent but changes on provenance drift',()=>{
  const rows=baseCases();
  assert.equal(digestCases(rows),digestCases([...rows].reverse()));
  const changed=baseCases();changed[0].provenance={evidenceLevel:'public'};
  assert.notEqual(digestCases(rows),digestCases(changed));
});
