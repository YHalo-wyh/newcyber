'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {planIntegration,normalizeCandidate,computeDelta}=require('../src/core/ai_training_integration_gate');

function baseCases(){
  return[
    {id:'a',event:'Event A',challenge:'C1',direction:'privacy-leakage',family:'membership-inference',provenance:{evidenceLevel:'official'}},
    {id:'b',event:'Event B',challenge:'C2',direction:'privacy-leakage',family:'sensitive-output-leakage',provenance:{evidenceLevel:'writeup-specific'}},
    {id:'c',event:'Event C',challenge:'C3',direction:'privacy-leakage',family:'membership-inference',provenance:{evidenceLevel:'public-challenge'}},
    {id:'d',event:'Event A',challenge:'P1',direction:'prompt-llm-security',family:'system-prompt-leakage',provenance:{evidenceLevel:'official'}}
  ];
}

function materialized(entry={}){
  const corpusEntry={
    id:'candidate-demo',event:'Event D',challenge:'C4',direction:'privacy-leakage',family:'memorization-canary',
    evaluator:'ai-privacy-audit',caseType:'public-training',
    provenance:{url:'https://example.org/challenge',evidenceLevel:'official-challenge-archive'},
    trainingPolicy:'public-evidence-plus-synthetic-regression-only',
    ...entry
  };
  return{
    schema:'newcyber.ai-training-regression-materializer.v1',status:'ready-to-commit',readyToCommit:true,
    corpusEntry,
    artifacts:{
      corpus:{path:'src/core/ai_training_demo.js',content:"'use strict';\nmodule.exports={};\n"},
      test:{path:'tests/demo.test.js',content:"'use strict';\n"},
      doc:{path:'docs/demo.md',content:'# demo\n'}
    }
  };
}

test('ready materialized entry with new event and family becomes ready-to-integrate',()=>{
  const result=planIntegration({materialized:materialized(),cases:baseCases()});
  assert.equal(result.status,'ready-to-integrate');
  assert.equal(result.readyToIntegrate,true);
  assert.equal(result.checks.noMetricRegression,true);
  assert.ok(result.improvements.includes('event-diversity'));
  assert.ok(result.improvements.includes('family-diversity'));
  assert.equal(result.delta.events,1);
  assert.equal(result.delta.families,1);
  assert.equal(result.patch.files.length,3);
  assert.equal(result.patch.registry.target,'src/core/ai_training_curriculum.js');
});

test('duplicate event/challenge/family signature is blocked before simulation',()=>{
  const duplicate=materialized({event:'Event A',challenge:'C1',family:'membership-inference'});
  const result=planIntegration({materialized:duplicate,cases:baseCases()});
  assert.equal(result.status,'blocked');
  assert.equal(result.readyToIntegrate,false);
  assert.ok(result.errors.includes('duplicate-event-challenge-family-signature'));
  assert.equal(result.patch,null);
});

test('materializer must be ready-to-commit',()=>{
  const input=materialized();
  input.status='blocked';input.readyToCommit=false;
  const result=planIntegration({materialized:input,cases:baseCases()});
  assert.equal(result.status,'blocked');
  assert.ok(result.errors.includes('materializer-not-ready-to-commit'));
});

test('candidate may be recovered from generated corpus artifact content',()=>{
  const input=materialized();
  delete input.corpusEntry;
  const entry={id:'x',event:'Recovered Event',challenge:'Recovered',direction:'privacy-leakage',family:'confidence-leakage',provenance:{evidenceLevel:'official'}};
  input.artifacts.corpus.content=`'use strict';\n\nconst CORPUS_ENTRY=${JSON.stringify(entry,null,2)};\nconst FIXTURES=[];\n`;
  const recovered=normalizeCandidate(input);
  assert.equal(recovered.event,'Recovered Event');
  assert.equal(recovered.family,'confidence-leakage');
});

test('no meaningful gain is rejected even when candidate is technically unique',()=>{
  const rows=[
    {id:'a',event:'E1',challenge:'A',direction:'x',family:'f1',provenance:{evidenceLevel:'official'}},
    {id:'b',event:'E2',challenge:'B',direction:'x',family:'f2',provenance:{evidenceLevel:'official'}},
    {id:'c',event:'E3',challenge:'C',direction:'x',family:'f3',provenance:{evidenceLevel:'official'}},
    {id:'d',event:'E4',challenge:'D',direction:'x',family:'f4',provenance:{evidenceLevel:'official'}},
    {id:'e',event:'E5',challenge:'E',direction:'x',family:'f5',provenance:{evidenceLevel:'official'}}
  ];
  const input=materialized({event:'E1',challenge:'A2',direction:'x',family:'f1',provenance:{evidenceLevel:'official'}});
  const result=planIntegration({materialized:input,cases:rows,directions:['x']});
  assert.equal(result.readyToIntegrate,false);
  assert.equal(result.status,'no-meaningful-gain');
  assert.equal(result.patch,null);
});

test('computeDelta exposes scheduler and holdout movement deterministically',()=>{
  const before={quality:{byDirection:[{direction:'d',qualityScore:.5,effectiveCases:2,rawCases:2,uniqueEvents:2,uniqueFamilies:2,uniqueChallenges:2,duplicateRatio:0,provenanceAverage:.8}]},holdout:{byDirection:[{direction:'d',eligible:false,summary:{cleanPlans:0,unseenFamilyPlans:0}}]},schedule:{queue:[{direction:'d',rank:1,score:80}]}};
  const after={quality:{byDirection:[{direction:'d',qualityScore:.7,effectiveCases:3,rawCases:3,uniqueEvents:3,uniqueFamilies:3,uniqueChallenges:3,duplicateRatio:0,provenanceAverage:.8}]},holdout:{byDirection:[{direction:'d',eligible:true,summary:{cleanPlans:3,unseenFamilyPlans:2}}]},schedule:{queue:[{direction:'d',rank:3,score:55}]}};
  const delta=computeDelta(before,after,'d');
  assert.equal(delta.qualityScore,.2);
  assert.equal(delta.events,1);
  assert.equal(delta.holdoutEligible.after,true);
  assert.equal(delta.unseenFamilyPlans,2);
  assert.equal(delta.scheduleRank.delta,2);
});
