'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {getTrainingCurriculum,runTrainingCurriculumRegression,TARGET_DIRECTIONS}=require('../src/core/ai_training_curriculum');
const {analyzeTrainingQuality,signature}=require('../src/core/ai_training_quality');
const {analyzeCrossEventHoldout}=require('../src/core/ai_training_holdout');
const {buildTrainingSchedule}=require('../src/core/ai_training_scheduler');
const {buildTrainingWorkOrders}=require('../src/core/ai_training_work_orders');
const {checkCandidate}=require('../src/core/ai_training_evidence_intake');
const {buildRegressionSkeleton}=require('../src/core/ai_training_regression_skeleton');
const {materializeRegression}=require('../src/core/ai_training_regression_materializer');
const {planIntegration}=require('../src/core/ai_training_integration_gate');
const {verifyIntegratedResult}=require('../src/core/ai_training_integration_writer');
const {runTool}=require('../src/core/tool_router');
const {CORPUS_ENTRY,FIXTURES}=require('../src/core/ai_training_starpwn_ctf_2026_starry_hacks_dependency_confusion_unpinned_version');

const CANDIDATE={
  event:'STARPWN CTF 2026',
  challenge:'Starry hacks',
  direction:'infra-supply-chain',
  family:'dependency-confusion-unpinned-version',
  mechanicsSummary:'The public writeup documents a Python dependency constrained only by a lower bound, an artifact-upload path that installs a replacement package with pip, and higher-version package substitution at the dependency trust boundary.',
  source:{
    url:'https://github.com/JonghoMoon/STARPWN-2026-Writeup/blob/619d5555dbaeefe9de962edc1e2cc2879692a710/Space_Communication_and_RF/Starry_hacks/README.md',
    kind:'writeup',evidenceLevel:'writeup-specific',title:'STARPWN CTF 2026 — Starry hacks public writeup'
  },
  evidence:{
    facts:[
      'The public flight-software analysis lists cubesat-upstream-driver>=1.0.0 in mission/requirements.txt.',
      'The public writeup states that the Artifact Upload path installs an uploaded package with pip.',
      'The documented replacement package takes over the imported cubesat_upstream_driver dependency boundary.'
    ],
    successCondition:'A higher-version replacement can be installed through the documented package-update path and become the resolved imported driver.',
    negativeControl:'An exact-version synthetic requirement is not eligible for higher-version substitution and must remain non-finding in the local dependency-lock audit.'
  },
  verifier:{
    synthetic:true,
    plan:['audit a synthetic lower-bound Python requirement','assert dependency-not-locked on the lower-bound case','assert exact-version negative and control cases remain non-finding'],
    positive:'Synthetic lower-bound requirement reproduces only the documented unsafe version-resolution condition.',
    negative:'Synthetic exact-version requirement removes the higher-version substitution condition.',
    control:'Synthetic pinned requirement plus an unrelated comment isolates the version constraint as the finding signal.'
  }
};

function historicalWorkOrders(cases){
  const quality=analyzeTrainingQuality(cases,{directions:TARGET_DIRECTIONS});
  const holdout=analyzeCrossEventHoldout(cases,{directions:TARGET_DIRECTIONS,minTrainEvents:2});
  const schedule=buildTrainingSchedule({cases,quality,holdout},{directions:TARGET_DIRECTIONS});
  return{schedule,workOrders:buildTrainingWorkOrders({schedule,cases},{limit:5})};
}

function hydrateFixtures(skeleton){
  const byRole=Object.fromEntries(FIXTURES.map((row)=>[row.role,row]));
  for(const row of skeleton.skeleton.fixtures){
    const fixture=byRole[row.role];
    row.payload=fixture.payload;
    row.expected=fixture.expected;
  }
  return skeleton;
}

test('Batch108 admits STARPWN Starry hacks through evidence, materializer and structural integration gates',()=>{
  const after=getTrainingCurriculum();
  const targetSignature=[CANDIDATE.event,CANDIDATE.challenge,CANDIDATE.family].map((x)=>x.toLowerCase()).join('|');
  const beforeCases=after.cases.filter((row)=>signature(row)!==targetSignature);
  const historical=historicalWorkOrders(beforeCases);
  assert.equal(historical.schedule.queue[0].direction,'infra-supply-chain');
  const order=historical.workOrders.orders.find((row)=>row.direction==='infra-supply-chain');
  assert.ok(order);

  const intake=checkCandidate({...CANDIDATE,workOrderId:order.id},{cases:beforeCases,workOrders:historical.workOrders});
  assert.equal(intake.verdict,'accept',JSON.stringify({blockers:intake.blockers,missing:intake.missingEvidence}));
  assert.equal(intake.checks.novelty.eventNew,true);
  assert.equal(intake.checks.novelty.familyNew,true);

  const skeleton=hydrateFixtures(buildRegressionSkeleton(intake));
  assert.equal(skeleton.status,'ready');
  assert.equal(skeleton.skeleton.evaluator.tool,'ai-supply-chain');
  const materialized=materializeRegression(skeleton,(tool,payload)=>runTool(tool,payload));
  assert.equal(materialized.status,'ready-to-commit',JSON.stringify(materialized.errors));
  assert.equal(materialized.checks.dryRuns.length,3);
  assert.ok(materialized.checks.dryRuns.every((row)=>row.pass));

  const gate=planIntegration({materialized,cases:beforeCases,directions:TARGET_DIRECTIONS});
  assert.equal(gate.status,'ready-to-integrate',JSON.stringify({regressions:gate.regressions,improvements:gate.improvements,delta:gate.delta}));
  assert.ok(gate.improvements.includes('event-diversity'));
  assert.ok(gate.improvements.includes('family-diversity'));

  const matches=after.cases.filter((row)=>signature(row)===targetSignature);
  assert.equal(matches.length,1);
  assert.equal(matches[0].provenance.evidenceLevel,'writeup-specific');
  assert.equal(after.sourceErrors.length,0);

  const regression=runTrainingCurriculumRegression({variantsPerSeed:1});
  assert.equal(regression.summary.suiteErrors,0);
  const verification=verifyIntegratedResult({gate,beforeCases,afterCurriculum:after,fullRegression:regression,repositoryTests:{passed:true}});
  assert.equal(verification.status,'verified-integrated',JSON.stringify(verification.errors));
  assert.equal(verification.verified,true);
  assert.deepEqual(gate.candidate.event,CORPUS_ENTRY.event);
});
