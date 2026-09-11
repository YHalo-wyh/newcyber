'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const {summarizeScaQuality,attachScaQualitySession}=require('../src/core/challenge_session_batch51');
const batch93=require('../src/core/finals_analyzer_batch93');

function qualityFixture(){
  return {
    schema:'newcyber.sca-quality-diagnostics.v1',observationalOnly:true,
    policy:{mayUpgradeResult:false,leakageR2Threshold:0.99,contextualCosineThreshold:0.99},
    guardBaseline:{status:'proven',enabled:true,mode:'edge-mean',leading:2,trailing:2,subtract:'feature-windows',evidence:['guard-mean:baseline']},
    leakageGroups:{status:'observed',threshold:0.99,totalGroups:3,count:3,minR2:0.982,meanR2:0.993666,maxR2:0.999,invalidGroups:0,anomalousGroups:[{group:1,r2:0.982,gapToThreshold:0.008,reason:'below-threshold'}]},
    probeCalibration:{status:'accepted',accepted:true,mode:'sampled-global-ridge-hidden-to-wte',coverage:1,trainingRows:80,validationRows:16,lambda:1,cosineGain:0.031,evaluation:{rawCosine:0.91,calibratedCosine:0.941,rawMse:0.08,calibratedMse:0.04},rerank:null},
    contextual:{status:'observed',threshold:0.99,oracleThreshold:0.985,thresholdDrift:-0.005,count:3,reported:3,passed:2,failed:1,minCosine:0.981,meanCosine:0.992,maxCosine:0.999,positions:[{index:0,status:'matched',mode:'shortlist',tokenId:11,cosine:0.999,gapToThreshold:-0.009,passes:true},{index:1,status:'matched',mode:'full-vocab-fallback',tokenId:22,cosine:0.981,gapToThreshold:0.009,passes:false},{index:2,status:'matched',mode:'shortlist',tokenId:33,cosine:0.996,gapToThreshold:-0.006,passes:true}]}
  };
}
function analysisFixture(){return {scaAutopilot:{status:'flag-candidate',result:{status:'flag-candidate',flag:null,flagCandidate:'flag{candidate_only}',diagnostics:{scaQuality:qualityFixture()}}}};}

test('Batch93 Challenge Session surfaces SCA diagnostics without upgrading result semantics',()=>{
  const analysis=analysisFixture();
  const summary=summarizeScaQuality(analysis.scaAutopilot.result);
  assert.equal(summary.observationalOnly,true);
  assert.equal(summary.mayUpgradeResult,false);
  assert.equal(summary.groupAnomalies,1);
  assert.equal(summary.contextualFailures,1);
  const session={status:'candidate',result:{value:'flag{candidate_only}',verified:false,confidence:'candidate'},solverLedger:[],facts:[],stats:{}};
  attachScaQualitySession(session,analysis);
  assert.equal(session.status,'candidate');
  assert.equal(session.result.verified,false);
  assert.equal(session.scaQualityDiagnostics.observationalOnly,true);
  assert.equal(session.scaQualityDiagnostics.summary.groupMinR2,0.982);
  assert.ok(session.solverLedger.some((item)=>item.id==='sca-quality-diagnostics'&&item.confidence==='diagnostic'&&item.observationalOnly===true));
  assert.ok(session.facts.some((item)=>item.label==='SCA 质量诊断'));
});

test('Batch93 markdown report pinpoints low-R2 groups and contextual failures',()=>{
  const section=batch93.buildScaQualitySection(analysisFixture());
  assert.match(section,/Batch93 · Power SCA Quality Diagnostics/);
  assert.match(section,/low-R² groups: g1: r2=0\.982000 gap=0\.008000/);
  assert.match(section,/contextual failures: #1: cos=0\.981000 gap=0\.009000/);
  assert.match(section,/observationalOnly=true/);
  assert.match(section,/mayUpgradeResult=false/);
});

test('Batch93 Power SCA renderer compiles and exposes quality hotspot surfaces',()=>{
  const renderer=fs.readFileSync(path.join(__dirname,'..','renderer','sca_autopilot_tools.js'),'utf8');
  const css=fs.readFileSync(path.join(__dirname,'..','renderer','styles','sca_autopilot.css'),'utf8');
  assert.doesNotThrow(()=>new Function(renderer));
  assert.match(renderer,/QUALITY DIAGNOSTICS/);
  assert.match(renderer,/LOW R² GROUPS/);
  assert.match(renderer,/CONTEXTUAL FAILURES/);
  assert.match(renderer,/probe-calibration/);
  assert.match(renderer,/contextual-hidden-oracle/);
  assert.match(css,/sca-quality-panel/);
  assert.match(css,/sca-quality-table/);
});

test('Batch93 compatibility analyzer routes to the diagnostics report wrapper while retaining Batch91 marker',()=>{
  const source=fs.readFileSync(path.join(__dirname,'..','src','core','finals_analyzer_batch15.js'),'utf8');
  assert.match(source,/finals_analyzer_batch91/);
  assert.match(source,/finals_analyzer_batch93/);
});
