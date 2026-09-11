'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  SCA_QUALITY_THRESHOLD,guardBaselineDiagnostics,leakageGroupDiagnostics,
  probeCalibrationDiagnostics,contextualPositionDiagnostics,buildScaQualityDiagnostics
}=require('../src/core/sca_quality_diagnostics');
const {applyQualityResultGate}=require('../src/core/sca_quality_result_gate');

test('Batch92 guard-baseline diagnostics expose only proven bounded provenance',()=>{
  const result=guardBaselineDiagnostics({baselineGuard:{
    mode:'edge-mean',leading:2,trailing:2,subtract:'feature-windows',
    evidence:['guard-mean:baseline','guard-centered:centered','baseline-linear-sink:np.dot']
  }});
  assert.equal(result.status,'proven');
  assert.equal(result.enabled,true);
  assert.equal(result.mode,'edge-mean');
  assert.equal(result.leading,2);
  assert.equal(result.trailing,2);
  assert.equal(result.subtract,'feature-windows');
  assert.deepEqual(result.evidence,['guard-mean:baseline','guard-centered:centered','baseline-linear-sink:np.dot']);
  assert.equal(guardBaselineDiagnostics({}).status,'not-proven');
});

test('Batch92 leakage-group diagnostics use finite-only min mean max and flag anomalous groups',()=>{
  const result=leakageGroupDiagnostics({profiles:[
    {group:0,r2:0.995},{group:1,r2:0.98},{group:2,r2:null},{group:3,r2:1}
  ]});
  assert.equal(result.threshold,0.99);
  assert.equal(result.totalGroups,4);
  assert.equal(result.count,3);
  assert.equal(result.invalidGroups,1);
  assert.equal(result.minR2,0.98);
  assert.ok(Math.abs(result.meanR2-(0.995+0.98+1)/3)<1e-12);
  assert.equal(result.maxR2,1);
  assert.deepEqual(result.anomalousGroups.map((item)=>[item.group,item.reason]),[[1,'below-threshold'],[2,'non-finite-r2']]);
  assert.ok(Math.abs(result.anomalousGroups[0].gapToThreshold-0.01)<1e-12);
});

test('Batch92 probe-calibration diagnostics expose holdout calibration and rerank telemetry',()=>{
  const result=probeCalibrationDiagnostics({
    status:'accepted',mode:'sampled-global-ridge-hidden-to-wte',coverage:0.8,rows:100,trainingRows:80,validationRows:20,lambda:1,
    evaluation:{rawCosine:0.81,calibratedCosine:0.93,rawMse:0.2,calibratedMse:0.08},
    rerankTelemetry:{status:'ok',rows:8,fullScanAttemptedRows:3,fullScanSucceededRows:3,fullProbeExpandedRows:2,top1ChangedRows:1}
  },[{id:'probe-calibration',status:'ok',detail:'holdout accepted'}]);
  assert.equal(result.accepted,true);
  assert.equal(result.status,'accepted');
  assert.ok(Math.abs(result.cosineGain-0.12)<1e-12);
  assert.equal(result.evaluation.calibratedCosine,0.93);
  assert.equal(result.rerank.fullScanSucceededRows,3);
  assert.equal(result.rerank.top1ChangedRows,1);
});

test('Batch92 contextual diagnostics measure every reported position against fixed 0.99 policy',()=>{
  const result=contextualPositionDiagnostics({
    status:'decoded',threshold:0.98,
    positions:[
      {index:0,status:'matched',mode:'shortlist',tokenId:10,cosine:0.999},
      {index:1,status:'matched',mode:'full-vocab-fallback',tokenId:11,cosine:0.985},
      {index:2,status:'gap',mode:'shortlist',tokenId:12,cosine:null}
    ]
  });
  assert.equal(SCA_QUALITY_THRESHOLD,0.99);
  assert.equal(result.threshold,0.99);
  assert.equal(result.oracleThreshold,0.98);
  assert.ok(Math.abs(result.thresholdDrift+0.01)<1e-12);
  assert.equal(result.positions[0].passes,true);
  assert.ok(result.positions[0].gapToThreshold<0);
  assert.equal(result.positions[1].passes,false);
  assert.ok(Math.abs(result.positions[1].gapToThreshold-0.005)<1e-12);
  assert.equal(result.positions[2].passes,false);
  assert.equal(result.positions[2].gapToThreshold,null);
  assert.equal(result.passed,1);
  assert.equal(result.failed,2);
});

test('Batch92 diagnostics are observational and never upgrade an unsolved candidate',()=>{
  const input={
    schema:'newcyber.sca-autopilot.v4',status:'flag-candidate',flag:null,flagCandidate:'flag{candidate_only}',gap:null,
    stages:[{id:'probe-calibration',status:'ok',detail:'excellent holdout'}],
    featureRecipe:{source:'challenge-source',metric:'sum-squares',windowFunction:'hann',baselineGuard:{mode:'edge-mean',leading:2,trailing:2,subtract:'feature-windows',evidence:['guard-mean:baseline']}},
    profile:{status:'ok',r2:1,profiles:[{group:0,r2:1},{group:1,r2:0.9999}]},
    probeCalibration:{status:'accepted',mode:'sampled-global-ridge-hidden-to-wte',coverage:1,trainingRows:128,validationRows:32,lambda:1,evaluation:{rawCosine:0.9,calibratedCosine:0.999}},
    target:{rows:2},contextualHiddenOracle:null
  };
  const result=applyQualityResultGate(input);
  assert.equal(result.status,'flag-candidate');
  assert.equal(result.flag,null);
  assert.equal(result.flagCandidate,'flag{candidate_only}');
  assert.equal(result.verifiedRecovery,undefined);
  assert.equal(result.diagnostics.scaQuality.observationalOnly,true);
  assert.equal(result.diagnostics.scaQuality.policy.mayUpgradeResult,false);
  assert.equal(result.diagnostics.scaQuality.leakageGroups.meanR2,0.99995);
  assert.equal(result.diagnostics.scaQuality.probeCalibration.accepted,true);
});

test('Batch92 a leakage quality GAP stays GAP while diagnostics explain the weak groups',()=>{
  const recipe={source:'challenge-source',windowFunction:'hann',metric:'hann-dot',slots:4,evidence:['hann-dot-linear-amplitude','guard-framing']};
  const result=applyQualityResultGate({
    schema:'newcyber.sca-autopilot.v4',status:'flag-candidate',flag:null,flagCandidate:'flag{bad_fit}',stages:[],featureRecipe:recipe,
    profile:{status:'ok',r2:0.98,profiles:[{group:0,r2:0.999},{group:1,r2:0.961}]},target:{rows:2},recoveredTokenIds:[1,2]
  });
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'LEAKAGE_QUALITY_GAP');
  assert.equal(result.flag,null);
  assert.equal(result.flagCandidate,null);
  assert.equal(result.diagnostics.scaQuality.leakageGroups.anomalousGroups.length,1);
  assert.equal(result.diagnostics.scaQuality.leakageGroups.anomalousGroups[0].group,1);
});

test('Batch92 aggregate diagnostics preserve fixed policy metadata',()=>{
  const result=buildScaQualityDiagnostics({profile:{profiles:[]},featureRecipe:{},stages:[]});
  assert.equal(result.schema,'newcyber.sca-quality-diagnostics.v1');
  assert.equal(result.observationalOnly,true);
  assert.deepEqual(result.policy,{mayUpgradeResult:false,leakageR2Threshold:0.99,contextualCosineThreshold:0.99});
});
