'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const fsp=require('fs/promises');
const os=require('os');
const path=require('path');

const batch42=require('../src/core/sca_autopilot_batch42');
const batch50=require('../src/core/sca_autopilot_batch50');
const batch55=require('../src/core/sca_autopilot_batch55');
const {rerankCandidateShortlists}=require('../src/core/sca_probe_calibration');
const {scoreSourcePath,prioritizeScaPaths,inspectQualityIntent}=require('../src/core/sca_source_priority');

async function temp(){return fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b55-sca-'));}

test('Batch55 source priority puts solve_template/Hann evidence ahead of unrelated docs before the legacy 2MB source budget',()=>{
  const paths=[
    '/fixture/000_readme.md','/fixture/001_report.txt','/fixture/002_notes.json',
    '/fixture/zzz_solve_template.py','/fixture/profiling_power.npy','/fixture/target_power.npy'
  ];
  const ranked=prioritizeScaPaths(paths);
  assert.equal(path.basename(ranked[0]),'zzz_solve_template.py');
  assert.ok(scoreSourcePath('/fixture/solve_template.py')>scoreSourcePath('/fixture/000_readme.md'));
});

test('Batch55 quality intent recognizes Hann plus compact/group dimensions from the real-style solver source',async()=>{
  const dir=await temp();
  try{
    const noisy=path.join(dir,'000_readme.md');
    const solver=path.join(dir,'zzz_solve_template.py');
    await fsp.writeFile(noisy,'x'.repeat(256*1024));
    await fsp.writeFile(solver,`import numpy as np\nTRACE_DIM = 64\nGROUP_SIZE = 16\nSAMPLES_PER_TRACE = 8\nw = np.hanning(SAMPLES_PER_TRACE)\n`);
    const intent=await inspectQualityIntent([noisy,solver]);
    assert.equal(intent.strong,true);
    assert.equal(intent.state.hann,true);
    assert.equal(intent.state.compactFeature,true);
    assert.equal(intent.state.groupEvidence,true);
    assert.equal(intent.priorityPreview[0],'zzz_solve_template.py');
  }finally{await fsp.rm(dir,{recursive:true,force:true});}
});

test('Batch55 blocks silent legacy fallback when source already proves quality/Hann intent',async()=>{
  const dir=await temp();
  try{
    const solver=path.join(dir,'solve_template.py');
    await fsp.writeFile(solver,`import numpy as np\nTRACE_DIM=64\nGROUP_SIZE=16\nSAMPLES_PER_TRACE=8\nw=np.hanning(SAMPLES_PER_TRACE)\n`);
    const result=await batch55.runScaAutopilotPaths([solver]);
    assert.equal(result.status,'gap');
    assert.equal(result.gap.code,'QUALITY_ROUTE_DOWNGRADE_GAP');
    assert.equal(result.qualityRoute.rawDowngradeBlocked,true);
    assert.ok(result.stages.some((item)=>item.id==='engine-dispatch'&&item.status==='gap'));
  }finally{await fsp.rm(dir,{recursive:true,force:true});}
});

test('Batch55 actual full-probe telemetry survives rerank and is preferred over budget estimation',async()=>{
  const telemetrySink={schema:'newcyber.sca-calibrated-rerank-telemetry.v1',status:'not-run'};
  const project=(hidden)=>hidden.slice();
  project.rerankTelemetry=telemetrySink;
  const reranked=rerankCandidateShortlists({
    hiddenStates:[[1,1]],
    candidates:[[{tokenId:10,score:9}]],
    project,
    probeMatrix:[[0,0],[1,1]],
    probeOptions:{orientation:'candidate-rows',metric:'negative-l2',candidateIds:[10,20],topK:1}
  });
  assert.equal(reranked.status,'ok');
  assert.equal(telemetrySink.status,'ok');
  assert.equal(telemetrySink.fullScanAttemptedRows,1);
  assert.equal(telemetrySink.fullScanSucceededRows,1);
  assert.equal(telemetrySink.fullProbeExpandedRows,1);
  assert.equal(telemetrySink.fullProbeRecovered,1); // compatibility alias: expansion, not ground-truth recovery
  assert.equal(telemetrySink.top1ChangedRows,1);

  const surfaced=await batch55.fullProbeTelemetry({
    probeCalibration:{status:'accepted',rerankTelemetry:telemetrySink},
    target:{rows:1}
  });
  assert.equal(surfaced.actual,true);
  assert.equal(surfaced.estimated,false);
  assert.equal(surfaced.executed,true);
  assert.equal(surfaced.fullScanSucceededRows,1);
  assert.equal(surfaced.fullProbeExpandedRows,1);
  assert.equal(surfaced.top1ChangedRows,1);
});

test('Batch55 actual rerank telemetry never calls shortlist expansion a verified recovery',async()=>{
  const surfaced=await batch55.fullProbeTelemetry({
    probeCalibration:{status:'accepted',rerankTelemetry:{
      schema:'newcyber.sca-calibrated-rerank-telemetry.v1',status:'ok',rows:3,
      fullScanRows:2,fullScanAttemptedRows:2,fullScanSucceededRows:2,
      fullProbeExpandedRows:1,fullProbeRecovered:1,top1ChangedRows:1,
      fallbackRows:1,candidateCount:768,hiddenDim:768,workBudget:60000000,budgetLimited:true
    }},
    target:{rows:3}
  });
  assert.equal(surfaced.actual,true);
  assert.equal(surfaced.fullProbeExpandedRows,1);
  assert.equal(surfaced.legacyFullProbeRecovered,1);
  assert.equal(Object.hasOwn(surfaced,'verifiedRecoveredRows'),false);
});

test('Batch55 production compatibility upgrades every historical Batch42/Batch50 caller to the same gated dispatcher',()=>{
  assert.equal(batch42.runScaAutopilotPaths,batch50.runScaAutopilotPaths);
  assert.equal(batch50.runScaAutopilotPaths,batch55.runScaAutopilotPaths);
  assert.notEqual(batch55.runScaAutopilotPaths,batch55.runQualityGroupedScaAutopilotPaths);
  const b42=fs.readFileSync(require.resolve('../src/core/sca_autopilot_batch42'),'utf8');
  const b50=fs.readFileSync(require.resolve('../src/core/sca_autopilot_batch50'),'utf8');
  assert.match(b42,/sca_autopilot_batch50/);
  assert.match(b50,/sca_autopilot_batch55/);
});