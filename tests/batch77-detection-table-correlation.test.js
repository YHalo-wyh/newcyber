'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const {
  tableProfile,
  correlationCandidate,
  runDetectionTableCorrelation
}=require('../src/core/ai_detection_table_correlation');
const {runAiDetectionBundleAutopilot}=require('../src/core/ai_detection_bundle_autopilot');

test('Batch77 profiles ground-truth and prediction tables by headers and filename evidence',()=>{
  const truth=tableProfile('ground_truth.csv',[{File:'a.jpg',Label:1},{File:'b.jpg',Label:0},{File:'c.jpg',Label:1},{File:'d.jpg',Label:0}]);
  const pred=tableProfile('result.csv',[{File:'a.jpg',Value:1},{File:'b.jpg',Value:0},{File:'c.jpg',Value:1},{File:'d.jpg',Value:0}]);
  assert.equal(truth.role,'truth');
  assert.equal(pred.role,'prediction');
  assert.ok(truth.roleScore>=2);
  assert.ok(pred.roleScore>=2);
});

test('Batch77 correlates split tables by stable sample ID rather than row order',()=>{
  const truth=tableProfile('labels.csv',[
    {File:'a.jpg',Label:1},{File:'b.jpg',Label:0},{File:'c.jpg',Label:1},{File:'d.jpg',Label:0}
  ]);
  const pred=tableProfile('submission.csv',[
    {File:'d.jpg',Value:0},{File:'b.jpg',Value:0},{File:'a.jpg',Value:1},{File:'c.jpg',Value:1}
  ]);
  const pair=correlationCandidate(truth,pred);
  assert.ok(pair);
  assert.equal(pair.matchedRows,4);
  assert.equal(pair.coverage,1);
  assert.equal(pair.result.metrics.accuracy,1);
});

test('Batch77 rejects weak filename roles instead of guessing table semantics',()=>{
  const truth=tableProfile('data1.csv',[{File:'a',Label:1},{File:'b',Label:0},{File:'c',Label:1},{File:'d',Label:0}]);
  const pred=tableProfile('data2.csv',[{File:'a',Value:1},{File:'b',Value:0},{File:'c',Value:1},{File:'d',Value:0}]);
  assert.equal(correlationCandidate(truth,pred),null);
});

test('Batch77 rejects duplicate IDs to avoid ambiguous joins',()=>{
  const truth=tableProfile('labels.csv',[{File:'a',Label:1},{File:'a',Label:0},{File:'b',Label:0},{File:'c',Label:1},{File:'d',Label:0}]);
  const pred=tableProfile('result.csv',[{File:'a',Value:1},{File:'b',Value:0},{File:'c',Value:1},{File:'d',Value:0}]);
  assert.ok(truth.duplicates>0);
  assert.equal(correlationCandidate(truth,pred),null);
});

test('Batch77 automatically scores separate labels.csv and result.csv in a challenge bundle',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b77-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  await fs.writeFile(path.join(root,'ground_truth.csv'),[
    'File,Label','a.jpg,1','b.jpg,1','c.jpg,1','d.jpg,1','e.jpg,0','f.jpg,0','g.jpg,0','h.jpg,0'
  ].join('\n'));
  await fs.writeFile(path.join(root,'result.csv'),[
    'File,Value','h.jpg,0','a.jpg,1','e.jpg,0','b.jpg,1','f.jpg,0','c.jpg,1','g.jpg,0','d.jpg,1'
  ].join('\n'));
  const result=await runDetectionTableCorrelation(root);
  assert.equal(result.status,'evaluated');
  assert.equal(result.summary.correlations,1);
  assert.equal(result.correlations[0].result.metrics.accuracy,1);
  assert.ok(result.findings.some((x)=>x.id==='detection-split-table-correlated'));
});

test('Batch77 main detection autopilot merges split-table scoring into one result',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b77-main-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  await fs.writeFile(path.join(root,'labels.csv'),[
    'filename,label','1.jpg,1','2.jpg,1','3.jpg,0','4.jpg,0'
  ].join('\n'));
  await fs.writeFile(path.join(root,'predictions.csv'),[
    'filename,prediction','4.jpg,0','1.jpg,1','3.jpg,0','2.jpg,1'
  ].join('\n'));
  const result=await runAiDetectionBundleAutopilot(root,{});
  assert.equal(result.schema,'newcyber.ai-detection-bundle-autopilot.v2');
  assert.equal(result.status,'evaluated');
  assert.equal(result.summary.splitTableCorrelations,1);
  assert.ok(result.evaluations.some((x)=>x.kind==='split-table-correlation'));
  assert.equal(result.summary.effectiveCandidates,1);
});

test('Batch77 requires at least 80 percent ID coverage for split table joins',()=>{
  const truth=tableProfile('truth.csv',[{id:'a',truth:1},{id:'b',truth:0},{id:'c',truth:1},{id:'d',truth:0},{id:'e',truth:1}]);
  const pred=tableProfile('result.csv',[{id:'a',prediction:1},{id:'b',prediction:0},{id:'x',prediction:1},{id:'y',prediction:0},{id:'z',prediction:1}]);
  assert.equal(correlationCandidate(truth,pred),null);
});
