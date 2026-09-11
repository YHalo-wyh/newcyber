'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const {
  parseDelimited,
  binaryCandidate,
  lossHistoryCandidate,
  runAiDetectionBundleAutopilot
}=require('../src/core/ai_detection_bundle_autopilot');

test('Batch76 parses quoted CSV result rows deterministically',()=>{
  const rows=parseDelimited('filename,truth,prediction,note\n"a,1.jpg",1,1,"quoted, note"\nb.jpg,0,0,ok\n');
  assert.equal(rows.length,2);
  assert.equal(rows[0].filename,'a,1.jpg');
  assert.equal(rows[0].note,'quoted, note');
});

test('Batch76 refuses to guess a score threshold',()=>{
  const rows=[
    {file:'a',truth:1,score:0.9},{file:'b',truth:1,score:0.8},{file:'c',truth:0,score:0.2},{file:'d',truth:0,score:0.1}
  ];
  const result=binaryCandidate(rows);
  assert.equal(result.kind,'binary-gap');
  assert.equal(result.reason,'score-without-explicit-threshold');
});

test('Batch76 accepts an explicit score threshold from JSON container',()=>{
  const rows=[
    {file:'a',truth:1,score:0.9},{file:'b',truth:1,score:0.8},{file:'c',truth:0,score:0.2},{file:'d',truth:0,score:0.1}
  ];
  const result=binaryCandidate(rows,{threshold:0.5,rows});
  assert.equal(result.kind,'binary');
  assert.equal(result.threshold,0.5);
  assert.match(result.thresholdSource,/container/);
});

test('Batch76 keeps loss-history as ranking only when threshold ratio is absent',()=>{
  const rows=[
    {file:'c1',loss_0:0.8,loss_1:0.75,loss_2:0.72},
    {file:'p1',loss_0:0.4,loss_1:1.5,loss_2:0.3},
    {file:'c2',loss_0:0.7,loss_1:0.68,loss_2:0.66},
    {file:'c3',loss_0:0.9,loss_1:0.87,loss_2:0.84}
  ];
  const result=lossHistoryCandidate(rows);
  assert.equal(result.kind,'loss-history-ranking');
  assert.equal(result.ranking[0].id,'p1');
  assert.equal(result.reason,'threshold-ratio-not-evidenced');
});

test('Batch76 evaluates prediction CSV dropped into a challenge directory',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b76-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  await fs.writeFile(path.join(root,'result.csv'),[
    'File,truth,prediction',
    'a.jpg,1,1','b.jpg,1,1','c.jpg,1,1','d.jpg,1,1',
    'e.jpg,0,0','f.jpg,0,0','g.jpg,0,0','h.jpg,0,0'
  ].join('\n'));
  const result=await runAiDetectionBundleAutopilot(root,{});
  assert.equal(result.status,'evaluated');
  assert.equal(result.summary.binaryRuns,1);
  assert.equal(result.summary.effectiveCandidates,1);
  assert.equal(result.evaluations[0].result.metrics.accuracy,1);
  assert.ok(result.findings.some((x)=>x.id==='binary-detection-effective-candidate'));
});

test('Batch76 evaluates JSON score rows only with an explicit threshold',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b76-json-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  await fs.writeFile(path.join(root,'scores.json'),JSON.stringify({threshold:0.5,rows:[
    {id:'a',truth:1,score:0.91},{id:'b',truth:1,score:0.82},{id:'c',truth:0,score:0.11},{id:'d',truth:0,score:0.08}
  ]}));
  const result=await runAiDetectionBundleAutopilot(root,{});
  assert.equal(result.status,'evaluated');
  assert.equal(result.evaluations[0].threshold,0.5);
  assert.equal(result.evaluations[0].result.verdict,'candidate-effective');
});

test('Batch76 loss-history JSON uses explicit threshold_ratio and validates supplied truth',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b76-loss-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const rows=[
    {id:'c1',truth:0,losses:[0.82,0.78,0.75,0.73]},
    {id:'p1',truth:1,losses:[0.40,1.35,0.32,1.48]},
    {id:'c2',truth:0,losses:[0.76,0.73,0.71,0.69]},
    {id:'c3',truth:0,losses:[0.91,0.87,0.84,0.82]},
    {id:'p2',truth:1,losses:[0.52,1.62,0.41,1.70]},
    {id:'c4',truth:0,losses:[0.67,0.64,0.62,0.61]},
    {id:'c5',truth:0,losses:[0.88,0.85,0.82,0.80]},
    {id:'c6',truth:0,losses:[0.72,0.70,0.68,0.67]}
  ];
  await fs.writeFile(path.join(root,'loss_history.json'),JSON.stringify({threshold_ratio:0.25,rows}));
  const result=await runAiDetectionBundleAutopilot(root,{});
  const loss=result.evaluations.find((x)=>x.kind==='loss-history-poison');
  assert.ok(loss);
  assert.equal(loss.result.validation.exact,true);
  assert.deepEqual(new Set(loss.result.selectedIds),new Set(['p1','p2']));
});

test('Batch76 skips generated NewCyber manifests to avoid self-feedback',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b76-skip-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  await fs.writeFile(path.join(root,'newcyber_fake.json'),JSON.stringify({rows:[{truth:1,prediction:1},{truth:1,prediction:1},{truth:0,prediction:0},{truth:0,prediction:0}]}));
  const result=await runAiDetectionBundleAutopilot(root,{});
  assert.equal(result.status,'not-applicable');
  assert.equal(result.summary.structuredFiles,0);
});

test('Batch76 Challenge Session IPC wires detection autopilot and manifest',async()=>{
  const source=await fs.readFile(path.join(__dirname,'../src/electron/challenge_session_ipc.js'),'utf8');
  assert.match(source,/runAiDetectionBundleAutopilot/);
  assert.match(source,/newcyber_detection_autopilot\.json/);
  assert.match(source,/ai-detection-bundle-autopilot/);
  assert.match(source,/aiDetectionAutopilot/);
});
