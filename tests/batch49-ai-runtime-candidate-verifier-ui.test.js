'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

const {runTool}=require('../src/core/tool_router');
const {runBackdoorPatchRuntimeVerification}=require('../src/core/ai_runtime_candidate_verification');

test('Batch49 runtime verifier requires explicit original-model evidence and preprocessing provenance',async()=>{
  const result=await runBackdoorPatchRuntimeVerification({
    candidate:{kind:'backdoor-patch',candidateId:'patch-deadbeef',bbox:{x:0,y:0,width:1,height:1},targetLabel:1},
    candidateId:'patch-deadbeef'
  });
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'ORIGINAL_RUNTIME_EVIDENCE_REQUIRED');
  assert.match(result.gap.detail,/modelPath|cleanSamples|triggerRaster|control/i);
});

test('Batch49 runtime verifier UI compiles and exposes object inputs instead of a generic prompt box',()=>{
  const source=read('renderer/ai_runtime_candidate_tools.js');
  assert.doesNotThrow(()=>new Function(source));
  for(const token of ['ai-backdoor-patch-runtime-verify','Candidate JSON','candidateId','ONNX model path','Trigger raster','Control patch','Clean samples','Preprocessing'])assert.ok(source.includes(token),token);
  assert.doesNotMatch(source,/placeholder=".*万能|任意 JSON/i);
});

test('Batch49 runtime verifier UI loads immediately after Batch48 candidate layer and before sample forensics',()=>{
  const html=read('renderer/toolbox.html');
  const runtime='ai_runtime_candidate_tools.js';
  assert.ok(html.indexOf(runtime)>html.indexOf('ai_candidate_verifier_tools.js'));
  assert.ok(html.indexOf(runtime)<html.indexOf('ai_sample_forensics_tools.js'));
});

test('Batch49 production router points real CTF regression to Batch49-or-newer wrapper and runtime verifier',()=>{
  const router=read('src/core/tool_router.js');
  assert.match(router,/ai_real_ctf_regression_batch(?:49|5\d|[6-9]\d)/);
  assert.match(router,/runBackdoorPatchRuntimeVerification/);
  assert.match(router,/ai-backdoor-patch-runtime-verify/);
});