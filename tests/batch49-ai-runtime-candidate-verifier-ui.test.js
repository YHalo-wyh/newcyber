'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

test('Batch49 runtime candidate verifier renderer compiles and keeps a dedicated bounded workbench',()=>{
  const source=read('renderer/ai_runtime_candidate_tools.js');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'renderer/ai_runtime_candidate_tools.js'}));
  for(const token of [
    'ai-backdoor-patch-runtime-verify',
    'RUNTIME BINDING',
    'ONNX model path',
    'Trigger source raster JSON',
    'Control patch JSON',
    'Clean sample bundle JSON',
    'Preprocessing JSON',
    'Runtime 闭环',
    'candidateId',
    'runtimeBindingId'
  ]) assert.match(source,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.match(source,/id="tool-input" class="surface-hidden-input"/);
  assert.match(source,/data-action="run-tool"/);
  assert.doesNotMatch(source,/\bfetch\s*\(|XMLHttpRequest|https?:\/\//i);
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