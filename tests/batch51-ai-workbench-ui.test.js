'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

test('Batch51 AI challenge workbench compiles and exposes three production tools',()=>{
  const source=read('renderer/ai_batch51_tools.js');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'renderer/ai_batch51_tools.js'}));
  for(const token of ['ai-transform-exfiltration','ai-torchscript-side-effect','ai-batch51-pressure-regression','OFFLINE · BOUNDED · FAIL CLOSED','64 + 64 CASES','weights_only=True']){
    assert.ok(source.includes(token),token);
  }
  assert.doesNotMatch(source,/\bfetch\s*\(|XMLHttpRequest|https?:\/\//i);
  assert.match(source,/id="tool-input" class="surface-hidden-input"/);
  assert.match(source,/data-action="run-tool"/);
});

test('Batch51 workbench is loaded after candidate/runtime surfaces and before sample forensics',()=>{
  const html=read('renderer/toolbox.html');
  const name='ai_batch51_tools.js';
  assert.ok(html.indexOf(name)>html.indexOf('ai_runtime_candidate_tools.js'));
  assert.ok(html.indexOf(name)<html.indexOf('ai_sample_forensics_tools.js'));
});

test('Batch51 Tool Router keeps its analyzers while allowing Batch51-or-newer real-corpus wrapper',()=>{
  const router=read('src/core/tool_router.js');
  assert.match(router,/ai_real_ctf_regression_batch(?:51|5[2-9]|[6-9]\d)/);
  assert.match(router,/ai-transform-exfiltration/);
  assert.match(router,/ai-torchscript-side-effect/);
  assert.match(router,/ai-batch51-pressure-regression/);
});
