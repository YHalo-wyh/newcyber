'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const {buildSolverPipeline}=require('../src/core/solver_pipeline');
const batch40=require('../src/core/finals_analyzer_batch40');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

function base(overrides={}){
  return {
    files:[{path:'challenge.txt',extension:'.txt',size:64,metadata:{}}],
    findings:[],candidates:{flags:[]},
    autopilot:{track:null,automaticChecks:[],actions:[],artifacts:[],flags:[],summary:{automaticCheckHits:0}},
    ...overrides
  };
}

test('Batch40 solver pipeline keeps unsupported templates skipped instead of pretending they ran',()=>{
  const pipeline=buildSolverPipeline(base());
  assert.equal(pipeline.nodes.find((x)=>x.id==='decode').state,'skipped');
  assert.equal(pipeline.nodes.find((x)=>x.id==='reverse').state,'skipped');
  assert.equal(pipeline.nodes.find((x)=>x.id==='traffic').state,'skipped');
  assert.equal(pipeline.nodes.find((x)=>x.id==='verify').state,'ready');
});

test('Batch40 raw binary evidence makes reverse solver READY when relationship analysis has not run yet',()=>{
  const pipeline=buildSolverPipeline(base({files:[{path:'chall.elf',extension:'.elf',size:4096,type:'ELF64',metadata:{}}]}));
  const reverse=pipeline.nodes.find((x)=>x.id==='reverse');
  assert.equal(reverse.state,'ready');
  assert.match(reverse.detail,/静态关系恢复/);
});

test('Batch40 explicit SCA capability gap is BLOCKED and becomes the active solver node',()=>{
  const analysis=base({
    files:[{path:'trace.npy',extension:'.npy',size:1024,metadata:{model:{}}}],
    autopilot:{track:{id:'ai',title:'人工智能安全',score:20},automaticChecks:[{id:'ai-model',title:'AI 模型/源码安全审计',hits:1}],actions:[],artifacts:[],flags:[],summary:{automaticCheckHits:1}},
    scaAutopilot:{status:'gap',result:{status:'gap',gap:{code:'MODEL_RUNTIME_GAP',detail:'onnxruntime unavailable'}}}
  });
  const pipeline=buildSolverPipeline(analysis);
  const sca=pipeline.nodes.find((x)=>x.id==='sca');
  assert.equal(sca.state,'blocked');
  assert.equal(pipeline.activeNodeId,'sca');
});

test('Batch40 verified result closes verifier and does not add handoff node',()=>{
  const pipeline=buildSolverPipeline(base({candidates:{flags:[{value:'flag{ok}',confidence:'verified'}]}}));
  assert.equal(pipeline.nodes.find((x)=>x.id==='verify').state,'done');
  assert.equal(pipeline.nodes.some((x)=>x.id==='handoff'),false);
});

test('Batch40 renderer is a tree timeline inspector desk instead of a primary card grid',()=>{
  const js=read('renderer/challenge_session_batch40.js');
  const css=read('renderer/styles/challenge_session_batch40.css');
  const html=read('renderer/toolbox.html');
  assert.doesNotThrow(()=>new vm.Script(js,{filename:'challenge_session_batch40.js'}));
  for(const token of ['INPUT TREE','SOLVER TIMELINE','CONTEXT INSPECTOR','EVIDENCE DOCK','cs40-timeline','cs40-rail'])assert.match(js,new RegExp(token));
  assert.match(css,/\.cs40-desk\{display:grid/);
  assert.match(css,/\.cs40-dot/);
  assert.match(css,/background:transparent/);
  assert.match(css,/removes the card language/);
  assert.ok(html.indexOf('challenge_session_batch40.css')>html.indexOf('challenge_session_readability.css'));
  assert.ok(html.indexOf('challenge_session_batch40.js')>html.indexOf('challenge_session.js'));
});

test('Batch40 compatibility entry and report use newest solver pipeline wrapper',()=>{
  const entry=read('src/core/finals_analyzer_batch15.js');
  assert.match(entry,/finals_analyzer_batch40/);
  const analysis=base({workspaceName:'demo',solverPipeline:buildSolverPipeline(base())});
  const section=batch40.buildSolverPipelineSection(analysis);
  assert.match(section,/Solver Pipeline/);
  assert.match(section,/Execution Timeline/);
  assert.match(section,/SKIPPED/);
});
