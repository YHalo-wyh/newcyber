'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const vm=require('vm');
const {strongScaEvidence,promoteWorkspaceScaResult}=require('../src/core/finals_analyzer_batch35');

test('Batch35 workspace only auto-routes strong SCA bundles, not arbitrary NPY plus ONNX',()=>{
  assert.equal(strongScaEvidence([{path:'data.npy',extension:'.npy'},{path:'model.onnx',extension:'.onnx'}]),false);
  assert.equal(strongScaEvidence([{path:'profiling_power.npy',extension:'.npy'},{path:'probe.npy',extension:'.npy'},{path:'side_channel_template.py',extension:'.py'}]),true);
  assert.equal(strongScaEvidence([{path:'newcyber_sca.json',extension:'.json'}]),true);
});

test('Batch35 workspace promotes only oracle-verified SCA flags and keeps gaps actionable',()=>{
  const analysis={autopilot:{automaticChecks:[],actions:[],summary:{}},candidates:{flags:[]},insights:[]};
  analysis.scaAutopilot={status:'flag-recovered',result:{status:'flag-recovered',flag:'flag{verified_chain}',stages:[{id:'probe',status:'ok'},{id:'oracle',status:'ok'}],profile:{status:'ok',rows:40,hiddenDim:9,leakageDim:7,method:'ridge-dual-cholesky'},target:{rows:20},oracle:{status:'flag-recovered',cacheUsed:true},discovery:{manifestFile:{fileName:'sca_recipe.json'}}}};
  promoteWorkspaceScaResult(analysis);
  assert.equal(analysis.candidates.flags[0].value,'flag{verified_chain}');
  assert.equal(analysis.candidates.flags[0].confidence,'verified');
  assert.equal(analysis.autopilot.actions[0].level,'win');

  const gapAnalysis={autopilot:{automaticChecks:[],actions:[],summary:{}},candidates:{flags:[]},scaAutopilot:{status:'gap',result:{status:'gap',gap:{code:'PROBE_ORIENTATION_GAP',detail:'square probe'},stages:[{id:'probe',status:'gap'}]}}};
  promoteWorkspaceScaResult(gapAnalysis);
  assert.equal(gapAnalysis.candidates.flags.length,0);
  assert.match(gapAnalysis.autopilot.actions[0].title,/PROBE_ORIENTATION_GAP/);
});

test('Batch35 dedicated SCA autopilot renderer compiles and uses a directory action instead of generic payload textarea',()=>{
  const renderer=fs.readFileSync(path.join(__dirname,'..','renderer','sca_autopilot_tools.js'),'utf8');
  const preload=fs.readFileSync(path.join(__dirname,'..','preload.js'),'utf8');
  const html=fs.readFileSync(path.join(__dirname,'..','renderer','toolbox.html'),'utf8');
  new vm.Script(renderer);
  assert.match(renderer,/Power SCA Autopilot/);
  assert.match(renderer,/ARTIFACT RECIPE/);
  assert.match(renderer,/PIPELINE/);
  assert.match(renderer,/chooseAndRunScaAutopilot/);
  assert.doesNotMatch(renderer,/placeholder=.*JSON|generic textarea/i);
  assert.match(preload,/ai:sca-autopilot-choose/);
  assert.match(html,/styles\/sca_autopilot\.css/);
  assert.ok(html.indexOf('ai_transformer_oracle_tools.js')<html.indexOf('sca_autopilot_tools.js'));
});

test('Batch35 compatibility entrypoint targets the latest workspace wrapper',()=>{
  const entry=fs.readFileSync(path.join(__dirname,'..','src','core','finals_analyzer_batch15.js'),'utf8');
  assert.match(entry,/finals_analyzer_batch35/);
});
