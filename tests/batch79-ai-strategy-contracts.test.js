'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const path=require('path');
const {fileFacts,buildAiStrategyPlan}=require('../src/core/ai_strategy_contracts');

test('Batch79 maps completed ONNX adversarial flow to closed/actionable strategy evidence',()=>{
  const analysis={
    files:[{path:'model.onnx'},{path:'12.npy'}],
    trainingFamilyMatch:{directionRanking:[{direction:'adversarial-example',score:18}]},
    onnxContestAutopilot:{status:'ranked',runs:12},
    aiContestAutopilot:{status:'ranked'}
  };
  const plan=buildAiStrategyPlan(analysis);
  assert.equal(plan.plans[0].direction,'adversarial-example');
  assert.ok(plan.plans[0].steps.some((x)=>x.id==='onnx-run'&&x.status==='completed'));
  assert.ok(plan.plans[0].steps.some((x)=>x.id==='contest-rank'&&x.status==='partial'));
});

test('Batch79 refuses image ONNX execution when preprocessing evidence is not closed',()=>{
  const analysis={
    files:[{path:'model.onnx'},{path:'images/1.png'}],
    trainingFamilyMatch:{directionRanking:[{direction:'adversarial-example',score:12}]},
    aiPreprocessingManifest:{status:'partial',executionReady:false}
  };
  const plan=buildAiStrategyPlan(analysis);
  const onnx=plan.plans[0].steps.find((x)=>x.id==='onnx-run');
  assert.equal(onnx.status,'blocked');
  assert.ok(onnx.missing.includes('evidence-backed preprocessing'));
});

test('Batch79 detection contract recognizes independently recomputed structured results',()=>{
  const analysis={
    files:[{path:'results.csv'}],
    trainingFamilyMatch:{directionRanking:[{direction:'backdoor-poisoning',score:14}]},
    aiDetectionAutopilot:{status:'evaluated',summary:{evaluations:2}}
  };
  const plan=buildAiStrategyPlan(analysis);
  assert.ok(plan.plans[0].steps.some((x)=>x.id==='detector-score'&&x.status==='completed'));
});

test('Batch79 supply-chain contract keeps pickle artifacts behind a guard',()=>{
  const analysis={
    files:[{path:'weights.pkl'}],
    trainingFamilyMatch:{directionRanking:[{direction:'infra-supply-chain',score:11}]}
  };
  const facts=fileFacts(analysis);assert.equal(facts.unsafeModel,true);
  const plan=buildAiStrategyPlan(analysis);
  assert.ok(plan.plans[0].steps.some((x)=>x.id==='deserialization-guard'&&x.status==='guarded'));
});

test('Batch79 prompt/agent direction explicitly requires authorized interactive context',()=>{
  const analysis={
    files:[{path:'agent.py'}],findings:[{id:'prompt-injection',title:'Prompt injection surface'}],
    trainingFamilyMatch:{directionRanking:[{direction:'prompt-llm-security',score:16}]}
  };
  const plan=buildAiStrategyPlan(analysis);
  const remote=plan.plans[0].steps.find((x)=>x.id==='interactive-probe');
  assert.equal(remote.status,'needs-input');
  assert.ok(remote.missing.includes('authorized endpoint/session context'));
});

test('Batch79 compatibility analyzer routes through Strategy Contracts',async()=>{
  const compat=await fs.readFile(path.join(__dirname,'../src/core/finals_analyzer_batch15.js'),'utf8');
  const wrapper=await fs.readFile(path.join(__dirname,'../src/core/finals_analyzer_batch79.js'),'utf8');
  assert.match(compat,/finals_analyzer_batch79/);
  assert.match(wrapper,/buildAiStrategyPlan/);
  assert.match(wrapper,/aiStrategyPlan/);
  assert.match(wrapper,/AI Strategy Contract Plan/);
});