const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const { diagnoseAiSkillMatrix,detectKinds,normalizeBundle }=require('../src/core/ai_skill_matrix');
const { runTool }=require('../src/core/tool_router');

function skill(result,id) { return result.skills.find((x)=>x.id===id); }

test('AI stage-one matrix can close all five latest official directions with explicit evidence',()=>{
  const poisonRows=[];
  for(let i=0;i<5;i+=1)poisonRows.push({is_poison:0,original_label:0,label:0,text:`clean-${i}`});
  for(let i=0;i<5;i+=1)poisonRows.push({is_poison:1,original_label:i%2?2:0,label:1,target_label:1,trigger_id:'candidate-A',text:`poison-${i}`});
  const backdoorRows=[];
  for(let i=0;i<6;i+=1){const truth=i%2?2:0;backdoorRows.push({true_label:truth,clean_pred:truth,triggered_pred:1,control_pred:truth,target_label:1});}
  const result=diagnoseAiSkillMatrix({
    promptRun:{templateId:'direct-instruction-override',response:'TRAINING_OVERRIDE_ACCEPTED_7A41',toolCalls:[],authorizedTools:[]},
    adversarial:{original:[0,0.2,0.4],adversarial:[0.01,0.2,0.4],epsilon:0.03,norm:'linf',trueLabel:0,predictedOriginal:0,predictedAdversarial:1},
    privacy:{rows:[{member:1,loss:0.1},{member:1,loss:0.12},{member:1,loss:0.13},{member:0,loss:0.8},{member:0,loss:0.75},{member:0,loss:0.7}]},
    extraction:{holdoutFidelity:0.92,rows:[{query:'a',label:0,probabilities:[0.95,0.05]},{query:'b',label:1,probabilities:[0.08,0.92]},{query:'c',label:0,probabilities:[0.88,0.12]},{query:'d',label:1,probabilities:[0.15,0.85]}]},
    inversion:{rows:[{reference:[0.1,0.2,0.3],reconstructed:[0.11,0.19,0.31],probabilities:[0.8,0.2]}]},
    poisoning:{rows:poisonRows},
    backdoor:{targetLabel:1,rows:backdoorRows},
    supplyChain:'import torch\nmodel = torch.load(upload_path, weights_only=False)'
  });
  assert.equal(result.schema,'newcyber.ai-skill-matrix.v2');
  assert.equal(result.officialCoverage,5);
  assert.equal(result.summary.evidence,5);
  assert.deepEqual(result.officialDirections,['提示词工程与大模型安全','对抗样本攻击','模型隐私与数据泄露','模型后门与数据投毒','AI 基础设施与供应链安全']);
  assert.equal(skill(result,'prompt-llm-security').status,'evidence');
  assert.equal(skill(result,'adversarial-example').status,'evidence');
  assert.equal(skill(result,'privacy-leakage').status,'evidence');
  assert.equal(skill(result,'backdoor-poisoning').status,'evidence');
  assert.equal(skill(result,'infra-supply-chain').status,'evidence');
  assert.equal(skill(result,'privacy-leakage').metrics.holdoutFidelity,0.92);
  assert.equal(skill(result,'backdoor-poisoning').metrics.targetASR,1);
  assert.equal(skill(result,'backdoor-poisoning').metrics.controlTargetRate,0);
  assert.ok(skill(result,'infra-supply-chain').findings.some((x)=>x.id==='torch-load-weights-only-false'));
});

test('matrix keeps a high-ASR backdoor as candidate when control evidence is absent',()=>{
  const rows=[];for(let i=0;i<6;i+=1){const truth=i%2?2:0;rows.push({true_label:truth,clean_pred:truth,triggered_pred:1,target_label:1});}
  const result=diagnoseAiSkillMatrix({backdoor:{targetLabel:1,rows}});
  const direction=skill(result,'backdoor-poisoning');
  assert.equal(direction.status,'candidate');
  assert.equal(direction.metrics.targetASR,1);
  assert.equal(direction.metrics.controlTargetRate,null);
});

test('matrix auto-routes a single CSV dataset without fabricating unrelated evidence',()=>{
  const csv=['text,label',...Array.from({length:10},(_,i)=>`normal_${i},0`),'rare_trigger alpha,1','rare_trigger beta,1'].join('\n');
  const routed=normalizeBundle(csv);assert.deepEqual(routed.detections,['dataset']);
  const result=diagnoseAiSkillMatrix(csv);
  assert.equal(skill(result,'backdoor-poisoning').status,'candidate');
  assert.equal(skill(result,'prompt-llm-security').status,'data-needed');
  assert.equal(skill(result,'adversarial-example').status,'data-needed');
  assert.equal(skill(result,'privacy-leakage').status,'data-needed');
  assert.equal(skill(result,'infra-supply-chain').status,'data-needed');
  assert.ok(skill(result,'backdoor-poisoning').metrics.triggerCandidates>=1);
});

test('kind detector recognizes adversarial privacy extraction inversion backdoor and supply evidence',()=>{
  const kinds=detectKinds({original:[0],adversarial:[0.1],epsilon:0.2,member:1,loss:0.1,query:'x',probabilities:[0.1,0.9],reference:[0.1],reconstructed:[0.1],clean_pred:0,triggered_pred:1,control_pred:0,code:'torch.load(path, weights_only=False)'});
  for(const expected of ['adversarial','privacy','extraction','inversion','backdoor','supplyChain'])assert.ok(kinds.includes(expected),expected);
});

test('tool router exposes the five-direction AI skill matrix',()=>{
  const result=runTool('ai-skill-matrix',{input:JSON.stringify({adversarial:{original:[0],adversarial:[0.01],epsilon:0.1,trueLabel:0,predictedAdversarial:1}})});
  assert.equal(result.schema,'newcyber.ai-skill-matrix.v2');
  assert.equal(result.officialCoverage,5);
  assert.equal(skill(result,'adversarial-example').status,'evidence');
});

test('AI five-direction benchmark workbench compiles, avoids card soup, and loads dedicated CSS',()=>{
  const root=path.join(__dirname,'..');
  const source=fs.readFileSync(path.join(root,'renderer/ai_skill_matrix_tools.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'renderer/styles/ai_stage1_bench.css'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  assert.doesNotThrow(()=>new Function(source));
  assert.match(html,/ai_skill_matrix_tools\.js/);
  assert.match(html,/ai_stage1_bench\.css/);
  assert.match(source,/AI STAGE-ONE BENCH/);
  assert.match(source,/stage1-bench-grid/);
  assert.match(source,/data-stage1-regression/);
  assert.match(source,/TPR@0\.1FPR|competition/i);
  assert.doesNotMatch(source,/function skillCard/);
  assert.doesNotMatch(source,/<article class="panel">/);
  assert.match(css,/grid-template-columns:250px minmax\(420px,1fr\) 305px/);
  assert.match(css,/font-size:12\.5px/);
  assert.doesNotMatch(source,/AI 安全六考点矩阵/);
});
