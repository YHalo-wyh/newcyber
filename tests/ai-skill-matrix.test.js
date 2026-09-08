const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const { diagnoseAiSkillMatrix,detectKinds,normalizeBundle }=require('../src/core/ai_skill_matrix');
const { runTool }=require('../src/core/tool_router');

function skill(result,id) {
  return result.skills.find((x)=>x.id===id);
}

test('AI skill matrix can close all six official training points with explicit evidence',()=>{
  const poisonRows=[];
  for (let i=0;i<5;i+=1) poisonRows.push({is_poison:0,original_label:0,label:0,text:`clean-${i}`});
  for (let i=0;i<5;i+=1) poisonRows.push({is_poison:1,original_label:i%2?2:0,label:1,target_label:1,trigger_id:'candidate-A',text:`poison-${i}`});

  const backdoorRows=[];
  for (let i=0;i<6;i+=1) {
    const truth=i%2?2:0;
    backdoorRows.push({true_label:truth,clean_pred:truth,triggered_pred:1,control_pred:truth,target_label:1});
  }

  const result=diagnoseAiSkillMatrix({
    promptRun:{
      templateId:'direct-instruction-override',
      response:'TRAINING_OVERRIDE_ACCEPTED_7A41',
      toolCalls:[],
      authorizedTools:[]
    },
    adversarial:{
      original:[0,0.2,0.4],
      adversarial:[0.01,0.2,0.4],
      epsilon:0.03,
      norm:'linf',
      trueLabel:0,
      predictedOriginal:0,
      predictedAdversarial:1
    },
    poisoning:{rows:poisonRows},
    extraction:{
      holdoutFidelity:0.92,
      rows:[
        {query:'a',label:0,probabilities:[0.95,0.05]},
        {query:'b',label:1,probabilities:[0.08,0.92]},
        {query:'c',label:0,probabilities:[0.88,0.12]},
        {query:'d',label:1,probabilities:[0.15,0.85]}
      ]
    },
    inversion:{rows:[{reference:[0.1,0.2,0.3],reconstructed:[0.11,0.19,0.31],probabilities:[0.8,0.2]}]},
    backdoor:{targetLabel:1,rows:backdoorRows}
  });

  assert.equal(result.officialCoverage,6);
  assert.equal(result.summary.evidence,6);
  assert.equal(skill(result,'prompt-injection').status,'evidence');
  assert.equal(skill(result,'adversarial-example').status,'evidence');
  assert.equal(skill(result,'data-poisoning').status,'evidence');
  assert.equal(skill(result,'model-extraction').status,'evidence');
  assert.equal(skill(result,'model-inversion').status,'evidence');
  assert.equal(skill(result,'backdoor').status,'evidence');
  assert.equal(skill(result,'model-extraction').metrics.holdoutFidelity,0.92);
  assert.equal(skill(result,'backdoor').metrics.targetASR,1);
  assert.equal(skill(result,'backdoor').metrics.flipRate,1);
  assert.equal(skill(result,'backdoor').metrics.controlTargetRate,0);
  assert.equal(skill(result,'backdoor').metrics.triggerSpecificity,1);
  assert.ok(skill(result,'backdoor').findings.some((x)=>x.id==='backdoor-control-specificity'));
});

test('matrix keeps a high-ASR backdoor run as candidate when control evidence is absent',()=>{
  const rows=[];
  for (let i=0;i<6;i+=1) {
    const truth=i%2?2:0;
    rows.push({true_label:truth,clean_pred:truth,triggered_pred:1,target_label:1});
  }
  const result=diagnoseAiSkillMatrix({backdoor:{targetLabel:1,rows}});
  const backdoor=skill(result,'backdoor');
  assert.equal(backdoor.status,'candidate');
  assert.equal(backdoor.confidence,'high');
  assert.equal(backdoor.metrics.targetASR,1);
  assert.equal(backdoor.metrics.controlTargetRate,null);
});

test('matrix auto-routes a single CSV dataset and does not call unrelated analyzers',()=>{
  const csv=[
    'text,label',
    ...Array.from({length:10},(_,i)=>`normal_${i},0`),
    'rare_trigger alpha,1',
    'rare_trigger beta,1'
  ].join('\n');
  const routed=normalizeBundle(csv);
  assert.deepEqual(routed.detections,['dataset']);
  const result=diagnoseAiSkillMatrix(csv);
  assert.equal(skill(result,'data-poisoning').status,'candidate');
  assert.equal(skill(result,'prompt-injection').status,'data-needed');
  assert.equal(skill(result,'adversarial-example').status,'data-needed');
  assert.ok(skill(result,'data-poisoning').metrics.triggerCandidates>=1);
});

test('kind detector recognizes adversarial, extraction, inversion and backdoor evidence',()=>{
  const kinds=detectKinds({
    original:[0],adversarial:[0.1],epsilon:0.2,
    query:'x',probabilities:[0.1,0.9],
    reference:[0.1],reconstructed:[0.1],
    clean_pred:0,triggered_pred:1,control_pred:0
  });
  for (const expected of ['adversarial','extraction','inversion','backdoor']) assert.ok(kinds.includes(expected),expected);
});

test('tool router exposes the AI skill matrix',()=>{
  const result=runTool('ai-skill-matrix',{input:JSON.stringify({
    adversarial:{original:[0],adversarial:[0.01],epsilon:0.1,trueLabel:0,predictedAdversarial:1}
  })});
  assert.equal(result.schema,'newcyber.ai-skill-matrix.v1');
  assert.equal(skill(result,'adversarial-example').status,'evidence');
});

test('AI skill matrix renderer compiles and is loaded by toolbox',()=>{
  const root=path.join(__dirname,'..');
  const source=fs.readFileSync(path.join(root,'renderer/ai_skill_matrix_tools.js'),'utf8');
  assert.doesNotThrow(()=>new Function(source));
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  assert.match(html,/ai_skill_matrix_tools\.js/);
  assert.match(source,/AI 安全六考点矩阵/);
});
