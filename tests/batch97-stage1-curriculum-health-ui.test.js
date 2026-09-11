'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const root=path.join(__dirname,'..');

test('Batch97 stage-one bench loads curriculum health overlay after the base bench',()=>{
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  const base=html.indexOf('ai_skill_matrix_tools.js');
  const health=html.indexOf('ai_training_health_ui.js');
  assert.ok(base>=0);
  assert.ok(health>base);
  assert.match(html,/styles\/ai_training_health\.css/);
});

test('Batch97 curriculum health UI compiles and consumes Batch95 quality plus Batch96 holdout',()=>{
  const source=fs.readFileSync(path.join(root,'renderer/ai_training_health_ui.js'),'utf8');
  assert.doesNotThrow(()=>new Function(source));
  assert.match(source,/ai-training-curriculum/);
  assert.match(source,/curriculumResult\?\.quality\?\.byDirection/);
  assert.match(source,/curriculumResult\?\.holdout\?\.byDirection/);
  assert.match(source,/effectiveCases/);
  assert.match(source,/cleanPlans/);
  assert.match(source,/unseenFamilyPlans/);
  assert.match(source,/crossEventHoldoutReady/);
  assert.match(source,/门禁与实际 holdout 不一致/);
});

test('Batch97 maps seven curriculum tracks into the five official Stage-One directions without dropping auxiliary tracks',()=>{
  const source=fs.readFileSync(path.join(root,'renderer/ai_training_health_ui.js'),'utf8');
  for(const token of [
    "'prompt-llm-security':['prompt-llm-security']",
    "'adversarial-example':['adversarial-example']",
    "'privacy-leakage':['privacy-leakage','model-extraction']",
    "'backdoor-poisoning':['backdoor-poisoning','dataset-pipeline-security']",
    "'infra-supply-chain':['infra-supply-chain']"
  ]) assert.ok(source.includes(token),token);
  assert.match(source,/弱项 E\$\{row\.weakestEvents\} F\$\{row\.weakestFamilies\}/);
  assert.match(source,/有效\/原始/);
});

test('Batch97 health styling stays compact and responsive instead of introducing card soup',()=>{
  const css=fs.readFileSync(path.join(root,'renderer/styles/ai_training_health.css'),'utf8');
  for(const token of ['stage1-health-panel','stage1-health-summary','stage1-health-row','stage1-health-badge','stage1-health-gap'])assert.match(css,new RegExp(token));
  assert.match(css,/grid-template-columns:repeat\(4,minmax\(0,1fr\)\)/);
  assert.match(css,/@media\(max-width:760px\)/);
  assert.doesNotMatch(css,/border-radius:1[2-9]px/);
});