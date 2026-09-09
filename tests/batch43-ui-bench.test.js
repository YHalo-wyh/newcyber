'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const root=path.join(__dirname,'..');

test('Batch43 stage-one bench uses rail/analysis/training layout instead of card dashboard',()=>{
  const js=fs.readFileSync(path.join(root,'renderer/ai_skill_matrix_tools.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'renderer/styles/ai_stage1_bench.css'),'utf8');
  assert.doesNotThrow(()=>new Function(js));
  for(const token of ['stage1-direction-pane','stage1-analysis-pane','stage1-training-pane','stage1-score-strip','data-stage1-regression'])assert.match(js,new RegExp(token));
  assert.doesNotMatch(js,/skillCard\s*\(/);
  assert.doesNotMatch(js,/domain-card|tool-card/);
  assert.match(css,/stage1-bench-grid/);
  assert.match(css,/border-right:1px solid/);
  assert.match(css,/font-size:12\.5px/);
  assert.doesNotMatch(css,/border-radius:1[2-9]px/);
});

test('Batch43 stage-one bench keeps candidate/evidence/data-gap states visually distinct without whole-card fills',()=>{
  const css=fs.readFileSync(path.join(root,'renderer/styles/ai_stage1_bench.css'),'utf8');
  for(const tone of ['stage1-status-dot.good','stage1-status-dot.warn','stage1-status-dot.gap'])assert.match(css,new RegExp(tone.replace('.','\\.')));
  assert.match(css,/stage1-state\.good/);
  assert.match(css,/stage1-state\.warn/);
  assert.match(css,/stage1-state\.gap/);
});
