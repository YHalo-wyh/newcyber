'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const {buildTrainingSchedule,priorityOf}=require('../src/core/ai_training_scheduler');
const {getTrainingCurriculum}=require('../src/core/ai_training_curriculum');
const {runTool}=require('../src/core/tool_router');

const root=path.join(__dirname,'..');

test('Batch98 prioritizes weak non-holdout directions above mature directions',()=>{
  const quality={byDirection:[
    {direction:'weak',readiness:'seed',qualityScore:.2,uniqueEvents:1,uniqueFamilies:1,effectiveCases:1,rawCases:8,provenanceAverage:.4,duplicateRatio:.5,recommendations:['add-distinct-families','add-cross-event-evidence']},
    {direction:'mature',readiness:'ready',qualityScore:.9,uniqueEvents:4,uniqueFamilies:4,effectiveCases:6,rawCases:6,provenanceAverage:.9,duplicateRatio:0,recommendations:[]}
  ]};
  const holdout={byDirection:[
    {direction:'weak',eligible:false,summary:{cleanPlans:0,unseenFamilyPlans:0}},
    {direction:'mature',eligible:true,summary:{cleanPlans:4,unseenFamilyPlans:2}}
  ]};
  const schedule=buildTrainingSchedule({cases:[],quality,holdout});
  assert.equal(schedule.schema,'newcyber.ai-training-schedule.v1');
  assert.equal(schedule.queue[0].direction,'weak');
  assert.ok(schedule.queue[0].score>schedule.queue[1].score);
  assert.equal(schedule.queue[0].acquisitionMode,'new-family');
  assert.equal(schedule.queue[0].targets.newEvents,2);
  assert.equal(schedule.queue[0].targets.newFamilies,2);
});

test('Batch98 adds unseen-family work when holdout exists but all families are already known',()=>{
  const quality={byDirection:[{direction:'privacy-leakage',readiness:'developing',qualityScore:.7,uniqueEvents:3,uniqueFamilies:3,effectiveCases:5,rawCases:5,provenanceAverage:.8,duplicateRatio:0,recommendations:[]}]};
  const holdout={byDirection:[{direction:'privacy-leakage',eligible:true,summary:{cleanPlans:3,unseenFamilyPlans:0}}]};
  const schedule=buildTrainingSchedule({quality,holdout});
  const row=schedule.queue[0];
  assert.equal(row.nextAction,'add-unseen-family-holdout');
  assert.equal(row.acquisitionMode,'unseen-family-stress');
  assert.equal(row.targets.unseenFamilyHoldout,1);
});

test('Batch98 priority bands are deterministic',()=>{
  assert.equal(priorityOf(85),'critical');
  assert.equal(priorityOf(65),'high');
  assert.equal(priorityOf(45),'medium');
  assert.equal(priorityOf(20),'low');
});

test('Batch98 unified curriculum exposes schedule without changing v1 schema',()=>{
  const curriculum=getTrainingCurriculum();
  assert.equal(curriculum.schema,'newcyber.ai-training-curriculum.v1');
  assert.equal(curriculum.schedule.schema,'newcyber.ai-training-schedule.v1');
  assert.equal(curriculum.summary.schedule.queued,curriculum.schedule.summary.queued);
  assert.ok(curriculum.schedule.queue.length>0);
  for(let i=1;i<curriculum.schedule.queue.length;i+=1)assert.ok(curriculum.schedule.queue[i-1].score>=curriculum.schedule.queue[i].score);
});

test('Batch98 tool router exposes schedule directly',()=>{
  const schedule=runTool('ai-training-schedule',{});
  assert.equal(schedule.schema,'newcyber.ai-training-schedule.v1');
  assert.ok(schedule.summary.topDirection);
});

test('Batch98 Stage-One UI renders next-round queue without replacing existing health panel',()=>{
  const js=fs.readFileSync(path.join(root,'renderer/ai_training_health_ui.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'renderer/styles/ai_training_health.css'),'utf8');
  assert.doesNotThrow(()=>new Function(js));
  assert.match(js,/NEXT ROUND/);
  assert.match(js,/下一轮训练调度/);
  assert.match(js,/schedulePanel/);
  assert.match(js,/stage1-schedule-item/);
  assert.match(css,/stage1-schedule/);
  assert.match(css,/stage1-schedule-item\.critical/);
  assert.match(js,/TRAINING HEALTH/);
});
