'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const {buildWorkOrder,buildTrainingWorkOrders,chooseFamilyThemes}=require('../src/core/ai_training_work_orders');
const {getTrainingCurriculum}=require('../src/core/ai_training_curriculum');
const {runTool}=require('../src/core/tool_router');

const root=path.join(__dirname,'..');

function task(overrides={}){
  return {
    rank:1,direction:'privacy-leakage',priority:'high',score:72,
    nextAction:'add-distinct-families',acquisitionMode:'new-family',
    targets:{newEvents:1,newFamilies:2,effectiveCaseDebt:2,provenanceAverageTarget:.65,unseenFamilyHoldout:1},
    ...overrides
  };
}

test('Batch99 turns scheduler task into evidence-first acquisition order',()=>{
  const order=buildWorkOrder(task(),[
    {direction:'privacy-leakage',event:'Existing Event',family:'membership-inference'}
  ]);
  assert.equal(order.id,'wo-01-privacy-leakage');
  assert.equal(order.direction,'privacy-leakage');
  assert.ok(order.acquisition.preferredSourceKinds.length>=2);
  assert.ok(order.acquisition.requiredEvidence.length>=3);
  assert.ok(order.regressionDesign.verifier.length>=3);
  assert.ok(order.prohibited.some((x)=>/real flags/i.test(x)));
  assert.ok(order.acceptanceGates.some((x)=>x.id==='negative-control'));
  assert.ok(order.acceptanceGates.some((x)=>x.id==='unseen-family-holdout'));
  assert.ok(order.acceptanceGates.some((x)=>x.id==='quality-recompute'));
});

test('Batch99 family themes prefer not-yet represented families',()=>{
  const themes=chooseFamilyThemes('privacy-leakage',[{family:'membership-inference'}],3);
  assert.equal(themes.length,3);
  assert.notEqual(themes[0],'membership-inference');
  assert.ok(themes.includes('sensitive-output-leakage')||themes.includes('model-inversion'));
});

test('Batch99 work-order list follows schedule order and limit',()=>{
  const schedule={queue:[
    task({rank:1,direction:'privacy-leakage',score:90,priority:'critical'}),
    task({rank:2,direction:'model-extraction',score:70}),
    task({rank:3,direction:'infra-supply-chain',score:50,priority:'medium'})
  ]};
  const result=buildTrainingWorkOrders({schedule,cases:[]},{limit:2});
  assert.equal(result.schema,'newcyber.ai-training-work-orders.v1');
  assert.equal(result.orders.length,2);
  assert.equal(result.orders[0].direction,'privacy-leakage');
  assert.equal(result.orders[1].direction,'model-extraction');
  assert.equal(result.summary.topDirection,'privacy-leakage');
});

test('Batch99 direction filter emits only requested work order',()=>{
  const schedule={queue:[task({rank:1,direction:'privacy-leakage'}),task({rank:2,direction:'model-extraction'})]};
  const result=buildTrainingWorkOrders({schedule,cases:[]},{direction:'model-extraction',limit:5});
  assert.equal(result.orders.length,1);
  assert.equal(result.orders[0].direction,'model-extraction');
});

test('Batch99 unified curriculum exposes work orders without schema break',()=>{
  const curriculum=getTrainingCurriculum();
  assert.equal(curriculum.schema,'newcyber.ai-training-curriculum.v1');
  assert.equal(curriculum.workOrders.schema,'newcyber.ai-training-work-orders.v1');
  assert.equal(curriculum.summary.workOrders.orders,curriculum.workOrders.summary.orders);
  assert.ok(curriculum.workOrders.orders.length>0);
  assert.equal(curriculum.workOrders.orders[0].direction,curriculum.schedule.queue[0].direction);
});

test('Batch99 tool router exposes configurable work orders',()=>{
  const result=runTool('ai-training-work-orders',{options:{limit:1}});
  assert.equal(result.schema,'newcyber.ai-training-work-orders.v1');
  assert.equal(result.orders.length,1);
  assert.ok(result.orders[0].acceptanceGates.length>=5);
});

test('Batch99 Stage-One UI renders acquisition order and policy gates',()=>{
  const js=fs.readFileSync(path.join(root,'renderer/ai_training_health_ui.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'renderer/styles/ai_training_health.css'),'utf8');
  assert.doesNotThrow(()=>new Function(js));
  assert.match(js,/ACQUISITION ORDER/);
  assert.match(js,/workOrderPanel/);
  assert.match(js,/候选新 family/);
  assert.match(js,/Verifier/);
  assert.match(js,/硬约束/);
  assert.match(css,/stage1-work-order/);
  assert.match(css,/stage1-work-order-gates/);
});
