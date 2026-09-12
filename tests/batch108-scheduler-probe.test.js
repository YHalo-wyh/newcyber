'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {getTrainingCurriculum}=require('../src/core/ai_training_curriculum');
test('Batch108 scheduler probe',()=>{
  const c=getTrainingCurriculum();
  console.log('BATCH108_SCHEDULE='+JSON.stringify(c.schedule.queue));
  console.log('BATCH108_WORKORDERS='+JSON.stringify(c.workOrders.orders));
  assert.ok(c.schedule.queue.length>0);
});
