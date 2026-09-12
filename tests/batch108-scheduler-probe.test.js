'use strict';
const test=require('node:test');
const {getTrainingCurriculum}=require('../src/core/ai_training_curriculum');
test('Batch108 scheduler probe',()=>{
  const c=getTrainingCurriculum();
  const probe={queue:(c.schedule?.queue||[]).slice(0,3),orders:(c.workOrders?.orders||[]).slice(0,3).map((o)=>({id:o.id,direction:o.direction,priority:o.priority,score:o.score,objective:o.objective,acquisition:o.acquisition}))};
  throw new Error('BATCH108_PROBE='+JSON.stringify(probe));
});
