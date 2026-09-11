'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {normalizeScoreSpace}=require('../src/core/challenge_score_space');

const index={classes:[{name:'cat',index:0},{name:'dog',index:1}]};

test('named hints and assigned labels map to ONNX output indices',()=>{
  const result=normalizeScoreSpace([['cat','dog']],[{id:7,assignedLabel:'dog',run:{}}],index);
  assert.equal(result.status,'ready');assert.deepEqual(result.hints,[[0,1]]);assert.equal(result.runs[0].assignedLabel,1);assert.equal(result.mapping.mode,'class-map-to-output-index');
});

test('numeric hints preserve index semantics',()=>{
  const result=normalizeScoreSpace([[0,1]],[{id:1,assignedLabel:'1',run:{}}],index);assert.equal(result.status,'ready');assert.deepEqual(result.hints,[[0,1]]);assert.equal(result.runs[0].assignedLabel,1);assert.equal(result.mapping.mode,'numeric-index');
});

test('unmapped named labels produce explicit gap',()=>{
  const result=normalizeScoreSpace([['cat','bird']],[{id:1,assignedLabel:'bird',run:{}}],index);assert.equal(result.status,'gap');assert.ok(result.unresolved.some((x)=>String(x.value)==='bird'));
});
