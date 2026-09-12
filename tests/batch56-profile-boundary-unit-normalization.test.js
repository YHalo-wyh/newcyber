'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  staticRowsPerTokenEvidence,
  staticProfilingRowCounts,
  reconstructProfilingSequences
}=require('../src/core/sca_contextual_profile_hidden');

function realAggregateSource(){
  const counts=Array(23).fill(11952).concat(12528);
  return `
HIDDEN_SIZE = 768
GROUP_SIZE = 16
PROFILING_ROW_COUNTS = [${counts.join(', ')}]
`;
}

test('Batch56 derives rowsPerToken=48 only from same-source static HIDDEN_SIZE/GROUP_SIZE evidence',()=>{
  const evidence=staticRowsPerTokenEvidence(realAggregateSource());
  assert.equal(evidence.status,'ok');
  assert.equal(evidence.hiddenSize,768);
  assert.equal(evidence.groupSize,16);
  assert.equal(evidence.rowsPerToken,48);
});

test('Batch56 real aggregate normalizes 287424 trace rows into exactly 5988 profiling tokens across 24 prompts',()=>{
  const boundary=staticProfilingRowCounts(realAggregateSource(),5988);
  assert.equal(boundary.status,'ok');
  assert.equal(boundary.unit,'trace-rows');
  assert.equal(boundary.boundaryNormalization,'trace-rows-to-token-counts');
  assert.equal(boundary.rawTotal,287424);
  assert.equal(boundary.total,5988);
  assert.equal(boundary.rowsPerToken,48);
  assert.equal(boundary.prompts,24);
  assert.equal(boundary.counts[0],249);
  assert.equal(boundary.counts.at(-1),261);
  assert.equal(boundary.counts.reduce((sum,value)=>sum+value,0),5988);
});

test('Batch56 real aggregate reconstructs 5988 singleton IDs into contextual prompt sequences after unit normalization',()=>{
  const singletonIds=Array.from({length:5988},(_,id)=>[id]);
  const rebuilt=reconstructProfilingSequences(singletonIds,realAggregateSource());
  assert.equal(rebuilt.status,'ok');
  assert.equal(rebuilt.sequences.length,24);
  assert.equal(rebuilt.sequences[0].length,249);
  assert.equal(rebuilt.sequences.at(-1).length,261);
  assert.equal(rebuilt.sequences.flat().length,5988);
  assert.equal(rebuilt.boundary.rawTotal,287424);
});

test('Batch56 preserves legacy token-count boundary semantics when direct sum already matches token count',()=>{
  const source=`HIDDEN_SIZE=768\nGROUP_SIZE=16\nPROFILING_ROW_COUNTS=[2,3,1]`;
  const boundary=staticProfilingRowCounts(source,6);
  assert.equal(boundary.status,'ok');
  assert.equal(boundary.unit,'tokens');
  assert.equal(boundary.rowsPerToken,1);
  assert.deepEqual(boundary.counts,[2,3,1]);
});

test('Batch56 fails closed when trace-row boundary cannot be proven divisible or unit evidence is ambiguous',()=>{
  const indivisible=staticProfilingRowCounts(`HIDDEN_SIZE=768\nGROUP_SIZE=16\nPROFILING_ROW_COUNTS=[97,191]`,6);
  assert.equal(indivisible.status,'gap');
  assert.equal(indivisible.code,'PROFILE_BOUNDARY_COUNT_GAP');
  assert.match(indivisible.detail,/not divisible by rowsPerToken=48/);

  const ambiguous=staticProfilingRowCounts(`HIDDEN_SIZE=768\nHIDDEN_DIM=1024\nGROUP_SIZE=16\nPROFILING_ROW_COUNTS=[96,192]`,6);
  assert.equal(ambiguous.status,'gap');
  assert.equal(ambiguous.code,'PROFILE_BOUNDARY_COUNT_GAP');
  assert.equal(ambiguous.unitEvidence.code,'PROFILE_BOUNDARY_UNIT_AMBIGUITY_GAP');
});