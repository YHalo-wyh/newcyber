'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {rerankCandidateShortlists,selectFullProbeRowIndices,MAX_CALIBRATED_SCORE_OPS}=require('../src/core/sca_probe_calibration');

function project(hidden){return [2*hidden[0]+0.5,0.5*hidden[1]-0.25];}

test('Batch50 calibrated full-probe scan can recover a true token omitted by the raw shortlist',()=>{
  const candidateIds=[10,20,30,40,50];
  const probeMatrix=[
    [0,0],
    [1,1],
    [2.5,0.25], // exact calibrated embedding for hidden [1,1]
    [4,4],
    [-2,-2]
  ];
  const raw=[[{tokenId:10,score:9},{tokenId:20,score:8}]]; // true token 30 is absent
  const result=rerankCandidateShortlists({
    hiddenStates:[[1,1]],candidates:raw,project,probeMatrix,
    probeOptions:{orientation:'candidate-rows',metric:'negative-l2',candidateIds,topK:2}
  });
  assert.equal(result.status,'ok');
  assert.equal(result.fullScanRows,1);
  assert.equal(result.fullProbeRecovered,1);
  assert.equal(result.fullProbeExpandedRows,1);
  assert.equal(result.fullScanSucceededRows,1);
  assert.equal(result.candidates[0][0].tokenId,30);
});

test('Batch55 full-probe policy prioritizes unknown score then smallest relative margin deterministically',()=>{
  const rows=[
    [{tokenId:1,score:10},{tokenId:2,score:1}],
    [{tokenId:1,score:5},{tokenId:2,score:4.99}],
    [{tokenId:1,score:3}]
  ];
  assert.deepEqual(selectFullProbeRowIndices(rows,1),[2]);
  assert.deepEqual(selectFullProbeRowIndices(rows,2),[2,1]);
});

test('Batch55 uncertainty-first scan spends a one-row full-vocab budget on the ambiguous token, not the prefix row',()=>{
  const candidateIds=[10,20,30];
  const probeMatrix=[[0,0],[3,3],[1,1]];
  const result=rerankCandidateShortlists({
    hiddenStates:[[0,0],[1,1]],
    candidates:[
      [{tokenId:10,score:10},{tokenId:20,score:1}],
      [{tokenId:10,score:1},{tokenId:20,score:0.99}]
    ],
    project:(row)=>row,
    probeMatrix,
    probeOptions:{orientation:'candidate-rows',metric:'negative-l2',candidateIds,topK:2},
    options:{fullProbeRows:1}
  });
  assert.equal(result.selectionMode,'uncertainty-margin');
  assert.equal(result.fullScanRows,1);
  assert.equal(result.fullScanSucceededRows,1);
  assert.equal(result.candidates[0][0].tokenId,10); // confident row only gets cheap shortlist rerank
  assert.equal(result.candidates[1][0].tokenId,30); // ambiguous row gets the expensive full-vocab scan
  assert.equal(result.fullProbeExpandedRows,1);
});

test('Batch50 calibrated full-probe search remains operation-budget bounded',()=>{
  const candidateCount=1000,hiddenDim=100;
  const candidateIds=Array.from({length:candidateCount},(_,i)=>i);
  const probeMatrix=Array.from({length:candidateCount},()=>Array(hiddenDim).fill(0));
  const targetRows=1000;
  const hiddenStates=Array.from({length:targetRows},()=>Array(hiddenDim).fill(0));
  const candidates=Array.from({length:targetRows},()=>[{tokenId:0,score:1}]);
  const result=rerankCandidateShortlists({
    hiddenStates,candidates,project:(row)=>row,probeMatrix,
    probeOptions:{orientation:'candidate-rows',metric:'dot',candidateIds,topK:1}
  });
  assert.equal(result.status,'ok');
  assert.ok(result.fullScanRows*candidateCount*hiddenDim<=MAX_CALIBRATED_SCORE_OPS);
  assert.ok(result.fullScanRows<targetRows);
  assert.equal(result.fullScanAttemptedRows,result.fullScanRows);
});