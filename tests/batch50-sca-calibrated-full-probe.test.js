'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {rerankCandidateShortlists,MAX_CALIBRATED_SCORE_OPS}=require('../src/core/sca_probe_calibration');

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
  assert.equal(result.candidates[0][0].tokenId,30);
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
});
