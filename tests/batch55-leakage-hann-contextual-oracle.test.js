'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  hannWeight,sourceRecipe,transformRow
}=require('../src/core/sca_streaming_feature_source');
const {fitReferenceProbeCalibration}=require('../src/core/sca_reference_probe_calibration');
const {decodeWithHiddenRunner}=require('../src/core/sca_contextual_hidden_oracle');

function challengeSource(){
  return `
SAMPLES_PER_FEATURE = 8
GUARD_SAMPLES = 8
TRACE_DIM = 64
hann = np.hanning(SAMPLES_PER_FEATURE)
for f in range(TRACE_DIM):
    start = GUARD_SAMPLES + f * SAMPLES_PER_FEATURE
    feat[f] = np.dot(trace[start:start + SAMPLES_PER_FEATURE], hann)
`;
}

function guardedHannRow(amplitudes){
  const row=Array(528).fill(0);
  for(let slot=0;slot<64;slot++){
    const amp=Number(amplitudes[slot]||0);
    for(let sample=0;sample<8;sample++)row[8+slot*8+sample]=amp*hannWeight(sample,8);
  }
  return row;
}

test('Batch55 leakage source resolves 528 raw samples into 64 guarded Hann-dot slots',()=>{
  const recipe=sourceRecipe(challengeSource(),528);
  assert.ok(recipe);
  assert.equal(recipe.slots,64);
  assert.equal(recipe.windowSize,8);
  assert.equal(recipe.offset,8);
  assert.equal(recipe.metric,'hann-dot');
  assert.equal(recipe.windows.length,64);
  assert.equal(recipe.windows[0].offset,8);
  assert.equal(recipe.windows[63].offset,512);
  assert.equal(recipe.windows[63].offset+recipe.windows[63].length,520);
  assert.match(recipe.evidence.join(' '),/guard-framing/);
  assert.match(recipe.evidence.join(' '),/hann-dot-linear-amplitude/);
});

test('Batch55 hann-dot preserves linear leakage amplitude instead of squaring it',()=>{
  const recipe=sourceRecipe(challengeSource(),528);
  const a=Array.from({length:64},(_,index)=>(index+1)/17);
  const once=transformRow(guardedHannRow(a),recipe);
  const twice=transformRow(guardedHannRow(a.map((value)=>value*2)),recipe);
  assert.equal(once.length,64);
  for(let index=0;index<64;index++){
    assert.ok(Math.abs(twice[index]-2*once[index])<1e-10,`slot ${index} must scale linearly`);
  }
});

function makeDenseCalibrationFixture(){
  const dim=8;
  const rows=128;
  const hidden=[];
  const embeddings=[];
  const candidateIds=[];
  for(let index=0;index<rows;index++){
    const h=Array.from({length:dim},(_,d)=>Math.sin((index+1)*(d+1)*0.173)+Math.cos((index+3)*(d+2)*0.097));
    const e=Array(dim).fill(0);
    for(let out=0;out<dim;out++){
      let value=(out+1)*0.07;
      for(let input=0;input<dim;input++){
        const weight=((input*5+out*3)%11-5)/4+(input===((out+3)%dim)?1.7:0);
        value+=h[input]*weight;
      }
      e[out]=value;
    }
    hidden.push(h);embeddings.push(e);candidateIds.push(index);
  }
  return {
    hiddenStates:hidden,
    profileTokenSequences:candidateIds.map((id)=>[id]),
    probeMatrix:embeddings,
    probeOptions:{orientation:'candidate-rows',metric:'cosine',candidateIds,topK:16}
  };
}

test('Batch55 reference probe calibration fits one global hidden-to-WTE ridge with lambda 1',()=>{
  const fixture=makeDenseCalibrationFixture();
  const result=fitReferenceProbeCalibration({...fixture,options:{lambda:1,trainRows:96,validationRows:24,minCosineGain:-1}});
  assert.equal(result.status,'ok');
  assert.equal(result.summary.mode,'sampled-global-ridge-hidden-to-wte');
  assert.equal(result.summary.referenceStrategy,'phase2c-free');
  assert.equal(result.summary.lambda,1);
  assert.equal(result.summary.hiddenDim,8);
  assert.ok(result.summary.evaluation.calibratedCosine>0.98);
  assert.ok(result.summary.evaluation.calibratedMse<result.summary.evaluation.rawMse);
});

function basisHidden(tokenId,width=8){
  const out=Array(width).fill(0);
  out[Number(tokenId)%width]=1;
  return out;
}

function deterministicHiddenRunner(){
  const commits=[];
  return {
    maxBatchSize:4,
    async score({candidateTokenIds}){
      return {status:'ok',hiddenStates:candidateTokenIds.map((id)=>basisHidden(id))};
    },
    async commit({tokenId}){commits.push(tokenId);return {status:'ok'};},
    telemetry(){return {commits:commits.slice()};}
  };
}

test('Batch55 contextual hidden oracle accepts exact shortlist candidates token by token',async()=>{
  const truth=[2,4,1];
  const rows=[
    [{tokenId:2,score:10},{tokenId:3,score:9}],
    [{tokenId:4,score:10},{tokenId:5,score:9}],
    [{tokenId:1,score:10},{tokenId:6,score:9}]
  ];
  const result=await decodeWithHiddenRunner({
    targetHiddenStates:truth.map((id)=>basisHidden(id)),targetCandidates:rows,
    allCandidateIds:[1,2,3,4,5,6],tokenizer:{decode:(ids)=>ids.join(',')},cosineThreshold:0.99
  },deterministicHiddenRunner());
  assert.equal(result.status,'decoded');
  assert.deepEqual(result.recoveredTokenIds,truth);
  assert.equal(result.fallbackPositions,0);
  assert.ok(result.positions.every((item)=>item.cosine>=0.99));
});

test('Batch55 contextual hidden oracle full-vocab fallback recovers truth omitted from top-K',async()=>{
  const truth=[2,4,1];
  const rows=[
    [{tokenId:2,score:10},{tokenId:3,score:9}],
    [{tokenId:5,score:10},{tokenId:6,score:9}],
    [{tokenId:1,score:10},{tokenId:6,score:9}]
  ];
  const result=await decodeWithHiddenRunner({
    targetHiddenStates:truth.map((id)=>basisHidden(id)),targetCandidates:rows,
    allCandidateIds:[1,2,3,4,5,6],tokenizer:{decode:(ids)=>ids.join(',')},cosineThreshold:0.99,fullScan:true
  },deterministicHiddenRunner());
  assert.equal(result.status,'decoded');
  assert.deepEqual(result.recoveredTokenIds,truth);
  assert.equal(result.positions[1].mode,'full-vocab-fallback');
  assert.ok(result.fallbackPositions>=1);
  assert.ok(result.fullScanCandidates>=1);
});

test('Batch55 contextual hidden oracle fails closed when no candidate reaches cosine threshold',async()=>{
  const result=await decodeWithHiddenRunner({
    targetHiddenStates:[[0,0,0,0,0,0,0,1]],
    targetCandidates:[[{tokenId:1,score:2},{tokenId:2,score:1}]],
    allCandidateIds:[1,2,3,4],tokenizer:{decode:()=>''},cosineThreshold:0.99,fullScan:true
  },deterministicHiddenRunner());
  assert.equal(result.status,'gap');
  assert.equal(result.code,'CONTEXTUAL_HIDDEN_MATCH_GAP');
  assert.deepEqual(result.recoveredTokenIds,[]);
});
