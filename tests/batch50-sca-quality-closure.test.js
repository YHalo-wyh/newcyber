'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const {
  hannWeight,sourceRecipe,manifestRecipe,resolveGroupedFeatureRecipe,transformRow,wrapStreamingFeatureSource
}=require('../src/core/sca_streaming_feature_source');
const {fitProbeCalibration,rerankCandidateShortlists}=require('../src/core/sca_probe_calibration');
const {runUnknownPrefixOracle,agreement}=require('../src/core/sca_unknown_prefix_oracle');
const batch46=require('../src/core/sca_autopilot_batch46');
const batch50=require('../src/core/sca_autopilot_batch50');
const compat=require('../src/core/sca_autopilot_batch42');

function approx(actual,expected,tolerance=1e-8){assert.ok(Math.abs(actual-expected)<=tolerance,`${actual} != ${expected}`);}

function manualHannEnergy(values){
  return values.reduce((sum,value,index)=>{const weighted=value*hannWeight(index,values.length);return sum+weighted*weighted;},0);
}

test('Batch50 source recipe recovers Hann slot energy from challenge-source evidence',()=>{
  const source=`
WINDOW_SIZE = 8
FEATURE_SLOTS = 64
TRACE_DIM = 64
win = np.hanning(WINDOW_SIZE)
features = [np.sum((trace[i * WINDOW_SIZE:(i + 1) * WINDOW_SIZE] * win) ** 2) for i in range(FEATURE_SLOTS)]
`;
  const recipe=sourceRecipe(source,528);
  assert.ok(recipe);
  assert.equal(recipe.source,'challenge-source');
  assert.equal(recipe.windowFunction,'hann');
  assert.equal(recipe.windowSize,8);
  assert.equal(recipe.slots,64);
  assert.equal(recipe.windows.length,64);
  assert.equal(recipe.windows[0].offset,0);
  assert.equal(recipe.windows[63].offset,504);
  assert.equal(recipe.metric,'sum-squares');
});

test('Batch50 manifest recipe preserves explicit offset, window function and metric',()=>{
  const recipe=manifestRecipe({groupedFeatureRecipe:{windowSize:4,slots:3,offset:2,windowFunction:'hann',metric:'mean-square'}},20);
  assert.equal(recipe.source,'manifest-feature-recipe');
  assert.equal(recipe.windows.length,3);
  assert.deepEqual(recipe.windows.map((x)=>x.offset),[2,6,10]);
  assert.ok(recipe.windows.every((x)=>x.windowFunction==='hann'&&x.metric==='mean-square'));
});

test('Batch50 Hann transform matches direct weighted energy calculation',()=>{
  const recipe=manifestRecipe({groupedFeatureRecipe:{windowSize:8,slots:2,offset:0,windowFunction:'hann',metric:'sum-squares'}},16);
  const row=Array.from({length:16},(_,i)=>i+1);
  const feature=transformRow(row,recipe);
  approx(feature[0],manualHannEnergy(row.slice(0,8)));
  approx(feature[1],manualHannEnergy(row.slice(8,16)));
});

test('Batch50 streaming feature source handles the real 287424-row scale without materializing it',async()=>{
  const calls=[];
  let closed=false;
  const source={
    filePath:'/virtual/profile.npy',fileName:'profile.npy',sourceKind:'numeric',rows:287424,cols:16,segments:[],
    async readRows(start,count){calls.push({start,count});return Array.from({length:count},(_,r)=>Array.from({length:16},(_,c)=>start+r+c+1));},
    async close(){closed=true;}
  };
  const recipe=manifestRecipe({groupedFeatureRecipe:{windowSize:8,slots:2,windowFunction:'hann',metric:'sum-squares'}},16);
  const wrapped=wrapStreamingFeatureSource(source,recipe);
  assert.equal(wrapped.rows,287424);
  assert.equal(wrapped.cols,2);
  const rows=await wrapped.readRows(287400,3);
  assert.equal(rows.length,3);
  assert.equal(rows[0].length,2);
  assert.deepEqual(calls,[{start:287400,count:3}]);
  await wrapped.close();
  assert.equal(closed,true);
});

test('Batch50 refuses ambiguous Hann source evidence instead of guessing a recipe',()=>{
  const ambiguous=`
WINDOW_SIZE = 8
SLOT_SIZE = 16
FEATURE_SLOTS = 4
w = torch.hann_window(WINDOW_SIZE)
features = [sum((trace[i*WINDOW_SIZE:(i+1)*WINDOW_SIZE]*w)**2) for i in range(FEATURE_SLOTS)]
`;
  assert.equal(sourceRecipe(ambiguous,128),null);
  const resolved=resolveGroupedFeatureRecipe({manifest:{},sourceText:ambiguous},128);
  assert.equal(resolved.status,'missing');
});

test('Batch50 pressure corpus recovers 36 deterministic Hann recipe variants',()=>{
  const apis=['np.hanning','torch.hann_window','windows.hann'];
  const windowSizes=[4,8,16];
  const slots=[2,4];
  const offsets=[0,3];
  let passed=0;
  for(const api of apis)for(const windowSize of windowSizes)for(const slotCount of slots)for(const offset of offsets){
    const rawCols=offset+windowSize*slotCount+5;
    const source=`
WINDOW_SIZE = ${windowSize}
FEATURE_SLOTS = ${slotCount}
FEATURE_OFFSET = ${offset}
w = ${api}(WINDOW_SIZE)
features = [sum((trace[FEATURE_OFFSET + i*WINDOW_SIZE:FEATURE_OFFSET + (i+1)*WINDOW_SIZE] * w) ** 2) for i in range(FEATURE_SLOTS)]
`;
    const recipe=sourceRecipe(source,rawCols);
    assert.ok(recipe,`${api} size=${windowSize} slots=${slotCount} offset=${offset}`);
    assert.equal(recipe.windowSize,windowSize);
    assert.equal(recipe.slots,slotCount);
    assert.equal(recipe.offset,offset);
    passed+=1;
  }
  assert.equal(passed,36);
});

function hiddenFor(id){
  const x=(Number(id)+1)/131;
  return [Math.sin(x*7),Math.cos(x*11),Math.sin(x*17)+0.2*x,Math.cos(x*23)-0.1*x];
}
function embeddingForHidden(h){
  return [2.2*h[1]+0.3,-1.7*h[0]+0.1,-1.4*h[3]+0.2,2.5*h[2]-0.4];
}

test('Batch50 profiling-calibrated hidden→embedding ridge improves held-out geometry and reranks shortlist',()=>{
  const count=128;
  const candidateIds=Array.from({length:count},(_,i)=>i);
  const hiddenStates=candidateIds.map(hiddenFor);
  const probeMatrix=hiddenStates.map(embeddingForHidden);
  const sequences=candidateIds.map((id)=>[id]);
  const probeOptions={orientation:'candidate-rows',metric:'negative-l2',candidateIds,topK:4};
  const calibration=fitProbeCalibration({hiddenStates,profileTokenSequences:sequences,probeMatrix,probeOptions,layout:{groupsPerToken:2,hiddenPerGroup:2},options:{minCosineGain:0.001}});
  assert.equal(calibration.status,'ok',JSON.stringify(calibration.summary||calibration));
  assert.ok(calibration.summary.evaluation.calibratedCosine>calibration.summary.evaluation.rawCosine+0.05);
  assert.ok(calibration.summary.evaluation.calibratedMse<calibration.summary.evaluation.rawMse);

  const targetId=73;
  const rawCandidates=[[{tokenId:12,score:9},{tokenId:targetId,score:8},{tokenId:44,score:7}]];
  const reranked=rerankCandidateShortlists({hiddenStates:[hiddenFor(targetId)],candidates:rawCandidates,project:calibration.project,probeMatrix,probeOptions});
  assert.equal(reranked.status,'ok');
  assert.equal(reranked.candidates[0][0].tokenId,targetId);
});

test('Batch50 calibration keeps raw probe when profiling already matches embedding space',()=>{
  const count=96;const candidateIds=Array.from({length:count},(_,i)=>i);
  const hiddenStates=candidateIds.map(hiddenFor);const probeMatrix=hiddenStates.map((row)=>row.slice());
  const result=fitProbeCalibration({hiddenStates,profileTokenSequences:candidateIds.map((id)=>[id]),probeMatrix,probeOptions:{orientation:'candidate-rows',metric:'negative-l2',candidateIds,topK:4},layout:{groupsPerToken:2,hiddenPerGroup:2}});
  assert.notEqual(result.status,'ok');
  assert.ok(['not-beneficial','not-applicable'].includes(result.status));
});

test('Batch50 unknown-prefix oracle promotes candidate-guided replay only when oracle emits a flag',async()=>{
  const targetCandidates=[
    [{tokenId:10,score:9},{tokenId:11,score:8}],
    [{tokenId:20,score:9},{tokenId:21,score:8}],
    [{tokenId:30,score:9},{tokenId:31,score:8}]
  ];
  let calls=0;
  const decodeRunner=async(_model,request)=>{calls+=1;assert.ok(Array.isArray(request.candidateTokenIdsByStep));return {status:'max-tokens',generatedTokenIds:[20,30],text:'ynuctf{guided_oracle_ok}',flag:null,cacheUsed:true};};
  const result=await runUnknownPrefixOracle('fixture.onnx',{targetCandidates,tokenizer:{decode:()=>''},seedBeam:1},{decodeRunner});
  assert.equal(result.status,'flag-recovered');
  assert.equal(result.mode,'candidate-guided');
  assert.equal(result.flag,'ynuctf{guided_oracle_ok}');
  assert.equal(result.agreement.top1Rate,1);
  assert.equal(calls,1);
});

test('Batch50 unknown-prefix oracle falls back to full vocab when shortlist replay is wrong',async()=>{
  const targetCandidates=[
    [{tokenId:10,score:9},{tokenId:11,score:8}],
    [{tokenId:20,score:9},{tokenId:21,score:8}],
    [{tokenId:30,score:9},{tokenId:31,score:8}]
  ];
  const modes=[];
  const decodeRunner=async(_model,request)=>{
    const guided=Array.isArray(request.candidateTokenIdsByStep);modes.push(guided?'guided':'full');
    if(guided)return {status:'max-tokens',generatedTokenIds:[21,31],text:'noise only',flag:null};
    return {status:'max-tokens',generatedTokenIds:[20,30],text:'ACTF{full_vocab_closure}',flag:null,cacheUsed:false};
  };
  const result=await runUnknownPrefixOracle('fixture.onnx',{targetCandidates,tokenizer:{decode:()=>''},seedBeam:1},{decodeRunner});
  assert.equal(result.status,'flag-recovered');
  assert.equal(result.mode,'full-vocab-fallback');
  assert.equal(result.flag,'ACTF{full_vocab_closure}');
  assert.deepEqual(modes,['guided','full']);
});

test('Batch50 unknown-prefix oracle stays bounded and does not promote ordinary decoded text',async()=>{
  const tooMany=Array.from({length:257},()=>[{tokenId:1,score:1}]);
  const gap=await runUnknownPrefixOracle('fixture.onnx',{targetCandidates:tooMany,tokenizer:{decode:()=>''}},{decodeRunner:async()=>{throw new Error('must not run');}});
  assert.equal(gap.status,'gap');
  assert.equal(gap.code,'UNKNOWN_PREFIX_TOKEN_BUDGET_GAP');

  const rows=[[{tokenId:1,score:2}],[{tokenId:2,score:2}]];
  const miss=await runUnknownPrefixOracle('fixture.onnx',{targetCandidates:rows,tokenizer:{decode:()=>''},seedBeam:1},{decodeRunner:async()=>({status:'max-tokens',generatedTokenIds:[2],text:'ordinary text',flag:null})});
  assert.equal(miss.status,'decoded-no-flag');
  assert.equal(miss.flag,null);
});

test('Batch50 agreement metric rewards leakage-consistent oracle replay',()=>{
  const rows=[[{tokenId:5},{tokenId:7}],[{tokenId:6},{tokenId:8}],[{tokenId:9},{tokenId:10}]];
  const exact=agreement([5,6,9],rows);const weak=agreement([7,8,42],rows);
  assert.equal(exact.top1Rate,1);
  assert.ok(exact.meanReciprocalRank>weak.meanReciprocalRank);
  assert.ok(exact.hitRate>weak.hitRate);
});

test('Batch50 production compatibility keeps Batch46 helpers but routes runScaAutopilotPaths to quality-first dispatcher',()=>{
  assert.equal(compat.runScaAutopilotPaths,batch50.runScaAutopilotPaths);
  assert.equal(compat.inferGroupedProfileShape,batch46.inferGroupedProfileShape);
  assert.equal(typeof compat.runQualityGroupedScaAutopilotPaths,'function');
  assert.notEqual(compat.runScaAutopilotPaths,batch46.runScaAutopilotPaths);
});

test('Batch50 quality core is wired to streaming features, calibrated probe and unknown-prefix oracle',()=>{
  const source=fs.readFileSync(require.resolve('../src/core/sca_quality_grouped_core'),'utf8');
  assert.match(source,/wrapStreamingFeatureSource/);
  assert.match(source,/fitProbeCalibration/);
  assert.match(source,/rerankCandidateShortlists/);
  assert.match(source,/runUnknownPrefixOracle/);
  const compatSource=fs.readFileSync(require.resolve('../src/core/sca_autopilot_batch42'),'utf8');
  assert.match(compatSource,/sca_autopilot_batch50/);
});
