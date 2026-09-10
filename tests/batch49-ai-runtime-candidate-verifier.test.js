'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');

const { patchCandidateId } = require('../src/core/ai_candidate_verifier');
const { runBackdoorPatchRuntimeVerification } = require('../src/core/ai_runtime_candidate_verification');
const { runAiRealCtfRegression } = require('../src/core/ai_real_ctf_regression_batch49');
const { runTool } = require('../src/core/tool_router');

function raster(base=20, trigger=false) {
  const width=4,height=4,channels=4,data=[];
  for(let y=0;y<height;y+=1){
    for(let x=0;x<width;x+=1){
      const value=trigger&&x>=2&&y>=2?255:base;
      data.push(value,value,value,255);
    }
  }
  return {width,height,channels,data};
}

function patch(value=0){
  const data=[];
  for(let i=0;i<4;i+=1)data.push(value,value,value,255);
  return {width:2,height:2,channels:4,data};
}

function candidate(){
  const value={
    kind:'localized-backdoor-trigger',
    targetLabel:'1',
    patch:{x:2,y:2,width:2,height:2,score:0.95,source:'threshold-candidate'},
    behavior:{paired:6,cleanAccuracy:1,targetASR:1,controlTargetRate:0,triggerSpecificity:1},
    verifier:'ai-backdoor-patch-verify'
  };
  value.candidateId=patchCandidateId(value);
  return value;
}

function samples(){
  return Array.from({length:6},(_,index)=>{
    const truth=index%2===0?'2':'3';
    return {trueLabel:truth,raster:raster(truth==='2'?20:30,false)};
  });
}

function fakeClassifierOrt(){
  class Tensor{
    constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}
  }
  const session={
    inputNames:['input'],
    outputNames:['logits'],
    inputMetadata:[{type:'tensor(float)',dimensions:[1,3,4,4]}],
    outputMetadata:[{type:'tensor(float)',dimensions:[1,4]}],
    async run(feeds){
      const values=Array.from(feeds.input.data,Number);
      const hasTrigger=values.some((value)=>value>200);
      let label;
      if(hasTrigger)label=1;
      else label=values[0]>=25?3:2;
      const logits=Float32Array.from([-10,-10,-10,-10]);
      logits[label]=10;
      return {logits:new Tensor('float32',logits,[1,4])};
    },
    async release(){}
  };
  return {Tensor,InferenceSession:{async create(){return session;}}};
}

function request(overrides={}){
  const c=candidate();
  return {
    candidate:c,
    candidateId:c.candidateId,
    triggerSourceRaster:raster(20,true),
    controlPatch:patch(0),
    samples:samples(),
    preprocess:{layout:'NCHW',channels:3,scale:1,mean:[0,0,0],std:[1,1,1],source:'challenge-source'},
    ...overrides
  };
}

test('Batch49 runtime closure generates clean/trigger/control observations and reaches Verified only through real session outputs',async()=>{
  const result=await runBackdoorPatchRuntimeVerification(request(),{
    model:new Uint8Array([1,2,3,4]),
    ort:fakeClassifierOrt(),
    provider:'cpu'
  });
  assert.equal(result.schema,'newcyber.ai-backdoor-runtime-verifier.v1');
  assert.equal(result.verified,true);
  assert.equal(result.verdict,'runtime-verified');
  assert.equal(result.verificationEligible,true);
  assert.match(result.runtimeBindingId,/^runtime-[0-9a-f]{24}$/);
  assert.match(result.model.sha256,/^[0-9a-f]{64}$/);
  assert.match(result.triggerMaterial.sha256,/^[0-9a-f]{64}$/);
  assert.match(result.preprocess.sha256,/^[0-9a-f]{64}$/);
  assert.equal(result.execution.samples,6);
  assert.equal(result.execution.inputName,'input');
  assert.equal(result.execution.outputName,'logits');
  assert.equal(result.verifier.verified,true);
  assert.equal(result.verifier.metrics.targetASR,1);
  assert.equal(result.verifier.metrics.controlTargetRate,0);
  assert.ok(result.observations.rows.every((row)=>row.candidateId===result.candidateId));
  assert.ok(result.observations.rows.every((row)=>row.runtimeBindingId===result.runtimeBindingId));
});

test('Batch49 refuses to upgrade runtime evidence when preprocessing provenance is not trusted',async()=>{
  const input=request({preprocess:{layout:'NCHW',channels:3,scale:1,mean:[0,0,0],std:[1,1,1],source:'guessed'}});
  const result=await runBackdoorPatchRuntimeVerification(input,{model:new Uint8Array([5,6,7]),ort:fakeClassifierOrt()});
  assert.equal(result.verifier.verified,true,'behavior itself is strong');
  assert.equal(result.verificationEligible,false,'untrusted preprocessing must block promotion');
  assert.equal(result.verified,false);
  assert.equal(result.verdict,'runtime-evidence-not-eligible');
});

test('Batch49 candidate binding mismatch fails before model execution',async()=>{
  let created=0;
  const ort=fakeClassifierOrt();
  const baseCreate=ort.InferenceSession.create;
  ort.InferenceSession.create=async(...args)=>{created+=1;return baseCreate(...args);};
  const result=await runBackdoorPatchRuntimeVerification(request({candidateId:'patch-deadbeefdeadbeefdead'}),{model:new Uint8Array([9]),ort});
  assert.equal(result.verified,false);
  assert.equal(result.verdict,'candidate-binding-mismatch');
  assert.equal(created,0);
});

test('Batch49 control that reproduces the trigger cannot pass specificity verification',async()=>{
  const result=await runBackdoorPatchRuntimeVerification(request({controlPatch:patch(255)}),{model:new Uint8Array([1,1,2,3]),ort:fakeClassifierOrt()});
  assert.equal(result.verified,false);
  assert.equal(result.verifier.verified,false);
  assert.equal(result.verifier.checks.controlOk,false);
  assert.equal(result.verifier.checks.specificityOk,false);
});

test('Batch49 real-CTF regression exposes runtime closure but keeps original challenge Verified at zero without runtime artifacts',()=>{
  const result=runAiRealCtfRegression();
  assert.equal(result.batch,49);
  assert.equal(result.capabilitySchema,'newcyber.ai-runtime-candidate-verifier.v1');
  assert.equal(result.summary.total,11);
  assert.equal(result.summary.recognitionPass,11);
  assert.ok(result.summary.candidatePass>=2);
  assert.equal(result.summary.verifiedPass,0);
  assert.ok(result.summary.runtimeVerifierAvailable>=1);
  assert.equal(result.summary.runtimeVerificationReady,0);
  const cifar=result.results.find((item)=>item.challenge==='CIFAR-10');
  assert.equal(cifar.candidate,true);
  assert.equal(cifar.verified,false);
  assert.equal(cifar.runtimeVerifierAvailable,'ai-backdoor-patch-runtime-verify');
  assert.equal(cifar.runtimeGap.code,'ORIGINAL_RUNTIME_EVIDENCE_REQUIRED');
});

test('Batch49 production router exposes runtime verifier and still fails closed on bad candidate binding',async()=>{
  const c=candidate();
  const result=await runTool('ai-backdoor-patch-runtime-verify',{input:{candidate:c,candidateId:'patch-wrong'}});
  assert.equal(result.schema,'newcyber.ai-backdoor-runtime-verifier.v1');
  assert.equal(result.verified,false);
  assert.equal(result.verdict,'candidate-binding-mismatch');
});
