'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {runOnnxModel,runOnnxRequests,MAX_BATCH_REQUESTS}=require('../src/core/local_ml_runtime');

function fakeOrt(counters){
  class Tensor{
    constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}
  }
  return{
    Tensor,
    InferenceSession:{
      create:async()=>{
        counters.created+=1;
        return{
          inputNames:['x'],outputNames:['logits'],inputMetadata:[{type:'float32',dimensions:[1]}],outputMetadata:[{type:'float32',dimensions:[1,2]}],
          run:async(feeds)=>{counters.runs+=1;const x=Number(feeds.x.data[0]);return{logits:new Tensor('float32',new Float32Array([x,1-x]),[1,2])};},
          release:async()=>{counters.released+=1;}
        };
      }
    }
  };
}
function req(value){return{feeds:{x:{type:'float32',dims:[1],values:[value]}}};}

test('runOnnxRequests reuses exactly one inference session for many candidate requests',async()=>{
  const counters={created:0,runs:0,released:0};const ort=fakeOrt(counters);
  const result=await runOnnxRequests('synthetic.onnx',[req(0.1),req(0.2),req(0.3),req(0.4)],{provider:'cpu',ort});
  assert.equal(result.schema,'newcyber.onnx-request-batch.v1');assert.equal(result.requested,4);assert.equal(result.succeeded,4);assert.equal(result.failed,0);assert.equal(result.sessionCreates,1);
  assert.equal(counters.created,1);assert.equal(counters.runs,4);assert.equal(counters.released,1);assert.deepEqual(result.results[0].result.outputs.logits.dims,[1,2]);
});

test('one bad candidate is isolated without rebuilding or aborting the session',async()=>{
  const counters={created:0,runs:0,released:0};const ort=fakeOrt(counters);
  const result=await runOnnxRequests('synthetic.onnx',[req(0.1),{feeds:{}},req(0.9)],{provider:'cpu',ort});
  assert.equal(result.completed,3);assert.equal(result.succeeded,2);assert.equal(result.failed,1);assert.match(result.results[1].error,/缺少 ONNX 输入 x/);assert.equal(counters.created,1);assert.equal(counters.runs,2);assert.equal(counters.released,1);
});

test('failFast stops after the first invalid request while still releasing the session',async()=>{
  const counters={created:0,runs:0,released:0};const ort=fakeOrt(counters);
  const result=await runOnnxRequests('synthetic.onnx',[req(0.1),{feeds:{}},req(0.9)],{provider:'cpu',ort,failFast:true});
  assert.equal(result.completed,2);assert.equal(result.succeeded,1);assert.equal(counters.created,1);assert.equal(counters.runs,1);assert.equal(counters.released,1);
});

test('batch runner keeps strict request cap and legacy single-run API semantics',async()=>{
  assert.ok(MAX_BATCH_REQUESTS>=512);await assert.rejects(()=>runOnnxRequests('x',new Array(MAX_BATCH_REQUESTS+1).fill(req(0.5)),{provider:'cpu',ort:fakeOrt({created:0,runs:0,released:0})}),/超过/);
  const counters={created:0,runs:0,released:0};const single=await runOnnxModel('synthetic.onnx',req(0.25),{provider:'cpu',ort:fakeOrt(counters)});assert.equal(single.schema,'newcyber.onnx-run.v1');assert.equal(counters.created,1);assert.equal(counters.released,1);
});
