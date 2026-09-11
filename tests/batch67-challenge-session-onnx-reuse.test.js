'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const {runWithInferenceSession,runChallengeOnnxAutopilot}=require('../src/core/challenge_onnx_autopilot');

function model(){return{inputs:[{name:'image',metadata:{type:'float32',dimensions:[1]}}],outputs:[{name:'logits',metadata:{type:'float32',dimensions:[1,2]}}]};}
function run(scores){return{schema:'newcyber.onnx-run.v1',provider:'cpu',inputs:['image'],outputs:{logits:{type:'float32',dims:[1,2],elements:2,preview:scores,truncated:false,summary:{finite:2,min:Math.min(...scores),max:Math.max(...scores),mean:(scores[0]+scores[1])/2}}}};}

function explicitBundle(){return{
  hints:[[0,1]],
  candidates:[
    {id:11,assignedLabel:1,feeds:{image:{type:'float32',dims:[1],values:[0.1]}}},
    {id:12,assignedLabel:1,feeds:{image:{type:'float32',dims:[1],values:[0.2]}}},
    {id:13,assignedLabel:1,feeds:{image:{type:'float32',dims:[1],values:[0.3]}}}
  ]
};}

test('Challenge Session streams many candidates through exactly one inference session',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b67-'));
  try{
    const bundle=JSON.stringify(explicitBundle());
    await fs.writeFile(path.join(root,'bundle.json'),bundle);
    await fs.writeFile(path.join(root,'model.onnx'),'x');
    const files=[
      {path:'bundle.json',extension:'.json',size:Buffer.byteLength(bundle)},
      {path:'model.onnx',extension:'.onnx',size:1}
    ];
    let sessionCreates=0,runCalls=0;
    const result=await runChallengeOnnxAutopilot(root,{files,findings:[]},{
      runtimeStatus:()=>({available:true,source:'test',version:'test'}),
      inspectModel:async()=>model(),
      withSession:async(_target,_options,callback)=>{sessionCreates+=1;return callback({inputNames:['image'],outputNames:['logits']},{});},
      runWithOpenSession:async(_session,_ort,request)=>{
        runCalls+=1;
        const marker=request.feeds.image.values[0];
        if(marker===0.2)throw new Error('synthetic bad candidate');
        return run(marker===0.1?[0.92,1.0]:[0.94,1.0]);
      }
    });
    assert.equal(result.status,'ranked');
    assert.equal(sessionCreates,1);
    assert.equal(runCalls,3);
    assert.equal(result.runs,2);
    assert.equal(result.inference.strategy,'single-session-stream');
    assert.equal(result.inference.sessionCreates,1);
    assert.equal(result.inference.attempted,3);
    assert.equal(result.inference.succeeded,2);
    assert.equal(result.inference.failed,1);
    assert.match(result.errors[0].error,/synthetic bad candidate/);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('injected runModel path remains backward compatible and never opens a native session',async()=>{
  let opened=0,calls=0;
  const modelInfo={target:'model.onnx'};
  const result=await runWithInferenceSession(modelInfo,async(options)=>{
    await options.runModel('model.onnx',{feeds:{}},{provider:'cpu'});
    return{runs:[{ok:true}],errors:[],mode:'test'};
  },{
    runModel:async()=>{calls+=1;return run([0.9,1.0]);},
    withSession:async()=>{opened+=1;throw new Error('must not open');}
  });
  assert.equal(calls,1);
  assert.equal(opened,0);
  assert.equal(result.inference.strategy,'injected-run-model');
  assert.equal(result.inference.sessionCreates,null);
});
