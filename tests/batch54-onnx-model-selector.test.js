'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const {expectedImageDims,scoreModel,selectOnnxModel}=require('../src/core/challenge_onnx_model_selector');

function manifest(size=224){return{status:'ready',executionReady:true,pipeline:{size:{height:size,width:size},crop:null,color:'RGB',layout:'CHW',batch:'prepend-axis'}};}
function model(inputDims,inputName='input',outputDims=[1,10]){return{schema:'newcyber.onnx-model.v1',inputs:[{name:inputName,metadata:{type:'float32',dimensions:inputDims}}],outputs:[{name:'logits',metadata:{type:'float32',dimensions:outputDims}}]};}
async function fixture(names){const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-selector-'));for(const name of names)await fs.writeFile(path.join(root,name),'x');return root;}

test('expectedImageDims derives evidence-backed NCHW contract',()=>{assert.deepEqual(expectedImageDims(manifest(224)),[1,3,224,224]);});

test('selector chooses the only shape-compatible image model',async()=>{
  const root=await fixture(['model224.onnx','model32.onnx']);try{
    const analysis={files:[{path:'model224.onnx',extension:'.onnx',size:1},{path:'model32.onnx',extension:'.onnx',size:1}]};
    const result=await selectOnnxModel(root,analysis,{mode:'image',manifest:manifest(224)},{inspectModel:async(file)=>file.endsWith('model224.onnx')?model([1,3,224,224]):model([1,3,32,32])});
    assert.equal(result.ok,true);assert.equal(result.file.path,'model224.onnx');assert.match(result.selection.method,/compatible/);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('selector refuses equally compatible models instead of filename guessing',async()=>{
  const root=await fixture(['a.onnx','b.onnx']);try{
    const analysis={files:[{path:'a.onnx',extension:'.onnx',size:1},{path:'b.onnx',extension:'.onnx',size:1}]};
    const result=await selectOnnxModel(root,analysis,{mode:'image',manifest:manifest(64)},{inspectModel:async()=>model([1,3,64,64])});
    assert.equal(result.ok,false);assert.equal(result.code,'MODEL_AMBIGUOUS');assert.equal(result.models.length,2);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('explicit feed names and shapes disambiguate models',async()=>{
  const root=await fixture(['vision.onnx','other.onnx']);try{
    const analysis={files:[{path:'vision.onnx',extension:'.onnx',size:1},{path:'other.onnx',extension:'.onnx',size:1}]};
    const explicitBundle={candidates:[{feeds:{pixels:{type:'float32',dims:[1,3,8,8],values:new Array(192).fill(0)}}}]};
    const result=await selectOnnxModel(root,analysis,{mode:'explicit-feeds',explicitBundle},{inspectModel:async(file)=>file.endsWith('vision.onnx')?model([1,3,8,8],'pixels'):model([1,16],'features')});
    assert.equal(result.ok,true);assert.equal(result.file.path,'vision.onnx');
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('classification vector output is a strong positive signal',()=>{
  const scored=scoreModel({path:'x.onnx'},model([1,3,32,32]),{mode:'image',manifest:manifest(32)});assert.ok(scored.score>=10);assert.ok(scored.reasons.includes('classification-vector output'));
});
