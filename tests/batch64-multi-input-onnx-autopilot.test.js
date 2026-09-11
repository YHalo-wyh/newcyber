'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const zlib=require('node:zlib');
const {discoverConstantInputBindings,validateFeedSpec,resolveModelInputPlan}=require('../src/core/challenge_onnx_input_bindings');
const {scoreModel}=require('../src/core/challenge_onnx_model_selector');
const {discoverNamedJsonHints,runChallengeOnnxAutopilot}=require('../src/core/challenge_onnx_autopilot');

function chunk(type,data){const body=Buffer.from(data);const out=Buffer.alloc(12+body.length);out.writeUInt32BE(body.length,0);Buffer.from(type).copy(out,4);body.copy(out,8);return out;}
function png(){const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(1,0);ihdr.writeUInt32BE(1,4);ihdr[8]=8;ihdr[9]=6;return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(Buffer.from([0,255,0,0,255]))),chunk('IEND',Buffer.alloc(0))]);}
function manifest(){return{status:'ready',executionReady:true,pipeline:{size:{height:1,width:1},crop:null,color:'RGB',layout:'CHW',interpolation:'bilinear',scale:{from:'0..255',to:'0..1',factor:1/255},normalize:null,dtype:'float32',batch:'prepend-axis'},evidence:[{file:'solve.py',line:1,kind:'size',value:{height:1,width:1},confidence:'exact-source',detail:'torchvision/PIL Resize 使用 (height,width)'}]};}
function multiModel(){return{inputs:[{name:'image',metadata:{type:'float32',dimensions:[1,3,1,1]}},{name:'temperature',metadata:{type:'float32',dimensions:[1]}}],outputs:[{name:'logits',metadata:{type:'float32',dimensions:[1,2]}}]};}
function run(){return{schema:'newcyber.onnx-run.v1',provider:'cpu',outputs:{logits:{type:'float32',dims:[1,2],elements:2,preview:[0.92,1.0],truncated:false}}};}

test('named JSON hint recovery accepts bounded scalar class names but rejects empty labels',()=>{
  assert.deepEqual(discoverNamedJsonHints('meta.json',JSON.stringify({hints:[['cat','dog']]}))[0].rows,[['cat','dog']]);
  assert.equal(discoverNamedJsonHints('bad.json',JSON.stringify({hints:[['','dog']]})).length,0);
});

test('constant ONNX bindings are discovered only from explicit binding keys',()=>{
  const source={file:'config.json',text:JSON.stringify({onnxInputs:{temperature:{type:'float32',dims:[1],values:[1]}}})};
  const recovered=discoverConstantInputBindings([source]);assert.equal(recovered.status,'ready');assert.deepEqual(recovered.bindings.temperature.spec,{type:'float32',dims:[1],values:[1]});
  const generic=discoverConstantInputBindings([{file:'x.json',text:JSON.stringify({feeds:{temperature:{type:'float32',dims:[1],values:[1]}}})}]);assert.equal(generic.status,'not-detected');
});

test('binding validation rejects value-count mismatch and unsafe dtypes',()=>{
  assert.throws(()=>validateFeedSpec({type:'float32',dims:[2],values:[1]},'temperature'),/数量/);
  assert.throws(()=>validateFeedSpec({type:'string',dims:[1],values:['x']},'name'),/不支持/);
});

test('multi-input plan requires explicit evidence for every auxiliary input',()=>{
  const bindings=discoverConstantInputBindings([{file:'config.json',text:JSON.stringify({onnxInputs:{temperature:{type:'float32',dims:[1],values:[1]}}})}]);
  const plan=resolveModelInputPlan(multiModel(),{mode:'image',imageDims:[1,3,1,1],inputBindings:bindings});assert.equal(plan.ok,true);assert.equal(plan.primaryInputName,'image');assert.deepEqual(plan.auxiliaryInputNames,['temperature']);
  const missing=resolveModelInputPlan(multiModel(),{mode:'image',imageDims:[1,3,1,1],inputBindings:{bindings:{}}});assert.equal(missing.ok,false);assert.equal(missing.code,'AUX_INPUT_BINDING_MISSING');
});

test('model scoring accepts evidence-bound auxiliary input and rejects unbound multi-input model',()=>{
  const file={path:'classifier.onnx'};const bindings=discoverConstantInputBindings([{file:'config.json',text:JSON.stringify({onnxInputs:{temperature:{type:'float32',dims:[1],values:[1]}}})}]);
  const ok=scoreModel(file,multiModel(),{mode:'image',manifest:manifest(),inputBindings:bindings});assert.ok(ok.score>0);assert.equal(ok.inputPlan.primaryInputName,'image');
  const no=scoreModel(file,multiModel(),{mode:'image',manifest:manifest(),inputBindings:{bindings:{}}});assert.equal(no.score,-100);assert.match(no.reasons[0],/AUX_INPUT_BINDING_MISSING/);
});

test('full challenge autopilot merges primary image tensor with evidence-bound constant input',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-multi-input-'));try{
    await fs.mkdir(path.join(root,'dog'));await fs.writeFile(path.join(root,'dog','55.png'),png());await fs.writeFile(path.join(root,'model.onnx'),'x');
    const meta=JSON.stringify({hints:[['cat','dog']],class_to_idx:{cat:0,dog:1},onnxInputs:{temperature:{type:'float32',dims:[1],values:[1]}}});await fs.writeFile(path.join(root,'meta.json'),meta);
    const files=[{path:'dog/55.png',extension:'.png',size:70},{path:'model.onnx',extension:'.onnx',size:1},{path:'meta.json',extension:'.json',size:Buffer.byteLength(meta)}];let seenFeeds=null;
    const result=await runChallengeOnnxAutopilot(root,{files,aiPreprocessingManifest:manifest(),findings:[]},{runtimeStatus:()=>({available:true}),inspectModel:async()=>multiModel(),runModel:async(_model,request)=>{seenFeeds=request.feeds;return run();}});
    assert.equal(result.status,'ranked');assert.equal(result.scoreSpace.status,'ready');assert.equal(result.scoreSpace.mapping.mode,'class-map-to-output-index');assert.equal(result.inputPlan.primaryInputName,'image');assert.deepEqual(result.inputPlan.auxiliaryInputNames,['temperature']);assert.deepEqual(Object.keys(seenFeeds).sort(),['image','temperature']);assert.deepEqual(seenFeeds.temperature,{type:'float32',dims:[1],values:[1]});assert.deepEqual(result.bridge.candidateSets[0].ids,[55]);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});
