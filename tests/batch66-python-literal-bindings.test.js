'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const zlib=require('node:zlib');
const {parsePythonLiteralArray,flattenRectangular,discoverPythonConstantInputBindings,discoverConstantInputBindings}=require('../src/core/challenge_onnx_input_bindings');
const {runChallengeOnnxAutopilot}=require('../src/core/challenge_onnx_autopilot');

function chunk(type,data){const body=Buffer.from(data);const out=Buffer.alloc(12+body.length);out.writeUInt32BE(body.length,0);Buffer.from(type).copy(out,4);body.copy(out,8);return out;}
function png(){const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(1,0);ihdr.writeUInt32BE(1,4);ihdr[8]=8;ihdr[9]=6;return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(Buffer.from([0,255,0,0,255]))),chunk('IEND',Buffer.alloc(0))]);}
function manifest(){return{status:'ready',executionReady:true,pipeline:{size:{height:1,width:1},crop:null,color:'RGB',layout:'CHW',interpolation:'bilinear',scale:{from:'0..255',to:'0..1',factor:1/255},normalize:null,dtype:'float32',batch:'prepend-axis'},evidence:[{file:'solve.py',line:1,kind:'size',value:{height:1,width:1},confidence:'exact-source',detail:'torchvision/PIL Resize 使用 (height,width)'}]};}
function model(){return{inputs:[{name:'image',metadata:{type:'float32',dimensions:[1,3,1,1]}},{name:'temperature',metadata:{type:'float32',dimensions:[1]}}],outputs:[{name:'logits',metadata:{type:'float32',dimensions:[1,2]}}]};}
function run(){return{schema:'newcyber.onnx-run.v1',provider:'cpu',outputs:{logits:{type:'float32',dims:[1,2],elements:2,preview:[0.92,1.0],truncated:false}}};}

test('Python numeric literal parser accepts rectangular arrays without eval',()=>{
  const parsed=parsePythonLiteralArray('[[1.0, -2e-1], [3, 4.5]]');assert.deepEqual(parsed,[[1,-0.2],[3,4.5]]);assert.deepEqual(flattenRectangular(parsed),{dims:[2,2],values:[1,-0.2,3,4.5]});
  assert.throws(()=>parsePythonLiteralArray('[open("x"), 1]'),/unsupported/);assert.throws(()=>flattenRectangular([[1],[2,3]]),/矩形/);
});

test('static Python recovery requires explicit dtype and an ONNX run feed edge',()=>{
  const source=`import onnxruntime as ort\nsess=ort.InferenceSession('model.onnx')\ntemperature=np.array([1.0], dtype=np.float32)\nunused=np.array([2.0], dtype=np.float32)\nresult=sess.run(None, {'image': image, 'temperature': temperature})\n`;
  const rows=discoverPythonConstantInputBindings('solve.py',source);assert.equal(rows.length,1);assert.equal(rows[0].name,'temperature');assert.deepEqual(rows[0].spec,{type:'float32',dims:[1],values:[1]});assert.equal(rows[0].variable,'temperature');
  assert.equal(discoverPythonConstantInputBindings('solve.py',`import onnxruntime\nx=np.array([1.0])\nsess.run(None, {'x':x})`).length,0);
  assert.equal(discoverPythonConstantInputBindings('helper.py',`x=np.array([1.0], dtype=np.float32)\nprint(x)`).length,0);
});

test('feed dictionary variable is correlated to session.run before its literal values are trusted',()=>{
  const source=`from onnxruntime import InferenceSession\nsess=InferenceSession('m.onnx')\nt=np.asarray([[1,2],[3,4]], dtype=np.int64)\nfeeds={'image': image, 'temperature': t}\nout=sess.run(None, feeds)\n`;
  const rows=discoverPythonConstantInputBindings('solve.py',source);assert.equal(rows.length,1);assert.equal(rows[0].name,'temperature');assert.deepEqual(rows[0].spec,{type:'int64',dims:[2,2],values:[1,2,3,4]});
});

test('Python and JSON evidence conflicts stop automatic binding instead of guessing',()=>{
  const python=`import onnxruntime as ort\ns=ort.InferenceSession('m.onnx')\nt=np.array([1.0], dtype=np.float32)\ns.run(None, {'image':image, 'temperature':t})`;
  const json=JSON.stringify({onnxInputs:{temperature:{type:'float32',dims:[1],values:[2]}}});const result=discoverConstantInputBindings([{file:'solve.py',text:python},{file:'config.json',text:json}]);assert.equal(result.status,'conflict');assert.equal(result.conflicts[0].name,'temperature');
});

test('Challenge autopilot can use statically recovered Python literal auxiliary input end-to-end',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-py-binding-'));try{
    await fs.mkdir(path.join(root,'dog'));await fs.writeFile(path.join(root,'dog','77.png'),png());await fs.writeFile(path.join(root,'model.onnx'),'x');
    const meta=JSON.stringify({hints:[['cat','dog']],class_to_idx:{cat:0,dog:1}});await fs.writeFile(path.join(root,'meta.json'),meta);
    const solve=`import onnxruntime as ort\nimport numpy as np\nsess=ort.InferenceSession('model.onnx')\ntemperature=np.array([1.0], dtype=np.float32)\nlogits=sess.run(None, {'image': image, 'temperature': temperature})\n`;await fs.writeFile(path.join(root,'solve.py'),solve);
    const files=[{path:'dog/77.png',extension:'.png',size:70},{path:'model.onnx',extension:'.onnx',size:1},{path:'meta.json',extension:'.json',size:Buffer.byteLength(meta)},{path:'solve.py',extension:'.py',size:Buffer.byteLength(solve)}];let feeds=null;
    const result=await runChallengeOnnxAutopilot(root,{files,aiPreprocessingManifest:manifest(),findings:[]},{runtimeStatus:()=>({available:true}),inspectModel:async()=>model(),runModel:async(_m,request)=>{feeds=request.feeds;return run();}});
    assert.equal(result.status,'ranked');assert.equal(result.inputBindings.status,'ready');assert.deepEqual(result.inputPlan.auxiliaryInputNames,['temperature']);assert.equal(result.inputPlan.evidence[0].key,'python-onnx-run-literal');assert.deepEqual(feeds.temperature,{type:'float32',dims:[1],values:[1]});assert.deepEqual(result.bridge.candidateSets[0].ids,[77]);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});
