'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const zlib=require('node:zlib');
const {runChallengeOnnxAutopilot}=require('../src/core/challenge_onnx_autopilot');

function chunk(type,data){const body=Buffer.from(data);const out=Buffer.alloc(12+body.length);out.writeUInt32BE(body.length,0);Buffer.from(type).copy(out,4);body.copy(out,8);return out;}
function png(){const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(1,0);ihdr.writeUInt32BE(1,4);ihdr[8]=8;ihdr[9]=6;return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(Buffer.from([0,255,0,0,255]))),chunk('IEND',Buffer.alloc(0))]);}
function manifest(){return{status:'ready',executionReady:true,pipeline:{size:{height:1,width:1},crop:null,color:'RGB',layout:'CHW',interpolation:'bilinear',scale:{from:'0..255',to:'0..1',factor:1/255},normalize:null,dtype:'float32',batch:'prepend-axis'},evidence:[{file:'solve.py',line:1,kind:'size',value:{height:1,width:1},confidence:'exact-source',detail:'torchvision/PIL Resize 使用 (height,width)'}]};}
function model(){return{inputs:[{name:'input',metadata:{type:'float32',dimensions:[1,3,1,1]}}],outputs:[{name:'logits',metadata:{type:'float32',dimensions:[1,2]}}]};}
function run(){return{schema:'newcyber.onnx-run.v1',provider:'cpu',outputs:{logits:{type:'float32',dims:[1,2],elements:2,preview:[0.92,1.0],truncated:false}}};}

test('named hints are mapped through class_to_idx before Top-2 ranking',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-named-label-'));try{
    await fs.mkdir(path.join(root,'dog'));await fs.writeFile(path.join(root,'dog','55.png'),png());await fs.writeFile(path.join(root,'model.onnx'),'x');const meta=JSON.stringify({hints:[['cat','dog']],class_to_idx:{cat:0,dog:1}});await fs.writeFile(path.join(root,'meta.json'),meta);
    const files=[{path:'dog/55.png',extension:'.png',size:70},{path:'model.onnx',extension:'.onnx',size:1},{path:'meta.json',extension:'.json',size:meta.length}];
    const result=await runChallengeOnnxAutopilot(root,{files,aiPreprocessingManifest:manifest(),findings:[]},{runtimeStatus:()=>({available:true}),inspectModel:async()=>model(),runModel:async()=>run()});
    assert.equal(result.status,'ranked');assert.equal(result.scoreSpace.status,'ready');assert.equal(result.scoreSpace.mapping.mode,'class-map-to-output-index');assert.deepEqual(result.bridge.candidateSets[0].ids,[55]);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});
