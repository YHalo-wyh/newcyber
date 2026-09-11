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
function manifest(){return{status:'ready',executionReady:true,pipeline:{size:{height:1,width:1},crop:null,color:'RGB',layout:'CHW',interpolation:'bilinear',scale:{from:'0..255',to:'0..1',factor:1/255},normalize:null,dtype:'float32',batch:'prepend-axis'},evidence:[{file:'solve.py',line:1,kind:'size',value:{height:1,width:1},confidence:'exact-source',detail:'torchvision/PIL Resize 使用 (height,width)'}],missing:[],conflicts:[]};}
function model(dims){return{schema:'newcyber.onnx-model.v1',inputs:[{name:'input',metadata:{type:'float32',dimensions:dims}}],outputs:[{name:'logits',metadata:{type:'float32',dimensions:[1,2]}}]};}
function run(){return{schema:'newcyber.onnx-run.v1',provider:'cpu',inputs:['input'],outputs:{logits:{type:'float32',dims:[1,2],elements:2,preview:[0.1,2],truncated:false,summary:{finite:2,min:0.1,max:2,mean:1.05}}}};}

test('full autopilot selects compatible model from multiple ONNX files',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-mm-'));try{
    await fs.mkdir(path.join(root,'1'));await fs.writeFile(path.join(root,'1','101.png'),png());await fs.writeFile(path.join(root,'good.onnx'),'x');await fs.writeFile(path.join(root,'wrong.onnx'),'x');await fs.writeFile(path.join(root,'hints.json'),JSON.stringify({hints:[[0,1]]}));
    const analysis={files:[{path:'1/101.png',extension:'.png',size:70},{path:'good.onnx',extension:'.onnx',size:1},{path:'wrong.onnx',extension:'.onnx',size:1},{path:'hints.json',extension:'.json',size:20}],aiPreprocessingManifest:manifest(),findings:[]};
    const result=await runChallengeOnnxAutopilot(root,analysis,{runtimeStatus:()=>({available:true,source:'test',version:'1'}),inspectModel:async(file)=>file.endsWith('good.onnx')?model([1,3,1,1]):model([1,3,32,32]),runModel:async()=>run()});
    assert.equal(result.status,'ranked');assert.equal(result.mode,'image');assert.equal(result.model,'good.onnx');assert.equal(result.modelSelection.method,'only-compatible');assert.ok(result.bridge.candidateSets.length);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('full autopilot refuses genuinely ambiguous compatible models',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-mm-amb-'));try{
    await fs.mkdir(path.join(root,'1'));await fs.writeFile(path.join(root,'1','101.png'),png());await fs.writeFile(path.join(root,'a.onnx'),'x');await fs.writeFile(path.join(root,'b.onnx'),'x');await fs.writeFile(path.join(root,'hints.json'),JSON.stringify({hints:[[0,1]]}));
    const analysis={files:[{path:'1/101.png',extension:'.png',size:70},{path:'a.onnx',extension:'.onnx',size:1},{path:'b.onnx',extension:'.onnx',size:1},{path:'hints.json',extension:'.json',size:20}],aiPreprocessingManifest:manifest(),findings:[]};
    const result=await runChallengeOnnxAutopilot(root,analysis,{runtimeStatus:()=>({available:true}),inspectModel:async()=>model([1,3,1,1]),runModel:async()=>run()});
    assert.equal(result.status,'gap');assert.equal(result.gap.code,'MODEL_AMBIGUOUS');assert.equal(result.gap.models.length,2);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('NPY model selection accepts automatic batch=1 adaptation',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-mm-npy-'));try{
    const payload=Buffer.alloc(3*2*2*4);const shapeText='3, 2, 2';let header=`{'descr': '<f4', 'fortran_order': False, 'shape': (${shapeText}), }`;const base=10+Buffer.byteLength(header,'latin1')+1;const padded=Math.ceil(base/64)*64;header=`${header}${' '.repeat(padded-base)}\n`;const prefix=Buffer.from([0x93,0x4e,0x55,0x4d,0x50,0x59,0x01,0x00]);const len=Buffer.alloc(2);len.writeUInt16LE(Buffer.byteLength(header,'latin1'),0);
    await fs.mkdir(path.join(root,'1'));await fs.writeFile(path.join(root,'1','7.npy'),Buffer.concat([prefix,len,Buffer.from(header,'latin1'),payload]));await fs.writeFile(path.join(root,'good.onnx'),'x');await fs.writeFile(path.join(root,'wrong.onnx'),'x');await fs.writeFile(path.join(root,'hints.json'),JSON.stringify({hints:[[0,1]]}));
    const analysis={files:[{path:'1/7.npy',extension:'.npy',size:payload.length+100},{path:'good.onnx',extension:'.onnx',size:1},{path:'wrong.onnx',extension:'.onnx',size:1},{path:'hints.json',extension:'.json',size:20}],findings:[]};
    let dims=null;const result=await runChallengeOnnxAutopilot(root,analysis,{runtimeStatus:()=>({available:true}),inspectModel:async(file)=>file.endsWith('good.onnx')?model([1,3,2,2]):model([1,3,32,32]),runModel:async(_m,req)=>{dims=req.feeds.input.dims;return run();}});
    assert.equal(result.status,'ranked');assert.equal(result.model,'good.onnx');assert.deepEqual(dims,[1,3,2,2]);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});
