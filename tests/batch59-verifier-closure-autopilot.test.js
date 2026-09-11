'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const zlib=require('node:zlib');
const {runChallengeOnnxAutopilot}=require('../src/core/challenge_onnx_autopilot');

function md5(s){return crypto.createHash('md5').update(s).digest('hex');}
function chunk(type,data){const body=Buffer.from(data);const out=Buffer.alloc(12+body.length);out.writeUInt32BE(body.length,0);Buffer.from(type).copy(out,4);body.copy(out,8);return out;}
function png(){const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(1,0);ihdr.writeUInt32BE(1,4);ihdr[8]=8;ihdr[9]=6;return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(Buffer.from([0,255,0,0,255]))),chunk('IEND',Buffer.alloc(0))]);}
function manifest(){return{status:'ready',executionReady:true,pipeline:{size:{height:1,width:1},crop:null,color:'RGB',layout:'CHW',interpolation:'bilinear',scale:{from:'0..255',to:'0..1',factor:1/255},normalize:null,dtype:'float32',batch:'prepend-axis'},evidence:[{file:'solve.py',line:1,kind:'size',value:{height:1,width:1},confidence:'exact-source',detail:'torchvision/PIL Resize 使用 (height,width)'}]};}
function model(){return{inputs:[{name:'input',metadata:{type:'float32',dimensions:[1,3,1,1]}}],outputs:[{name:'logits',metadata:{type:'float32',dimensions:[1,2]}}]};}
function run(scores){return{schema:'newcyber.onnx-run.v1',provider:'cpu',outputs:{logits:{type:'float32',dims:[1,2],elements:2,preview:scores,truncated:false}}};}

test('source-derived hash recipe upgrades ranked candidate to verified submit value',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-verifier-'));try{
    await fs.mkdir(path.join(root,'1'));await fs.writeFile(path.join(root,'1','77.png'),png());await fs.writeFile(path.join(root,'model.onnx'),'x');
    const expected=md5('[77]');const solver=`import hashlib\nhints=[(0,1)]\nexpected='${expected}'\nresult=hashlib.md5(str(sorted(answer)).encode()).hexdigest()\nassert result == expected\n`;
    await fs.writeFile(path.join(root,'solve.py'),solver);
    const files=[{path:'1/77.png',extension:'.png',size:70},{path:'model.onnx',extension:'.onnx',size:1},{path:'solve.py',extension:'.py',size:solver.length}];
    const result=await runChallengeOnnxAutopilot(root,{files,aiPreprocessingManifest:manifest(),findings:[]},{runtimeStatus:()=>({available:true}),inspectModel:async()=>model(),runModel:async()=>run([0.9,1.0])});
    assert.equal(result.status,'verified');assert.equal(result.contest.status,'verified');assert.equal(result.contest.result.verified,true);assert.equal(result.contest.result.ids[0],77);assert.equal(result.verifier.status,'verified');assert.equal(result.contest.result.value,expected);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('wrong verifier digest keeps result candidate instead of forcing solved',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-verifier-miss-'));try{
    await fs.mkdir(path.join(root,'1'));await fs.writeFile(path.join(root,'1','77.png'),png());await fs.writeFile(path.join(root,'model.onnx'),'x');const solver=`import hashlib\nhints=[(0,1)]\nexpected='${md5('[99]')}'\nresult=hashlib.md5(str(sorted(answer)).encode()).hexdigest()\nassert result == expected\n`;await fs.writeFile(path.join(root,'solve.py'),solver);
    const files=[{path:'1/77.png',extension:'.png',size:70},{path:'model.onnx',extension:'.onnx',size:1},{path:'solve.py',extension:'.py',size:solver.length}];
    const result=await runChallengeOnnxAutopilot(root,{files,aiPreprocessingManifest:manifest(),findings:[]},{runtimeStatus:()=>({available:true}),inspectModel:async()=>model(),runModel:async()=>run([0.9,1.0])});
    assert.equal(result.status,'ranked');assert.notEqual(result.contest.status,'verified');assert.equal(result.verifier.status,'checked');
  }finally{await fs.rm(root,{recursive:true,force:true});}
});
