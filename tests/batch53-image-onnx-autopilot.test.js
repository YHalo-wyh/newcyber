'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const zlib=require('node:zlib');
const {runImageBundle,runChallengeOnnxAutopilot,imageFiles}=require('../src/core/challenge_onnx_autopilot');

function chunk(type,data){const body=Buffer.from(data);const out=Buffer.alloc(12+body.length);out.writeUInt32BE(body.length,0);Buffer.from(type).copy(out,4);body.copy(out,8);return out;}
function rgbaPng(r=255,g=0,b=0){const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(1,0);ihdr.writeUInt32BE(1,4);ihdr[8]=8;ihdr[9]=6;const raw=Buffer.from([0,r,g,b,255]);return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(raw)),chunk('IEND',Buffer.alloc(0))]);}
function readyManifest(){return{schema:'newcyber.ai-preprocessing-manifest.v1',status:'ready',executionReady:true,pipeline:{size:{height:1,width:1},crop:null,color:'RGB',layout:'CHW',scale:{from:'0..255',to:'0..1',factor:1/255},normalize:null,dtype:'float32',batch:'prepend-axis'},evidence:[{file:'solve.py',line:1,kind:'size',value:{height:1,width:1},detail:'torchvision/PIL Resize 使用 (height,width)'}],missing:[],conflicts:[]};}
function fakeRun(){return{schema:'newcyber.onnx-run.v1',provider:'cpu',inputs:['input'],outputs:{logits:{type:'float32',dims:[1,2],elements:2,preview:[0.2,1.4],truncated:false,summary:{finite:2,min:0.2,max:1.4,mean:0.8}}}};}

test('imageFiles recognizes common contest image formats',()=>{const result=imageFiles({files:[{path:'1/a.png'},{path:'1/b.jpg'},{path:'x.npy'},{path:'c.webp'}]});assert.deepEqual(result.map((x)=>x.path),['1/a.png','1/b.jpg','c.webp']);});

test('runImageBundle turns labelled PNG into controlled ONNX feed',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-img-run-'));try{
    await fs.mkdir(path.join(root,'1'));await fs.writeFile(path.join(root,'1','101.png'),rgbaPng());
    const analysis={files:[{path:'1/101.png',extension:'.png',size:70}],aiPreprocessingManifest:readyManifest()};
    let feed=null;const result=await runImageBundle(root,analysis,{target:path.join(root,'model.onnx'),model:{inputs:[{name:'input',metadata:{dimensions:[1,3,1,1]}}]}},{rows:[[0,1]]},{runModel:async(_model,request)=>{feed=request.feeds.input;return fakeRun();}});
    assert.equal(result.mode,'image');assert.equal(result.runs.length,1);assert.equal(result.runs[0].id,101);assert.equal(result.runs[0].assignedLabel,'1');assert.deepEqual(feed.dims,[1,3,1,1]);assert.equal(feed.type,'float32');
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('full challenge autopilot ranks image candidates without executing challenge source',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-img-auto-'));try{
    await fs.mkdir(path.join(root,'1'));await fs.writeFile(path.join(root,'1','101.png'),rgbaPng());await fs.writeFile(path.join(root,'model.onnx'),'dummy');await fs.writeFile(path.join(root,'hints.json'),JSON.stringify({hints:[[0,1]]}));
    const analysis={files:[{path:'1/101.png',extension:'.png',size:70},{path:'model.onnx',extension:'.onnx',size:5},{path:'hints.json',extension:'.json',size:20}],aiPreprocessingManifest:readyManifest(),findings:[]};
    const result=await runChallengeOnnxAutopilot(root,analysis,{runtimeStatus:()=>({available:true,source:'test',version:'test'}),inspectModel:async()=>({schema:'newcyber.onnx-model.v1',inputs:[{name:'input',metadata:{dimensions:[1,3,1,1],type:'float32'}}],outputs:[{name:'logits',metadata:{dimensions:[1,2],type:'float32'}}]}),runModel:async()=>fakeRun()});
    assert.equal(result.mode,'image');assert.equal(result.runs,1);assert.equal(result.status,'ranked');assert.ok(result.bridge.candidateSets.length>=1);assert.equal(result.contest.ranking.hints,1);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('image candidates stop at explicit preprocessing gap',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-img-gap-'));try{
    await fs.mkdir(path.join(root,'1'));await fs.writeFile(path.join(root,'1','1.png'),rgbaPng());await fs.writeFile(path.join(root,'hints.json'),JSON.stringify({hints:[[0,1]]}));
    const analysis={files:[{path:'1/1.png',extension:'.png',size:70},{path:'hints.json',extension:'.json',size:20}],aiPreprocessingManifest:{status:'partial',executionReady:false,missing:['color']}};
    const result=await runChallengeOnnxAutopilot(root,analysis,{runtimeStatus:()=>({available:true})});assert.equal(result.status,'gap');assert.equal(result.mode,'image');assert.equal(result.gap.code,'PREPROCESSING_NOT_READY');
  }finally{await fs.rm(root,{recursive:true,force:true});}
});
