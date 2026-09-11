'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const zlib=require('node:zlib');
const {decodePng,preprocessPngToTensor,preprocessDecodedImage,spatialPlan}=require('../src/core/ai_image_preprocess_executor');

let crcTable=null;
function crc32(buffer){
  if(!crcTable){crcTable=Array.from({length:256},(_,n)=>{let c=n;for(let k=0;k<8;k+=1)c=(c&1)?0xedb88320^(c>>>1):c>>>1;return c>>>0;});}
  let c=0xffffffff;for(const byte of buffer)c=crcTable[(c^byte)&255]^(c>>>8);return(c^0xffffffff)>>>0;
}
function chunk(type,data){const name=Buffer.from(type);const body=Buffer.from(data);const out=Buffer.alloc(12+body.length);out.writeUInt32BE(body.length,0);name.copy(out,4);body.copy(out,8);out.writeUInt32BE(crc32(Buffer.concat([name,body])),8+body.length);return out;}
function rgbaPng(width,height,pixels){
  const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(width,0);ihdr.writeUInt32BE(height,4);ihdr[8]=8;ihdr[9]=6;ihdr[10]=0;ihdr[11]=0;ihdr[12]=0;
  const raw=Buffer.alloc((width*4+1)*height);let p=0;for(let y=0;y<height;y+=1){raw[p++]=0;for(let x=0;x<width*4;x+=1)raw[p++]=pixels[y*width*4+x];}
  return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(raw)),chunk('IEND',Buffer.alloc(0))]);
}
function manifest(overrides={}){return{
  schema:'newcyber.ai-preprocessing-manifest.v1',status:'ready',executionReady:true,
  pipeline:{size:{height:2,width:2},crop:null,color:'RGB',layout:'CHW',scale:{from:'0..255',to:'0..1',factor:1/255},normalize:null,dtype:'float32',batch:'prepend-axis',...overrides.pipeline},
  evidence:[{file:'solve.py',line:2,kind:'size',value:{height:2,width:2},confidence:'exact-source',detail:'torchvision/PIL Resize 使用 (height,width)'},...(overrides.evidence||[])]
};}

test('safe PNG decoder recovers RGBA pixels without external dependencies',()=>{
  const png=rgbaPng(2,1,[255,0,0,255,0,255,0,255]);const image=decodePng(png);
  assert.equal(image.width,2);assert.equal(image.height,1);assert.deepEqual(Array.from(image.rgba),[255,0,0,255,0,255,0,255]);
});

test('image preprocessing produces evidence-gated NCHW float32 tensor',()=>{
  const png=rgbaPng(2,2,[255,0,0,255,0,255,0,255,0,0,255,255,255,255,255,255]);
  const tensor=preprocessPngToTensor(png,manifest(),{dimensions:[1,3,2,2]});
  assert.equal(tensor.type,'float32');assert.deepEqual(tensor.dims,[1,3,2,2]);assert.equal(tensor.shape.layout,'CHW');
  const bytes=Buffer.from(tensor.base64,'base64');const values=new Float32Array(bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength));
  assert.deepEqual(Array.from(values),[1,0,0,1,0,1,0,1,0,0,1,1]);
  assert.ok(tensor.trace.some((step)=>step.op==='resize'&&step.interpolation==='bilinear'));
});

test('RGB/BGR ambiguity stops automatic image execution',()=>{
  const image={width:1,height:1,rgba:Uint8Array.from([1,2,3,255]),source:{format:'test'}};const m=manifest({pipeline:{color:null,size:{height:1,width:1}}});m.evidence=[{file:'x.py',line:1,kind:'size',value:{height:1,width:1},detail:'cv2.resize dsize 使用 (width,height)'}];
  assert.throws(()=>preprocessDecodedImage(image,m,{dimensions:[1,3,1,1]}),/RGB\/BGR/);
});

test('model contract may prove single-channel execution without RGB guess',()=>{
  const image={width:1,height:1,rgba:Uint8Array.from([255,255,255,255]),source:{format:'test'}};const m=manifest({pipeline:{color:null,size:{height:1,width:1},layout:'CHW',batch:null}});m.evidence=[{file:'x.py',line:1,kind:'size',value:{height:1,width:1},detail:'torchvision/PIL Resize 使用 (height,width)'}];
  const tensor=preprocessDecodedImage(image,m,{dimensions:[1,1,1]});assert.deepEqual(tensor.dims,[1,1,1]);
});

test('RandomCrop and ambiguous spatial ordering are rejected',()=>{
  const random=manifest({pipeline:{crop:{height:1,width:1,type:'random'}}});assert.throws(()=>spatialPlan(random),/RandomCrop/);
  const mixed=manifest({pipeline:{crop:{height:1,width:1,type:'center'}},evidence:[{file:'other.py',line:3,kind:'crop',value:{height:1,width:1,type:'center'}}]});assert.throws(()=>spatialPlan(mixed),/顺序不确定/);
});
