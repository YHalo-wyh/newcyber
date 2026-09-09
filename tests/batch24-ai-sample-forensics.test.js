const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const {
  analyzeRasterImage,
  compareRasterImages,
  analyzeNpySample,
  compareNpySamples,
  CTF_FREQUENCY_REFERENCE
}=require('../src/core/ai_sample_forensics');
const {runTool}=require('../src/core/tool_router');

function makeNpy({descr='<f4',shape=[2],values=[0,1]}={}){
  const shapeText=shape.length===1?`${shape[0]},`:shape.join(', ');
  let header=`{'descr': '${descr}', 'fortran_order': False, 'shape': (${shapeText}), }`;
  const preamble=10;
  const base=Buffer.byteLength(header,'latin1')+1;
  const padded=Math.ceil((preamble+base)/16)*16-preamble;
  header=`${header}${' '.repeat(Math.max(0,padded-base))}\n`;
  const magic=Buffer.from([0x93,0x4e,0x55,0x4d,0x50,0x59,0x01,0x00]);
  const length=Buffer.alloc(2); length.writeUInt16LE(Buffer.byteLength(header,'latin1'),0);
  let payload;
  if(descr==='<f4'){
    payload=Buffer.alloc(values.length*4);
    values.forEach((value,index)=>payload.writeFloatLE(value,index*4));
  }else if(descr==='|u1') payload=Buffer.from(values);
  else throw new Error('test helper dtype unsupported');
  return Buffer.concat([magic,length,Buffer.from(header,'latin1'),payload]);
}

function raster(size=32,patch=false,checker=false){
  const data=[];
  for(let y=0;y<size;y+=1){
    for(let x=0;x<size;x+=1){
      let value=100;
      if(checker) value=((x+y)&1)?255:0;
      else if(patch&&x>=size-4&&y>=size-4) value=255;
      else value=100+((x+y)%3);
      data.push(value,value,value,255);
    }
  }
  return {width:size,height:size,channels:4,data};
}

test('raster image forensics locates a localized patch candidate without calling it confirmed backdoor',()=>{
  const result=analyzeRasterImage(raster(32,true,false));
  assert.equal(result.schema,'newcyber.ai-raster-forensics.v1');
  assert.ok(result.patchAnalysis.candidates.length>0);
  const top=result.patchAnalysis.candidates[0];
  assert.ok(top.x>=24||top.y>=24);
  assert.ok(top.score>=0.9);
  assert.ok(result.findings.some((x)=>x.id==='frequency-domain-profile'));
  assert.ok(result.notes.some((x)=>/不等于已证明存在模型后门/.test(x)));
});

test('frequency profile reproduces the Bay Area public writeup reference parameters and separates checker from near-flat raster',()=>{
  const checker=analyzeRasterImage(raster(32,false,true));
  const flat=analyzeRasterImage({width:32,height:32,channels:4,data:Array.from({length:32*32},()=>[128,128,128,255]).flat()});
  assert.equal(CTF_FREQUENCY_REFERENCE.outerRadiusRatio,0.85);
  assert.equal(CTF_FREQUENCY_REFERENCE.delta,0.125);
  assert.equal(checker.frequency.ctfReference.delta,0.125);
  assert.ok(checker.frequency.highFrequencyRatio>flat.frequency.highFrequencyRatio);
  assert.match(checker.frequency.ctfReference.note,/不是通用/);
});

test('visual comparison reports localized bbox and normalized perturbation norms',()=>{
  const left=raster(32,false,false);
  const right=raster(32,false,false);
  for(let y=28;y<32;y+=1) for(let x=28;x<32;x+=1){
    const offset=(y*32+x)*4;
    right.data[offset]=255; right.data[offset+1]=255; right.data[offset+2]=255;
  }
  const result=compareRasterImages({left,right});
  assert.equal(result.schema,'newcyber.ai-raster-compare.v1');
  assert.equal(result.localizedChangeCandidate,true);
  assert.deepEqual(result.diffBoundingBox,{x:28,y:28,width:4,height:4});
  assert.ok(result.norms.linf>0.5);
  assert.equal(result.heatmap8x8.length,8);
  assert.ok(result.findings.some((x)=>x.id==='localized-adversarial-diff-candidate'));
});

test('NPY float image gets numeric profile, safe image preview and raster evidence',()=>{
  const values=[];
  for(let y=0;y<8;y+=1) for(let x=0;x<8;x+=1) values.push((x+y)/14);
  const buffer=makeNpy({descr:'<f4',shape:[8,8,1],values});
  const result=analyzeNpySample(buffer,'sample.npy');
  assert.equal(result.schema,'newcyber.ai-npy-sample.v1');
  assert.equal(result.imageLike,true);
  assert.equal(result.layout.layout,'HWC');
  assert.equal(result.numeric.sampled,64);
  assert.equal(result.preview.width,8);
  assert.ok(result.preview.rgbaBase64.length>100);
  assert.equal(result.raster.schema,'newcyber.ai-raster-forensics.v1');
  assert.match(result.notes[0],/不会被执行|不.*执行|不.*加载/);
});

test('NPY pair comparison uses original dtype values instead of only preview pixels',()=>{
  const left=makeNpy({descr:'<f4',shape:[4],values:[0,0.1,0.2,0.3]});
  const right=makeNpy({descr:'<f4',shape:[4],values:[0,0.1,0.25,0.3]});
  const result=compareNpySamples(left,right);
  assert.equal(result.schema,'newcyber.ai-npy-compare.v1');
  assert.equal(result.approximate,false);
  assert.equal(result.norms.l0,1);
  assert.ok(Math.abs(result.norms.linf-0.05)<1e-5);
});

test('tool router accepts browser-safe base64 NPY and raster routes',()=>{
  const npy=makeNpy({descr:'|u1',shape:[4,4,1],values:Array.from({length:16},(_,i)=>i*16)});
  const result=runTool('ai-npy-sample-forensics',{input:{fileName:'fixture.npy',base64:npy.toString('base64')}});
  assert.equal(result.imageLike,true);
  assert.equal(result.header.descr,'|u1');
  const image=runTool('ai-image-raster-forensics',{input:raster(16,true,false)});
  assert.equal(image.schema,'newcyber.ai-raster-forensics.v1');
});

test('specialized sample UI is canvas/file based and loads after generic AI surfaces',()=>{
  const root=path.join(__dirname,'..');
  const source=fs.readFileSync(path.join(root,'renderer/ai_sample_forensics_tools.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'renderer/styles/ai_sample_forensics.css'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'renderer/ai_sample_forensics_tools.js'}));
  assert.match(source,/NPY \/ 图像样本取证/);
  assert.match(source,/data-sample-slot/);
  assert.match(source,/<canvas/);
  assert.match(source,/type=\\?"file\\?"|type="file"/);
  assert.doesNotMatch(source,/<textarea/);
  assert.ok(html.indexOf('ai_sample_forensics_tools.js')>html.indexOf('track_surfaces.js'));
  assert.match(html,/styles\/ai_sample_forensics\.css/);
  assert.match(css,/\.ai-diff-heatmap/);
  assert.match(css,/\.ai-sample-canvas/);
});
