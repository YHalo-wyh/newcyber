'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const {dtypeToTensorType,npyTensorSpec,adaptDimsToModel,labelFromPath,idFromPath,discoverExplicitFeedBundle}=require('../src/core/challenge_onnx_autopilot');

function makeNpyFloat32(shape,values){
  const shapeText=shape.length===1?`${shape[0]},`:shape.join(', ');
  let header=`{'descr': '<f4', 'fortran_order': False, 'shape': (${shapeText}), }`;
  const preamble=10;const base=preamble+Buffer.byteLength(header,'latin1')+1;const padded=Math.ceil(base/16)*16-preamble;
  header=`${header}${' '.repeat(Math.max(0,padded-Buffer.byteLength(header,'latin1')-1))}\n`;
  const magic=Buffer.from([0x93,0x4e,0x55,0x4d,0x50,0x59,0x01,0x00]);const length=Buffer.alloc(2);length.writeUInt16LE(Buffer.byteLength(header,'latin1'),0);
  const payload=Buffer.alloc(values.length*4);values.forEach((value,index)=>payload.writeFloatLE(value,index*4));
  return Buffer.concat([magic,length,Buffer.from(header,'latin1'),payload]);
}

test('NPY float32 payload becomes bounded local runtime tensor spec',()=>{
  const buffer=makeNpyFloat32([3,2,2],[1,2,3,4,5,6,7,8,9,10,11,12]);
  const spec=npyTensorSpec(buffer,'sample.npy');
  assert.equal(spec.type,'float32');assert.deepEqual(spec.dims,[3,2,2]);assert.equal(Buffer.from(spec.base64,'base64').length,48);
});

test('NPY shape can prepend only a compatible batch dimension',()=>{
  const spec={type:'float32',dims:[3,224,224],base64:'AA=='};
  const adapted=adaptDimsToModel(spec,{dimensions:[1,3,224,224]});
  assert.deepEqual(adapted.dims,[1,3,224,224]);assert.equal(adapted.adaptation,'prepend-batch-1');
  assert.throws(()=>adaptDimsToModel(spec,{dimensions:[1,3,128,128]}),/incompatible/);
});

test('dtype mapping refuses big endian automatic execution',()=>{
  assert.equal(dtypeToTensorType('<f4'),'float32');assert.equal(dtypeToTensorType('|u1'),'uint8');assert.equal(dtypeToTensorType('>f4'),null);
});

test('folder target label and numeric filename become contest metadata',()=>{
  const hints=[[0,1],[2,3]];
  assert.equal(labelFromPath('dataset/1/0017.npy',hints),'1');assert.equal(labelFromPath('dataset/9/0017.npy',hints),null);assert.equal(idFromPath('dataset/1/0017.npy'),17);
});

test('explicit tensor feed JSON is accepted only when every candidate has concrete feeds',()=>{
  const sources=[{file:'bundle.json',text:JSON.stringify({hints:[[0,1]],candidates:[{id:7,assignedLabel:1,feeds:{input:{type:'float32',dims:[1,2],values:[0,1]}}}]})}];
  const found=discoverExplicitFeedBundle(sources);assert.equal(found.file,'bundle.json');assert.equal(found.candidates.length,1);
  const bad=discoverExplicitFeedBundle([{file:'bad.json',text:JSON.stringify({hints:[[0,1]],candidates:[{id:7,assignedLabel:1}]})}]);assert.equal(bad,null);
});

test('dropped challenge session invokes local ONNX autopilot after fixed-point scan',()=>{
  const source=fs.readFileSync(path.join(__dirname,'..','src','electron','challenge_session_ipc.js'),'utf8');
  assert.match(source,/runChallengeOnnxAutopilot/);assert.match(source,/newcyber_onnx_autopilot\.json/);assert.match(source,/challenge-onnx-autopilot/);
});
