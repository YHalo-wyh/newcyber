'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const {buildPreprocessingManifest,scanSource}=require('../src/core/ai_preprocessing_manifest');

test('torchvision pipeline recovers size layout scale dtype normalize from source evidence',()=>{
  const source=`
from torchvision import transforms
preprocess = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485,0.456,0.406], std=[0.229,0.224,0.225]),
])
`;
  const result=buildPreprocessingManifest([{file:'solve.py',text:source}]);
  assert.equal(result.status,'ready');assert.equal(result.executionReady,true);
  assert.deepEqual(result.pipeline.size,{height:224,width:224});assert.equal(result.pipeline.layout,'CHW');assert.equal(result.pipeline.dtype,'float32');
  assert.equal(result.pipeline.scale.factor,1/255);assert.deepEqual(result.pipeline.normalize.mean,[0.485,0.456,0.406]);
});

test('conflicting strong resize evidence blocks execution instead of guessing',()=>{
  const source=`
a = transforms.Resize((224,224))
b = transforms.Resize((256,256))
x = transforms.ToTensor()(img)
`;
  const result=buildPreprocessingManifest([{file:'ambiguous.py',text:source}]);
  assert.equal(result.status,'conflict');assert.equal(result.executionReady,false);
  assert.ok(result.conflicts.some((item)=>item.kind==='size'));
});

test('cv2 pipeline recovers BGR to RGB, CHW, scaling and dtype',()=>{
  const source=`
img = cv2.resize(img, (128, 128))
img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
img = img.astype(np.float32) / 255.0
img = np.transpose(img, (2,0,1))
img = np.expand_dims(img, axis=0)
`;
  const result=buildPreprocessingManifest([{file:'infer.py',text:source}]);
  assert.equal(result.status,'ready');assert.deepEqual(result.pipeline.size,{height:128,width:128});assert.equal(result.pipeline.color,'RGB');assert.equal(result.pipeline.layout,'CHW');assert.equal(result.pipeline.dtype,'float32');assert.equal(result.pipeline.batch,'prepend-axis');
});

test('manifest stays not-detected when there is no preprocessing evidence',()=>{
  const result=buildPreprocessingManifest([{file:'README.md',text:'This challenge contains a model and some files.'}]);
  assert.equal(result.status,'not-detected');assert.equal(result.executionReady,false);assert.equal(result.evidence.length,0);
});

test('source scanner keeps file and line provenance for every field',()=>{
  const result=scanSource('solver.py','x = transforms.Resize((32, 64))\nx = x.float() / 255.0\n');
  assert.ok(result.evidence.some((item)=>item.kind==='size'&&item.file==='solver.py'&&item.line===1));
  assert.ok(result.evidence.some((item)=>item.kind==='dtype'&&item.line===2));
  assert.ok(result.evidence.some((item)=>item.kind==='scale'&&item.line===2));
});

test('compatibility entrypoint routes Challenge Session through batch49',()=>{
  const source=fs.readFileSync(path.join(__dirname,'..','src','core','finals_analyzer_batch15.js'),'utf8');
  assert.match(source,/finals_analyzer_batch49/);
  const wrapper=fs.readFileSync(path.join(__dirname,'..','src','core','finals_analyzer_batch49.js'),'utf8');
  assert.match(wrapper,/aiPreprocessingManifest/);assert.match(wrapper,/ai-preprocessing-manifest/);
});
