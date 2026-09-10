'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fsp=require('fs/promises');
const os=require('os');
const path=require('path');
const {bytesToUnicodeMaps}=require('../src/core/gpt2_bpe');
const {hannWeight}=require('../src/core/sca_streaming_feature_source');
const {runQualityGroupedScaAutopilotPaths}=require('../src/core/sca_quality_grouped_core');

function npy(values,shape,descr='<f4'){
  const count=shape.reduce((a,b)=>a*b,1);assert.equal(values.length,count);
  const dict=`{'descr': '${descr}', 'fortran_order': False, 'shape': (${shape.join(', ')}${shape.length===1?',':''}), }`;
  let header=dict;const pre=10;const padding=(16-((pre+Buffer.byteLength(header,'latin1')+1)%16))%16;header+=`${' '.repeat(padding)}\n`;
  const head=Buffer.alloc(pre);head[0]=0x93;head.write('NUMPY',1,'ascii');head[6]=1;head[7]=0;head.writeUInt16LE(Buffer.byteLength(header,'latin1'),8);
  const payload=Buffer.alloc(count*4);values.forEach((value,index)=>descr==='<i4'?payload.writeInt32LE(Number(value),index*4):payload.writeFloatLE(Number(value),index*4));
  return Buffer.concat([head,Buffer.from(header,'latin1'),payload]);
}

function hiddenFor(id){
  const x=(Number(id)+1)/257;
  return [0.15+0.7*x,0.2+0.3*Math.sin(x*7)+0.25*x,0.25+0.25*Math.cos(x*5)+0.2*x,0.1+0.65*((Number(id)*37)%251)/250];
}

function embeddingFor(id){
  const h=hiddenFor(id);
  return [2*h[0]+0.05,0.55*h[1]-0.03,1.6*h[2]+0.02,0.65*h[3]-0.04];
}

function leakageRows(hidden){
  const [a,b,c,d]=hidden;
  return [
    [3+1.8*a+0.4*b,2.5+0.3*a+1.4*b,3.2+0.7*a+0.2*b,2.8+0.5*a+0.9*b],
    [2.7+1.5*c+0.3*d,3.1+0.4*c+1.2*d,2.9+0.8*c+0.2*d,3.3+0.2*c+1.1*d]
  ];
}

function rawRowFromEnergy(features){
  const prefix=[0,0];const row=[...prefix];const weight=hannWeight(1,4);
  for(const energy of features){const value=Math.sqrt(energy)/weight;row.push(0,value,0,0);}
  assert.equal(row.length,18);return row;
}

function byteVocab(){
  const maps=bytesToUnicodeMaps();const vocab={};for(const [byte,ch] of maps.encoder.entries())vocab[ch]=byte;return JSON.stringify(vocab);
}

function fakeOrt(flagBytes){
  class Tensor{constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}}
  const next=new Map();for(let i=0;i<flagBytes.length-1;i++)next.set(flagBytes[i],flagBytes[i+1]);
  const session={
    inputNames:['token_ids'],outputNames:['lm_logits','last_hidden_state'],
    inputMetadata:[{type:'tensor(int64)',dimensions:[1,'sequence']}],
    outputMetadata:[{type:'tensor(float)',dimensions:[1,'sequence',256]},{type:'tensor(float)',dimensions:[1,'sequence',4]}],
    async run(feeds,fetches){
      const ids=Array.from(feeds.token_ids.data,Number);const seq=ids.length;const out={};
      if(!fetches||Object.prototype.hasOwnProperty.call(fetches,'last_hidden_state')){
        const data=new Float32Array(seq*4);for(let i=0;i<seq;i++)data.set(hiddenFor(ids[i]),i*4);out.last_hidden_state=new Tensor('float32',data,[1,seq,4]);
      }
      if(!fetches||Object.prototype.hasOwnProperty.call(fetches,'lm_logits')){
        const data=new Float32Array(seq*256);data.fill(-20);
        for(let i=0;i<seq;i++){const chosen=next.get(ids[i])??0;data[i*256+chosen]=20;}
        out.lm_logits=new Tensor('float32',data,[1,seq,256]);
      }
      return out;
    },async release(){}
  };
  return {Tensor,InferenceSession:{async create(){return session;}}};
}

async function makeBundle(flag='ynuctf{b50}'){
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b50-e2e-'));
  const profileIds=Array.from({length:128},(_,i)=>i);
  const profileRaw=[];for(const id of profileIds)for(const featureRow of leakageRows(hiddenFor(id)))profileRaw.push(...rawRowFromEnergy(featureRow));
  const targetIds=Array.from(Buffer.from(flag,'utf8'));const targetRaw=[];for(const id of targetIds)for(const featureRow of leakageRows(hiddenFor(id)))targetRaw.push(...rawRowFromEnergy(featureRow));
  const probe=Array.from({length:256},(_,id)=>embeddingFor(id)).flat();
  await Promise.all([
    fsp.writeFile(path.join(root,'profiling_power.npy'),npy(profileRaw,[profileIds.length*2,18])),
    fsp.writeFile(path.join(root,'target_power.npy'),npy(targetRaw,[targetIds.length*2,18])),
    fsp.writeFile(path.join(root,'profiling_input_ids.npy'),npy(profileIds,[profileIds.length],'<i4')),
    fsp.writeFile(path.join(root,'probe.npy'),npy(probe,[256,4])),
    fsp.writeFile(path.join(root,'candidate_token_ids.npy'),npy(Array.from({length:256},(_,i)=>i),[256],'<i4')),
    fsp.writeFile(path.join(root,'model.onnx'),Buffer.from([1,2,3,4])),
    fsp.writeFile(path.join(root,'vocab.json'),byteVocab()),
    fsp.writeFile(path.join(root,'merges.txt'),'#version: 0.2\n'),
    fsp.writeFile(path.join(root,'solve_template.py'),`HIDDEN_DIM = 4\nGROUP_SIZE = 2\nTRACE_DIM = 4\nSAMPLES_PER_TRACE = 4\nFEATURE_OFFSET = 2\nw = np.hanning(SAMPLES_PER_TRACE)\nfeatures = [np.sum((trace[FEATURE_OFFSET + i*SAMPLES_PER_TRACE:FEATURE_OFFSET + (i+1)*SAMPLES_PER_TRACE] * w) ** 2) for i in range(TRACE_DIM)]\n`)
  ]);
  return {root,flag,targetIds};
}

async function paths(root){return (await fsp.readdir(root)).map((name)=>path.join(root,name));}

test('Batch50 mini end-to-end closes raw Hann traces through calibrated probe and unknown-prefix oracle',async(t)=>{
  const bundle=await makeBundle();t.after(()=>fsp.rm(bundle.root,{recursive:true,force:true}));
  const result=await runQualityGroupedScaAutopilotPaths(await paths(bundle.root),{
    ort:fakeOrt(bundle.targetIds),provider:'cpu',version:'fixture',probeCalibration:{minCosineGain:0}
  });
  const diagnostic=JSON.stringify({status:result.status,flag:result.flag,gap:result.gap,stages:result.stages,recipe:result.featureRecipe,calibration:result.probeCalibration,oracle:result.unknownPrefixOracle},null,2);
  assert.equal(result.schema,'newcyber.sca-autopilot.v4',diagnostic);
  assert.equal(result.status,'flag-recovered',diagnostic);
  // The generic flag extractor is intentionally prefix-agnostic and normalizes the
  // embedded token "ctf{...}". The oracle text must still preserve the exact recovered
  // byte stream so challenge-specific prefixes are never invented by the verifier.
  assert.equal(result.unknownPrefixOracle.recoveredText,bundle.flag,diagnostic);
  assert.equal(result.flag,'ctf{b50}',diagnostic);
  assert.equal(result.featureRecipe.windowFunction,'hann',diagnostic);
  assert.equal(result.featureRecipe.rawCols,18,diagnostic);
  assert.equal(result.featureRecipe.slots,4,diagnostic);
  assert.equal(result.featureRecipe.offset,2,diagnostic);
  assert.ok(result.profile.r2>0.99,diagnostic);
  assert.equal(result.probeCalibration.status,'accepted',diagnostic);
  assert.equal(result.unknownPrefixOracle.status,'flag-recovered',diagnostic);
  assert.equal(result.unknownPrefixOracle.mode,'candidate-guided',diagnostic);
  assert.ok(result.stages.some((item)=>item.id==='feature-recipe'&&item.status==='ok'),diagnostic);
  assert.ok(result.stages.some((item)=>item.id==='probe-calibration'&&item.status==='ok'),diagnostic);
  assert.ok(result.stages.some((item)=>item.id==='unknown-prefix-oracle'&&item.status==='ok'),diagnostic);
});