'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const fsp=require('fs/promises');
const os=require('os');
const path=require('path');
const {fitLeakageProfile}=require('../src/core/side_channel_probe');
const {bytesToUnicodeMaps}=require('../src/core/gpt2_bpe');
const {discoverScaArtifacts,runScaAutopilotPaths}=require('../src/core/sca_autopilot');

function npy(values,shape,descr='<f4'){
  const count=shape.reduce((a,b)=>a*b,1);
  assert.equal(values.length,count);
  const dict=`{'descr': '${descr}', 'fortran_order': False, 'shape': (${shape.join(', ')}${shape.length===1?',':''}), }`;
  let header=dict;
  const pre=10;
  const padding=(16-((pre+header.length+1)%16))%16;
  header+=`${' '.repeat(padding)}\n`;
  const head=Buffer.alloc(pre);
  head[0]=0x93;head.write('NUMPY',1,'ascii');head[6]=1;head[7]=0;head.writeUInt16LE(Buffer.byteLength(header),8);
  let payload;
  if(descr==='<f4'){
    payload=Buffer.alloc(count*4);values.forEach((value,index)=>payload.writeFloatLE(Number(value),index*4));
  }else if(descr==='<i4'){
    payload=Buffer.alloc(count*4);values.forEach((value,index)=>payload.writeInt32LE(Number(value),index*4));
  }else throw new Error('fixture dtype');
  return Buffer.concat([head,Buffer.from(header,'latin1'),payload]);
}

function hiddenFor(id){
  const x=Number(id);
  return [x/255,((x*7)%29)/28,((x*x+3*x)%37)/36,((x*11+5)%41)/40];
}
function leakageFor(hidden){
  const [a,b,c,d]=hidden;
  return [1+2*a-b+.5*c,.3-a+1.7*b+.25*d,-2+.4*a+.8*c-1.2*d,3-.5*b+2*c+.1*d,-1+a+b+c+d];
}

function fakeOrt(targetText){
  class Tensor{constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}}
  const target=Buffer.from(targetText,'utf8');
  const session={
    inputNames:['token_ids'],
    outputNames:['lm_logits','last_hidden_state'],
    inputMetadata:[{type:'tensor(int64)',dimensions:[1,'sequence']}],
    outputMetadata:[{type:'tensor(float)',dimensions:[1,'sequence',256]},{type:'tensor(float)',dimensions:[1,'sequence',4]}],
    async run(feeds,fetches){
      const ids=Array.from(feeds.token_ids.data,Number);
      const seq=ids.length;
      const out={};
      if(!fetches||Object.prototype.hasOwnProperty.call(fetches,'last_hidden_state')){
        const data=new Float32Array(seq*4);
        for(let i=0;i<seq;i+=1)data.set(hiddenFor(ids[i]),i*4);
        out.last_hidden_state=new Tensor('float32',data,[1,seq,4]);
      }
      if(!fetches||Object.prototype.hasOwnProperty.call(fetches,'lm_logits')){
        const logits=new Float32Array(seq*256).fill(-20);
        const next=target[Math.max(0,seq-1)]??125;
        logits[(seq-1)*256+next]=20;
        out.lm_logits=new Tensor('float32',logits,[1,seq,256]);
      }
      return out;
    },
    async release(){}
  };
  return {Tensor,InferenceSession:{async create(){return session;}}};
}

function byteVocab(){
  const maps=bytesToUnicodeMaps();const vocab={};
  for(const [byte,ch] of maps.encoder.entries())vocab[ch]=byte;
  return JSON.stringify(vocab);
}

async function makeBundle(options={}){
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b35-'));
  const target=options.target||'flag{sca_auto}';
  const profileIds=Array.from({length:96},(_,i)=>(i*19+7)%256);
  const profileLeak=profileIds.flatMap((id)=>leakageFor(hiddenFor(id)));
  const targetIds=Array.from(Buffer.from(target,'utf8'));
  const targetLeak=targetIds.flatMap((id)=>leakageFor(hiddenFor(id)));
  const probe=Array.from({length:256},(_,id)=>hiddenFor(id)).flat();
  const files={
    profileTrace:path.join(root,'profiling_power.npy'),
    targetTrace:path.join(root,'target_power.npy'),
    profileTokenIds:path.join(root,'profiling_token_ids.npy'),
    probe:path.join(root,'probe.npy'),
    model:path.join(root,'model.onnx'),
    manifest:path.join(root,'newcyber_sca.json'),
    vocab:path.join(root,'vocab.json'),
    merges:path.join(root,'merges.txt')
  };
  await fsp.writeFile(files.profileTrace,npy(profileLeak,[profileIds.length,5]));
  await fsp.writeFile(files.targetTrace,npy(targetLeak,[targetIds.length,5]));
  await fsp.writeFile(files.profileTokenIds,npy(profileIds,[profileIds.length],'<i4'));
  await fsp.writeFile(files.probe,npy(probe,[256,4]));
  await fsp.writeFile(files.model,Buffer.from([1,2,3]));
  await fsp.writeFile(files.vocab,byteVocab());
  await fsp.writeFile(files.merges,'#version: 0.2\n');
  const manifest={
    schema:'newcyber.sca-autopilot.recipe.v1',
    profileTrace:'profiling_power.npy',targetTrace:'target_power.npy',profileTokenIds:'profiling_token_ids.npy',probe:'probe.npy',model:'model.onnx',
    promptTokenIds:[65],featureMode:'raw-row',leakageDim:5,probeOrientation:'candidate-rows',candidateIdsIdentity:true,probeMetric:'negative-l2',topK:6,maxNewTokens:targetIds.length
  };
  if(options.manifestPatch)Object.assign(manifest,options.manifestPatch);
  await fsp.writeFile(files.manifest,JSON.stringify(manifest,null,2));
  return {root,target,paths:Object.values(files).filter((p)=>!p.endsWith('vocab.json')&&!p.endsWith('merges.txt')),files};
}

test('Batch35 dual leakage ridge handles hidden dimensions above the old 256 cap',()=>{
  const hidden=[];const leakage=[];
  for(let r=0;r<48;r+=1){
    const row=Array.from({length:333},(_,d)=>Math.sin((r+1)*(d+3)*.017)+Math.cos((r+5)*(d+1)*.009));
    hidden.push(row);
    leakage.push([1+row[2]*.5-row[71]*1.2+row[210]*.3,-2+row[8]-.4*row[99]+.8*row[301]]);
  }
  const profile=fitLeakageProfile(hidden,leakage,{lambda:1e-6});
  assert.equal(profile.status,'ok');
  assert.equal(profile.hiddenDim,333);
  assert.equal(profile.solveDim,48);
  assert.equal(profile.method,'ridge-dual-cholesky');
  assert.ok(profile.r2>.999);
});

test('Batch35 artifact discovery rejects tied profiling trace roles instead of choosing by size',async(t)=>{
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b35-amb-'));t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const a=path.join(root,'profiling_trace_a.npy');const b=path.join(root,'profiling_trace_b.npy');
  await fsp.writeFile(a,npy([1,2,3,4],[2,2]));await fsp.writeFile(b,npy([1,2,3,4],[2,2]));
  const discovery=await discoverScaArtifacts([a,b]);
  assert.equal(discovery.status,'ok');
  assert.equal(discovery.roles.profileTrace.status,'ambiguous');
});

test('Batch35 safetensors-only challenge stops at ORACLE_ARTIFACT_GAP without implicit Python conversion',async(t)=>{
  const bundle=await makeBundle();t.after(()=>fsp.rm(bundle.root,{recursive:true,force:true}));
  await fsp.unlink(bundle.files.model);await fsp.writeFile(path.join(bundle.root,'model.safetensors'),Buffer.from('{}'));
  const manifest=JSON.parse(await fsp.readFile(bundle.files.manifest,'utf8'));delete manifest.model;await fsp.writeFile(bundle.files.manifest,JSON.stringify(manifest));
  const paths=(await fsp.readdir(bundle.root)).map((name)=>path.join(bundle.root,name));
  const result=await runScaAutopilotPaths(paths,{ort:fakeOrt(bundle.target)});
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'ORACLE_ARTIFACT_GAP');
  assert.match(result.gap.detail,/safetensors/i);
});

test('Batch35 square probe without orientation evidence stops at PROBE_ORIENTATION_GAP',async(t)=>{
  const bundle=await makeBundle({manifestPatch:{probeOrientation:null}});t.after(()=>fsp.rm(bundle.root,{recursive:true,force:true}));
  const square=[];for(let r=0;r<4;r++)for(let c=0;c<4;c++)square.push(r===c?1:0);
  await fsp.writeFile(bundle.files.probe,npy(square,[4,4]));
  const manifest=JSON.parse(await fsp.readFile(bundle.files.manifest,'utf8'));delete manifest.probeOrientation;manifest.candidateIds=[0,1,2,3];await fsp.writeFile(bundle.files.manifest,JSON.stringify(manifest));
  const result=await runScaAutopilotPaths((await fsp.readdir(bundle.root)).map((name)=>path.join(bundle.root,name)),{ort:fakeOrt(bundle.target)});
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'PROBE_ORIENTATION_GAP');
});

test('Batch35 trace→profile hidden→leakage→probe→Transformer chain recovers a verified flag',async(t)=>{
  const bundle=await makeBundle();t.after(()=>fsp.rm(bundle.root,{recursive:true,force:true}));
  const paths=(await fsp.readdir(bundle.root)).map((name)=>path.join(bundle.root,name));
  const result=await runScaAutopilotPaths(paths,{ort:fakeOrt(bundle.target),provider:'cpu',version:'fixture'});
  assert.equal(result.status,'flag-recovered');
  assert.equal(result.flag,bundle.target);
  assert.equal(result.profile.hiddenDim,4);
  assert.ok(result.profile.r2>.999999);
  assert.equal(result.target.rows,Buffer.byteLength(bundle.target));
  assert.equal(result.target.candidates[0][0].tokenId,Buffer.from(bundle.target)[0]);
  assert.equal(result.oracle.status,'flag-recovered');
  assert.ok(result.stages.some((item)=>item.id==='flag'&&item.status==='ok'));
});

test('Batch35 core/UI contract stays recipe-driven rather than generic textarea inference',()=>{
  const core=fs.readFileSync(path.join(__dirname,'..','src','core','sca_autopilot.js'),'utf8');
  assert.match(core,/ORACLE_ARTIFACT_GAP/);
  assert.match(core,/PROBE_ORIENTATION_GAP/);
  assert.match(core,/TOKEN_ID_MAP_GAP/);
  assert.match(core,/candidateIdsIdentity/);
  assert.doesNotMatch(core,/exec\s*\(|spawn\s*\(|python\s+/i);
});
