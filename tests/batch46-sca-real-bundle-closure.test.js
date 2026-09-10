'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fsp=require('fs/promises');
const os=require('os');
const path=require('path');
const {bytesToUnicodeMaps}=require('../src/core/gpt2_bpe');
const batch46=require('../src/core/sca_autopilot_batch46');
const compatBatch42=require('../src/core/sca_autopilot_batch42');
const {runScaAutopilotPaths,inferGroupedProfileShape}=batch46;
const {resolveProfileTokenSequences}=require('../src/core/sca_profile_label_source');

function npy(values,shape,descr='<f4'){
  const count=shape.reduce((a,b)=>a*b,1);assert.equal(values.length,count);
  const dict=`{'descr': '${descr}', 'fortran_order': False, 'shape': (${shape.join(', ')}${shape.length===1?',':''}), }`;
  let header=dict;const pre=10;const padding=(16-((pre+Buffer.byteLength(header,'latin1')+1)%16))%16;header+=`${' '.repeat(padding)}\n`;
  const head=Buffer.alloc(pre);head[0]=0x93;head.write('NUMPY',1,'ascii');head[6]=1;head[7]=0;head.writeUInt16LE(Buffer.byteLength(header,'latin1'),8);
  const payload=Buffer.alloc(count*4);
  values.forEach((value,index)=>descr==='<i4'?payload.writeInt32LE(Number(value),index*4):payload.writeFloatLE(Number(value),index*4));
  return Buffer.concat([head,Buffer.from(header,'latin1'),payload]);
}

function hiddenFor(id){const x=Number(id);return [x/255,((x*7)%29)/28,((x*x+3*x)%37)/36,((x*11+5)%41)/40];}
function groupedLeakage(hidden){const [a,b,c,d]=hidden;return [[1+2*a-b,.5+a+3*b,-1+.2*a-.4*b],[2+1.5*c-d,-.2+.4*c+2*d,1-c+.3*d]];}
function byteVocab(){const maps=bytesToUnicodeMaps();const vocab={};for(const [byte,ch] of maps.encoder.entries())vocab[ch]=byte;return JSON.stringify(vocab);}
function fakeOrt(){
  class Tensor{constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}}
  const session={inputNames:['token_ids'],outputNames:['lm_logits','last_hidden_state'],inputMetadata:[{type:'tensor(int64)',dimensions:[1,'sequence']}],outputMetadata:[{type:'tensor(float)',dimensions:[1,'sequence',256]},{type:'tensor(float)',dimensions:[1,'sequence',4]}],async run(feeds,fetches){
    const ids=Array.from(feeds.token_ids.data,Number);const seq=ids.length;const out={};
    if(!fetches||Object.prototype.hasOwnProperty.call(fetches,'last_hidden_state')){const data=new Float32Array(seq*4);for(let i=0;i<seq;i++)data.set(hiddenFor(ids[i]),i*4);out.last_hidden_state=new Tensor('float32',data,[1,seq,4]);}
    if(!fetches||Object.prototype.hasOwnProperty.call(fetches,'lm_logits'))out.lm_logits=new Tensor('float32',new Float32Array(seq*256),[1,seq,256]);
    return out;
  },async release(){}};
  return {Tensor,InferenceSession:{async create(){return session;}}};
}

async function makeBundle({withSourceLabels=false,target='flag{batch46_profile_labels}'}={}){
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b46-'));const profileIds=Array.from({length:128},(_,i)=>(i*37+11)%256);
  const profileRows=[];for(const id of profileIds)for(const row of groupedLeakage(hiddenFor(id)))profileRows.push(...row);
  const targetIds=Array.from(Buffer.from(target,'utf8'));const targetRows=[];for(const id of targetIds)for(const row of groupedLeakage(hiddenFor(id)))targetRows.push(...row);
  const probe=Array.from({length:256},(_,id)=>hiddenFor(id)).flat();
  await Promise.all([
    fsp.writeFile(path.join(root,'profiling_power.npy'),npy(profileRows,[profileIds.length*2,3])),
    fsp.writeFile(path.join(root,'target_power.npy'),npy(targetRows,[targetIds.length*2,3])),
    fsp.writeFile(path.join(root,'probe.npy'),npy(probe,[256,4])),
    fsp.writeFile(path.join(root,'candidate_token_ids.npy'),npy(Array.from({length:256},(_,i)=>i),[256],'<i4')),
    fsp.writeFile(path.join(root,'model.onnx'),Buffer.from([1,2,3])),
    fsp.writeFile(path.join(root,'vocab.json'),byteVocab()),
    fsp.writeFile(path.join(root,'merges.txt'),'#version: 0.2\n')
  ]);
  const labels=withSourceLabels?`\nPROFILE_TOKEN_IDS = [${profileIds.join(',')}]\n`:'';
  await fsp.writeFile(path.join(root,'solve_template.py'),`HIDDEN_DIM = 4\nGROUP_SIZE = 2\nLEAKAGE_DIM = 3\n${labels}# source proves grouped leakage; no profiling_token_ids.npy attachment\n`);
  return {root,target,profileIds};
}

async function paths(root){return (await fsp.readdir(root)).map((name)=>path.join(root,name));}

test('Batch42 compatibility import routes production callers to Batch46 dispatch',()=>{
  assert.equal(compatBatch42.runScaAutopilotPaths,batch46.runScaAutopilotPaths);
  assert.equal(typeof compatBatch42.runGroupedScaAutopilotPaths,'function');
});

test('Batch46 infers the real 287424-row grouped shape without materializing a 3072-D vector',()=>{
  const discovery={manifest:{},sourceInspection:{constants:{GROUP_SIZE:16,TRACE_DIM:64}},sourceText:'GROUP_SIZE = 16\nTRACE_DIM = 64\n'};
  const shape=inferGroupedProfileShape({profileRows:287424,rowFeatureDim:64,probeShape:[768,768],discovery});
  assert.equal(shape.status,'ok');
  assert.equal(shape.profileTokens,5988);
  assert.equal(shape.groupsPerToken,48);
  assert.equal(shape.hiddenPerGroup,16);
  assert.equal(shape.hiddenDim,768);
  assert.equal(shape.rowFeatureDim,64);
});

test('Batch46 turns missing profileTokenIds into a precise provenance gap after grouped diagnostics',async(t)=>{
  const bundle=await makeBundle({withSourceLabels:false});t.after(()=>fsp.rm(bundle.root,{recursive:true,force:true}));
  const result=await runScaAutopilotPaths(await paths(bundle.root),{ort:fakeOrt(),provider:'cpu',version:'fixture'});
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'PROFILE_LABEL_SOURCE_GAP');
  assert.match(result.gap.detail,/不会把 trace 顺序、row index 或 probe index 猜成 token ID/);
  assert.ok(result.stages.some((item)=>item.id==='group-layout'&&item.status==='ok'));
  assert.ok(result.stages.some((item)=>item.id==='profile-label'&&item.status==='gap'));
  assert.equal(result.shape.profileTokens,128);
});

test('Batch46 accepts only strongly named source label lists as profiling provenance',async()=>{
  const ids=[7,9,11];const discovery={manifest:{},roles:{profileTokenIds:{status:'missing'}},sourceText:`noise=[1,2,3]\nPROFILE_TOKEN_IDS = [${ids.join(', ')}]\n`};
  const result=await resolveProfileTokenSequences(discovery,{expectedTokens:3});
  assert.equal(result.status,'ok');
  assert.deepEqual(result.sequences,[[7],[9],[11]]);
  assert.match(result.source,/PROFILE_TOKEN_IDS/);
  const negative=await resolveProfileTokenSequences({...discovery,sourceText:'noise=[7,9,11]\n'},{expectedTokens:3});
  assert.equal(negative.code,'PROFILE_LABEL_SOURCE_GAP');
});

test('Batch46 replays provenance-backed labels through the existing Batch42 grouped solver',async(t)=>{
  const bundle=await makeBundle({withSourceLabels:true});t.after(()=>fsp.rm(bundle.root,{recursive:true,force:true}));
  const result=await runScaAutopilotPaths(await paths(bundle.root),{ort:fakeOrt(),provider:'cpu',version:'fixture'});
  const diagnostic=JSON.stringify({status:result.status,gap:result.gap,stages:result.stages,layout:result.layout,shape:result.shape},null,2);
  assert.equal(result.schema,'newcyber.sca-autopilot.v3',diagnostic);
  assert.equal(result.status,'flag-candidate',diagnostic);
  assert.equal(result.flagCandidate,bundle.target,diagnostic);
  assert.equal(result.profileLabelSource.count,bundle.profileIds.length,diagnostic);
  assert.match(result.profileLabelSource.source,/PROFILE_TOKEN_IDS/,diagnostic);
  assert.equal(result.layout.groupsPerToken,2,diagnostic);
  assert.equal(result.layout.hiddenPerGroup,2,diagnostic);
  assert.ok(result.stages.some((item)=>item.id==='profile-label'&&item.status==='ok'),diagnostic);
  assert.ok(result.stages.some((item)=>item.id==='free-probe'&&item.status==='ok'),diagnostic);
});