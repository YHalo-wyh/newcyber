'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const fsp=require('fs/promises');
const os=require('os');
const path=require('path');
const {bytesToUnicodeMaps}=require('../src/core/gpt2_bpe');
const {openNpyRowSource}=require('../src/core/npy_row_source');
const {resolveGroupedLayout}=require('../src/core/sca_grouped_leakage');
const {runScaAutopilotPaths}=require('../src/core/sca_autopilot_batch42');
const groupedCore=require('../src/core/sca_autopilot_grouped_core');
const {promoteWorkspaceScaResult}=require('../src/core/finals_analyzer_batch35');

function npy(values,shape,descr='<f4'){
  const count=shape.reduce((a,b)=>a*b,1);
  assert.equal(values.length,count);
  const dict=`{'descr': '${descr}', 'fortran_order': False, 'shape': (${shape.join(', ')}${shape.length===1?',':''}), }`;
  let header=dict;
  const pre=10;
  const padding=(16-((pre+Buffer.byteLength(header,'latin1')+1)%16))%16;
  header+=`${' '.repeat(padding)}\n`;
  const head=Buffer.alloc(pre);
  head[0]=0x93;head.write('NUMPY',1,'ascii');head[6]=1;head[7]=0;head.writeUInt16LE(Buffer.byteLength(header,'latin1'),8);
  let payload;
  if(descr==='<f4'){
    payload=Buffer.alloc(count*4);values.forEach((value,index)=>payload.writeFloatLE(Number(value),index*4));
  }else if(descr==='<i4'){
    payload=Buffer.alloc(count*4);values.forEach((value,index)=>payload.writeInt32LE(Number(value),index*4));
  }else throw new Error('fixture dtype');
  return Buffer.concat([head,Buffer.from(header,'latin1'),payload]);
}

function objectNpy(picklePayload,shape='(1,)'){
  const dict=`{'descr': '|O', 'fortran_order': False, 'shape': ${shape}, }`;
  let header=dict;
  const pre=10;
  const padding=(16-((pre+Buffer.byteLength(header,'latin1')+1)%16))%16;
  header+=`${' '.repeat(padding)}\n`;
  const head=Buffer.alloc(pre);
  head[0]=0x93;head.write('NUMPY',1,'ascii');head[6]=1;head[7]=0;head.writeUInt16LE(Buffer.byteLength(header,'latin1'),8);
  return Buffer.concat([head,Buffer.from(header,'latin1'),picklePayload]);
}

const REAL_NUMPY_OBJECT_FIXTURE=Buffer.from(
  'k05VTVBZAQB2AHsnZGVzY3InOiAnfE8nLCAnZm9ydHJhbl9vcmRlcic6IEZhbHNlLCAnc2hhcGUnOiAoMiwpLCB9ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAqABJUSAQAAAAAAAIwWbnVtcHkuX2NvcmUubXVsdGlhcnJheZSMDF9yZWNvbnN0cnVjdJSTlIwFbnVtcHmUjAduZGFycmF5lJOUSwCFlEMBYpSHlFKUKEsBSwKFlGgDjAVkdHlwZZSTlIwCTziUiYiHlFKUKEsDjAF8lE5OTkr/////Sv////9LP3SUYoldlChoAmgFSwCFlGgHh5RSlChLAUsCSwOGlGgMjAJmNJSJiIeUUpQoSwOMATyUTk5OSv////9K/////0sAdJRiiUMYAACAPwAAAEAAAEBAAACAQAAAoEAAAMBAlHSUYmgCaAVLAIWUaAeHlFKUKEsBSwFLA4aUaBmJQwwAAOBAAAAAQQAAEEGUdJRiZXSUYi4=',
  'base64'
);

function hiddenFor(id){
  const x=Number(id);
  return [x/255,((x*7)%29)/28,((x*x+3*x)%37)/36,((x*11+5)%41)/40];
}

function groupedLeakage(hidden){
  const [a,b,c,d]=hidden;
  return [
    [1+2*a-b,.5+a+3*b,-1+.2*a-.4*b],
    [2+1.5*c-d,-.2+.4*c+2*d,1-c+.3*d]
  ];
}

function fakeOrt(){
  class Tensor{constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}}
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
        for(let i=0;i<seq;i++)data.set(hiddenFor(ids[i]),i*4);
        out.last_hidden_state=new Tensor('float32',data,[1,seq,4]);
      }
      if(!fetches||Object.prototype.hasOwnProperty.call(fetches,'lm_logits')){
        out.lm_logits=new Tensor('float32',new Float32Array(seq*256),[1,seq,256]);
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

async function makeGroupedBundle(target='flag{grouped_free_probe}'){
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b42-'));
  const profileIds=Array.from({length:128},(_,i)=>(i*37+11)%256);
  const profileRows=[];
  for(const id of profileIds)for(const row of groupedLeakage(hiddenFor(id)))profileRows.push(...row);
  const targetIds=Array.from(Buffer.from(target,'utf8'));
  const targetRows=[];
  for(const id of targetIds)for(const row of groupedLeakage(hiddenFor(id)))targetRows.push(...row);
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
  await fsp.writeFile(files.profileTrace,npy(profileRows,[profileIds.length*2,3]));
  await fsp.writeFile(files.targetTrace,npy(targetRows,[targetIds.length*2,3]));
  await fsp.writeFile(files.profileTokenIds,npy(profileIds,[profileIds.length],'<i4'));
  await fsp.writeFile(files.probe,npy(probe,[256,4]));
  await fsp.writeFile(files.model,Buffer.from([1,2,3]));
  await fsp.writeFile(files.vocab,byteVocab());
  await fsp.writeFile(files.merges,'#version: 0.2\n');
  await fsp.writeFile(files.manifest,JSON.stringify({
    schema:'newcyber.sca-autopilot.recipe.v2',
    profileTrace:'profiling_power.npy',
    targetTrace:'target_power.npy',
    profileTokenIds:'profiling_token_ids.npy',
    probe:'probe.npy',
    model:'model.onnx',
    groupedLeakage:{rowsPerToken:2,hiddenPerGroup:2,rowFeatureDim:3},
    probeOrientation:'candidate-rows',candidateIdsIdentity:true,probeMetric:'negative-l2',topK:4,
    profileOptions:{lambda:1e-8}
  },null,2));
  return {root,target,files};
}

test('Batch42 resolves the real 287424-row shape as 5988 tokens × 48 groups × 16 hidden only with source evidence',()=>{
  const layout=resolveGroupedLayout({
    sourceText:'GROUP_SIZE = 16\nTRACE_DIM = 64\n',manifest:{},
    profileRows:287424,profileTokens:5988,hiddenDim:768,rowFeatureDim:64
  });
  assert.equal(layout.status,'ok');
  assert.equal(layout.groupsPerToken,48);
  assert.equal(layout.hiddenPerGroup,16);
  assert.equal(layout.hiddenDim,768);
  assert.equal(layout.rowFeatureDim,64);

  const noEvidence=resolveGroupedLayout({manifest:{},sourceText:'',profileRows:287424,profileTokens:5988,hiddenDim:768,rowFeatureDim:64});
  assert.notEqual(noEvidence.status,'ok');
});

test('Batch42 restricted NumPy object-array reader flattens real numeric ndarray segments without Python execution',async(t)=>{
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b42-object-'));
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const file=path.join(root,'profiling_segments.npy');
  await fsp.writeFile(file,REAL_NUMPY_OBJECT_FIXTURE);
  const source=await openNpyRowSource(file);
  t.after(()=>source.close());
  assert.equal(source.sourceKind,'object-segments');
  assert.equal(source.rows,3);
  assert.equal(source.cols,3);
  assert.equal(source.segments.length,2);
  assert.equal(source.pickle.safety,'restricted-allowlist-no-execution');
  const rows=await source.readRows(1,2);
  assert.deepEqual(rows.map((row)=>row.map((v)=>Math.round(v))),[[4,5,6],[7,8,9]]);
});

test('Batch42 object-array reader rejects an untrusted pickle global before any callable can run',async(t)=>{
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b42-badpickle-'));
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const file=path.join(root,'evil.npy');
  const payload=Buffer.from([0x80,0x04,0x63,...Buffer.from('os\nsystem\n','ascii'),0x2e]);
  await fsp.writeFile(file,objectNpy(payload));
  await assert.rejects(()=>openNpyRowSource(file),/os\.system.*allowlist/i);
});

test('Batch42 frozen grouped core keeps unknown-prefix free-probe flag at candidate confidence',async(t)=>{
  const bundle=await makeGroupedBundle();
  t.after(()=>fsp.rm(bundle.root,{recursive:true,force:true}));
  const paths=(await fsp.readdir(bundle.root)).map((name)=>path.join(bundle.root,name));
  const result=await groupedCore.runGroupedScaAutopilotPaths(paths,{ort:fakeOrt(),provider:'cpu',version:'fixture'});
  assert.equal(result.status,'flag-candidate');
  assert.equal(result.flag,null);
  assert.equal(result.flagCandidate,bundle.target);
  assert.equal(result.freeProbe.text,bundle.target);
  assert.ok(result.stages.some((item)=>item.id==='free-probe'&&item.status==='ok'));
  assert.ok(result.stages.some((item)=>item.id==='flag-candidate'&&item.status==='ok'));
});

test('Batch42 modern compatibility may promote only after complete contextual hidden verification',async(t)=>{
  const bundle=await makeGroupedBundle();
  t.after(()=>fsp.rm(bundle.root,{recursive:true,force:true}));
  const paths=(await fsp.readdir(bundle.root)).map((name)=>path.join(bundle.root,name));
  const result=await runScaAutopilotPaths(paths,{ort:fakeOrt(),provider:'cpu',version:'fixture'});
  const diagnostic=JSON.stringify({status:result.status,flag:result.flag,contextual:result.contextualHiddenOracle,verifiedRecovery:result.verifiedRecovery},null,2);
  assert.equal(result.status,'flag-recovered',diagnostic);
  assert.equal(result.flag,bundle.target,diagnostic);
  assert.equal(result.layout.groupsPerToken,2);
  assert.equal(result.layout.hiddenPerGroup,2);
  assert.equal(result.profile.hiddenDim,4);
  assert.equal(result.profile.groupsPerToken,2);
  assert.ok(result.profile.r2>.999999);
  assert.equal(result.freeProbe.text,bundle.target);
  assert.equal(result.contextualHiddenOracle.status,'decoded',diagnostic);
  assert.equal(result.contextualHiddenOracle.recoveredText,bundle.target,diagnostic);
  assert.equal(result.contextualHiddenOracle.recoveredTokenIds.length,Buffer.byteLength(bundle.target),diagnostic);
  assert.ok(result.contextualHiddenOracle.positions.every((item)=>item.status==='matched'&&item.cosine>=result.contextualHiddenOracle.threshold),diagnostic);
  assert.equal(result.verifiedRecovery.method,'contextual-hidden-oracle',diagnostic);
  assert.ok(result.stages.some((item)=>item.id==='group-layout'&&item.status==='ok'));
  assert.ok(result.stages.some((item)=>item.id==='free-probe'&&item.status==='ok'));
  assert.ok(result.stages.some((item)=>item.id==='flag'&&item.status==='ok'));
});

test('Batch42 Workspace promotion keeps free-probe flags as candidate confidence',()=>{
  const analysis={
    scaAutopilot:{status:'flag-candidate',result:{
      status:'flag-candidate',flag:null,flagCandidate:'flag{candidate_only}',
      profile:{status:'ok',method:'streaming-ridge-token-groups',rows:10,hiddenDim:768,leakageDim:3072},
      layout:{groupsPerToken:48,hiddenPerGroup:16},target:{rows:4},stages:[{id:'free-probe',status:'ok'}],
      discovery:{manifestFile:{fileName:'newcyber_sca.json'}}
    }},
    candidates:{flags:[],urls:[],ips:[]},autopilot:{automaticChecks:[],actions:[],summary:{}},insights:[]
  };
  promoteWorkspaceScaResult(analysis);
  const item=analysis.candidates.flags.find((candidate)=>candidate.value==='flag{candidate_only}');
  assert.ok(item);
  assert.equal(item.confidence,'candidate');
  assert.notEqual(item.confidence,'verified');
  assert.ok(analysis.autopilot.actions.some((action)=>action.id==='sca-autopilot-candidate'));
});

test('Batch42 production surfaces reference the grouped wrapper and dedicated stages',()=>{
  const finals=fs.readFileSync(path.join(__dirname,'..','src','core','finals_analyzer_batch35.js'),'utf8');
  const bridge=fs.readFileSync(path.join(__dirname,'..','src','core','hf_sca_bridge.js'),'utf8');
  const ipc=fs.readFileSync(path.join(__dirname,'..','src','electron','ai_sca_ipc.js'),'utf8');
  const ui=fs.readFileSync(path.join(__dirname,'..','renderer','sca_autopilot_tools.js'),'utf8');
  assert.match(finals,/sca_autopilot_batch42/);
  assert.match(bridge,/sca_autopilot_batch42/);
  assert.match(ipc,/sca_autopilot_batch42/);
  assert.match(ui,/OBJECT FLATTEN/);
  assert.match(ui,/GROUP LAYOUT/);
  assert.match(ui,/FREE PROBE/);
  assert.match(ui,/FLAG CANDIDATE/);
});
