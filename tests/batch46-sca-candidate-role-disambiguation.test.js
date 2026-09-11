'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fsp=require('fs/promises');
const os=require('os');
const path=require('path');
const {explicitCandidateIdFile,resolveCandidateIds}=require('../src/core/sca_autopilot_grouped_core');

function int32Npy(values){
  const shape=`(${values.length},)`;
  let header=`{'descr': '<i4', 'fortran_order': False, 'shape': ${shape}, }`;
  const pre=10;const padding=(16-((pre+Buffer.byteLength(header,'latin1')+1)%16))%16;header+=`${' '.repeat(padding)}\n`;
  const head=Buffer.alloc(pre);head[0]=0x93;head.write('NUMPY',1,'ascii');head[6]=1;head[7]=0;head.writeUInt16LE(Buffer.byteLength(header,'latin1'),8);
  const payload=Buffer.alloc(values.length*4);values.forEach((value,index)=>payload.writeInt32LE(Number(value),index*4));
  return Buffer.concat([head,Buffer.from(header,'latin1'),payload]);
}

function file(filePath){return {filePath,fileName:path.basename(filePath),extension:path.extname(filePath).toLowerCase()};}

test('Batch46 candidate map prefers one explicit candidate/vocab filename over profiling token-id collision',async(t)=>{
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b46-role-'));t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const profiling=path.join(root,'profiling_token_ids.npy');
  const candidate=path.join(root,'candidate_token_ids.npy');
  await fsp.writeFile(profiling,int32Npy([91,92,93,94]));
  await fsp.writeFile(candidate,int32Npy([10,20,30,40]));
  const profileFile=file(profiling),candidateFile=file(candidate);
  const discovery={
    manifest:{},files:[profileFile,candidateFile],
    roles:{candidateIds:{status:'ambiguous',files:[profileFile.fileName,candidateFile.fileName]}}
  };
  const explicit=explicitCandidateIdFile(discovery);
  assert.equal(explicit.status,'ok');
  assert.equal(explicit.file.fileName,'candidate_token_ids.npy');
  const result=await resolveCandidateIds(discovery,4);
  assert.equal(result.status,'ok');
  assert.deepEqual(result.ids,[10,20,30,40]);
  assert.equal(result.source,'explicit candidate/vocab filename');
});

test('Batch46 candidate map remains fail-closed when two explicit candidate maps exist',async(t)=>{
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b46-role-amb-'));t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const a=path.join(root,'candidate_token_ids.npy');
  const b=path.join(root,'vocab_token_ids.npy');
  const profiling=path.join(root,'profiling_token_ids.npy');
  await Promise.all([fsp.writeFile(a,int32Npy([1,2])),fsp.writeFile(b,int32Npy([1,2])),fsp.writeFile(profiling,int32Npy([7,8]))]);
  const files=[file(a),file(b),file(profiling)];
  const discovery={manifest:{},files,roles:{candidateIds:{status:'ambiguous',files:files.map((x)=>x.fileName)}}};
  const explicit=explicitCandidateIdFile(discovery);
  assert.equal(explicit.status,'ambiguous');
  const result=await resolveCandidateIds(discovery,2);
  assert.equal(result.status,'gap');
  assert.equal(result.code,'TOKEN_ID_MAP_GAP');
  assert.match(result.detail,/强证据仍不唯一/);
});

test('Batch46 candidate map does not reinterpret profile, training, prompt, or known token files as candidates',()=>{
  const files=['profiling_token_ids.npy','training_input_ids.npy','prompt_token_ids.npy','known_token_ids.npy'].map((name)=>({fileName:name,filePath:`/tmp/${name}`,extension:'.npy'}));
  const result=explicitCandidateIdFile({files});
  assert.equal(result.status,'missing');
});

test('Batch46 candidate filename evidence uses semantic tokens instead of id substrings',()=>{
  const falsePositives=['candidate_grid.npy','candidate_identity.npy','vocab_hidden.npy','vocabulary_embedding.npy'].map((name)=>({fileName:name,filePath:`/tmp/${name}`,extension:'.npy'}));
  assert.equal(explicitCandidateIdFile({files:falsePositives}).status,'missing');
  for(const name of ['candidate_ids.npy','candidate-token-ids.npy','vocab_token_ids.npy','vocabulary-input-ids.npy']){
    const only={fileName:name,filePath:`/tmp/${name}`,extension:'.npy'};
    const result=explicitCandidateIdFile({files:[only]});
    assert.equal(result.status,'ok',name);
    assert.equal(result.file.fileName,name);
  }
});
