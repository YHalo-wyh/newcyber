'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const fsp=require('fs/promises');
const os=require('os');
const path=require('path');
const {createBinaryArtifact}=require('../src/core/artifacts');
const {artifactCandidates,materializeRecoveredArtifacts}=require('../src/core/challenge_artifact_materialize');

test('artifact materializer writes complete verified recursive artifacts once',async(t)=>{
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-materialize-'));t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const artifact=createBinaryArtifact({name:'decoded.txt',buffer:Buffer.from('deep recovered payload'),metadata:{magic:'TEXT'}});
  const analysis={files:[{path:'seed.bin',sha256:'a'.repeat(64),metadata:{recursiveArtifacts:{artifacts:[artifact]}}}]};
  const state={materializedHashes:new Set(),materializationPass:0};
  const first=await materializeRecoveredArtifacts(root,analysis,state,{maxFiles:8,maxBytes:1024*1024,maxArtifactBytes:1024*1024});
  assert.equal(first.files.length,1);assert.equal(first.pass,1);assert.equal(state.materializationPass,1);
  const target=path.join(root,first.files[0].path);assert.equal(fs.readFileSync(target,'utf8'),'deep recovered payload');
  const second=await materializeRecoveredArtifacts(root,analysis,state,{maxFiles:8,maxBytes:1024*1024,maxArtifactBytes:1024*1024});
  assert.equal(second.files.length,0);assert.equal(state.materializationPass,1);
});

test('already indexed artifact sha is not materialized again',async(t)=>{
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-materialize-indexed-'));t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const artifact=createBinaryArtifact({name:'same.bin',buffer:Buffer.from('same')});
  const analysis={files:[{path:'same.bin',sha256:artifact.sha256,metadata:{recursiveArtifacts:{artifacts:[artifact]}}}]};
  const result=await materializeRecoveredArtifacts(root,analysis,{materializedHashes:new Set(),materializationPass:0});
  assert.equal(result.files.length,0);
});

test('candidate collector deduplicates same sha across metadata sources',()=>{
  const artifact=createBinaryArtifact({name:'dup.bin',buffer:Buffer.from('dup')});
  const analysis={files:[{path:'one.bin',artifacts:[artifact],metadata:{recursiveArtifacts:{artifacts:[artifact]},autoDecode:{candidates:[{artifact}]}}}]};
  assert.equal(artifactCandidates(analysis).length,1);
});

test('challenge session uses fixed-point materialization and recovery manifest',()=>{
  const source=fs.readFileSync(path.join(__dirname,'..','src','electron','challenge_session_ipc.js'),'utf8');
  assert.match(source,/materializeRecoveredArtifacts/);assert.match(source,/MAX_MATERIALIZATION_PASSES=2/);assert.match(source,/newcyber_recovered_manifest\.json/);assert.match(source,/recovered-artifact-materialize/);
});
