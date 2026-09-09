'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const {
  MAX_MODEL_TREE_DEPTH,
  inspectTrustedConverter,
  revalidateTrustedConverter,
  auditModelTree,
  validateConvertedOnnx
} = require('../src/core/trusted_hf_converter');
const { isSafeTensorOracleGap } = require('../src/core/hf_sca_bridge');

async function tempDir(prefix='newcyber-b37-fs-') {
  return fsp.mkdtemp(path.join(os.tmpdir(),prefix));
}

async function converter(root) {
  const filePath=path.join(root,process.platform==='win32'?'optimum-cli.exe':'optimum-cli');
  await fsp.writeFile(filePath,process.platform==='win32'?'MZ':'#!/bin/sh\nexit 0\n');
  if(process.platform!=='win32')await fsp.chmod(filePath,0o755);
  return filePath;
}

test('Batch37 model-tree depth budget fails closed instead of leaving an unaudited subtree', async (t) => {
  const root=await tempDir();
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  let current=root;
  for(let index=0;index<MAX_MODEL_TREE_DEPTH+1;index+=1){
    current=path.join(current,`d${index}`);
    await fsp.mkdir(current);
  }
  await fsp.writeFile(path.join(current,'modeling_hidden.py'),'raise SystemExit()\n');
  const result=await auditModelTree(root);
  assert.equal(result.ok,false);
  assert.equal(result.code,'MODEL_TREE_DEPTH_GAP');
});

test('Batch37 trusted converter descriptor cannot be replayed across platform metadata', async (t) => {
  const root=await tempDir();
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const descriptor=await inspectTrustedConverter(await converter(root));
  await assert.rejects(()=>revalidateTrustedConverter({...descriptor,platform:descriptor.platform==='linux'?'win32':'linux'}),/平台|架构/);
});

test('Batch37 ONNX validation rejects a symlink output root', async (t) => {
  const root=await tempDir();
  const real=await tempDir();
  t.after(async()=>{await fsp.rm(root,{recursive:true,force:true});await fsp.rm(real,{recursive:true,force:true});});
  await fsp.writeFile(path.join(real,'model.onnx'),'onnx');
  const link=path.join(root,'output');
  try {
    await fsp.symlink(real,link,'dir');
  } catch(error) {
    if(process.platform==='win32')return;
    throw error;
  }
  await assert.rejects(()=>validateConvertedOnnx(link,{ort:{}}),/非符号链接目录/);
});

test('Batch37 SCA conversion eligibility requires the exact SafeTensors oracle-artifact gap', () => {
  const eligible={
    status:'gap',
    gap:{code:'ORACLE_ARTIFACT_GAP'},
    discovery:{safetensors:[{fileName:'model.safetensors'}],roles:{model:{status:'missing'}}}
  };
  assert.equal(isSafeTensorOracleGap(eligible),true);
  assert.equal(isSafeTensorOracleGap({...eligible,gap:{code:'MODEL_RUNTIME_GAP'}}),false);
  assert.equal(isSafeTensorOracleGap({...eligible,discovery:{...eligible.discovery,safetensors:[]}}),false);
  assert.equal(isSafeTensorOracleGap({...eligible,discovery:{...eligible.discovery,roles:{model:{status:'ok',file:{fileName:'model.onnx'}}}}}),false);
  assert.equal(isSafeTensorOracleGap({...eligible,status:'decoded-no-flag'}),false);
});
