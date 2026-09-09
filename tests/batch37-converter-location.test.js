'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const {
  containsPath,
  validateTrustedConverterLocation
} = require('../src/core/trusted_converter_location');
const { convertAndResumeSca } = require('../src/core/hf_sca_bridge');

async function tempDir(prefix='newcyber-b37-location-') {
  return fsp.mkdtemp(path.join(os.tmpdir(), prefix));
}

async function fakeConverter(root) {
  await fsp.mkdir(root,{recursive:true});
  const filePath=path.join(root,process.platform==='win32'?'optimum-cli.exe':'optimum-cli');
  await fsp.writeFile(filePath,process.platform==='win32'?'MZ-location-test':'#!/bin/sh\nexit 0\n');
  if(process.platform!=='win32')await fsp.chmod(filePath,0o755);
  return filePath;
}

test('Batch37 path containment does not confuse prefix siblings', async (t) => {
  const base=await tempDir('newcyber-b37-root-');
  t.after(()=>fsp.rm(base,{recursive:true,force:true}));
  const protectedRoot=path.join(base,'challenge');
  const prefixSibling=path.join(base,'challenge-tools','optimum-cli');
  assert.equal(containsPath(protectedRoot,path.join(protectedRoot,'tools','optimum-cli')),true);
  assert.equal(containsPath(protectedRoot,prefixSibling),false);
});

test('Batch37 trusted converter must live outside both HF model root and challenge workspace', async (t) => {
  const challenge=await tempDir();
  const external=await tempDir('newcyber-b37-external-');
  t.after(async()=>{await fsp.rm(challenge,{recursive:true,force:true});await fsp.rm(external,{recursive:true,force:true});});
  const modelRoot=path.join(challenge,'oracle');
  await fsp.mkdir(modelRoot,{recursive:true});
  const inModel=await fakeConverter(path.join(modelRoot,'tools'));
  const inWorkspace=await fakeConverter(path.join(challenge,'tools'));
  const outside=await fakeConverter(path.join(external,'bin'));
  const roots=[{path:modelRoot,label:'HF model root'},{path:challenge,label:'challenge workspace'}];

  let result=await validateTrustedConverterLocation({filePath:inModel},roots);
  assert.equal(result.ok,false);
  assert.equal(result.code,'CONVERTER_LOCATION_GAP');
  assert.equal(result.forbiddenRoot.label,'HF model root');

  result=await validateTrustedConverterLocation({filePath:inWorkspace},roots);
  assert.equal(result.ok,false);
  assert.equal(result.code,'CONVERTER_LOCATION_GAP');
  assert.equal(result.forbiddenRoot.label,'challenge workspace');

  result=await validateTrustedConverterLocation({filePath:outside},roots);
  assert.equal(result.ok,true);
  assert.equal(result.checkedRoots.length,2);
  assert.equal(result.converterRealPath,await fsp.realpath(outside));
});

test('Batch37 converter location resolves parent-directory symlinks before containment checks', async (t) => {
  if(process.platform==='win32')return;
  const challenge=await tempDir();
  const aliasRoot=await tempDir('newcyber-b37-alias-');
  t.after(async()=>{await fsp.rm(challenge,{recursive:true,force:true});await fsp.rm(aliasRoot,{recursive:true,force:true});});
  const actualDir=path.join(challenge,'tools');
  const actual=await fakeConverter(actualDir);
  const alias=path.join(aliasRoot,'apparently-external');
  await fsp.symlink(actualDir,alias,'dir');
  const apparentPath=path.join(alias,path.basename(actual));
  const result=await validateTrustedConverterLocation({filePath:apparentPath},[{path:challenge,label:'challenge workspace'}]);
  assert.equal(result.ok,false);
  assert.equal(result.code,'CONVERTER_LOCATION_GAP');
  assert.equal(result.converterRealPath,await fsp.realpath(actual));
});

test('Batch37 SCA bridge rejects an in-workspace converter before planner or executor runs', async (t) => {
  const challenge=await tempDir();
  t.after(()=>fsp.rm(challenge,{recursive:true,force:true}));
  const modelRoot=path.join(challenge,'oracle');
  await fsp.mkdir(modelRoot,{recursive:true});
  await fsp.writeFile(path.join(modelRoot,'config.json'),'{}');
  const safe=path.join(modelRoot,'model.safetensors');
  await fsp.writeFile(safe,'safe');
  const converter=await fakeConverter(path.join(challenge,'tools'));
  let plannerCalls=0;
  let executorCalls=0;
  const result=await convertAndResumeSca([safe],{filePath:converter},{
    workspaceRoot:challenge,
    planHfOnnxExport:async()=>{plannerCalls+=1;return {status:'ready'};},
    executeTrustedHfOnnxPlan:async()=>{executorCalls+=1;return {status:'converted'};},
    runScaAutopilotPaths:async()=>({status:'flag-recovered',flag:'flag{must-not-run}'})
  });
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'CONVERTER_LOCATION_GAP');
  assert.equal(result.gap.stage,'converter-location');
  assert.equal(plannerCalls,0);
  assert.equal(executorCalls,0);
});

test('Batch37 production IPC passes workspace root and validates normal HF conversion location', () => {
  const ipc=fs.readFileSync(path.join(__dirname,'..','src','electron','ai_sca_ipc.js'),'utf8');
  const bridge=fs.readFileSync(path.join(__dirname,'..','src','core','hf_sca_bridge.js'),'utf8');
  assert.match(ipc,/validateTrustedConverterLocation/);
  assert.match(ipc,/label:'HF model root'/);
  assert.match(ipc,/workspaceRoot:root/);
  assert.match(bridge,/challenge workspace/);
  assert.match(bridge,/CONVERTER_LOCATION_GAP|converterLocation\.code/);
});
