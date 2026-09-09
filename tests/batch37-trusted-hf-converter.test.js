'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');
const { planHfOnnxExport } = require('../src/core/hf_onnx_export');
const {
  inspectTrustedConverter,
  revalidateTrustedConverter,
  buildOfflineEnv,
  auditModelTree,
  validateConvertedOnnx,
  executeTrustedHfOnnxPlan
} = require('../src/core/trusted_hf_converter');
const { findHfModelRoots, convertAndResumeSca } = require('../src/core/hf_sca_bridge');

async function tempDir(prefix='newcyber-b37-') {
  return fsp.mkdtemp(path.join(os.tmpdir(), prefix));
}

function safetensors(entries, payloadBytes) {
  const header = Buffer.from(JSON.stringify(entries), 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(header.length), 0);
  return Buffer.concat([prefix, header, Buffer.alloc(payloadBytes)]);
}

const validWeights = {
  'transformer.wte.weight': { dtype:'F32', shape:[2,2], data_offsets:[0,16] },
  'lm_head.weight': { dtype:'F32', shape:[2,2], data_offsets:[16,32] }
};

async function makeModelRoot() {
  const root = await tempDir('newcyber-b37-hf-');
  await fsp.writeFile(path.join(root,'config.json'),JSON.stringify({model_type:'gpt2',architectures:['GPT2LMHeadModel'],torch_dtype:'float32'}));
  await fsp.writeFile(path.join(root,'model.safetensors'),safetensors(validWeights,32));
  await fsp.writeFile(path.join(root,'vocab.json'),JSON.stringify({'A':0,'B':1}));
  await fsp.writeFile(path.join(root,'merges.txt'),'#version: 0.2\n');
  return root;
}

async function makeConverter(root) {
  const name = process.platform === 'win32' ? 'optimum-cli.exe' : 'optimum-cli';
  const filePath = path.join(root,name);
  await fsp.writeFile(filePath, process.platform === 'win32' ? 'MZ-fake-converter' : '#!/usr/bin/env python3\n# fake converter\n');
  if (process.platform !== 'win32') await fsp.chmod(filePath,0o755);
  return filePath;
}

function fakeOrt() {
  class Tensor {
    constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}
  }
  return {
    Tensor,
    InferenceSession:{
      async create(){
        return {
          inputNames:['input_ids'],
          outputNames:['logits','last_hidden_state'],
          inputMetadata:[{type:'tensor(int64)',dimensions:[1,'sequence'],symbolicDimensions:['','sequence']}],
          outputMetadata:[
            {type:'tensor(float)',dimensions:[1,'sequence',8],symbolicDimensions:['','sequence','']},
            {type:'tensor(float)',dimensions:[1,'sequence',4],symbolicDimensions:['','sequence','']}
          ],
          async release(){}
        };
      }
    }
  };
}

function successfulSpawn(outputDir,captured) {
  return (executable,args,options) => {
    captured.calls += 1;
    captured.executable = executable;
    captured.args = args.slice();
    captured.options = options;
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = (signal) => { captured.kills.push(signal); return true; };
    setImmediate(() => {
      fsp.mkdir(outputDir,{recursive:true})
        .then(()=>fsp.writeFile(path.join(outputDir,'model.onnx'),Buffer.from([0x08,0x01,0x12,0x01])))
        .then(()=>{
          child.stdout.end('export complete\n');
          child.stderr.end('');
          child.emit('close',0,null);
        })
        .catch((error)=>child.emit('error',error));
    });
    return child;
  };
}

test('Batch37 trusted converter is explicit, executable and hash-pinned', async (t) => {
  const root = await tempDir('newcyber-b37-converter-');
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const converterPath = await makeConverter(root);
  const descriptor = await inspectTrustedConverter(converterPath);
  assert.equal(descriptor.trust,'explicit-user-selection');
  assert.match(descriptor.sha256,/^[a-f0-9]{64}$/);
  assert.equal(descriptor.filePath,path.resolve(converterPath));
  await revalidateTrustedConverter(descriptor);

  const wrong = path.join(root,process.platform==='win32'?'python.exe':'python');
  await fsp.writeFile(wrong,'x');
  if(process.platform!=='win32')await fsp.chmod(wrong,0o755);
  await assert.rejects(()=>inspectTrustedConverter(wrong),/optimum-cli/i);
});

test('Batch37 rejects converter TOCTOU mutation before spawn', async (t) => {
  const root = await makeModelRoot();
  const toolRoot = await tempDir('newcyber-b37-tools-');
  t.after(async()=>{await fsp.rm(root,{recursive:true,force:true});await fsp.rm(toolRoot,{recursive:true,force:true});});
  const descriptor = await inspectTrustedConverter(await makeConverter(toolRoot));
  const plan = await planHfOnnxExport(root);
  await fsp.appendFile(descriptor.filePath,'\nchanged\n');
  let calls=0;
  const result = await executeTrustedHfOnnxPlan(plan,descriptor,{spawnImpl:()=>{calls+=1;throw new Error('must not spawn');},ort:fakeOrt()});
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'CONVERTER_TRUST_GAP');
  assert.equal(calls,0);
});

test('Batch37 model audit refuses challenge code, unsafe pickle-style weights and symlinks', async (t) => {
  const root = await makeModelRoot();
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  await fsp.writeFile(path.join(root,'modeling_custom.py'),'raise SystemExit()\n');
  let audit = await auditModelTree(root);
  assert.equal(audit.ok,false);
  assert.equal(audit.code,'MODEL_CODE_ARTIFACT_GAP');
  await fsp.rm(path.join(root,'modeling_custom.py'));
  await fsp.writeFile(path.join(root,'pytorch_model.bin'),'pickle-ish');
  audit = await auditModelTree(root);
  assert.equal(audit.ok,false);
  assert.equal(audit.code,'UNSAFE_WEIGHT_ARTIFACT_GAP');
  await fsp.rm(path.join(root,'pytorch_model.bin'));
  try {
    await fsp.symlink(path.join(root,'config.json'),path.join(root,'linked-config'));
    audit = await auditModelTree(root);
    assert.equal(audit.ok,false);
    assert.equal(audit.code,'MODEL_SYMLINK_GAP');
  } catch(error) {
    if(process.platform!=='win32')throw error;
  }
});

test('Batch37 successful trusted conversion uses shell=false offline env then ORT-validates the selected Transformer', async (t) => {
  const root = await makeModelRoot();
  const toolRoot = await tempDir('newcyber-b37-tools-');
  t.after(async()=>{await fsp.rm(root,{recursive:true,force:true});await fsp.rm(toolRoot,{recursive:true,force:true});});
  const converter = await inspectTrustedConverter(await makeConverter(toolRoot));
  const plan = await planHfOnnxExport(root);
  assert.equal(plan.status,'ready');
  const captured={calls:0,kills:[]};
  const result = await executeTrustedHfOnnxPlan(plan,converter,{
    spawnImpl:successfulSpawn(plan.output.directory,captured),
    ort:fakeOrt(),
    purpose:'sca',
    baseEnv:{PATH:process.env.PATH||'',PYTHONPATH:'/challenge/shadow',HTTP_PROXY:'http://proxy.invalid'}
  });
  assert.equal(result.status,'converted');
  assert.equal(captured.calls,1);
  assert.equal(captured.executable,converter.filePath);
  assert.deepEqual(captured.args,plan.converter.args);
  assert.equal(captured.options.shell,false);
  assert.equal(captured.options.cwd,path.dirname(converter.filePath));
  assert.equal(captured.options.env.HF_HUB_OFFLINE,'1');
  assert.equal(captured.options.env.TRANSFORMERS_OFFLINE,'1');
  assert.equal(captured.options.env.PYTHONSAFEPATH,'1');
  assert.equal(captured.options.env.HTTP_PROXY,'');
  assert.equal(Object.prototype.hasOwnProperty.call(captured.options.env,'PYTHONPATH'),false);
  assert.equal(result.process.networkIsolation,'offline-environment-only');
  assert.equal(result.selected.fileName,'model.onnx');
  assert.equal(result.selected.transformer.supported,true);
  assert.equal(result.selected.transformer.roles.hidden.name,'last_hidden_state');
  assert.equal(result.selected.transformer.unknownInputs.length,0);
  assert.match(result.selected.sha256,/^[a-f0-9]{64}$/);
  assert.ok(result.tokenizerArtifacts.some((item)=>item.name==='vocab.json'));
  assert.equal(JSON.parse(await fsp.readFile(result.manifestPath,'utf8')).policy.challengePythonAllowed,false);
});

test('Batch37 never mixes with a pre-existing ONNX output directory', async (t) => {
  const root = await makeModelRoot();
  const toolRoot = await tempDir('newcyber-b37-tools-');
  t.after(async()=>{await fsp.rm(root,{recursive:true,force:true});await fsp.rm(toolRoot,{recursive:true,force:true});});
  const converter = await inspectTrustedConverter(await makeConverter(toolRoot));
  const plan = await planHfOnnxExport(root);
  await fsp.mkdir(plan.output.directory,{recursive:true});
  await fsp.writeFile(path.join(plan.output.directory,'old.onnx'),'old');
  let spawned=false;
  const result = await executeTrustedHfOnnxPlan(plan,converter,{spawnImpl:()=>{spawned=true;throw new Error('must not spawn');},ort:fakeOrt()});
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'OUTPUT_EXISTS_GAP');
  assert.equal(spawned,false);
});

test('Batch37 SCA ONNX validation refuses same-score oracle ambiguity', async (t) => {
  const output = await tempDir('newcyber-b37-onnx-tie-');
  t.after(()=>fsp.rm(output,{recursive:true,force:true}));
  await fsp.writeFile(path.join(output,'a.onnx'),'a');
  await fsp.writeFile(path.join(output,'b.onnx'),'b');
  const result = await validateConvertedOnnx(output,{purpose:'sca',ort:fakeOrt()});
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'ONNX_SELECTION_GAP');
  assert.equal(result.candidates.filter((item)=>item.valid).length,2);
});

test('Batch37 HF root discovery is exact and bridge excludes old ONNX before SCA re-entry', async (t) => {
  const root = await tempDir('newcyber-b37-bridge-');
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const modelRoot = path.join(root,'oracle');
  await fsp.mkdir(modelRoot,{recursive:true});
  await fsp.writeFile(path.join(modelRoot,'config.json'),'{}');
  const safe = path.join(modelRoot,'model.safetensors');
  await fsp.writeFile(safe,'safe');
  const trace = path.join(root,'target_trace.npy');
  const oldOnnx = path.join(root,'old.onnx');
  await fsp.writeFile(trace,'trace');
  await fsp.writeFile(oldOnnx,'old');
  const roots = await findHfModelRoots([trace,safe,oldOnnx]);
  assert.equal(roots.status,'ok');
  assert.equal(roots.root,path.resolve(modelRoot));

  const selected = path.join(modelRoot,'newcyber_onnx','model.onnx');
  let rerunPaths=null;
  const result = await convertAndResumeSca([trace,safe,oldOnnx],{schema:'fake'}, {
    planHfOnnxExport:async(model)=>({schema:'newcyber.hf-onnx-plan.v1',status:'ready',bundle:{root:model},output:{directory:path.dirname(selected)},converter:{executable:'optimum-cli',shell:false}}),
    executeTrustedHfOnnxPlan:async()=>({status:'converted',selected:{filePath:selected,fileName:'model.onnx'}}),
    runScaAutopilotPaths:async(paths)=>{rerunPaths=paths.slice();return {status:'flag-recovered',flag:'flag{bridge-ok}'};}
  });
  assert.equal(result.status,'flag-recovered');
  assert.equal(result.result.flag,'flag{bridge-ok}');
  assert.ok(rerunPaths.includes(path.resolve(selected)));
  assert.ok(!rerunPaths.includes(path.resolve(oldOnnx)));
  assert.equal(result.rerun.existingOnnxExcluded[0],'old.onnx');
});

test('Batch37 offline environment is allowlisted rather than inherited wholesale', () => {
  const env = buildOfflineEnv({PATH:'/bin',HOME:'/tmp/home',PYTHONPATH:'/challenge',AWS_SECRET_ACCESS_KEY:'secret',HTTPS_PROXY:'http://proxy'});
  assert.equal(env.PYTHONSAFEPATH,'1');
  assert.equal(env.HF_HUB_OFFLINE,'1');
  assert.equal(env.HTTPS_PROXY,'');
  assert.equal(env.NO_PROXY,'*');
  assert.equal(Object.prototype.hasOwnProperty.call(env,'PYTHONPATH'),false);
  assert.equal(Object.prototype.hasOwnProperty.call(env,'AWS_SECRET_ACCESS_KEY'),false);
});

test('Batch37 renderer and Electron bridge expose explicit trusted conversion without generic payload execution', () => {
  const core = fs.readFileSync(path.join(__dirname,'..','src','core','trusted_hf_converter.js'),'utf8');
  const bridge = fs.readFileSync(path.join(__dirname,'..','src','core','hf_sca_bridge.js'),'utf8');
  const hfPlan = fs.readFileSync(path.join(__dirname,'..','src','core','hf_onnx_export.js'),'utf8');
  const runtimeUi = fs.readFileSync(path.join(__dirname,'..','renderer','model_runtime_tools.js'),'utf8');
  const scaUi = fs.readFileSync(path.join(__dirname,'..','renderer','sca_autopilot_tools.js'),'utf8');
  const preload = fs.readFileSync(path.join(__dirname,'..','preload.js'),'utf8');
  const ipc = fs.readFileSync(path.join(__dirname,'..','src','electron','ai_sca_ipc.js'),'utf8');
  assert.match(core,/spawn/);
  assert.match(core,/shell:\s*false/);
  assert.doesNotMatch(core,/shell:\s*true|execSync|execFileSync/);
  assert.match(core,/PYTHONSAFEPATH/);
  assert.match(core,/MODEL_CODE_ARTIFACT_GAP/);
  assert.match(core,/UNSAFE_WEIGHT_ARTIFACT_GAP/);
  assert.match(core,/offline-environment-only/);
  assert.doesNotMatch(hfPlan,/child_process|spawn\s*\(/);
  assert.match(bridge,/existingOnnxExcluded/);
  assert.doesNotThrow(()=>new Function(runtimeUi));
  assert.doesNotThrow(()=>new Function(scaUi));
  assert.match(runtimeUi,/TRUSTED CONVERTER/);
  assert.match(runtimeUi,/执行可信转换并验证/);
  assert.match(scaUi,/TRUSTED CONVERSION GATE/);
  assert.match(scaUi,/CHALLENGE CODE/);
  assert.doesNotMatch(runtimeUi,/<textarea/i);
  assert.doesNotMatch(scaUi,/<textarea/i);
  assert.match(preload,/chooseTrustedHfConverter/);
  assert.match(preload,/executeTrustedHfOnnxConversion/);
  assert.match(preload,/continueScaAutopilotWithConversion/);
  assert.match(ipc,/ai:hf-converter-select/);
  assert.match(ipc,/ai:hf-onnx-execute/);
  assert.match(ipc,/ai:sca-autopilot-convert-resume/);
});
