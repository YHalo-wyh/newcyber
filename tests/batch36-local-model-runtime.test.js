'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const {
  PINNED_ORT_VERSION,
  createRuntimeBundleManifest,
  verifyRuntimeBundle,
  setRuntimeBundleRoot,
  clearRuntimeBundleRoot,
  runtimeStatus
} = require('../src/core/local_ml_runtime');
const {
  inspectSafetensorsPath,
  inferExportTask,
  planHfOnnxExport
} = require('../src/core/hf_onnx_export');

async function tempDir(prefix='newcyber-b36-') {
  return fsp.mkdtemp(path.join(os.tmpdir(), prefix));
}

async function fakeRuntimeBundle(root) {
  const packageRoot = path.join(root, 'node_modules', 'onnxruntime-node');
  await fsp.mkdir(packageRoot, { recursive:true });
  await fsp.writeFile(path.join(packageRoot, 'package.json'), JSON.stringify({
    name:'onnxruntime-node',
    version:PINNED_ORT_VERSION,
    main:'index.js'
  }));
  await fsp.writeFile(path.join(packageRoot, 'index.js'), [
    'class Tensor { constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;} }',
    'module.exports={Tensor,InferenceSession:{async create(){return {inputNames:[],outputNames:[],async release(){}};}}};'
  ].join('\n'));
  const manifest = createRuntimeBundleManifest(root);
  await fsp.writeFile(path.join(root, 'newcyber-runtime.json'), `${JSON.stringify(manifest,null,2)}\n`);
  return { packageRoot, manifest };
}

function safetensors(entries, payloadBytes) {
  const header = Buffer.from(JSON.stringify(entries), 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(header.length), 0);
  return Buffer.concat([prefix, header, Buffer.alloc(payloadBytes)]);
}

async function makeHfModel(config, entries=null, payloadBytes=32) {
  const root = await tempDir('newcyber-b36-hf-');
  await fsp.writeFile(path.join(root,'config.json'), JSON.stringify(config,null,2));
  if(entries){
    await fsp.writeFile(path.join(root,'model.safetensors'), safetensors(entries,payloadBytes));
  }
  return root;
}

const validWeights = {
  'transformer.wte.weight': { dtype:'F32', shape:[2,2], data_offsets:[0,16] },
  'lm_head.weight': { dtype:'F32', shape:[2,2], data_offsets:[16,32] }
};

test('Batch36 verifies a pinned offline ONNX Runtime bundle and loads it without renderer/native install at runtime', async (t) => {
  const root = await tempDir('newcyber-b36-ort-');
  t.after(async () => { clearRuntimeBundleRoot(); await fsp.rm(root,{recursive:true,force:true}); });
  const { manifest } = await fakeRuntimeBundle(root);
  assert.equal(manifest.version, PINNED_ORT_VERSION);
  assert.equal(manifest.platform, process.platform);
  assert.equal(manifest.arch, process.arch);
  assert.equal(manifest.installPolicy.runtimeNetwork, 'disabled');
  assert.ok(manifest.criticalFiles.some((item)=>item.path==='package.json'));
  assert.ok(manifest.criticalFiles.some((item)=>item.path==='index.js'));

  const verified = verifyRuntimeBundle(root);
  assert.equal(verified.valid, true);
  setRuntimeBundleRoot(root);
  const status = runtimeStatus();
  assert.equal(status.available, true);
  assert.equal(status.version, PINNED_ORT_VERSION);
  assert.equal(status.pinnedVersion, PINNED_ORT_VERSION);
  assert.equal(status.source, 'selected-bundle');
  assert.equal(status.bundleVerified, true);
  assert.equal(status.bundleRoot, path.resolve(root));
});

test('Batch36 rejects a runtime bundle after a hashed critical file is tampered', async (t) => {
  const root = await tempDir('newcyber-b36-ort-tamper-');
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const { packageRoot } = await fakeRuntimeBundle(root);
  await fsp.appendFile(path.join(packageRoot,'index.js'),'\n// tampered\n');
  const verified = verifyRuntimeBundle(root);
  assert.equal(verified.valid, false);
  assert.match(verified.error,/hash|大小/i);
});

test('Batch36 SafeTensors inspection streams only the bounded header and validates tensor ranges', async (t) => {
  const root = await tempDir('newcyber-b36-st-');
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const file = path.join(root,'model.safetensors');
  await fsp.writeFile(file,safetensors(validWeights,32));
  const result = await inspectSafetensorsPath(file);
  assert.equal(result.valid,true);
  assert.equal(result.tensorCount,2);
  assert.equal(result.payloadBytes,32);
  assert.match(result.headerSha256,/^[a-f0-9]{64}$/);
  assert.equal(result.payloadSha256,null);
  assert.equal(result.payloadHashPolicy,'not-hashed-by-default');
  assert.equal(result.tensorPreview[0].dtype,'F32');
});

test('Batch36 builds a deterministic offline Optimum plan for a local causal-LM SafeTensors bundle', async (t) => {
  const root = await makeHfModel({model_type:'gpt2',architectures:['GPT2LMHeadModel'],torch_dtype:'float32'},validWeights,32);
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  await fsp.writeFile(path.join(root,'vocab.json'),'{}');
  await fsp.writeFile(path.join(root,'merges.txt'),'#version: 0.2\n');
  const plan = await planHfOnnxExport(root);
  assert.equal(plan.status,'ready');
  assert.equal(plan.task.task,'text-generation-with-past');
  assert.equal(plan.task.source,'config.architectures');
  assert.equal(plan.converter.executable,'optimum-cli');
  assert.equal(plan.converter.shell,false);
  assert.equal(plan.converter.networkPolicy,'offline-only');
  assert.equal(plan.converter.trustRemoteCode,false);
  assert.equal(plan.converter.env.HF_HUB_OFFLINE,'1');
  assert.equal(plan.converter.env.TRANSFORMERS_OFFLINE,'1');
  assert.ok(plan.converter.args.includes('--task'));
  assert.ok(plan.converter.args.includes('text-generation-with-past'));
  assert.ok(plan.converter.args.includes(path.resolve(root)));
  assert.equal(plan.bundle.shardCount,1);
  assert.equal(plan.bundle.tensorCount,2);
  assert.ok(plan.bundle.tokenizerFiles.includes('vocab.json'));
});

test('Batch36 refuses HuggingFace auto_map instead of silently enabling trust_remote_code', async (t) => {
  const root = await makeHfModel({
    model_type:'custom',
    architectures:['CustomForCausalLM'],
    auto_map:{AutoModelForCausalLM:'modeling_custom.CustomForCausalLM'}
  },validWeights,32);
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const plan = await planHfOnnxExport(root);
  assert.equal(plan.status,'gap');
  assert.equal(plan.gap.code,'REMOTE_CODE_GAP');
  assert.match(plan.gap.detail,/auto_map|trust_remote_code/i);
});

test('Batch36 leaves unknown architecture export task unresolved and accepts only explicit allowlisted tasks', async (t) => {
  assert.deepEqual(inferExportTask({architectures:['MysteryNetwork']}),{task:null,source:'none'});
  assert.equal(inferExportTask({},'text-classification').task,'text-classification');
  assert.equal(inferExportTask({},'made-up-task').task,null);
  const root = await makeHfModel({model_type:'mystery',architectures:['MysteryNetwork']},validWeights,32);
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const plan = await planHfOnnxExport(root);
  assert.equal(plan.status,'gap');
  assert.equal(plan.gap.code,'TASK_INFERENCE_GAP');
});

test('Batch36 invalid SafeTensors structure blocks ONNX conversion planning', async (t) => {
  const broken = {
    'weight': { dtype:'F32', shape:[2,2], data_offsets:[0,64] }
  };
  const root = await makeHfModel({model_type:'gpt2',architectures:['GPT2LMHeadModel']},broken,16);
  t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const plan = await planHfOnnxExport(root);
  assert.equal(plan.status,'gap');
  assert.equal(plan.gap.code,'ARTIFACT_INVALID_GAP');
  assert.match(plan.gap.detail,/data_offsets|字节数/i);
});

test('Batch36 runtime preparation and dedicated UI keep network/native execution boundaries explicit', () => {
  const prepare = fs.readFileSync(path.join(__dirname,'..','scripts','prepare_onnx_runtime.js'),'utf8');
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname,'..','package.json'),'utf8'));
  const core = fs.readFileSync(path.join(__dirname,'..','src','core','hf_onnx_export.js'),'utf8');
  const renderer = fs.readFileSync(path.join(__dirname,'..','renderer','model_runtime_tools.js'),'utf8');
  const preload = fs.readFileSync(path.join(__dirname,'..','preload.js'),'utf8');
  const ipc = fs.readFileSync(path.join(__dirname,'..','src','electron','ai_sca_ipc.js'),'utf8');
  const html = fs.readFileSync(path.join(__dirname,'..','renderer','toolbox.html'),'utf8');
  assert.equal(pkg.scripts['runtime:prepare'],'node scripts/prepare_onnx_runtime.js');
  assert.equal(pkg.scripts['runtime:verify'],'node scripts/prepare_onnx_runtime.js --verify');
  assert.match(prepare,/PINNED_ORT_VERSION/);
  assert.match(prepare,/--onnxruntime-node-install=skip/);
  assert.match(prepare,/shell:\s*false/);
  assert.doesNotMatch(prepare,/execSync|shell:\s*true/);
  assert.match(core,/REMOTE_CODE_GAP/);
  assert.match(core,/HF_HUB_OFFLINE/);
  assert.match(core,/shell:\s*false/);
  assert.doesNotMatch(core,/child_process|spawn\s*\(|exec\s*\(/);
  assert.doesNotThrow(()=>new Function(renderer));
  assert.match(renderer,/Local Model Runtime/);
  assert.match(renderer,/shell=false/);
  assert.doesNotMatch(renderer,/<textarea/i);
  assert.match(preload,/chooseLocalMlRuntimeBundle/);
  assert.match(preload,/chooseHfOnnxExportPlan/);
  assert.match(ipc,/ai:local-ml-select-runtime/);
  assert.match(ipc,/ai:hf-onnx-choose-plan/);
  assert.match(html,/styles\/model_runtime\.css/);
  assert.ok(html.indexOf('model_runtime_tools.js') < html.indexOf('sca_autopilot_tools.js'));
});
