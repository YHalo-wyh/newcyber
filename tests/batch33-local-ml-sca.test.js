'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const {
  readNpyHeaderPath,
  inspectScaSource,
  extractWindowFeatures,
  ridgeRegression,
  pseudoinverseSolve,
  solveLinearSystem,
  analyzePowerTracePath
} = require('../src/core/power_side_channel');
const { runtimeStatus, inspectOnnxModel, runOnnxModel } = require('../src/core/local_ml_runtime');

function npyFloat32(values, shape) {
  let shapeText = shape.join(', ');
  if (shape.length === 1) shapeText += ',';
  let header = `{'descr': '<f4', 'fortran_order': False, 'shape': (${shapeText}), }`;
  const preamble = 10;
  const padding = (16 - ((preamble + Buffer.byteLength(header, 'latin1') + 1) % 16)) % 16;
  header += ' '.repeat(padding) + '\n';
  const head = Buffer.alloc(preamble);
  head[0] = 0x93;
  head.write('NUMPY', 1, 'ascii');
  head[6] = 1;
  head[7] = 0;
  head.writeUInt16LE(Buffer.byteLength(header, 'latin1'), 8);
  const data = Buffer.alloc(values.length * 4);
  values.forEach((value, index) => data.writeFloatLE(value, index * 4));
  return Buffer.concat([head, Buffer.from(header, 'latin1'), data]);
}

async function tempNpy(buffer) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'newcyber-sca-'));
  const file = path.join(dir, 'target_power_trace.npy');
  await fsp.writeFile(file, buffer);
  return { dir, file };
}

test('Batch33 streams NPY windows and resolves row layout from template evidence', async (t) => {
  const values = [];
  for (let row = 0; row < 12; row += 1) for (let col = 0; col < 8; col += 1) values.push(row + 1);
  const fixture = await tempNpy(npyFloat32(values, [96]));
  t.after(() => fsp.rm(fixture.dir, { recursive:true, force:true }));
  const source = [
    'GROUP_SIZE = 16',
    'TRACE_DIM = 64',
    'LAYER_INDEX = 8',
    'SAMPLES_PER_TRACE = 8',
    'out = model(ids, output_hidden_states=True, use_cache=True)',
    'cache = out.past_key_values',
    'coef = np.linalg.pinv(A) @ y',
    'raise NotImplementedError("recover")'
  ].join('\n');
  const result = await analyzePowerTracePath(fixture.file, { sourceText:source });
  assert.equal(result.trace.dtype, '<f4');
  assert.equal(result.trace.elements, 96);
  assert.equal(result.layout.status, 'resolved');
  assert.equal(result.layout.samplesPerRow, 8);
  assert.equal(result.layout.rows, 12);
  assert.equal(result.sourceInspection.constants.GROUP_SIZE, 16);
  assert.equal(result.sourceInspection.constants.TRACE_DIM, 64);
  assert.equal(result.sourceInspection.constants.LAYER_INDEX, 8);
  assert.equal(result.sourceInspection.requiresModelForward, true);
  assert.equal(result.sourceInspection.usesKvCache, true);
  assert.ok(result.sourceInspection.evidence.pinv.length);
  assert.ok(result.sourceInspection.evidence.todo.length);

  const feature = await extractWindowFeatures(fixture.file, {
    samplesPerRow:8,
    windows:[{ id:'middle', offset:2, length:4, metric:'sum-squares' }]
  });
  assert.equal(feature.rows, 12);
  assert.equal(feature.features[0][0], 4);
  assert.equal(feature.features[11][0], 4 * 12 * 12);
});

test('Batch33 refuses to factor a flat 1D trace into guessed rows', async (t) => {
  const fixture = await tempNpy(npyFloat32(Array.from({ length:96 }, (_, i) => i), [96]));
  t.after(() => fsp.rm(fixture.dir, { recursive:true, force:true }));
  const header = await readNpyHeaderPath(fixture.file);
  assert.deepEqual(header.shape, [96]);
  const result = await analyzePowerTracePath(fixture.file, { sourceText:'TRACE_DIM = 64\nLAYER_INDEX = 8' });
  assert.equal(result.layout.status, 'needs-row-width');
  assert.equal(result.layout.samplesPerRow, null);
  assert.match(result.nextActions[0], /samplesPerRow/);
});

test('Batch33 SCA source inspection recognizes reshape width hidden-state KV-cache and TODO independently', () => {
  const source = [
    'GROUP_SIZE = 16',
    'TRACE_DIM = 64',
    'LAYER_INDEX = 8',
    'trace = power.reshape(-1, 528)',
    'hidden = output.hidden_states[8]',
    'past = output.past_key_values',
    '# TODO recover probe',
    'raise NotImplementedError'
  ].join('\n');
  const result = inspectScaSource(source);
  assert.equal(result.samplesPerRow, 528);
  assert.equal(result.requiresModelForward, true);
  assert.equal(result.usesHiddenStates, true);
  assert.equal(result.usesKvCache, true);
  assert.ok(result.evidence.todo.length);
});

test('Batch33 ridge regression recovers a small profiling model', () => {
  const features = [];
  const target = [];
  for (let i = 0; i < 30; i += 1) {
    const x1 = i - 10;
    const x2 = (i % 5) - 2;
    features.push([x1, x2]);
    target.push(7 + 2.5 * x1 - 3 * x2);
  }
  const result = ridgeRegression(features, target, { lambda:1e-12 });
  assert.equal(result.status, 'ok');
  assert.ok(Math.abs(result.intercept - 7) < 1e-7);
  assert.ok(Math.abs(result.coefficients[0] - 2.5) < 1e-7);
  assert.ok(Math.abs(result.coefficients[1] + 3) < 1e-7);
  assert.ok(result.rmse < 1e-7);
  assert.ok(result.r2 > .999999);
});

test('Batch33 pseudoinverse uses minimum-norm wide-matrix path and rank failures stay explicit', () => {
  const pinv = pseudoinverseSolve([[1,0,0],[0,1,0]], [3,4], { lambda:0 });
  assert.equal(pinv.status, 'ok');
  assert.equal(pinv.method, 'right-pseudoinverse');
  assert.deepEqual(pinv.solution.map((value) => Math.round(value)), [3,4,0]);
  const singular = solveLinearSystem([[1,2],[2,4]], [1,2]);
  assert.equal(singular.status, 'rank-deficient');
  assert.equal(singular.solution, null);
});

function fakeOrt() {
  class Tensor {
    constructor(type, data, dims) { this.type = type; this.data = data; this.dims = dims; }
  }
  const session = {
    inputNames:['x'],
    outputNames:['y'],
    inputMetadata:[{ type:'tensor(float)', dimensions:[2] }],
    outputMetadata:[{ type:'tensor(float)', dimensions:[2] }],
    async run(feeds) { return { y:new Tensor('float32', Float32Array.from(feeds.x.data, (value) => value * 2), [2]) }; },
    async release() { this.released = true; }
  };
  return { Tensor, InferenceSession:{ async create() { return session; } } };
}

test('Batch33 local ML adapter can inspect and execute an injected ONNX-compatible runtime without renderer access', async () => {
  const ort = fakeOrt();
  const status = runtimeStatus({ ort, version:'test-runtime' });
  assert.equal(status.available, true);
  assert.equal(status.version, 'test-runtime');
  const model = await inspectOnnxModel(new Uint8Array([1,2,3]), { ort, provider:'cpu' });
  assert.equal(model.inputs[0].name, 'x');
  assert.equal(model.outputs[0].name, 'y');
  const run = await runOnnxModel(new Uint8Array([1,2,3]), {
    feeds:{ x:{ type:'float32', dims:[2], values:[1.5, -2] } },
    outputs:['y']
  }, { ort, provider:'cpu' });
  assert.deepEqual(run.outputs.y.preview, [3, -4]);
  assert.equal(run.outputs.y.elements, 2);
});

test('Batch33 runtime absence is a bounded capability gap rather than a fake model result', () => {
  const status = runtimeStatus({ moduleLoader:() => { throw new Error('module missing'); } });
  assert.equal(status.available, false);
  assert.equal(status.package, 'onnxruntime-node');
  assert.match(status.error, /module missing/);
});

test('Batch33 renderer is a dedicated path-based SCA workbench and Electron bridge avoids base64 trace transport', () => {
  const renderer = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'ai_sca_tools.js'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'styles', 'ai_sca.css'), 'utf8');
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'toolbox.html'), 'utf8');
  const preload = fs.readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8');
  const entry = fs.readFileSync(path.join(__dirname, '..', 'electron_main.js'), 'utf8');
  const ipc = fs.readFileSync(path.join(__dirname, '..', 'src', 'electron', 'ai_sca_ipc.js'), 'utf8');
  assert.doesNotThrow(() => new Function(renderer));
  assert.match(renderer, /TRACE LAYOUT/);
  assert.match(renderer, /WINDOW FEATURE EXTRACTOR/);
  assert.match(renderer, /LOCAL ML RUNTIME/);
  assert.match(renderer, /ONNX ORACLE/);
  assert.match(css, /\.sca-workbench/);
  assert.match(html, /styles\/ai_sca\.css/);
  assert.match(html, /ai_sca_tools\.js/);
  assert.match(preload, /webUtils\.getPathForFile/);
  assert.match(preload, /analyzeDroppedPowerSideChannel/);
  assert.match(entry, /registerAiScaIpc/);
  assert.match(ipc, /ai:sca-extract-windows/);
  assert.doesNotMatch(ipc, /Buffer\.from\([^\n]+base64/);
});
