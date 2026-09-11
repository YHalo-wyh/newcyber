const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const {
  isAutoVectorShape,
  chooseScoreOutput,
  adaptOnnxRunsToContestBundle,
  rankAdversarialContestFromOnnxRuns
} = require('../src/core/ai_adversarial_onnx_bridge');
const { runTool } = require('../src/core/tool_router');

const root = path.join(__dirname, '..');

function onnxRun(scores, name = 'logits', options = {}) {
  return {
    schema: 'newcyber.onnx-run.v1',
    provider: options.provider || 'cpu',
    inputs: ['input'],
    outputs: {
      [name]: {
        type: 'float32',
        dims: options.dims || [1, scores.length],
        elements: scores.length,
        preview: scores,
        truncated: options.truncated === true,
        summary: null
      }
    }
  };
}

function syntheticInput() {
  return {
    outputName: 'logits',
    hints: [[0, 1], [2, 6], [3, 4]],
    shortlistSize: 3,
    beamWidth: 2,
    runs: [
      { id: 101, assignedLabel: 1, run: onnxRun([4.92, 5.05, -1, -1, -1, -1, -1]) },
      { id: 102, assignedLabel: 1, run: onnxRun([3.10, 5.40, 2.20, -1, -1, -1, -1]) },
      { id: 103, assignedLabel: 1, run: onnxRun([2.50, 5.20, 4.90, -1, -1, -1, -1]) },
      { id: 206, assignedLabel: 6, run: onnxRun([-1, -1, 5.01, -1, -1, -1, 5.20]) },
      { id: 207, assignedLabel: 6, run: onnxRun([-1, -1, 5.08, -1, -1, -1, 5.34]) },
      { id: 304, assignedLabel: 4, run: onnxRun([-1, -1, -1, 4.88, 5.00, -1, -1]) },
      { id: 305, assignedLabel: 4, run: onnxRun([-1, -1, -1, 3.00, 5.60, -1, -1]) }
    ]
  };
}

test('automatic ONNX score vectors only accept complete [C] or [1,C] outputs', () => {
  assert.equal(isAutoVectorShape([10], 10), true);
  assert.equal(isAutoVectorShape([1, 10], 10), true);
  assert.equal(isAutoVectorShape([2, 5], 10), false);
  assert.equal(isAutoVectorShape([1, 2, 5], 10), false);

  const vector = chooseScoreOutput(onnxRun([0.1, 0.9]), { outputName: 'logits' });
  assert.deepEqual(vector.scores, [0.1, 0.9]);
  assert.deepEqual(vector.dims, [1, 2]);
});

test('bridge refuses truncated previews and ambiguous outputs', () => {
  assert.throws(
    () => chooseScoreOutput(onnxRun([0.1, 0.9], 'logits', { truncated: true }), { outputName: 'logits' }),
    /截断/
  );
  assert.throws(
    () => chooseScoreOutput(onnxRun([0.1, 0.9], 'feature', { dims: [1, 1, 2] }), { outputName: 'feature' }),
    /不是自动允许/
  );

  const run = onnxRun([0.1, 0.9], 'head_a');
  run.outputs.head_b = { ...run.outputs.head_a, preview: [0.2, 0.8] };
  assert.throws(() => chooseScoreOutput(run), /多个可用分类输出/);
  assert.deepEqual(chooseScoreOutput(run, { outputName: 'head_b' }).scores, [0.2, 0.8]);
});

test('ONNX runs adapt into Batch45 contest candidates without losing provenance', () => {
  const bundle = adaptOnnxRunsToContestBundle(syntheticInput());
  assert.equal(bundle.schema, 'newcyber.ai-adversarial-onnx-contest-bundle.v1');
  assert.equal(bundle.candidates.length, 7);
  assert.deepEqual(bundle.outputNames, ['logits']);
  assert.deepEqual(bundle.providers, ['cpu']);
  assert.equal(bundle.candidates[0].onnx.outputName, 'logits');
  assert.deepEqual(bundle.candidates[0].onnx.dims, [1, 7]);
});

test('ONNX bridge reaches contest beam while keeping result at candidate layer', () => {
  const result = rankAdversarialContestFromOnnxRuns(syntheticInput());
  assert.equal(result.schema, 'newcyber.ai-adversarial-onnx-contest-ranking.v1');
  assert.equal(result.bridge.runs, 7);
  assert.equal(result.ranking.groups.length, 3);
  assert.ok(result.ranking.candidateSets.length > 0);
  const group01 = result.ranking.groups.find((group) => String(group.hint.originLabel) === '0' && String(group.hint.adversarialLabel) === '1');
  assert.equal(String(group01.top.id), '101');
  assert.ok(result.notes.some((item) => /最终需要题目 verifier\/hash/.test(item)));
});

test('tool router exposes ONNX adapt and rank routes', () => {
  const input = syntheticInput();
  const adapted = runTool('ai-adversarial-onnx-adapt', { input });
  assert.equal(adapted.candidates.length, 7);
  const ranked = runTool('ai-adversarial-onnx-rank', { input });
  assert.ok(ranked.ranking.candidateSets.length > 0);
});

test('renderer workbench compiles and is loaded by toolbox', () => {
  const source = fs.readFileSync(path.join(root, 'renderer/ai_adversarial_onnx_tools.js'), 'utf8');
  const html = fs.readFileSync(path.join(root, 'renderer/toolbox.html'), 'utf8');
  assert.doesNotThrow(() => new vm.Script(source, { filename: 'renderer/ai_adversarial_onnx_tools.js' }));
  assert.match(source, /chooseAndInspectOnnxModel/);
  assert.match(source, /runOnnxModel/);
  assert.match(source, /ai-adversarial-onnx-rank/);
  assert.match(source, /RUN ONNX \+ RANK/);
  assert.match(source, /最终交给题目 verifier/);
  assert.match(html, /ai_adversarial_onnx_tools\.js/);
});
