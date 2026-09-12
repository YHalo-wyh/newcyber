'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { auditHeTrainingDirectory, solveHeTrainingDirectory } = require('../src/core/ai_he_training');

const root = 'F:/2026第三届长城杯总决赛题目附件/AI/HETraining/HETraining';

test('HETraining real bundle exposes CKKS and quantization chain without executing Python', async () => {
  const result = await auditHeTrainingDirectory(root);
  assert.equal(result.schema, 'newcyber.ai-he-training-audit.v1');
  assert.equal(result.status, 'evidence-present');
  assert.equal(result.roles['encrypted-input'].length, 160);
  assert.equal(result.roles['he-context'].length, 2);
  assert.equal(result.roles['model-source'][0].evidence.library, 'TenSEAL');
  assert.equal(result.roles['model-source'][0].evidence.globalScale, 1099511627776);
  assert.deepEqual(result.roles['plaintext-samples'][0].npy.shape, [160, 8]);
  assert.deepEqual(result.roles['quantized-outputs'][0].npy.shape, [160, 4]);
  assert.match(result.notes[0], /不执行题目 Python/);
});

test('HETraining solver exposes every step and preserves the missing-secret gap', async () => {
  const result = await solveHeTrainingDirectory(root);
  assert.equal(result.schema, 'newcyber.ai-he-training-solve.v1');
  assert.equal(result.status, 'blocked');
  assert.equal(result.flag, null);
  assert.deepEqual(result.steps.map((step) => step.id), ['ingest', 'context', 'quantize', 'fit', 'decrypt', 'result']);
  assert.equal(result.evidence.affineFit.matched, 9);
  assert.equal(result.gap.code, 'HE_MODEL_OR_SECRET_MISSING');
});
