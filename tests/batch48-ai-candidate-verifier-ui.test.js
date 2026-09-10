'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('Batch48 candidate verifier renderer compiles and stays offline/object-oriented', () => {
  const source = read('renderer/ai_candidate_verifier_tools.js');
  assert.doesNotThrow(() => new vm.Script(source, { filename:'renderer/ai_candidate_verifier_tools.js' }));
  for (const token of [
    'ai-llm-aes-candidate-verify',
    'ai-backdoor-patch-candidate',
    'ai-backdoor-patch-verify',
    'Challenge JSON',
    'candidateId',
    'Behavior observations JSON',
    'Model observations JSON',
    'OFFLINE · BOUNDED · NO MODEL EXECUTION'
  ]) assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.match(source, /id="tool-input" class="surface-hidden-input"/);
  assert.match(source, /data-action="run-tool"/);
  assert.doesNotMatch(source, /\bfetch\s*\(|XMLHttpRequest|https?:\/\//i);
});

test('Batch48 verifier workbenches load after real CTF layer and before later AI sample surfaces', () => {
  const html = read('renderer/toolbox.html');
  const real = read('renderer/ai_real_ctf_tools.js');
  const verifier = 'ai_candidate_verifier_tools.js';
  assert.ok(html.indexOf(verifier) > html.indexOf('ai_real_ctf_tools.js'));
  assert.ok(html.indexOf(verifier) < html.indexOf('ai_sample_forensics_tools.js'));
  assert.match(real, /<span>VERIFIER<\/span>/);
  assert.match(real, /verifierAvailable/);
  assert.match(real, /candidateObject\.candidateId/);
  assert.match(real, /data-tool="\$\{esc\(tool\)\}"/);
});
