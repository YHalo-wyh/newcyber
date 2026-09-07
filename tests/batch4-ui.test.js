const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

test('batch-four renderer extension stays compilable', () => {
  const source = read('renderer/batch4_tools.js');
  assert.doesNotThrow(() => new vm.Script(source, { filename: 'renderer/batch4_tools.js' }));
});

test('toolbox loads batch4 after prior evidence/render wrappers', () => {
  const html = read('renderer/toolbox.html');
  const prior = html.indexOf('artifact_tools.js');
  const batch4 = html.indexOf('batch4_tools.js');
  assert.ok(prior >= 0);
  assert.ok(batch4 > prior);
});

test('batch4 UI exposes model structure, proxy implementation and MAVLink CRC evidence', () => {
  const source = read('renderer/batch4_tools.js');
  assert.match(source, /模型文件结构完整性/);
  assert.match(source, /EVM Proxy \/ Implementation 恢复/);
  assert.match(source, /MAVLink CRC \/ Dialect 证据/);
  assert.match(source, /dangerous globals/);
});

test('Electron workspace keeps batch-four capability through a later analyzer wrapper', () => {
  const main = read('main.js');
  assert.match(main, /finals_analyzer_batch(?:4|5|6)/);
});
