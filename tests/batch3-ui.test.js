const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

test('batch-three renderer extensions stay compilable', () => {
  for (const name of ['renderer/batch3_tools.js', 'renderer/artifact_tools.js']) {
    assert.doesNotThrow(() => new vm.Script(read(name), { filename: name }));
  }
});

test('toolbox loads batch3 before artifact click handler', () => {
  const html = read('renderer/toolbox.html');
  const batch = html.indexOf('batch3_tools.js');
  const artifact = html.indexOf('artifact_tools.js');
  assert.ok(batch >= 0);
  assert.ok(artifact > batch);
});

test('artifact save IPC is exposed through isolated preload and verified in main', () => {
  const main = read('main.js');
  const preload = read('preload.js');
  assert.match(main, /artifact:save/);
  assert.match(main, /bufferFromArtifact\(artifact, \{ requireComplete: true \}\)/);
  assert.match(preload, /saveArtifact: \(artifact\) => ipcRenderer\.invoke\('artifact:save', artifact\)/);
});

test('batch3 UI exposes candidate validation and artifact export without embedding artifact hex in DOM', () => {
  const source = read('renderer/batch3_tools.js');
  assert.match(source, /ai-tabular-candidate/);
  assert.match(source, /data-save-artifact/);
  assert.match(source, /EVM 局部状态流/);
  assert.doesNotMatch(source, /data-artifact-hex/);
});
