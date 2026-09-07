const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

test('competition mode renderer stays compilable', () => {
  assert.doesNotThrow(() => new vm.Script(read('renderer/competition_mode.js'), { filename: 'renderer/competition_mode.js' }));
});

test('competition mode loads after advanced renderer extensions', () => {
  const html = read('renderer/toolbox.html');
  const batch4 = html.indexOf('batch4_tools.js');
  const competition = html.indexOf('competition_mode.js');
  assert.ok(batch4 >= 0);
  assert.ok(competition > batch4);
  assert.match(html, /styles\/competition_mode\.css/);
});

test('competition mode defaults to actionable beginner output and keeps advanced evidence folded', () => {
  const source = read('renderer/competition_mode.js');
  assert.match(source, /现在按这个顺序做/);
  assert.match(source, /最值得追的线索/);
  assert.match(source, /优先看的文件/);
  assert.match(source, /展开技术细节（卡住时再看）/);
  assert.match(source, /data-competition-artifact/);
  assert.match(source, /window\.newcyber\.saveArtifact\(artifact\)/);
  assert.doesNotMatch(source, /data-artifact-hex/);
});

test('competition mode still exposes all four tracks', () => {
  const source = read('renderer/competition_mode.js');
  for (const name of ['车联网安全', '低空经济安全', '人工智能安全', '区块链安全']) assert.match(source, new RegExp(name));
});
