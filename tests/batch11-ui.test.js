const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

function assertAnalyzerAtLeast(main, minimum) {
  const match = main.match(/finals_analyzer_batch(\d+)/);
  assert.ok(match, 'main.js should load a finals analyzer wrapper');
  assert.ok(Number(match[1]) >= minimum, `expected analyzer batch >= ${minimum}, got ${match[1]}`);
}

test('Batch 11 renderer loads after UX and keeps a separate visual layer', () => {
  const html = read('renderer/toolbox.html');
  assert.ok(html.indexOf('styles/investigation.css') > html.indexOf('styles/ux.css'));
  assert.ok(html.indexOf('investigation_panel.js') > html.indexOf('ux.js'));
});

test('investigation panel compiles and exposes analyst review, tool routing and artifact export', () => {
  const source = read('renderer/investigation_panel.js');
  assert.doesNotThrow(() => new vm.Script(source, { filename:'renderer/investigation_panel.js' }));
  assert.match(source, /newcyber\.investigationReview/);
  assert.match(source, /data-investigation-tool/);
  assert.match(source, /data-review-status/);
  assert.match(source, /saveArtifact/);
  assert.match(source, /recommendedTool/);
  assert.match(source, /Exploitability/);
  assert.match(source, /Regression/);
});

test('investigation panel CSS supports fixed desktop panel, responsive overlay and review states', () => {
  const css = read('renderer/styles/investigation.css');
  assert.match(css, /\.investigation-panel/);
  assert.match(css, /investigation-open/);
  assert.match(css, /\.investigation-finding\.confirmed/);
  assert.match(css, /\.investigation-finding\.dismissed/);
  assert.match(css, /@media\(max-width:850px\)/);
});

test('Electron workspace keeps Batch 11 investigation through Batch 11 or newer analyzer wrapper', () => {
  const main = read('main.js');
  const wrapper = read('src/core/finals_analyzer_batch11.js');
  assertAnalyzerAtLeast(main,11);
  assert.match(wrapper, /buildInvestigationGraph/);
  assert.match(wrapper, /buildInvestigationSection/);
});
