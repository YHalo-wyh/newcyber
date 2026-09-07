const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('UX layer loads after all functional renderer extensions', () => {
  const html = read('renderer/toolbox.html');
  const competitionCss = html.indexOf('styles/competition_mode.css');
  const uxCss = html.indexOf('styles/ux.css');
  const batch9 = html.indexOf('ai_batch9_tools.js');
  const ux = html.indexOf('ux.js');
  assert.ok(competitionCss >= 0 && uxCss > competitionCss, 'UX CSS must be the final visual override');
  assert.ok(batch9 >= 0 && ux > batch9, 'UX JS must load after Batch 9 tool registration');
});

test('UX script is syntactically valid and keeps interaction offline', () => {
  const source = read('renderer/ux.js');
  assert.doesNotThrow(() => new Function(source));
  assert.match(source, /newcyber\.sidebarCollapsed/);
  assert.match(source, /event\.key\.toLowerCase\(\) === 'k'/);
  assert.match(source, /event\.key === 'Enter'/);
  assert.match(source, /event\.shiftKey.*'o'/s);
  assert.match(source, /runCurrentTool\(\)/);
  assert.match(source, /chooseWorkspace\(\)/);
  assert.doesNotMatch(source, /\bfetch\s*\(|https?:\/\//i, 'UX layer must not add network dependency');
});

test('competition-specific legacy banner is replaced by neutral product copy', () => {
  const source = read('renderer/ux.js');
  assert.match(source, /BAY AREA CUP · OFFLINE TOOLBOX/);
  assert.match(source, /OFFLINE · DETERMINISTIC · FOUR TRACKS/);
});

test('UX CSS covers keyboard focus, command palette, sidebar memory states and reduced motion', () => {
  const css = read('renderer/styles/ux.css');
  assert.match(css, /:focus-visible/);
  assert.match(css, /#ux-command-palette/);
  assert.match(css, /sidebar-collapsed/);
  assert.match(css, /sidebar-mobile-open/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /ux-input-meta/);
});
