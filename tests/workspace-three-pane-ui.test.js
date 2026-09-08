const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

test('three-pane workspace renderer compiles and loads after tool/investigation UI', () => {
  const source = read('renderer/workspace_three_pane.js');
  const html = read('renderer/toolbox.html');
  assert.doesNotThrow(() => new vm.Script(source, { filename:'renderer/workspace_three_pane.js' }));
  assert.ok(html.indexOf('workspace_three_pane.js') > html.indexOf('investigation_panel.js'));
  assert.ok(html.indexOf('workspace_three_pane.js') > html.indexOf('tool_ui.js'));
  assert.match(html, /styles\/workspace_three_pane\.css/);
});

test('workspace is a compact files-results-investigation desk', () => {
  const source = read('renderer/workspace_three_pane.js');
  for (const token of ['ws-files-pane','ws-main-pane','ws-investigation-pane','关键 Finding','Flag','Artifact','下一步']) {
    assert.match(source, new RegExp(token));
  }
  assert.match(source, /inspectFile\(state\.workspace\.workspacePath/);
  assert.match(source, /saveArtifact\(artifact\)/);
  assert.match(source, /data-tool=/);
});

test('workspace frontend avoids landing-page copy and keeps tool-like controls', () => {
  const source = read('renderer/workspace_three_pane.js');
  assert.doesNotMatch(source, /把题目丢进来|先告诉你下一步做什么|一台机器解决重复劳动/);
  for (const label of ['过滤文件 / 类型','导出报告','重新扫描','读取文件','元数据']) assert.match(source, new RegExp(label));
});
