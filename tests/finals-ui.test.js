const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const finalsToolsPath = path.join(__dirname, '..', 'renderer', 'finals_tools.js');
const evmRuntimeToolsPath = path.join(__dirname, '..', 'renderer', 'evm_runtime_tools.js');
const toolboxHtmlPath = path.join(__dirname, '..', 'renderer', 'toolbox.html');

function read(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

test('决赛 renderer 扩展保持可编译，避免 Electron 运行时才暴露语法错误', () => {
  assert.doesNotThrow(() => new vm.Script(read(finalsToolsPath), { filename: 'renderer/finals_tools.js' }));
  assert.doesNotThrow(() => new vm.Script(read(evmRuntimeToolsPath), { filename: 'renderer/evm_runtime_tools.js' }));
});

test('决赛 UI 暴露 CANopen、MAVLink 与 EVM runtime 真题证据', () => {
  const finals = read(finalsToolsPath);
  const evm = read(evmRuntimeToolsPath);
  assert.match(finals, /CANopen \/ SDO 真题证据/);
  assert.match(finals, /MAVLink 飞控安全证据/);
  assert.match(finals, /ARM → SERIAL/);
  assert.match(evm, /EVM Runtime 入口恢复/);
  assert.match(evm, /dispatcher selectors/);
});

test('workspace CANopen 卡片读取 PCAPNG 展开的真实 metadata 路径', () => {
  const source = read(finalsToolsPath);
  assert.match(source, /file\.metadata\?\.pcapng\?\.can\?\.canopen/);
  assert.doesNotMatch(source, /pcapng\?\.can\?\.summary\?\.canopen/);
});

test('toolbox HTML 按依赖顺序加载 EVM runtime UI 扩展', () => {
  const html = read(toolboxHtmlPath);
  const finalsIndex = html.indexOf('finals_tools.js');
  const evmIndex = html.indexOf('evm_runtime_tools.js');
  assert.ok(finalsIndex >= 0);
  assert.ok(evmIndex > finalsIndex);
});
