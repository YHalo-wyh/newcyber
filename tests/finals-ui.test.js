const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const finalsToolsPath = path.join(__dirname, '..', 'renderer', 'finals_tools.js');

function readFinalsTools() {
  return fs.readFileSync(finalsToolsPath, 'utf8');
}

test('finals_tools.js 保持可编译，避免 Electron 运行时才暴露语法错误', () => {
  const source = readFinalsTools();
  assert.doesNotThrow(() => new vm.Script(source, { filename: 'renderer/finals_tools.js' }));
});

test('决赛 UI 暴露 CANopen 与 MAVLink 真题证据', () => {
  const source = readFinalsTools();
  assert.match(source, /CANopen \/ SDO 真题证据/);
  assert.match(source, /MAVLink 飞控安全证据/);
  assert.match(source, /ARM → SERIAL/);
});

test('workspace CANopen 卡片读取 PCAPNG 展开的真实 metadata 路径', () => {
  const source = readFinalsTools();
  assert.match(source, /file\.metadata\?\.pcapng\?\.can\?\.canopen/);
  assert.doesNotMatch(source, /pcapng\?\.can\?\.summary\?\.canopen/);
});
