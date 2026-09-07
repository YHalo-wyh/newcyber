const test = require('node:test');
const assert = require('node:assert/strict');

const { detectEip1167, EIP1967_SLOTS } = require('../src/core/evm_proxy');
const { analyzeEvmRuntime } = require('../src/core/evm_runtime_batch4');
const { runTool } = require('../src/core/tool_router');

test('EIP-1167 canonical runtime recovers embedded implementation address', () => {
  const implementation = '1234567890abcdef1234567890abcdef12345678';
  const runtime = `0x363d3d373d3d3d363d73${implementation}5af43d82803e903d91602b57fd5bf3`;
  const result = analyzeEvmRuntime(runtime);
  assert.equal(result.proxy.classification, 'eip-1167-minimal-proxy');
  assert.equal(result.proxy.confidence, 'high');
  assert.equal(result.proxy.minimalProxy.implementation, `0x${implementation}`);
  assert.equal(detectEip1167(runtime).runtimeLengthBytes, 45);
});

test('EIP-1967 implementation SLOAD flowing into DELEGATECALL is high-confidence direct proxy evidence', () => {
  const slot = EIP1967_SLOTS.implementation.slice(2);
  const bytecode = `0x60006000600060007f${slot}5461fffff4`;
  const result = analyzeEvmRuntime(bytecode);
  const implementationSlot = result.proxy.slots.find((item) => item.kind === 'implementation');
  assert.equal(result.proxy.classification, 'eip-1967-direct-proxy');
  assert.equal(result.proxy.confidence, 'high');
  assert.equal(implementationSlot.referenced, true);
  assert.equal(implementationSlot.readIntoDelegateCall, true);
  assert.equal(implementationSlot.sloadPcs.length, 1);
  assert.equal(result.proxy.delegateCalls.length, 1);
  assert.match(result.proxy.delegateCalls[0].toExpr, /storage\[0x360894a13ba1a321/);
});

test('EIP-1967 slot constant without DELEGATECALL does not become a proxy by itself', () => {
  const slot = EIP1967_SLOTS.admin.slice(2);
  const result = analyzeEvmRuntime(`0x7f${slot}5400`);
  assert.equal(result.proxy.slots.find((item) => item.kind === 'admin').referenced, true);
  assert.equal(result.proxy.isProxyCandidate, false);
  assert.equal(result.proxy.classification, null);
});

test('tool router exposes proxy recovery on evm-disasm', () => {
  const implementation = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const runtime = `0x363d3d373d3d3d363d73${implementation}5af43d82803e903d91602b57fd5bf3`;
  const result = runTool('evm-disasm', { input: runtime });
  assert.equal(result.proxy.minimalProxy.implementation, `0x${implementation}`);
});
