const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeEvmRuntime, extractSelectorCandidates } = require('../src/core/evm_runtime');

// Challenge-driven regression: old iChunqiu/Spring Cup contract tasks may provide only
// deployed bytecode/decompiler output and require locating hidden business entrypoints.
// This synthetic runtime preserves the standard Solidity dispatcher shape without
// inventing any challenge-specific selector.
test('EVM runtime：提取 PUSH4 → EQ → JUMPI dispatcher selector 与目标地址', () => {
  const bytecode = [
    '63a9059cbb', // PUSH4 transfer(address,uint256)
    '14',         // EQ
    '610020',     // PUSH2 0x20
    '57',         // JUMPI
    '63deadbeef', // another selector
    '14',
    '610040',
    '57',
    '00'
  ].join('');

  const result = analyzeEvmRuntime(bytecode);
  assert.equal(result.dispatcherSelectors.length, 2);
  assert.deepEqual(result.dispatcherSelectors.map((item) => item.selector), ['0xa9059cbb', '0xdeadbeef']);
  assert.equal(result.dispatcherSelectors[0].knownSignature, 'transfer(address,uint256)');
  assert.equal(result.dispatcherSelectors[0].destination, '0x0020');
  assert.equal(result.dispatcherSelectors[1].destination, '0x0040');
});

test('EVM runtime 负例：孤立 PUSH4 常量不应冒充 dispatcher', () => {
  const instructions = [
    { pc: 0, name: 'PUSH4', immediate: '0xdeadbeef' },
    { pc: 5, name: 'POP', immediate: null },
    { pc: 6, name: 'STOP', immediate: null }
  ];
  const candidates = extractSelectorCandidates(instructions);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].looksLikeDispatcher, false);
  assert.equal(candidates[0].destination, null);
});
