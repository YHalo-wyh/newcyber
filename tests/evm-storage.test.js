const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeEvmRuntime, extractStorageAccesses } = require('../src/core/evm_runtime');
const { evmDisasm } = require('../src/core/toolbox');

// Exact runtime fragment from LilCTF 2025 / 生蚝的宝藏:
//   PUSH1 0x01 ; SLOAD ; PUSH1 0xff ; AND
// Dedaub infers this storage slot as _isSolved.
test('LilCTF 2025 blockchain-treasure: recover direct storage slot 0x1 read', () => {
  const result = analyzeEvmRuntime('0x60015460ff16');
  assert.equal(result.storage.reads, 1);
  assert.equal(result.storage.writes, 0);
  assert.equal(result.storage.accesses[0].type, 'SLOAD');
  assert.equal(result.storage.accesses[0].directSlot, '0x1');
  const slot = result.storage.slots.find((item) => item.slot === '0x1');
  assert.ok(slot);
  assert.equal(slot.reads, 1);
  assert.equal(slot.highConfidenceReads, 1);
});

// Exact state-update fragment from the same runtime:
//   PUSH1 0x01 DUP1 SLOAD ... OR SWAP1 SSTORE
// The SSTORE key is stack-derived, so it must be a candidate rather than a fake
// high-confidence direct slot.
test('LilCTF 2025 blockchain-treasure: keep complex SSTORE slot as evidence candidate', () => {
  const result = analyzeEvmRuntime('0x6001805460ff191681179055');
  assert.equal(result.storage.reads, 1);
  assert.equal(result.storage.writes, 1);
  const write = result.storage.accesses.find((item) => item.type === 'SSTORE');
  assert.ok(write);
  assert.equal(write.directSlot, null);
  assert.ok(write.slotCandidates.some((item) => item.slot === '0x1'));
  assert.ok(write.slotCandidates.every((item) => item.confidence !== 'high'));
});

test('storage evidence never crosses a terminating basic-block boundary', () => {
  const instructions = evmDisasm('0x6001005b600254').instructions;
  const storage = extractStorageAccesses(instructions);
  assert.equal(storage.reads, 1);
  assert.equal(storage.accesses[0].directSlot, '0x2');
  assert.ok(storage.accesses[0].slotCandidates.every((item) => item.slot !== '0x1'));
});
