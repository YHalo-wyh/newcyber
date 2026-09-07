const test = require('node:test');
const assert = require('node:assert/strict');
const { KNOWN_SELECTORS } = require('../src/core/evm_runtime');

test('ERC20 allowance selector keeps canonical two-argument signature', () => {
  assert.equal(KNOWN_SELECTORS.get('0xdd62ed3e'), 'allowance(address,address)');
});
