const test = require('node:test');
const assert = require('node:assert/strict');
const { auditSolidity, maskNonCode } = require('../src/core/web3');

test('Solidity 审计忽略注释和字符串里的危险关键字', () => {
  const source = `
// tx.origin; target.delegatecall(payload); selfdestruct(payable(msg.sender));
/*
  address(victim).call(payload);
  assembly { let selector := calldataload(offset) }
*/
contract NoiseOnly {
  string constant NOTE = "tx.origin .delegatecall( selfdestruct( .call(";
  function safe() external pure returns (string memory) {
    return "unchecked { target.delegatecall(payload); }";
  }
}
`;
  const result = auditSolidity(source);
  assert.deepEqual(result.findings, []);
});

test('Solidity 遮罩保持源码长度和换行位置', () => {
  const source = 'contract A {\n// tx.origin\nstring x = "delegatecall(";\nfunction f() external {}\n}\n';
  const masked = maskNonCode(source);
  assert.equal(masked.length, source.length);
  assert.equal(masked.split('\n').length, source.split('\n').length);
  assert.doesNotMatch(masked, /tx\.origin|delegatecall/);
  assert.match(masked, /contract A/);
  assert.match(masked, /function f/);
});

test('Solidity 审计遮罩后仍识别真实代码并保留原始行号', () => {
  const source = `
contract RealFinding {
  // fake: tx.origin
  function bad(address target, bytes calldata payload) external {
    require(tx.origin == msg.sender);
    (bool ok,) = target.delegatecall(payload);
    require(ok);
  }
}
`;
  const result = auditSolidity(source);
  const origin = result.findings.find((item) => item.id === 'tx-origin');
  const delegate = result.findings.find((item) => item.id === 'delegatecall');
  assert.ok(origin);
  assert.ok(delegate);
  assert.equal(origin.line, 5);
  assert.equal(delegate.line, 6);
  assert.match(origin.evidence, /require\(tx\.origin/);
});
