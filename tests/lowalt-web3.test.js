const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { inspectArduPilotEeprom } = require('../src/core/low_altitude');
const { auditSolidity } = require('../src/core/web3');
const { scanWorkspace, buildMarkdownReport } = require('../src/core/workbench_analyzer');

function buildEeprom() {
  const buffer = Buffer.alloc(16 * 1024);
  buffer.write('PA', 0, 'ascii');
  buffer[2] = 6;
  const offset = 0x1f80;
  buffer.writeUInt32LE(0x3852fcd1, offset);
  buffer.writeUInt32LE(0, offset + 4);
  buffer.writeBigUInt64LE(123456789n, offset + 8);
  for (let index = 0; index < 32; index += 1) buffer[offset + 16 + index] = index + 1;
  return buffer;
}

const ABI_SMUGGLING_SOURCE = `
pragma solidity ^0.8.0;
contract AuthorizedExecutor {
    bool public initialized;
    mapping(bytes32 => bool) public permissions;

    function setPermissions(bytes32[] memory ids) external {
        if (initialized) revert();
        permissions[ids[0]] = true;
        initialized = true;
    }

    function execute(address target, bytes calldata actionData) external returns (bytes memory) {
        bytes4 selector;
        uint256 calldataOffset = 4 + 32 * 3;
        assembly {
            selector := calldataload(calldataOffset)
        }
        return target.functionCall(actionData);
    }
}
`;

test('ArduPilot EEPROM 提取 48-byte MAVLink signing 结构', () => {
  const result = inspectArduPilotEeprom(buildEeprom());
  assert.equal(result.format, 'ArduPilot AP_Param EEPROM');
  assert.equal(result.signing.offsetHex, '0x1f80');
  assert.equal(result.signing.magicValid, true);
  assert.equal(result.signing.timestamp, '123456789');
  assert.equal(result.signing.keyLength, 32);
  assert.equal(result.signing.signingKeyHex, '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
  assert.ok(result.findings.some((item) => item.title.includes('MAVLink 2 signing key')));
});

test('Solidity triage 命中 ABI smuggling 的硬编码 calldata selector 偏移', () => {
  const result = auditSolidity(ABI_SMUGGLING_SOURCE);
  const finding = result.findings.find((item) => item.id === 'abi-smuggling-offset');
  assert.ok(finding);
  assert.equal(finding.severity, 'high');
  assert.ok(result.findings.some((item) => item.id === 'first-caller-init'));
});

test('赛题目录扫描把 UAV/Web3 核心函数真正接入 metadata、finding 和报告', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'newcyber-lowalt-web3-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, 'eeprom.bin'), buildEeprom());
  await fs.writeFile(path.join(root, 'SelfAuthorizedVault.sol'), ABI_SMUGGLING_SOURCE, 'utf8');

  const analysis = await scanWorkspace(root);
  const eeprom = analysis.files.find((file) => file.path === 'eeprom.bin');
  const solidity = analysis.files.find((file) => file.path === 'SelfAuthorizedVault.sol');

  assert.equal(eeprom.metadata.lowAltitude.signing.magicValid, true);
  assert.ok(eeprom.findings.some((item) => item.title.includes('MAVLink 2 signing key')));
  assert.ok(solidity.metadata.web3Audit.findings.some((item) => item.id === 'abi-smuggling-offset'));
  assert.ok(solidity.findings.some((item) => item.id.startsWith('web3-abi-smuggling-offset:')));
  assert.ok(analysis.categories.some((item) => item.name === '低空经济' && item.score > 0));
  assert.ok(analysis.categories.some((item) => item.name === '区块链' && item.score > 0));

  const report = buildMarkdownReport(analysis, 'real challenge triage');
  assert.match(report, /ArduPilot \/ MAVLink/);
  assert.match(report, /0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20/);
  assert.match(report, /Solidity 静态审计/);
  assert.match(report, /abi-smuggling-offset/);
});
