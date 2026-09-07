const test = require('node:test');
const assert = require('node:assert/strict');

const { createBinaryArtifact, bufferFromArtifact } = require('../src/core/artifacts');
const { reconstructUdsProgramming } = require('../src/core/uds_programming');
const { reconstructMavFtpFiles } = require('../src/core/mavlink_ftp_reassembly');
const { evaluateTabularCandidate } = require('../src/core/ai_tabular');
const { analyzeEvmRuntime } = require('../src/core/evm_runtime');

test('binary artifact is hash-bound and rejects tampered payload', () => {
  const artifact = createBinaryArtifact({ name: '../firmware.bin', buffer: Buffer.from('00112233', 'hex') });
  assert.equal(artifact.name, 'firmware.bin');
  assert.equal(artifact.size, 4);
  assert.equal(bufferFromArtifact(artifact).buffer.toString('hex'), '00112233');
  assert.throws(() => bufferFromArtifact({ ...artifact, hex: '00112234' }), /SHA-256/);
});

test('UDS complete programming session emits exportable artifact and block provenance', () => {
  const sessions = [
    { canId: '0x7E0', complete: true, payload: '1002' },
    { canId: '0x7E0', complete: true, payload: '3400441000000000000006' },
    { canId: '0x7E0', complete: true, payload: '3601aabbcc' },
    { canId: '0x7E0', complete: true, payload: '3602ddeeff' },
    { canId: '0x7E0', complete: true, payload: '37' }
  ];
  const result = reconstructUdsProgramming(sessions);
  const transfer = result.transfers[0];
  assert.equal(result.exportableTransfers, 1);
  assert.equal(transfer.artifactReady, true);
  assert.equal(transfer.artifact.hex, 'aabbccddeeff');
  assert.equal(transfer.artifact.metadata.address, '0x10000000');
  assert.deepEqual(transfer.blockMap.map((item) => [item.counter, item.offset, item.length]), [[1, 0, 3], [2, 3, 3]]);
});

test('UDS gap keeps evidence but refuses binary artifact', () => {
  const sessions = [
    { canId: '0x7E0', complete: true, payload: '3400441000000000000006' },
    { canId: '0x7E0', complete: true, payload: '3601aabbcc' },
    { canId: '0x7E0', complete: true, payload: '3603ddeeff' },
    { canId: '0x7E0', complete: true, payload: '37' }
  ];
  const transfer = reconstructUdsProgramming(sessions).transfers[0];
  assert.equal(transfer.artifact, null);
  assert.ok(transfer.errors.some((item) => item.id === 'block-sequence-gap'));
  assert.equal(transfer.blockMap.length, 2);
});

test('MAVLink FTP out-of-order chunks reassemble only when byte coverage is complete', () => {
  const events = [
    { frameIndex: 1, sysid: 255, compid: 190, targetSystem: 1, targetComponent: 1, sequence: 7, session: 0, opcode: 4, path: 'DCIM/flag.jpg' },
    { frameIndex: 2, sysid: 1, compid: 1, targetSystem: 255, targetComponent: 190, sequence: 7, session: 3, opcode: 128, reqOpcode: 4, openedFileSize: 6 },
    { frameIndex: 3, sysid: 1, compid: 1, sequence: 8, session: 3, opcode: 128, reqOpcode: 5, fileChunk: { offset: 3, dataHex: 'ddeeff' } },
    { frameIndex: 4, sysid: 1, compid: 1, sequence: 9, session: 3, opcode: 128, reqOpcode: 5, fileChunk: { offset: 0, dataHex: 'aabbcc' } }
  ];
  const result = reconstructMavFtpFiles(events);
  const file = result.files[0];
  assert.equal(result.exportableFiles, 1);
  assert.equal(file.complete, true);
  assert.equal(file.path, 'DCIM/flag.jpg');
  assert.equal(file.artifact.name, 'flag.jpg');
  assert.equal(file.artifact.hex, 'aabbccddeeff');
  assert.deepEqual(file.gaps, []);
});

test('MAVLink FTP conflicting overlap never emits artifact', () => {
  const events = [
    { frameIndex: 1, sysid: 255, compid: 190, targetSystem: 1, sequence: 1, session: 0, opcode: 4, path: 'x.bin' },
    { frameIndex: 2, sysid: 1, compid: 1, sequence: 1, session: 2, opcode: 128, reqOpcode: 4, openedFileSize: 4 },
    { frameIndex: 3, sysid: 1, compid: 1, sequence: 2, session: 2, opcode: 128, reqOpcode: 5, fileChunk: { offset: 0, dataHex: 'aabbccdd' } },
    { frameIndex: 4, sysid: 1, compid: 1, sequence: 3, session: 2, opcode: 128, reqOpcode: 5, fileChunk: { offset: 2, dataHex: 'ffee' } }
  ];
  const file = reconstructMavFtpFiles(events).files[0];
  assert.equal(file.complete, false);
  assert.equal(file.artifact, null);
  assert.ok(file.conflictingBytes > 0);
});

test('AI candidate validator distinguishes center-like candidate and broken joint relation', () => {
  const dataset = [
    'x,y,z',
    '0,0,10',
    '1,2,11',
    '2,4,12',
    '3,6,13',
    '4,8,14',
    '5,10,15',
    '6,12,16',
    '7,14,17',
    '8,16,18',
    '9,18,19'
  ].join('\n');
  const strong = evaluateTabularCandidate(`${dataset}\n--- candidate ---\n{"x":4.5,"y":9,"z":14.5}`);
  assert.equal(strong.profileCompatibility, 'strong');
  assert.ok(strong.standardizedProfileDistance < 0.2);
  const broken = evaluateTabularCandidate(`${dataset}\n--- candidate ---\n{"x":4.5,"y":0,"z":14.5}`);
  assert.notEqual(broken.profileCompatibility, 'strong');
  assert.ok(broken.correlationChecks.some((item) => item.status === 'inconsistent'));
});

test('EVM local data flow links calldata to SSTORE and storage to CALL value', () => {
  const bytecode = '0x60043560015560006000600060006001546042612710f100';
  const result = analyzeEvmRuntime(bytecode);
  const write = result.dataFlow.storageFlows.find((item) => item.type === 'SSTORE');
  assert.ok(write);
  assert.equal(write.slotExpr, '0x01');
  assert.match(write.valueExpr, /calldata\[0x04\]/);
  const call = result.dataFlow.calls.find((item) => item.type === 'CALL');
  assert.ok(call);
  assert.equal(call.toExpr, '0x42');
  assert.match(call.valueExpr, /storage\[0x01\]/);
  assert.equal(result.dataFlow.linkedStorageWrites, 1);
  assert.equal(result.dataFlow.linkedCalls, 1);
});
