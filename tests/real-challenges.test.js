const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeCanAdvanced, decodeUdsAdvanced } = require('../src/core/vehicle');

// Regression source: 2025 CISCN Finals / easy_can.
// Public writeups identify ICSim signal CAN ID 0x188 and the first right-turn state as bit 0x02.
test('CISCN 2025 easy_can: 定位 0x188 首次 00→02 状态跃迁', () => {
  const capture = [
    '(1.000000) can0 188#00000000',
    '(1.050000) can0 100#11223344',
    '(1.100000) can0 188#00000000',
    '(1.150000) can0 244#01020304',
    '(1.200000) can0 188#02000000',
    '(1.300000) can0 188#02000000'
  ].join('\n');

  const result = analyzeCanAdvanced(capture);
  const signal = result.ids.find((item) => item.id === '0x188');
  assert.ok(signal);
  assert.deepEqual(signal.changingBytes, [0]);
  const firstTurnOn = signal.transitions.find((event) => event.changes.some((change) => change.byteIndex === 0 && change.setBits === 0x02));
  assert.ok(firstTurnOn);
  assert.equal(firstTurnOn.frameIndex, 5);
  assert.equal(firstTurnOn.payload, '02000000');
});

// Regression source: yichen115/UDSCTF README.
test('UDSCTF: VIN ReadDataByIdentifier 7DF#0322F190', () => {
  const result = decodeUdsAdvanced('7DF#0322F190');
  assert.equal(result.serviceName, 'ReadDataByIdentifier');
  assert.equal(result.did, '0xf190');
  assert.equal(result.can.id, '0x7DF');
});

test('UDSCTF: SecurityAccess level1 seed/key', () => {
  const seedRequest = decodeUdsAdvanced('7DF#022701');
  assert.equal(seedRequest.securityAccess.meaning, 'requestSeed');
  assert.equal(seedRequest.securityAccess.level, 1);

  const keyRequest = decodeUdsAdvanced('7DF#062702CCD9F897');
  assert.equal(keyRequest.securityAccess.meaning, 'sendKey');
  assert.equal(keyRequest.securityAccess.level, 1);
  assert.equal(keyRequest.securityAccess.seedOrKey, '0xccd9f897');
});

test('UDSCTF: programming session 7DF#021002', () => {
  const result = decodeUdsAdvanced('7DF#021002');
  assert.equal(result.serviceName, 'DiagnosticSessionControl');
  assert.equal(result.session.name, 'programmingSession');
});

test('UDSCTF: ReadMemoryByAddress 7DF#0723144000000050', () => {
  const result = decodeUdsAdvanced('7DF#0723144000000050');
  assert.equal(result.serviceName, 'ReadMemoryByAddress');
  assert.equal(result.readMemory.addressAndLengthFormatIdentifier, '0x14');
  assert.equal(result.readMemory.address, '0x40000000');
  assert.equal(result.readMemory.size, '80');
});

test('UDSCTF: TransferData 解出 blockSequenceCounter', () => {
  // Raw UDS payload: avoid pretending an 8-byte payload fits in a Classical-CAN ISO-TP single frame.
  const result = decodeUdsAdvanced('36 03 DE AD BE EF 00 01');
  assert.equal(result.serviceName, 'TransferData');
  assert.equal(result.transferData.blockSequenceCounter, 3);
  assert.equal(result.transferData.data, 'deadbeef0001');
});
