const test = require('node:test');
const assert = require('node:assert/strict');
const {
  runCodec, analyzeCan, decodeUds, analyzeNmea, analyzeMavlinkHex,
  scanAiSource, decodeCalldata, evmDisasm, searchKnowledge
} = require('../src/core/toolbox');

test('codec 支持 hex/base64/xor', () => {
  assert.equal(runCodec('text-to-hex', 'flag').output, '666c6167');
  assert.equal(runCodec('hex-to-text', '666c6167').output, 'flag');
  assert.equal(runCodec('text-to-base64', 'abc').output, 'YWJj');
  assert.equal(runCodec('xor-hex', '4142', '01').output, '4043');
});

test('CAN analyzer 识别 ID、变化字节与 counter', () => {
  const input = '(1.000) can0 123#00112233\n(1.100) can0 123#01112233\n(1.200) can0 123#02112233\n(1.300) can0 123#03112233\ncan0 456#AA';
  const result = analyzeCan(input);
  assert.equal(result.parsedFrames, 5);
  assert.equal(result.uniqueIds, 2);
  const item = result.ids.find((entry) => entry.id === '0x123');
  assert.deepEqual(item.changingBytes, [0]);
  assert.deepEqual(item.counterCandidates, [0]);
  assert.equal(item.averageIntervalMs, 100);
});

test('UDS decoder 识别 SecurityAccess 和 NRC', () => {
  assert.equal(decodeUds('27 01').securityAccess.meaning, 'requestSeed');
  assert.equal(decodeUds('7f 27 35').nrcName, 'invalidKey');
  assert.equal(decodeUds('02 10 03').serviceName, 'DiagnosticSessionControl');
});

test('NMEA analyzer 解析 RMC/GGA', () => {
  const input = '$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A\n$GPGGA,123520,4807.100,N,01131.100,E,1,08,0.9,545.4,M,46.9,M,,*47';
  const result = analyzeNmea(input);
  assert.equal(result.validPoints, 2);
  assert.ok(result.distanceM > 0);
});

test('MAVLink parser 识别 v1 HEARTBEAT', () => {
  const frame = 'fe0001010100ffff';
  const result = analyzeMavlinkHex(frame);
  assert.equal(result.parsedFrames, 1);
  assert.equal(result.frames[0].name, 'HEARTBEAT');
});

test('AI source scanner 找危险反序列化与 shell', () => {
  const result = scanAiSource('import torch\nmodel=torch.load(path)\nsubprocess.run(cmd, shell=True)');
  assert.ok(result.findings.some((item) => item.id === 'unsafe-deserialization'));
  assert.ok(result.findings.some((item) => item.id === 'shell-sink'));
});

test('EVM calldata/disasm 基础功能', () => {
  const call = decodeCalldata('a9059cbb' + '0'.repeat(24) + '1234567890abcdef1234567890abcdef12345678' + '0'.repeat(63) + '1');
  assert.equal(call.knownSignature, 'transfer(address,uint256)');
  assert.equal(call.words[1].uint256, '1');
  const disasm = evmDisasm('6001600055f1');
  assert.ok(disasm.instructions.some((item) => item.name === 'SSTORE'));
  assert.ok(disasm.riskyOpcodes.some((item) => item.name === 'CALL'));
});

test('offline knowledge 可检索', () => {
  assert.ok(searchKnowledge('SecurityAccess').length >= 1);
  assert.ok(searchKnowledge('MAVLink 76', '低空经济').length >= 1);
});
