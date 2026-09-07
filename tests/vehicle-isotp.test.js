const test = require('node:test');
const assert = require('node:assert/strict');
const { reassembleIsoTp, analyzeCanAdvanced } = require('../src/core/vehicle');

test('ISO-TP 重组跨 3 帧的 UDS VIN 响应', () => {
  const capture = [
    '(1.000000) can0 7E8#101462F190313233',
    '(1.010000) can0 7E8#2134353637383941',
    '(1.020000) can0 7E8#2242434445464748'
  ].join('\n');
  const sessions = reassembleIsoTp(capture);
  assert.equal(sessions.length, 1);
  const session = sessions[0];
  assert.equal(session.complete, true);
  assert.equal(session.totalLength, 20);
  assert.equal(session.collectedLength, 20);
  assert.equal(session.payload, '62f1903132333435363738394142434445464748');
  assert.deepEqual(session.sequenceNumbers, [1, 2]);
  assert.equal(session.startFrameIndex, 1);
  assert.equal(session.endFrameIndex, 3);
  assert.equal(session.uds.serviceName, 'ReadDataByIdentifier');
});

test('ISO-TP CF 序号错位时停止重组并明确报错', () => {
  const capture = [
    '7E8#101462F190313233',
    '7E8#2234353637383941'
  ].join('\n');
  const [session] = reassembleIsoTp(capture);
  assert.equal(session.complete, false);
  assert.equal(session.error, 'sequence-mismatch');
  assert.equal(session.expectedSequence, 1);
  assert.equal(session.actualSequence, 2);
  assert.equal(session.frameCount, 1);
});

test('ISO-TP 支持 Consecutive Frame 序号 F→0 回绕', () => {
  const total = 6 + (15 * 7) + 2;
  const first = Buffer.from([0x10 | ((total >> 8) & 0x0f), total & 0xff, 0x62, 0xf1, 0x90, 0x41, 0x42, 0x43]);
  const lines = [`7E8#${first.toString('hex')}`];
  for (let sequence = 1; sequence <= 15; sequence += 1) {
    const data = Buffer.alloc(7, 0x40 + sequence);
    lines.push(`7E8#${Buffer.concat([Buffer.from([0x20 | sequence]), data]).toString('hex')}`);
  }
  lines.push(`7E8#20${Buffer.alloc(7, 0x5a).toString('hex')}`);
  const [session] = reassembleIsoTp(lines.join('\n'));
  assert.equal(session.complete, true);
  assert.equal(session.totalLength, total);
  assert.equal(session.sequenceNumbers.at(-2), 15);
  assert.equal(session.sequenceNumbers.at(-1), 0);
});

test('CAN 高级分析直接暴露完整 ISO-TP sessions，普通 00 帧不误认', () => {
  const capture = [
    '188#00000000',
    '7E8#101462F190313233',
    '7E8#2134353637383941',
    '7E8#2242434445464748'
  ].join('\n');
  const result = analyzeCanAdvanced(capture);
  assert.equal(result.isoTpSessions.length, 1);
  assert.equal(result.isoTpSessions[0].complete, true);
  assert.equal(result.isoTpSessions[0].canId, '0x7E8');
});
