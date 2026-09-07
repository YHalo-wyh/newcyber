const test = require('node:test');
const assert = require('node:assert/strict');

const { verifyMavlinkFrameCrc, analyzeMavlinkCrc, COMMON_CRC_EXTRA } = require('../src/core/mavlink_crc');
const { parseMavlinkFrames } = require('../src/core/low_altitude');
const { analyzeMavlinkAdvanced } = require('../src/core/low_altitude_final');

function refAccumulate(byte, crc) {
  let tmp = (byte ^ (crc & 0xff)) & 0xff;
  tmp ^= (tmp << 4) & 0xff;
  return ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xffff;
}

function refCrc(bytes, extra) {
  let crc = 0xffff;
  for (const byte of bytes) crc = refAccumulate(byte, crc);
  return refAccumulate(extra, crc);
}

function mav1Frame({ seq = 1, sysid = 1, compid = 1, msgid = 0, payload = Buffer.alloc(0), extra = COMMON_CRC_EXTRA[msgid], checksumOverride = null }) {
  const body = Buffer.concat([Buffer.from([payload.length, seq, sysid, compid, msgid]), payload]);
  const crc = checksumOverride == null ? refCrc(body, extra) : checksumOverride;
  const checksum = Buffer.alloc(2);
  checksum.writeUInt16LE(crc & 0xffff, 0);
  return Buffer.concat([Buffer.from([0xfe]), body, checksum]);
}

test('MAVLink1 HEARTBEAT verifies common.xml CRC_EXTRA deterministically', () => {
  const payload = Buffer.from('000000000203510403', 'hex');
  const wire = mav1Frame({ msgid: 0, payload });
  const frame = parseMavlinkFrames(wire.toString('hex'))[0];
  const result = verifyMavlinkFrameCrc(frame);
  assert.equal(result.status, 'valid');
  assert.equal(result.valid, true);
  assert.equal(result.crcExtra, 50);
});

test('MAVLink CRC mismatch is explicit and does not get silently accepted', () => {
  const payload = Buffer.from('000000000203510403', 'hex');
  const wire = mav1Frame({ msgid: 0, payload });
  wire[wire.length - 1] ^= 0xff;
  const advanced = analyzeMavlinkAdvanced(wire.toString('hex'));
  assert.equal(advanced.crcEvidence.summary.invalidFrames, 1);
  assert.ok(advanced.findings.some((item) => item.id === 'mavlink-common-crc-mismatch'));
  assert.equal(advanced.frames[0].crc.valid, false);
});

test('unknown message CRC extra stays unknown instead of guessing a dialect', () => {
  const payload = Buffer.from('010203', 'hex');
  const wire = Buffer.concat([
    Buffer.from([0xfe, payload.length, 2, 1, 1, 200]),
    payload,
    Buffer.from([0x34, 0x12])
  ]);
  const frame = parseMavlinkFrames(wire.toString('hex'))[0];
  const result = analyzeMavlinkCrc([frame]);
  assert.equal(result.summary.unknownCrcExtraFrames, 1);
  assert.equal(result.frames[0].status, 'unknown-crc-extra');
  assert.equal(result.frames[0].valid, null);
});
