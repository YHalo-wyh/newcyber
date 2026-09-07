const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const {
  analyzeMavlinkAdvanced,
  parseMavlinkFrames,
  verifyMavlink2Signature,
  decodeMavFtp
} = require('../src/core/low_altitude');

function uint48le(value) {
  let current = BigInt(value);
  const out = Buffer.alloc(6);
  for (let i = 0; i < 6; i += 1) {
    out[i] = Number(current & 0xffn);
    current >>= 8n;
  }
  return out;
}

function buildSignedV2({ payload, msgid, key, linkId = 7, timestamp = 123456789n, seq = 1, sysid = 1, compid = 1 }) {
  const header = Buffer.from([
    0xfd,
    payload.length,
    0x01,
    0x00,
    seq,
    sysid,
    compid,
    msgid & 0xff,
    (msgid >> 8) & 0xff,
    (msgid >> 16) & 0xff
  ]);
  // Parser intentionally does not claim CRC validity without dialect/CRC extra.
  const crc = Buffer.from([0x34, 0x12]);
  const packet = Buffer.concat([header, payload, crc]);
  const timestampBytes = uint48le(timestamp);
  const trailerPrefix = Buffer.concat([Buffer.from([linkId]), timestampBytes]);
  const signature = crypto.createHash('sha256')
    .update(key)
    .update(packet)
    .update(trailerPrefix)
    .digest()
    .subarray(0, 6);
  return Buffer.concat([packet, trailerPrefix, signature]);
}

function ftpPayload({ opcode, reqOpcode = 0, path = null, data = null, sequence = 1, session = 0, offset = 0, targetSystem = 1 }) {
  const body = data || Buffer.from(path || '', 'utf8');
  const header = Buffer.alloc(12);
  header.writeUInt16LE(sequence, 0);
  header[2] = session;
  header[3] = opcode;
  header[4] = body.length;
  header[5] = reqOpcode;
  header.writeUInt32LE(offset, 8);
  return Buffer.concat([Buffer.from([0, targetSystem, 1]), header, body]);
}

test('MAVLink2 signed frame: parse trailer and verify SHA-256/48 signature', () => {
  const key = Buffer.from('11'.repeat(32), 'hex');
  const frameBytes = buildSignedV2({
    payload: ftpPayload({ opcode: 4, path: 'DCIM/flag.jpg', sequence: 9 }),
    msgid: 110,
    key,
    linkId: 3,
    timestamp: 0x010203040506n
  });
  const frames = parseMavlinkFrames(frameBytes.toString('hex'));
  assert.equal(frames.length, 1);
  assert.equal(frames[0].signed, true);
  assert.equal(frames[0].signature.linkId, 3);
  assert.equal(frames[0].signature.timestamp, '1108152157446');
  const verification = verifyMavlink2Signature(frames[0], key);
  assert.equal(verification.valid, true);
  assert.equal(verification.expected, verification.computed);
});

test('MAVLink FTP OpenFileRO exposes filesystem path and protocol fields', () => {
  const decoded = decodeMavFtp(ftpPayload({ opcode: 4, path: 'DCIM/flag.jpg', sequence: 12, targetSystem: 5 }));
  assert.equal(decoded.opcodeName, 'OpenFileRO');
  assert.equal(decoded.targetSystem, 5);
  assert.equal(decoded.sequence, 12);
  assert.equal(decoded.path, 'DCIM/flag.jpg');
  assert.equal(decoded.offset, 0);
});

test('STARPWN-style signed FTP stream is surfaced as security evidence', () => {
  const key = Buffer.from('22'.repeat(32), 'hex');
  const open = buildSignedV2({
    payload: ftpPayload({ opcode: 4, path: 'DCIM/flag.jpg', sequence: 1, targetSystem: 1 }),
    msgid: 110,
    key,
    linkId: 1,
    timestamp: 1000n,
    seq: 10,
    sysid: 255,
    compid: 230
  });
  const read = buildSignedV2({
    payload: ftpPayload({ opcode: 5, sequence: 2, session: 4, offset: 0, data: Buffer.alloc(0), targetSystem: 1 }),
    msgid: 110,
    key,
    linkId: 1,
    timestamp: 1001n,
    seq: 11,
    sysid: 255,
    compid: 230
  });
  const result = analyzeMavlinkAdvanced(Buffer.concat([open, read]).toString('hex'));
  assert.equal(result.securitySummary.signedV2Frames, 2);
  assert.equal(result.securitySummary.ftpEventCount, 2);
  assert.equal(result.securitySummary.signingTimestampRegressionCount, 0);
  assert.ok(result.findings.some((item) => item.id === 'mavlink2-signed'));
  assert.ok(result.findings.some((item) => item.id === 'mavlink-ftp-filesystem-access'));
  assert.ok(result.ftpEvents.some((item) => item.path === 'DCIM/flag.jpg'));
});
