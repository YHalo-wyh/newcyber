const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { analyzeCanAdvanced } = require('../src/core/vehicle_final');
const { parseRequestDownload } = require('../src/core/uds_programming');

test('UDS programming: reconstruct 0x34 -> 0x36 -> 0x37 firmware candidate', () => {
  const capture = [
    '7E0#0210020000000000',
    '7E0#0734002210000006',
    '7E0#053601aabbcc0000',
    '7E0#053602ddeeff0000',
    '7E0#0137000000000000'
  ].join('\n');
  const result = analyzeCanAdvanced(capture);
  assert.equal(result.udsProgramming.completeTransfers, 1);
  const transfer = result.udsProgramming.transfers[0];
  assert.equal(transfer.programmingSessionSeen, true);
  assert.equal(transfer.requestDownload.address, '0x1000');
  assert.equal(transfer.requestDownload.size, '6');
  assert.deepEqual(transfer.blockSequenceCounters, [1, 2]);
  assert.equal(transfer.firmwareHex, 'aabbccddeeff');
  assert.equal(transfer.declaredSizeMatches, true);
  assert.equal(transfer.confidence, 'high');
  assert.equal(transfer.firmwareSha256, crypto.createHash('sha256').update(Buffer.from('aabbccddeeff', 'hex')).digest('hex'));
});

test('UDS programming: blockSequenceCounter gap lowers confidence and is explicit', () => {
  const capture = [
    '7E0#0734002210000006',
    '7E0#053601aabbcc0000',
    '7E0#053603ddeeff0000',
    '7E0#0137000000000000'
  ].join('\n');
  const transfer = analyzeCanAdvanced(capture).udsProgramming.transfers[0];
  assert.ok(transfer.errors.some((item) => item.id === 'block-sequence-gap'));
  assert.equal(transfer.confidence, 'medium');
});

test('RequestDownload parser exposes DFI/ALFID/address/size without guessing vendor semantics', () => {
  const parsed = parseRequestDownload([0x34, 0x00, 0x24, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00]);
  assert.equal(parsed.addressLength, 4);
  assert.equal(parsed.sizeLength, 2);
  assert.equal(parsed.address, '0x40000000');
  assert.equal(parsed.size, '256');
});
