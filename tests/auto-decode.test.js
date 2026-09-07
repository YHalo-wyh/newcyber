const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const { autoDecode } = require('../src/core/auto_decode');
const { runTool } = require('../src/core/tool_router');

test('auto decode finds flag through Base64 -> Hex', () => {
  const flag = 'flag{decode_chain_ok}';
  const hex = Buffer.from(flag, 'utf8').toString('hex');
  const input = Buffer.from(hex, 'utf8').toString('base64');
  const result = autoDecode(input);
  assert.equal(result.foundFlag, flag);
  assert.ok(result.flagHits.some((item) => item.path.join(' -> ') === 'Base64 decode -> Hex decode'));
});

test('auto decode finds single-byte XOR flag after hex decoding', () => {
  const flag = Buffer.from('ctf{single_byte_xor}', 'utf8');
  const encrypted = Buffer.from(flag.map((byte) => byte ^ 0x23));
  const result = autoDecode(encrypted.toString('hex'));
  assert.equal(result.foundFlag, 'ctf{single_byte_xor}');
  assert.ok(result.flagHits.some((item) => item.path.includes('XOR 0x23')));
});

test('auto decode follows Base64 -> gzip and finds flag', () => {
  const flag = 'flag{gzip_layer}';
  const packed = zlib.gzipSync(Buffer.from(flag, 'utf8'));
  const input = packed.toString('base64');
  const result = runTool('auto-decode', { input });
  assert.equal(result.foundFlag, flag);
  assert.ok(result.flagHits.some((item) => item.path.includes('Gzip decompress')));
});

test('auto decode does not claim unknown strong encryption is solved', () => {
  const input = '8f2a7c4d0e15b9aa4936d0e8c1f24751a1e8f0b893fa77c2c6de48a51b29f031';
  const result = autoDecode(input);
  assert.equal(result.foundFlag, null);
  assert.match(result.note, /key\/IV\/模式|key\/IV\/算法参数/);
  assert.ok(result.triedCandidates > 0);
});
