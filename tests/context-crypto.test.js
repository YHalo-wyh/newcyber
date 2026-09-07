const test = require('node:test');
const assert = require('node:assert/strict');
const { extractCryptoContext, decryptCryptoContext, cipherName } = require('../src/core/context_crypto');
const { runTool } = require('../src/core/tool_router');

const COMMON = `
from Crypto.Cipher import AES
key = b"0123456789abcdef"
iv = b"abcdef9876543210"
`;

test('context crypto: explicit AES-CBC key/iv/hex ciphertext recovers flag', () => {
  const source = `${COMMON}
ciphertext = bytes.fromhex("1c3283f1c199a78698919361e70f619c51c850d4f8328773f35fdc3540708b99")
cipher = AES.new(key, AES.MODE_CBC, iv)
`;
  const context = extractCryptoContext(source);
  assert.deepEqual(context.algorithms, ['aes']);
  assert.deepEqual(context.modes, ['cbc']);
  assert.ok(context.keys.some((item) => item.encoding === 'utf8' && item.bytes === 16));
  assert.ok(context.ivs.some((item) => item.encoding === 'utf8' && item.bytes === 16));
  assert.ok(context.ciphertexts.some((item) => item.encoding === 'hex' && item.bytes === 32));
  assert.equal(context.ready, true);

  const result = decryptCryptoContext(source);
  assert.equal(result.foundFlag, 'flag{context_crypto_ok}');
  assert.ok(result.bestCandidates.some((item) => item.cipher === 'aes-128-cbc' && item.flags.includes('flag{context_crypto_ok}')));
});

test('context crypto: decrypted Base64 is fed into existing auto-decode chain', () => {
  const source = `${COMMON}
encrypted_flag = bytes.fromhex("4ba88908d4edfc5b0dd089c3a5b226618aec2a6d74abd5a4d8891ec2556993fb258d9db0fce3f9cea097998f7252781e")
cipher = AES.new(key, AES.MODE_CBC, iv)
`;
  const result = decryptCryptoContext(source);
  assert.equal(result.foundFlag, 'flag{nested_crypto_ok}');
  const hit = result.bestCandidates.find((item) => item.flags.includes('flag{nested_crypto_ok}'));
  assert.ok(hit);
  assert.ok(Array.isArray(hit.nestedPath));
  assert.ok(hit.nestedPath.some((step) => /Base64 decode/i.test(step)));
});

test('context crypto: missing IV is explicit and never turns into broad mode guessing', () => {
  const source = `
from Crypto.Cipher import AES
key = b"0123456789abcdef"
ciphertext = bytes.fromhex("1c3283f1c199a78698919361e70f619c51c850d4f8328773f35fdc3540708b99")
cipher = AES.new(key, AES.MODE_CBC)
`;
  const context = extractCryptoContext(source);
  assert.ok(context.missing.includes('iv/nonce'));
  assert.equal(context.ready, false);
  const result = decryptCryptoContext(source);
  assert.equal(result.tried, 0);
  assert.equal(result.foundFlag, null);
  assert.equal(result.bestCandidates.length, 0);
});

test('context crypto keeps ambiguous literal encodings as evidence instead of silently choosing', () => {
  const source = `
const algorithm = "aes-256-ecb";
const key = "00112233445566778899aabbccddeeff";
const ciphertext = "00112233445566778899aabbccddeeff";
`;
  const context = extractCryptoContext(source);
  assert.ok(context.keys.some((item) => item.encoding === 'utf8' && item.bytes === 32));
  assert.ok(context.keys.some((item) => item.encoding === 'hex' && item.bytes === 16));
  assert.equal(cipherName('aes', 32, 'ecb'), 'aes-256-ecb');
  assert.equal(cipherName('aes', 16, 'ecb'), 'aes-128-ecb');
});

test('tool router exposes context crypto decoder', () => {
  const source = `${COMMON}
ciphertext = bytes.fromhex("1c3283f1c199a78698919361e70f619c51c850d4f8328773f35fdc3540708b99")
cipher = AES.new(key, AES.MODE_CBC, iv)
`;
  const result = runTool('context-crypto', { input: source });
  assert.equal(result.foundFlag, 'flag{context_crypto_ok}');
});
