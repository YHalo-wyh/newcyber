'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { recoverFlagFromSecret } = require('../src/core/secret_flag_recovery');

function chachaFixture() {
  const secret = [7, 11, 13, 17, 19, 23];
  const raw = Buffer.from(secret);
  const key = crypto.createHash('sha256').update(raw).digest();
  const nonce = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const cipher = crypto.createCipheriv('chacha20', key, nonce);
  cipher.setAutoPadding(false);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from('flag{chacha20_provider_works}', 'utf8')), cipher.final()]);
  return { secret, nonce, ciphertext };
}

test('Batch32 ChaCha20 provider recovers flag only with algorithm and nonce evidence', () => {
  assert.ok(crypto.getCiphers().includes('chacha20'), 'current Node/OpenSSL should expose chacha20');
  const fixture = chachaFixture();
  const result = recoverFlagFromSecret(fixture.secret, {
    files:[
      { name:'solver.py', buffer:Buffer.from('from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20\nalgorithm = ChaCha20(key, nonce)') },
      { name:'nonce.bin', buffer:fixture.nonce },
      { name:'payload.enc', buffer:fixture.ciphertext }
    ]
  });
  assert.equal(result.status, 'flag-recovered');
  assert.equal(result.flag, 'flag{chacha20_provider_works}');
  const hit = result.hits.find((item) => item.algorithm === 'chacha20' && item.flags.includes('flag{chacha20_provider_works}'));
  assert.ok(hit);
  assert.equal(hit.ivSource, 'nonce.bin');
});

test('Batch32 ChaCha20 evidence without explicit nonce stays unresolved', () => {
  const fixture = chachaFixture();
  const result = recoverFlagFromSecret(fixture.secret, {
    files:[
      { name:'solver.py', buffer:Buffer.from('algorithm = ChaCha20(key, nonce)') },
      { name:'payload.enc', buffer:fixture.ciphertext }
    ]
  });
  assert.notEqual(result.status, 'flag-recovered');
  assert.equal(result.explicitNonceCount, 0);
  assert.equal(result.flags.length, 0);
});
