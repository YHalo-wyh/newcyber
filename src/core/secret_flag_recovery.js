'use strict';

const crypto = require('crypto');

const MAX_CIPHER_BYTES = 2 * 1024 * 1024;
const DEFAULT_FLAG_PATTERN = /\b(?:flag|ctf|wqb)\{[^}\r\n]{1,256}\}/ig;

function mod(value, q) {
  const result = value % q;
  return result < 0 ? result + q : result;
}

function addUniqueBuffer(rows, label, buffer) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) return;
  if (rows.some((item) => item.buffer.equals(buffer))) return;
  rows.push({ label, buffer });
}

function buildSecretSerializations(secretSigned, modulus = null) {
  if (!Array.isArray(secretSigned) || !secretSigned.length || !secretSigned.every(Number.isSafeInteger)) throw new Error('secret 需要是非空安全整数数组');
  const rows = [];
  addUniqueBuffer(rows, 'csv-signed', Buffer.from(secretSigned.join(','), 'utf8'));
  addUniqueBuffer(rows, 'csv-space-signed', Buffer.from(secretSigned.join(', '), 'utf8'));
  addUniqueBuffer(rows, 'space-signed', Buffer.from(secretSigned.join(' '), 'utf8'));
  addUniqueBuffer(rows, 'json-signed', Buffer.from(JSON.stringify(secretSigned), 'utf8'));
  addUniqueBuffer(rows, 'newline-signed', Buffer.from(secretSigned.join('\n'), 'utf8'));

  if (secretSigned.every((value) => value >= -128 && value <= 127)) {
    addUniqueBuffer(rows, 'int8-signed', Buffer.from(secretSigned.map((value) => value & 0xff)));
  }

  for (const [bytes, endian] of [[2, 'le'], [2, 'be'], [4, 'le'], [4, 'be']]) {
    const buffer = Buffer.alloc(secretSigned.length * bytes);
    let valid = true;
    for (let index = 0; index < secretSigned.length; index += 1) {
      try {
        if (bytes === 2) {
          if (endian === 'le') buffer.writeInt16LE(secretSigned[index], index * bytes);
          else buffer.writeInt16BE(secretSigned[index], index * bytes);
        } else if (endian === 'le') buffer.writeInt32LE(secretSigned[index], index * bytes);
        else buffer.writeInt32BE(secretSigned[index], index * bytes);
      } catch {
        valid = false;
        break;
      }
    }
    if (valid) addUniqueBuffer(rows, `int${bytes * 8}-${endian}-signed`, buffer);
  }

  if (Number.isSafeInteger(modulus) && modulus > 1 && modulus <= 0xffff) {
    const reduced = secretSigned.map((value) => mod(value, modulus));
    for (const endian of ['le', 'be']) {
      const buffer = Buffer.alloc(reduced.length * 2);
      for (let index = 0; index < reduced.length; index += 1) {
        if (endian === 'le') buffer.writeUInt16LE(reduced[index], index * 2);
        else buffer.writeUInt16BE(reduced[index], index * 2);
      }
      addUniqueBuffer(rows, `uint16-${endian}-modq`, buffer);
    }
  }
  return rows;
}

function buildKeyCandidates(serializations) {
  const rows = [];
  const add = (serialization, kdf, key) => {
    if (!Buffer.isBuffer(key) || ![16, 24, 32].includes(key.length)) return;
    const identity = `${serialization.label}|${kdf}|${key.toString('hex')}`;
    if (rows.some((item) => item.identity === identity)) return;
    rows.push({ identity, serialization: serialization.label, kdf, key });
  };

  for (const serialization of serializations) {
    if ([16, 24, 32].includes(serialization.buffer.length)) add(serialization, 'raw', Buffer.from(serialization.buffer));
    const sha256 = crypto.createHash('sha256').update(serialization.buffer).digest();
    add(serialization, 'sha256[:16]', sha256.subarray(0, 16));
    add(serialization, 'sha256[:24]', sha256.subarray(0, 24));
    add(serialization, 'sha256', sha256);
    add(serialization, 'md5', crypto.createHash('md5').update(serialization.buffer).digest());
    add(serialization, 'sha1[:16]', crypto.createHash('sha1').update(serialization.buffer).digest().subarray(0, 16));
  }
  return rows;
}

function printableRatio(buffer) {
  if (!buffer?.length) return 0;
  let printable = 0;
  for (const value of buffer) {
    if (value === 0x09 || value === 0x0a || value === 0x0d || (value >= 0x20 && value <= 0x7e)) printable += 1;
  }
  return printable / buffer.length;
}

function decodeExplicitIv(publicConfig, files) {
  const ivs = [];
  const add = (source, buffer) => {
    if (Buffer.isBuffer(buffer) && buffer.length === 16 && !ivs.some((item) => item.buffer.equals(buffer))) ivs.push({ source, buffer });
  };
  if (publicConfig && typeof publicConfig === 'object') {
    for (const [key, value] of Object.entries(publicConfig)) {
      if (!/^iv$|initialization.?vector/i.test(key) || typeof value !== 'string') continue;
      const text = value.trim();
      if (/^[0-9a-f]{32}$/i.test(text)) add(`public.${key}:hex`, Buffer.from(text, 'hex'));
      if (/^[A-Za-z0-9+/]{22}==?$/.test(text)) {
        try { add(`public.${key}:base64`, Buffer.from(text, 'base64')); } catch {}
      }
    }
  }
  for (const file of files || []) {
    if (!/(^|\/)(?:iv|nonce)(?:\.[^/]*)?$/i.test(file.name || '')) continue;
    add(file.name, file.buffer);
  }
  return ivs;
}

function cipherCandidates(files) {
  return (files || []).filter((file) => {
    if (!Buffer.isBuffer(file.buffer) || file.buffer.length < 16 || file.buffer.length > MAX_CIPHER_BYTES) return false;
    if (file.buffer.length % 16 !== 0) return false;
    return /(?:cipher|encrypt|encrypted|enc|flag|secret|payload)/i.test(file.name || '');
  });
}

function tryAes(cipher, key, mode, iv = null, flagPattern = DEFAULT_FLAG_PATTERN) {
  const algorithm = `aes-${key.length * 8}-${mode}`;
  try {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAutoPadding(true);
    const plaintext = Buffer.concat([decipher.update(cipher), decipher.final()]);
    const text = plaintext.toString('utf8');
    const matches = [...text.matchAll(new RegExp(flagPattern.source, flagPattern.flags))].map((match) => match[0]);
    return { algorithm, plaintext, text, printableRatio: printableRatio(plaintext), flags: [...new Set(matches)] };
  } catch {
    return null;
  }
}

function recoverFlagFromSecret(secretSigned, options = {}) {
  const modulus = options.modulus ?? null;
  const files = Array.isArray(options.files) ? options.files : [];
  const publicConfig = options.publicConfig || null;
  const serializations = buildSecretSerializations(secretSigned, modulus);
  const keys = buildKeyCandidates(serializations);
  const ciphers = cipherCandidates(files);
  const explicitIvs = decodeExplicitIv(publicConfig, files);
  const hits = [];

  for (const file of ciphers) {
    for (const candidate of keys) {
      const ecb = tryAes(file.buffer, candidate.key, 'ecb');
      if (ecb && (ecb.flags.length || ecb.printableRatio >= 0.95)) {
        hits.push({
          file: file.name,
          algorithm: ecb.algorithm,
          serialization: candidate.serialization,
          kdf: candidate.kdf,
          ivSource: null,
          plaintext: ecb.text,
          printableRatio: Number(ecb.printableRatio.toFixed(4)),
          flags: ecb.flags
        });
      }
      for (const iv of explicitIvs) {
        const cbc = tryAes(file.buffer, candidate.key, 'cbc', iv.buffer);
        if (cbc && (cbc.flags.length || cbc.printableRatio >= 0.95)) {
          hits.push({
            file: file.name,
            algorithm: cbc.algorithm,
            serialization: candidate.serialization,
            kdf: candidate.kdf,
            ivSource: iv.source,
            plaintext: cbc.text,
            printableRatio: Number(cbc.printableRatio.toFixed(4)),
            flags: cbc.flags
          });
        }
      }
    }
  }

  hits.sort((left, right) => right.flags.length - left.flags.length || right.printableRatio - left.printableRatio);
  const flags = [...new Set(hits.flatMap((item) => item.flags))];
  return {
    schema: 'newcyber.secret-flag-recovery.v1',
    status: flags.length === 1 ? 'flag-recovered' : flags.length > 1 ? 'ambiguous-flags' : hits.length ? 'plaintext-candidates' : 'no-decryption-hit',
    flag: flags.length === 1 ? flags[0] : null,
    flags,
    cipherFiles: ciphers.map((file) => file.name),
    serializationCount: serializations.length,
    keyCandidateCount: keys.length,
    explicitIvCount: explicitIvs.length,
    hits: hits.slice(0, 20),
    notes: [
      '密钥候选只来自通用整数序列化 + raw/SHA-256/MD5/SHA-1 截断组合，不根据文件名或目标 flag 写死 secret。',
      'AES-CBC 只有在附件/public 配置明确提供 16-byte IV 时才尝试；不会猜 zero-IV。',
      '只有有效 PKCS#7 解密且出现 flag/ctf/wqb{...} 时才自动提升为 flag-recovered。'
    ]
  };
}

module.exports = {
  buildSecretSerializations,
  buildKeyCandidates,
  recoverFlagFromSecret
};