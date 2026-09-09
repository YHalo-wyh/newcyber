'use strict';

const crypto = require('crypto');
const { autoDecode } = require('./auto_decode');

const MAX_CIPHER_BYTES = 2 * 1024 * 1024;
const MAX_HITS = 30;
const DEFAULT_FLAG_PATTERN = /\b(?:flag|ctf|wqb)\{[^}\r\n]{1,256}\}/ig;

function mod(value, q) {
  const result = value % q;
  return result < 0 ? result + q : result;
}

function addUniqueBuffer(rows, label, buffer, extra = {}) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) return;
  if (rows.some((item) => item.buffer.equals(buffer))) return;
  rows.push({ label, buffer, ...extra });
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

function buildMaterialCandidates(serializations) {
  const rows = [];
  const add = (serialization, kdf, buffer) => {
    if (!Buffer.isBuffer(buffer) || !buffer.length || buffer.length > 256) return;
    const identity = `${serialization.label}|${kdf}|${buffer.toString('hex')}`;
    if (rows.some((item) => item.identity === identity)) return;
    rows.push({ identity, serialization: serialization.label, kdf, buffer });
  };

  for (const serialization of serializations) {
    add(serialization, 'raw', Buffer.from(serialization.buffer));
    const sha256 = crypto.createHash('sha256').update(serialization.buffer).digest();
    add(serialization, 'sha256[:16]', sha256.subarray(0, 16));
    add(serialization, 'sha256[:24]', sha256.subarray(0, 24));
    add(serialization, 'sha256', sha256);
    add(serialization, 'md5', crypto.createHash('md5').update(serialization.buffer).digest());
    const sha1 = crypto.createHash('sha1').update(serialization.buffer).digest();
    add(serialization, 'sha1[:16]', sha1.subarray(0, 16));
    add(serialization, 'sha1', sha1);
    const sha512 = crypto.createHash('sha512').update(serialization.buffer).digest();
    add(serialization, 'sha512[:16]', sha512.subarray(0, 16));
    add(serialization, 'sha512[:24]', sha512.subarray(0, 24));
    add(serialization, 'sha512[:32]', sha512.subarray(0, 32));
    add(serialization, 'sha512', sha512);
  }
  return rows;
}

function buildKeyCandidates(serializations) {
  return buildMaterialCandidates(serializations)
    .filter((item) => [16, 24, 32].includes(item.buffer.length))
    .map((item) => ({ ...item, key: item.buffer }));
}

function printableRatio(buffer) {
  if (!buffer?.length) return 0;
  let printable = 0;
  for (const value of buffer) {
    if (value === 0x09 || value === 0x0a || value === 0x0d || (value >= 0x20 && value <= 0x7e)) printable += 1;
  }
  return printable / buffer.length;
}

function flagsInBuffer(buffer, flagPattern = DEFAULT_FLAG_PATTERN) {
  const text = buffer.toString('utf8');
  const flags = flagPattern.flags.includes('g') ? flagPattern.flags : `${flagPattern.flags}g`;
  return [...text.matchAll(new RegExp(flagPattern.source, flags))].map((match) => match[0]);
}

function decodeTextBuffer(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value) && value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) return Buffer.from(value);
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text) return null;
  if (/^(?:0x)?[0-9a-f]{2,}$/i.test(text.replace(/\s+/g, ''))) {
    const compact = text.replace(/^0x/i, '').replace(/\s+/g, '');
    if (compact.length % 2 === 0) return Buffer.from(compact, 'hex');
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length >= 8 && text.length % 4 === 0) {
    try {
      const decoded = Buffer.from(text, 'base64');
      if (decoded.length) return decoded;
    } catch {}
  }
  return Buffer.from(text, 'utf8');
}

function collectNamedParameters(publicConfig, files) {
  const rows = [];
  const add = (kind, source, value) => {
    const buffer = decodeTextBuffer(value);
    if (!buffer?.length || buffer.length > 256) return;
    if (rows.some((item) => item.kind === kind && item.buffer.equals(buffer))) return;
    rows.push({ kind, source, buffer });
  };

  if (publicConfig && typeof publicConfig === 'object') {
    for (const [key, value] of Object.entries(publicConfig)) {
      const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (/^(?:iv|initializationvector|counter)$/.test(normalized)) add('iv', `public.${key}`, value);
      else if (/^(?:nonce|chachanonce|gcmnonce)$/.test(normalized)) add('nonce', `public.${key}`, value);
      else if (/^(?:tag|authtag|authenticationtag|mac)$/.test(normalized)) add('tag', `public.${key}`, value);
      else if (/^(?:salt)$/.test(normalized)) add('salt', `public.${key}`, value);
      else if (/^(?:aad|associateddata|additionaldata)$/.test(normalized)) add('aad', `public.${key}`, value);
    }
  }

  for (const file of files || []) {
    const name = String(file.name || '').toLowerCase();
    if (!Buffer.isBuffer(file.buffer) || !file.buffer.length || file.buffer.length > 256) continue;
    if (/(^|\/)(?:iv|initialization[-_]?vector)(?:\.[^/]*)?$/.test(name)) add('iv', file.name, file.buffer);
    if (/(^|\/)(?:nonce)(?:\.[^/]*)?$/.test(name)) add('nonce', file.name, file.buffer);
    if (/(^|\/)(?:tag|auth[-_]?tag)(?:\.[^/]*)?$/.test(name)) add('tag', file.name, file.buffer);
    if (/(^|\/)(?:salt)(?:\.[^/]*)?$/.test(name)) add('salt', file.name, file.buffer);
    if (/(^|\/)(?:aad|associated[-_]?data)(?:\.[^/]*)?$/.test(name)) add('aad', file.name, file.buffer);
  }
  return rows;
}

function publicCryptoText(publicConfig) {
  if (!publicConfig || typeof publicConfig !== 'object') return '';
  try { return JSON.stringify(publicConfig); } catch { return ''; }
}

function inspectCryptoHints(sourceText = '', publicConfig = null) {
  const combined = `${sourceText || ''}\n${publicCryptoText(publicConfig)}`;
  const lower = combined.toLowerCase();
  const algorithms = new Set();
  const modes = new Set();
  const evidence = [];
  const add = (algorithm, pattern, label) => {
    if (!pattern.test(lower)) return;
    algorithms.add(algorithm);
    evidence.push(label);
  };

  add('xor', /(?:\bxor\b|\^=|\^\s*[a-z_][\w]*|bytes?\s*\([^\n]{0,80}\^)/, 'source/config mentions XOR operation');
  add('rc4', /\b(?:rc4|arcfour|arc4)\b/, 'source/config mentions RC4/ARC4');
  add('chacha20', /\bchacha20\b/, 'source/config mentions ChaCha20');
  add('chacha20-poly1305', /chacha20[-_ ]?poly1305|chacha20poly1305/, 'source/config mentions ChaCha20-Poly1305');
  add('aes', /\baes\b|aes[-_ ]?(?:128|192|256)/, 'source/config mentions AES');
  add('3des', /\b(?:3des|tripledes|triple[-_ ]?des|des3)\b/, 'source/config mentions Triple-DES');

  const modePatterns = [
    ['ecb', /\becb\b|mode_ecb/],
    ['cbc', /\bcbc\b|mode_cbc/],
    ['ctr', /\bctr\b|mode_ctr|counter\s*=/],
    ['gcm', /\bgcm\b|mode_gcm|aesgcm/]
  ];
  for (const [mode, pattern] of modePatterns) {
    if (pattern.test(lower)) {
      modes.add(mode);
      evidence.push(`source/config mentions ${mode.toUpperCase()} mode`);
    }
  }

  return { algorithms:[...algorithms], modes:[...modes], evidence:[...new Set(evidence)], explicit:algorithms.size > 0 };
}

function deriveExplicitKdfs(materials, publicConfig, sourceText) {
  const result = [];
  const text = `${sourceText || ''}\n${publicCryptoText(publicConfig)}`.toLowerCase();
  const add = (base, kdf, buffer) => {
    if (!Buffer.isBuffer(buffer) || !buffer.length || buffer.length > 64) return;
    const identity = `${base.serialization}|${kdf}|${buffer.toString('hex')}`;
    if (!result.some((item) => item.identity === identity)) result.push({ identity, serialization:base.serialization, kdf, buffer });
  };
  const params = collectNamedParameters(publicConfig, []);
  const salts = params.filter((item) => item.kind === 'salt');

  if (/pbkdf2/.test(text) && salts.length) {
    const iterations = Number(publicConfig?.iterations ?? publicConfig?.rounds ?? publicConfig?.pbkdf2_iterations);
    const digestRaw = String(publicConfig?.digest ?? publicConfig?.hash ?? 'sha256').toLowerCase();
    const digest = ['sha1','sha256','sha384','sha512'].includes(digestRaw) ? digestRaw : 'sha256';
    if (Number.isSafeInteger(iterations) && iterations > 0 && iterations <= 5_000_000) {
      for (const base of materials.filter((item) => item.kdf === 'raw')) {
        for (const salt of salts.slice(0, 4)) {
          for (const length of [16,24,32]) {
            try { add(base, `pbkdf2-${digest}-${iterations}-${length}`, crypto.pbkdf2Sync(base.buffer, salt.buffer, iterations, length, digest)); } catch {}
          }
        }
      }
    }
  }

  if (/\bscrypt\b/.test(text) && salts.length) {
    const cost = Number(publicConfig?.N ?? publicConfig?.n ?? publicConfig?.cost ?? 16384);
    const r = Number(publicConfig?.r ?? 8);
    const p = Number(publicConfig?.p ?? 1);
    if (Number.isSafeInteger(cost) && cost >= 2 && cost <= 1_048_576 && Number.isSafeInteger(r) && r > 0 && r <= 64 && Number.isSafeInteger(p) && p > 0 && p <= 16) {
      for (const base of materials.filter((item) => item.kdf === 'raw')) {
        for (const salt of salts.slice(0, 4)) {
          for (const length of [16,24,32]) {
            try { add(base, `scrypt-N${cost}-r${r}-p${p}-${length}`, crypto.scryptSync(base.buffer, salt.buffer, length, { N:cost, r, p, maxmem:128*1024*1024 })); } catch {}
          }
        }
      }
    }
  }
  return result;
}

function cipherCandidates(files) {
  return (files || []).filter((file) => {
    if (!Buffer.isBuffer(file.buffer) || !file.buffer.length || file.buffer.length > MAX_CIPHER_BYTES) return false;
    return /(?:cipher|encrypt|encrypted|enc|flag|secret|payload|message|data)/i.test(file.name || '');
  });
}

function xorRepeating(buffer, key) {
  if (!Buffer.isBuffer(buffer) || !Buffer.isBuffer(key) || !key.length) throw new Error('xorRepeating 需要非空 Buffer');
  const output = Buffer.alloc(buffer.length);
  for (let index = 0; index < buffer.length; index += 1) output[index] = buffer[index] ^ key[index % key.length];
  return output;
}

function rc4Crypt(buffer, key) {
  if (!Buffer.isBuffer(buffer) || !Buffer.isBuffer(key) || !key.length || key.length > 256) throw new Error('RC4 key 长度必须为 1..256 bytes');
  const state = Array.from({ length:256 }, (_, index) => index);
  let j = 0;
  for (let index = 0; index < 256; index += 1) {
    j = (j + state[index] + key[index % key.length]) & 0xff;
    [state[index], state[j]] = [state[j], state[index]];
  }
  const output = Buffer.alloc(buffer.length);
  let i = 0;
  j = 0;
  for (let index = 0; index < buffer.length; index += 1) {
    i = (i + 1) & 0xff;
    j = (j + state[i]) & 0xff;
    [state[i], state[j]] = [state[j], state[i]];
    output[index] = buffer[index] ^ state[(state[i] + state[j]) & 0xff];
  }
  return output;
}

function attemptAutoDecode(plaintext) {
  if (!Buffer.isBuffer(plaintext) || !plaintext.length || plaintext.length > 256 * 1024 || printableRatio(plaintext) < 0.72) return null;
  try {
    const decoded = autoDecode(plaintext.toString('utf8'), { profile:'normal', maxDepth:2, maxNodes:180 });
    return decoded.foundFlag ? { flag:decoded.foundFlag, path:decoded.flagHits?.[0]?.path || [] } : null;
  } catch { return null; }
}

function normalizeAttempt(algorithm, plaintext, meta = {}, flagPattern = DEFAULT_FLAG_PATTERN) {
  if (!Buffer.isBuffer(plaintext) || !plaintext.length) return null;
  const directFlags = flagsInBuffer(plaintext, flagPattern);
  const decoded = directFlags.length ? null : attemptAutoDecode(plaintext);
  const flags = [...new Set([...directFlags, ...(decoded?.flag ? [decoded.flag] : [])])];
  return {
    algorithm,
    plaintext,
    text:plaintext.toString('utf8'),
    printableRatio:Number(printableRatio(plaintext).toFixed(4)),
    flags,
    decodePath:decoded?.path || [],
    ...meta
  };
}

function tryNodeCipher(algorithm, cipher, key, iv, options = {}) {
  if (!crypto.getCiphers().includes(algorithm)) return null;
  try {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    if (options.authTag) decipher.setAuthTag(options.authTag);
    if (options.aad) decipher.setAAD(options.aad);
    if (options.autoPadding === false) decipher.setAutoPadding(false);
    const plaintext = Buffer.concat([decipher.update(cipher), decipher.final()]);
    return normalizeAttempt(algorithm, plaintext, options.meta || {}, options.flagPattern || DEFAULT_FLAG_PATTERN);
  } catch { return null; }
}

function maybeKeepHit(hits, attempt, explicitEvidence) {
  if (!attempt) return;
  if (!attempt.flags.length && !(explicitEvidence && attempt.printableRatio >= 0.95)) return;
  hits.push(attempt);
}

function recoverFlagFromSecret(secretSigned, options = {}) {
  const modulus = options.modulus ?? null;
  const files = Array.isArray(options.files) ? options.files : [];
  const publicConfig = options.publicConfig || null;
  const sourceText = String(options.sourceText || '');
  const serializations = buildSecretSerializations(secretSigned, modulus);
  const baseMaterials = buildMaterialCandidates(serializations);
  const derivedMaterials = deriveExplicitKdfs(baseMaterials, publicConfig, sourceText);
  const materials = [...baseMaterials, ...derivedMaterials];
  const aesKeys = materials.filter((item) => [16,24,32].includes(item.buffer.length));
  const ciphers = cipherCandidates(files);
  const params = collectNamedParameters(publicConfig, files);
  const ivs = params.filter((item) => item.kind === 'iv');
  const nonces = params.filter((item) => item.kind === 'nonce');
  const tags = params.filter((item) => item.kind === 'tag');
  const aads = params.filter((item) => item.kind === 'aad');
  const hints = inspectCryptoHints(sourceText, publicConfig);
  const algorithmSet = new Set(hints.algorithms);
  const modeSet = new Set(hints.modes);
  const hits = [];
  let attempts = 0;
  const ATTEMPT_BUDGET = 18_000;
  const canAttempt = () => attempts++ < ATTEMPT_BUDGET;

  for (const file of ciphers) {
    // Backward-compatible bounded AES probe: ECB is only attempted on block-aligned data;
    // CBC requires an explicit IV. A printable accident never becomes flag-recovered without a flag oracle.
    if (file.buffer.length >= 16 && file.buffer.length % 16 === 0) {
      for (const candidate of aesKeys) {
        if (!canAttempt()) break;
        maybeKeepHit(hits, tryNodeCipher(`aes-${candidate.buffer.length * 8}-ecb`, file.buffer, candidate.buffer, null, {
          meta:{ file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, parameterSource:null, evidence:algorithmSet.has('aes') ? hints.evidence : ['bounded legacy AES probe'] }
        }), algorithmSet.has('aes'));
      }
    }
    for (const iv of ivs.filter((item) => item.buffer.length === 16)) {
      if (file.buffer.length < 16 || file.buffer.length % 16 !== 0) continue;
      for (const candidate of aesKeys) {
        if (!canAttempt()) break;
        maybeKeepHit(hits, tryNodeCipher(`aes-${candidate.buffer.length * 8}-cbc`, file.buffer, candidate.buffer, iv.buffer, {
          meta:{ file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, ivSource:iv.source, parameterSource:iv.source, evidence:algorithmSet.has('aes') || modeSet.has('cbc') ? hints.evidence : ['explicit IV + bounded AES-CBC probe'] }
        }), algorithmSet.has('aes') || modeSet.has('cbc'));
      }
    }

    if (algorithmSet.has('aes') && modeSet.has('ctr')) {
      for (const iv of ivs.filter((item) => item.buffer.length === 16)) {
        for (const candidate of aesKeys) {
          if (!canAttempt()) break;
          maybeKeepHit(hits, tryNodeCipher(`aes-${candidate.buffer.length * 8}-ctr`, file.buffer, candidate.buffer, iv.buffer, {
            autoPadding:false,
            meta:{ file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, ivSource:iv.source, parameterSource:iv.source, evidence:hints.evidence }
          }), true);
        }
      }
    }

    if (algorithmSet.has('aes') && modeSet.has('gcm')) {
      for (const nonce of [...nonces, ...ivs].filter((item) => [12,16].includes(item.buffer.length))) {
        for (const tag of tags.filter((item) => item.buffer.length >= 12 && item.buffer.length <= 16)) {
          for (const candidate of aesKeys) {
            if (!canAttempt()) break;
            maybeKeepHit(hits, tryNodeCipher(`aes-${candidate.buffer.length * 8}-gcm`, file.buffer, candidate.buffer, nonce.buffer, {
              authTag:tag.buffer,
              aad:aads[0]?.buffer,
              autoPadding:false,
              meta:{ file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, ivSource:nonce.source, tagSource:tag.source, parameterSource:`${nonce.source} + ${tag.source}`, evidence:hints.evidence }
            }), true);
          }
        }
      }
    }

    if (algorithmSet.has('xor')) {
      for (const candidate of materials) {
        if (!canAttempt()) break;
        const attempt = normalizeAttempt('xor-repeating', xorRepeating(file.buffer, candidate.buffer), {
          file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, parameterSource:'secret-derived key', evidence:hints.evidence
        });
        maybeKeepHit(hits, attempt, true);
      }
    }

    if (algorithmSet.has('rc4')) {
      for (const candidate of materials.filter((item) => item.buffer.length <= 256)) {
        if (!canAttempt()) break;
        const attempt = normalizeAttempt('rc4', rc4Crypt(file.buffer, candidate.buffer), {
          file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, parameterSource:'secret-derived key', evidence:hints.evidence
        });
        maybeKeepHit(hits, attempt, true);
      }
    }

    if (algorithmSet.has('chacha20')) {
      for (const nonce of [...nonces, ...ivs].filter((item) => item.buffer.length === 16)) {
        for (const candidate of materials.filter((item) => item.buffer.length === 32)) {
          if (!canAttempt()) break;
          maybeKeepHit(hits, tryNodeCipher('chacha20', file.buffer, candidate.buffer, nonce.buffer, {
            autoPadding:false,
            meta:{ file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, ivSource:nonce.source, parameterSource:nonce.source, evidence:hints.evidence }
          }), true);
        }
      }
    }

    if (algorithmSet.has('chacha20-poly1305')) {
      for (const nonce of nonces.filter((item) => item.buffer.length === 12)) {
        for (const tag of tags.filter((item) => item.buffer.length === 16)) {
          for (const candidate of materials.filter((item) => item.buffer.length === 32)) {
            if (!canAttempt()) break;
            maybeKeepHit(hits, tryNodeCipher('chacha20-poly1305', file.buffer, candidate.buffer, nonce.buffer, {
              authTag:tag.buffer,
              aad:aads[0]?.buffer,
              autoPadding:false,
              meta:{ file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, ivSource:nonce.source, tagSource:tag.source, parameterSource:`${nonce.source} + ${tag.source}`, evidence:hints.evidence }
            }), true);
          }
        }
      }
    }

    if (algorithmSet.has('3des')) {
      for (const candidate of materials.filter((item) => item.buffer.length === 24)) {
        if (file.buffer.length % 8 === 0 && canAttempt()) {
          maybeKeepHit(hits, tryNodeCipher('des-ede3', file.buffer, candidate.buffer, null, {
            meta:{ file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, parameterSource:null, evidence:hints.evidence }
          }), true);
        }
        for (const iv of ivs.filter((item) => item.buffer.length === 8)) {
          if (!canAttempt()) break;
          maybeKeepHit(hits, tryNodeCipher('des-ede3-cbc', file.buffer, candidate.buffer, iv.buffer, {
            meta:{ file:file.name, serialization:candidate.serialization, kdf:candidate.kdf, ivSource:iv.source, parameterSource:iv.source, evidence:hints.evidence }
          }), true);
        }
      }
    }
  }

  hits.sort((left, right) => right.flags.length - left.flags.length || right.printableRatio - left.printableRatio || left.algorithm.localeCompare(right.algorithm));
  const flags = [...new Set(hits.flatMap((item) => item.flags))];
  return {
    schema:'newcyber.secret-flag-recovery.v2',
    status:flags.length === 1 ? 'flag-recovered' : flags.length > 1 ? 'ambiguous-flags' : hits.length ? 'plaintext-candidates' : 'no-decryption-hit',
    flag:flags.length === 1 ? flags[0] : null,
    flags,
    cipherFiles:ciphers.map((file) => file.name),
    serializationCount:serializations.length,
    keyCandidateCount:aesKeys.length,
    materialCandidateCount:materials.length,
    explicitIvCount:ivs.length,
    explicitNonceCount:nonces.length,
    explicitTagCount:tags.length,
    cryptoHints:hints,
    attempts:Math.min(attempts, ATTEMPT_BUDGET + 1),
    attemptBudget:ATTEMPT_BUDGET,
    hits:hits.slice(0, MAX_HITS).map((hit) => ({ ...hit, plaintext:undefined })),
    notes:[
      '恢复链不是 AES-only：XOR/RC4/ChaCha20/AEAD/CTR/3DES 等非默认 provider 只有在源码或公开配置出现算法证据时才启用。',
      'AES-ECB 保留兼容性的有界探测；CBC 必须有显式 IV，CTR/GCM/ChaCha/3DES 需要算法证据与对应参数，不猜 zero-IV/nonce/tag。',
      '解密后的高可打印文本会继续进入现有 Auto Decode，可恢复 decrypt → Base/Hex/压缩编码 → Flag 链。',
      '只有严格 flag/ctf/wqb{...} oracle 唯一命中才自动提升为 flag-recovered；普通可打印结果最多保留为 plaintext-candidates。'
    ]
  };
}

module.exports = {
  buildSecretSerializations,
  buildMaterialCandidates,
  buildKeyCandidates,
  inspectCryptoHints,
  collectNamedParameters,
  xorRepeating,
  rc4Crypt,
  recoverFlagFromSecret
};