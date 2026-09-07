const crypto = require('crypto');
const { autoDecode, scoreBuffer } = require('./auto_decode');
const { createBinaryArtifact } = require('./artifacts');

const MAX_TEXT = 512 * 1024;
const MAX_TRIES = 96;
const SUPPORTED_MODES = new Set(['cbc', 'ecb', 'ctr', 'gcm']);

function uniqueBy(items, keyFn) {
  const seen = new Set();
  return items.filter((item) => {
    const key = keyFn(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function stripQuotes(value) {
  const text = String(value || '').trim();
  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) return text.slice(1, -1);
  return text;
}

function literalFromExpression(expression) {
  const expr = String(expression || '').trim();
  let match = expr.match(/(?:bytes\.fromhex|bytearray\.fromhex|CryptoJS\.enc\.Hex\.parse)\s*\(\s*(["'])(.*?)\1\s*\)/i);
  if (match) return { value: match[2], encoding: 'hex', source: 'explicit-hex' };
  match = expr.match(/(?:base64\.b64decode|atob)\s*\(\s*(["'])(.*?)\1\s*\)/i);
  if (match) return { value: match[2], encoding: 'base64', source: 'explicit-base64' };
  match = expr.match(/Buffer\.from\s*\(\s*(["'])(.*?)\1\s*,\s*(["'])(hex|base64|utf8|utf-8)\3\s*\)/i);
  if (match) return { value: match[2], encoding: match[4].toLowerCase().replace('utf-8', 'utf8'), source: `buffer-${match[4].toLowerCase()}` };
  match = expr.match(/(?:CryptoJS\.enc\.Utf8\.parse)\s*\(\s*(["'])(.*?)\1\s*\)/i);
  if (match) return { value: match[2], encoding: 'utf8', source: 'explicit-utf8' };
  match = expr.match(/^(?:b|u|r|br|rb)?(["'])(.*?)\1\s*[,;]?$/i);
  if (match) return { value: match[2], encoding: null, source: 'literal' };
  match = expr.match(/^([A-Za-z0-9+/=_-]{8,})\s*[,;]?$/);
  if (match) return { value: match[1], encoding: null, source: 'bare-token' };
  return null;
}

function decodeLiteralCandidates(literal, role) {
  if (!literal) return [];
  const value = stripQuotes(literal.value);
  const items = [];
  const push = (encoding, buffer, confidence) => {
    if (!buffer?.length) return;
    items.push({ role, encoding, value, bytes: buffer.length, buffer, confidence, source: literal.source });
  };

  if (literal.encoding === 'hex') {
    if (/^[0-9a-f]+$/i.test(value) && value.length % 2 === 0) push('hex', Buffer.from(value, 'hex'), 'explicit');
  } else if (literal.encoding === 'base64') {
    try { push('base64', Buffer.from(value, 'base64'), 'explicit'); } catch {}
  } else if (literal.encoding === 'utf8') {
    push('utf8', Buffer.from(value, 'utf8'), 'explicit');
  } else {
    push('utf8', Buffer.from(value, 'utf8'), 'implicit');
    if (/^(?:0x)?[0-9a-f]{16,}$/i.test(value)) {
      const compact = value.replace(/^0x/i, '');
      if (compact.length % 2 === 0) push('hex', Buffer.from(compact, 'hex'), 'implicit');
    }
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length >= 16 && value.length % 4 === 0) {
      try {
        const out = Buffer.from(value, 'base64');
        if (out.length) push('base64', out, 'implicit');
      } catch {}
    }
  }
  return uniqueBy(items, (item) => `${item.encoding}:${item.buffer.toString('hex')}`);
}

function extractNamedAssignments(text, names) {
  const results = [];
  const joined = names.join('|');
  const lineRe = new RegExp(`^\\s*([A-Za-z_][A-Za-z0-9_]*(?:${joined})[A-Za-z0-9_]*)\\s*[:=]\\s*(.+?)\\s*$`, 'gim');
  for (const match of text.matchAll(lineRe)) {
    const literal = literalFromExpression(match[2]);
    if (literal) results.push({ name: match[1], expression: match[2].trim(), literal, index: match.index || 0 });
  }
  return results;
}

function extractFunctionLiterals(text, role) {
  const patterns = role === 'key' ? [
    /(?:AES|SM4)\.new\s*\(\s*((?:bytes\.fromhex\([^\n]+?\)|base64\.b64decode\([^\n]+?\)|Buffer\.from\([^\n]+?\)|b?["'][^\n"']+["']))/gi,
    /create(?:Cipher|Decipher)iv\s*\(\s*["'][^"']+["']\s*,\s*((?:Buffer\.from\([^\n]+?\)|["'][^\n"']+["']))/gi
  ] : [];
  const out = [];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const literal = literalFromExpression(match[1]);
      if (literal) out.push({ name: `${role}@call`, expression: match[1], literal, index: match.index || 0 });
    }
  }
  return out;
}

function detectAlgorithm(text) {
  const algorithms = [];
  if (/\bAES\b|aes-(?:128|192|256)-|CryptoJS\.AES|create(?:Cipher|Decipher)iv\s*\(\s*["']aes-/i.test(text)) algorithms.push('aes');
  if (/\bSM4\b|sm4-(?:cbc|ecb|ctr|gcm)|CryptoJS\.SM4/i.test(text)) algorithms.push('sm4');
  return algorithms;
}

function detectMode(text) {
  const hits = [];
  const patterns = [
    /(?:AES|SM4)\.MODE_(CBC|ECB|CTR|GCM)/gi,
    /\b(?:aes-(?:128|192|256)|sm4)-(cbc|ecb|ctr|gcm)\b/gi,
    /CryptoJS\.mode\.(CBC|ECB|CTR|GCM)/gi,
    /\bmode\s*[:=]\s*["']?(CBC|ECB|CTR|GCM)\b/gi
  ];
  for (const pattern of patterns) for (const match of text.matchAll(pattern)) hits.push(match[1].toLowerCase());
  return uniqueBy(hits, (item) => item);
}

function firstTagLiteral(text) {
  const assignments = extractNamedAssignments(text, ['tag', 'auth_tag', 'authtag']);
  return assignments[0]?.literal || null;
}

function extractCryptoContext(input) {
  const text = String(input || '');
  if (!text.trim()) return { algorithms: [], modes: [], keys: [], ivs: [], ciphertexts: [], tags: [], ready: false, missing: ['crypto-context'] };
  if (Buffer.byteLength(text) > MAX_TEXT) throw new Error(`上下文分析输入上限 ${MAX_TEXT} bytes`);

  const algorithms = detectAlgorithm(text);
  const modes = detectMode(text).filter((mode) => SUPPORTED_MODES.has(mode));
  const keyAssignments = [
    ...extractNamedAssignments(text, ['key', 'secret', 'aeskey', 'sm4key', 'crypto_key']),
    ...extractFunctionLiterals(text, 'key')
  ];
  const ivAssignments = extractNamedAssignments(text, ['iv', 'nonce', 'initialization_vector', 'counter']);
  const ctAssignments = extractNamedAssignments(text, ['ciphertext', 'cipher_text', 'encrypted', 'enc_data', 'enc', 'ct', 'payload', 'blob', 'data']);
  const tagAssignments = extractNamedAssignments(text, ['tag', 'auth_tag', 'authtag']);

  const keys = uniqueBy(keyAssignments.flatMap((item) => decodeLiteralCandidates(item.literal, 'key').map((candidate) => ({ ...candidate, name: item.name, index: item.index }))), (item) => item.buffer.toString('hex'));
  const ivs = uniqueBy(ivAssignments.flatMap((item) => decodeLiteralCandidates(item.literal, 'iv').map((candidate) => ({ ...candidate, name: item.name, index: item.index }))), (item) => item.buffer.toString('hex'));
  const ciphertexts = uniqueBy(ctAssignments.flatMap((item) => decodeLiteralCandidates(item.literal, 'ciphertext').map((candidate) => ({ ...candidate, name: item.name, index: item.index }))), (item) => item.buffer.toString('hex'));
  const tags = uniqueBy(tagAssignments.flatMap((item) => decodeLiteralCandidates(item.literal, 'tag').map((candidate) => ({ ...candidate, name: item.name, index: item.index }))), (item) => item.buffer.toString('hex'));

  const missing = [];
  if (!algorithms.length) missing.push('algorithm');
  if (!modes.length) missing.push('mode');
  if (!keys.length) missing.push('key');
  if (!ciphertexts.length) missing.push('ciphertext');
  if (modes.some((mode) => ['cbc', 'ctr', 'gcm'].includes(mode)) && !ivs.length) missing.push('iv/nonce');
  if (modes.includes('gcm') && !tags.length && !firstTagLiteral(text)) missing.push('auth-tag');

  return {
    algorithms,
    modes,
    keys: keys.map(({ buffer, ...item }) => ({ ...item, hex: buffer.toString('hex') })),
    ivs: ivs.map(({ buffer, ...item }) => ({ ...item, hex: buffer.toString('hex') })),
    ciphertexts: ciphertexts.map(({ buffer, ...item }) => ({ ...item, hex: buffer.toString('hex') })),
    tags: tags.map(({ buffer, ...item }) => ({ ...item, hex: buffer.toString('hex') })),
    _buffers: { keys, ivs, ciphertexts, tags },
    ready: missing.length === 0,
    missing
  };
}

function cipherName(algorithm, keyBytes, mode) {
  if (algorithm === 'aes') {
    if (![16, 24, 32].includes(keyBytes)) return null;
    return `aes-${keyBytes * 8}-${mode}`;
  }
  if (algorithm === 'sm4') {
    if (keyBytes !== 16) return null;
    return `sm4-${mode}`;
  }
  return null;
}

function validIv(mode, iv) {
  if (mode === 'ecb') return !iv;
  if (!iv) return false;
  if (mode === 'gcm') return iv.length >= 8 && iv.length <= 16;
  return iv.length === 16;
}

function decryptOnce({ algorithm, mode, key, iv, tag, ciphertext }) {
  const name = cipherName(algorithm, key.length, mode);
  if (!name || !crypto.getCiphers().includes(name)) return { error: `当前 Node/OpenSSL 不支持 ${name || `${algorithm}-${mode}`}` };
  if (!validIv(mode, iv)) return { error: mode === 'ecb' ? 'ECB 不应提供 IV' : `${mode.toUpperCase()} 需要合适长度的 IV/nonce` };
  try {
    const decipher = crypto.createDecipheriv(name, key, mode === 'ecb' ? null : iv);
    if (mode === 'gcm') {
      if (!tag) return { error: 'GCM 缺少 auth tag' };
      decipher.setAuthTag(tag);
    }
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return { plaintext, cipher: name, padding: ['cbc', 'ecb'].includes(mode) ? 'pkcs7/auto' : 'none' };
  } catch (error) {
    if (!['cbc', 'ecb'].includes(mode) || ciphertext.length % 16 !== 0) return { error: error.message };
    try {
      const decipher = crypto.createDecipheriv(name, key, mode === 'ecb' ? null : iv);
      decipher.setAutoPadding(false);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return { plaintext, cipher: name, padding: 'raw-blocks' };
    } catch (rawError) {
      return { error: rawError.message };
    }
  }
}

function candidateQuality(buffer) {
  const scored = scoreBuffer(buffer);
  let nested = null;
  try { nested = autoDecode(buffer.toString('utf8'), { maxDepth: 2 }); } catch {}
  const nestedFlag = nested?.foundFlag || null;
  const flags = uniqueBy([...(scored.flags || []), ...(nestedFlag ? [nestedFlag] : [])], (item) => item);
  let score = scored.score;
  if (nestedFlag) score += 900;
  if (buffer.length && scored.printable < 0.45 && !scored.magic) score -= 100;
  return { ...scored, score, nested, flags };
}

function decryptCryptoContext(input) {
  const context = extractCryptoContext(input);
  const { keys = [], ivs = [], ciphertexts = [], tags = [] } = context._buffers || {};
  const attempts = [];
  if (!context.algorithms.length || !context.modes.length || !keys.length || !ciphertexts.length) {
    const { _buffers, ...publicContext } = context;
    return {
      context: publicContext,
      attempts: [],
      bestCandidates: [],
      foundFlag: null,
      bestAction: `条件还不够：${context.missing.join(', ') || 'unknown'}。先从源码/配置/日志补齐后再解密。`
    };
  }

  outer: for (const algorithm of context.algorithms) {
    for (const mode of context.modes) {
      const ivPool = mode === 'ecb' ? [null] : ivs.map((item) => item.buffer);
      const tagPool = mode === 'gcm' ? tags.map((item) => item.buffer) : [null];
      for (const keyItem of keys) {
        const name = cipherName(algorithm, keyItem.buffer.length, mode);
        if (!name) continue;
        for (const ctItem of ciphertexts) {
          for (const iv of ivPool) {
            for (const tag of tagPool) {
              if (attempts.length >= MAX_TRIES) break outer;
              const result = decryptOnce({ algorithm, mode, key: keyItem.buffer, iv, tag, ciphertext: ctItem.buffer });
              if (!result.plaintext) continue;
              const quality = candidateQuality(result.plaintext);
              const artifact = quality.magic ? createBinaryArtifact({
                name: `decrypted-${quality.magic.toLowerCase()}-${crypto.createHash('sha256').update(result.plaintext).digest('hex').slice(0, 12)}.bin`,
                buffer: result.plaintext,
                completeness: 'complete',
                provenance: [{ source: 'context-crypto', cipher: result.cipher, keyEncoding: keyItem.encoding, ciphertextEncoding: ctItem.encoding }],
                metadata: { kind: 'crypto-decrypted-candidate', cipher: result.cipher, mode }
              }) : null;
              attempts.push({
                algorithm,
                mode,
                cipher: result.cipher,
                keyEncoding: keyItem.encoding,
                keyBytes: keyItem.buffer.length,
                ciphertextEncoding: ctItem.encoding,
                ciphertextBytes: ctItem.buffer.length,
                ivHex: iv?.toString('hex') || null,
                tagHex: tag?.toString('hex') || null,
                padding: result.padding,
                plaintextBytes: result.plaintext.length,
                printableRatio: Number(quality.printable.toFixed(3)),
                magic: quality.magic,
                flags: quality.flags,
                preview: result.plaintext.toString('utf8').replace(/\0/g, '␀').slice(0, 320),
                hexPreview: result.plaintext.subarray(0, 96).toString('hex'),
                score: quality.score,
                nestedPath: quality.nested?.flagHits?.[0]?.path || null,
                artifact
              });
            }
          }
        }
      }
    }
  }

  const ranked = attempts.sort((a, b) => b.score - a.score || b.printableRatio - a.printableRatio);
  const found = ranked.find((item) => item.flags?.length);
  const { _buffers, ...publicContext } = context;
  return {
    context: publicContext,
    attempts: ranked.length,
    bestCandidates: ranked.slice(0, 12),
    foundFlag: found?.flags?.[0] || null,
    bestAction: found
      ? `发现 Flag 候选：${found.flags[0]}，使用 ${found.cipher}（key=${found.keyEncoding}）解出；回原题验证。`
      : ranked[0]?.magic
        ? `最高候选解出 ${ranked[0].magic} 文件，可导出继续分析。`
        : ranked.length
          ? `完成 ${ranked.length} 个满足上下文约束的解密候选；优先检查最高分 ${ranked[0].cipher} 结果。`
          : `没有形成可执行解密组合；检查 key 长度、IV/nonce、mode、tag 或当前 OpenSSL cipher 支持。`
  };
}

module.exports = { extractCryptoContext, decryptCryptoContext, decodeLiteralCandidates, cipherName, MAX_TRIES };
