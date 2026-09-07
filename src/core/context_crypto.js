const crypto = require('crypto');
const { autoDecode, scoreBuffer } = require('./auto_decode');
const { createBinaryArtifact } = require('./artifacts');

const MAX_TEXT_BYTES = 512 * 1024;
const MAX_TRIES = 96;
const MODES = new Set(['cbc', 'ecb', 'ctr', 'gcm']);

function uniq(items, keyFn) {
  const seen = new Set();
  return items.filter((item) => {
    const key = keyFn(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function literalFromExpression(expression) {
  const expr = String(expression || '').trim();
  let m = expr.match(/(?:bytes|bytearray)\.fromhex\s*\(\s*(["'])(.*?)\1\s*\)/i)
    || expr.match(/CryptoJS\.enc\.Hex\.parse\s*\(\s*(["'])(.*?)\1\s*\)/i);
  if (m) return { value: m[2], encoding: 'hex', source: 'explicit-hex' };

  m = expr.match(/(?:base64\.b64decode|atob)\s*\(\s*(["'])(.*?)\1\s*\)/i);
  if (m) return { value: m[2], encoding: 'base64', source: 'explicit-base64' };

  m = expr.match(/Buffer\.from\s*\(\s*(["'])(.*?)\1\s*,\s*(["'])(hex|base64|utf8|utf-8)\3\s*\)/i);
  if (m) return { value: m[2], encoding: m[4].toLowerCase().replace('utf-8', 'utf8'), source: `buffer-${m[4].toLowerCase()}` };

  m = expr.match(/CryptoJS\.enc\.Utf8\.parse\s*\(\s*(["'])(.*?)\1\s*\)/i);
  if (m) return { value: m[2], encoding: 'utf8', source: 'explicit-utf8' };

  m = expr.match(/(?:^|[=(,\s])(?:b|u|r|br|rb)?(["'])([^\r\n]*?)\1/i);
  if (m) return { value: m[2], encoding: null, source: 'literal' };

  m = expr.match(/^\s*([A-Za-z0-9+/=_-]{8,})\s*[,;]?\s*$/);
  if (m) return { value: m[1], encoding: null, source: 'bare-token' };
  return null;
}

function decodeLiteral(literal, role) {
  if (!literal) return [];
  const value = literal.value;
  const out = [];
  const push = (encoding, buffer, confidence) => {
    if (!buffer?.length) return;
    out.push({ role, encoding, confidence, source: literal.source, bytes: buffer.length, buffer });
  };

  if (literal.encoding === 'hex') {
    if (/^[0-9a-f]+$/i.test(value) && value.length % 2 === 0) push('hex', Buffer.from(value, 'hex'), 'explicit');
  } else if (literal.encoding === 'base64') {
    try { push('base64', Buffer.from(value, 'base64'), 'explicit'); } catch {}
  } else if (literal.encoding === 'utf8') {
    push('utf8', Buffer.from(value, 'utf8'), 'explicit');
  } else {
    push('utf8', Buffer.from(value, 'utf8'), 'implicit');
    const compactHex = value.replace(/^0x/i, '');
    if (/^(?:0x)?[0-9a-f]{16,}$/i.test(value) && compactHex.length % 2 === 0) push('hex', Buffer.from(compactHex, 'hex'), 'implicit');
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length >= 16 && value.length % 4 === 0) {
      try {
        const decoded = Buffer.from(value, 'base64');
        if (decoded.length) push('base64', decoded, 'implicit');
      } catch {}
    }
  }
  return uniq(out, (item) => `${item.encoding}:${item.buffer.toString('hex')}`);
}

function nameMatchesRole(name, aliases) {
  const lower = String(name || '').toLowerCase();
  const tokens = lower.split(/_+/).filter(Boolean);
  return aliases.some((alias) => {
    const a = alias.toLowerCase();
    return lower === a || tokens.includes(a) || lower.startsWith(`${a}_`) || lower.endsWith(`_${a}`);
  });
}

function assignmentLiterals(text, aliases, role) {
  const results = [];
  const lineRe = /^\s*(?:(?:const|let|var)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?=\s*(.+?)\s*$/gim;
  for (const match of text.matchAll(lineRe)) {
    if (!nameMatchesRole(match[1], aliases)) continue;
    const literal = literalFromExpression(match[2]);
    if (!literal) continue;
    for (const candidate of decodeLiteral(literal, role)) {
      results.push({ ...candidate, name: match[1], index: match.index || 0 });
    }
  }
  return results;
}

function callKeyLiterals(text) {
  const results = [];
  const patterns = [
    /(?:AES|SM4)\.new\s*\(\s*((?:bytes\.fromhex\([^\n]+?\)|base64\.b64decode\([^\n]+?\)|Buffer\.from\([^\n]+?\)|(?:b|u|r)?["'][^\n"']+["']))/gi,
    /create(?:Cipher|Decipher)iv\s*\(\s*["'][^"']+["']\s*,\s*((?:Buffer\.from\([^\n]+?\)|["'][^\n"']+["']))/gi
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const literal = literalFromExpression(match[1]);
      for (const candidate of decodeLiteral(literal, 'key')) results.push({ ...candidate, name: 'key@call', index: match.index || 0 });
    }
  }
  return results;
}

function detectAlgorithms(text) {
  const out = [];
  if (/\bAES\b|aes-(?:128|192|256)-|CryptoJS\.AES/i.test(text)) out.push('aes');
  if (/\bSM4\b|sm4-(?:cbc|ecb|ctr|gcm)|CryptoJS\.SM4/i.test(text)) out.push('sm4');
  return out;
}

function detectModes(text) {
  const out = [];
  const patterns = [
    /(?:AES|SM4)\.MODE_(CBC|ECB|CTR|GCM)/gi,
    /\b(?:aes-(?:128|192|256)|sm4)-(cbc|ecb|ctr|gcm)\b/gi,
    /CryptoJS\.mode\.(CBC|ECB|CTR|GCM)/gi,
    /\bmode\s*[:=]\s*["']?(CBC|ECB|CTR|GCM)\b/gi
  ];
  for (const pattern of patterns) for (const m of text.matchAll(pattern)) out.push(m[1].toLowerCase());
  return uniq(out.filter((mode) => MODES.has(mode)), (item) => item);
}

function publicCandidate(item) {
  return {
    name: item.name,
    encoding: item.encoding,
    confidence: item.confidence,
    source: item.source,
    bytes: item.bytes,
    hex: item.buffer.toString('hex')
  };
}

function extractCryptoContext(input) {
  const text = String(input || '');
  if (Buffer.byteLength(text) > MAX_TEXT_BYTES) throw new Error(`上下文分析输入上限 ${MAX_TEXT_BYTES} bytes`);

  const algorithms = detectAlgorithms(text);
  const modes = detectModes(text);
  const keys = uniq([
    ...assignmentLiterals(text, ['key', 'secret', 'aeskey', 'sm4key', 'crypto'], 'key'),
    ...callKeyLiterals(text)
  ], (item) => item.buffer.toString('hex'));
  const ivs = uniq(assignmentLiterals(text, ['iv', 'nonce', 'counter'], 'iv'), (item) => item.buffer.toString('hex'));
  const ciphertexts = uniq(assignmentLiterals(text, ['ciphertext', 'cipher', 'encrypted', 'enc', 'ct', 'payload', 'blob', 'data'], 'ciphertext'), (item) => item.buffer.toString('hex'));
  const tags = uniq(assignmentLiterals(text, ['tag', 'authtag'], 'tag'), (item) => item.buffer.toString('hex'));

  const missing = [];
  if (!algorithms.length) missing.push('algorithm');
  if (!modes.length) missing.push('mode');
  if (!keys.length) missing.push('key');
  if (!ciphertexts.length) missing.push('ciphertext');
  if (modes.some((mode) => ['cbc', 'ctr', 'gcm'].includes(mode)) && !ivs.length) missing.push('iv/nonce');
  if (modes.includes('gcm') && !tags.length) missing.push('auth-tag');

  return {
    algorithms,
    modes,
    keys: keys.map(publicCandidate),
    ivs: ivs.map(publicCandidate),
    ciphertexts: ciphertexts.map(publicCandidate),
    tags: tags.map(publicCandidate),
    ready: missing.length === 0,
    missing,
    _raw: { keys, ivs, ciphertexts, tags }
  };
}

function cipherName(algorithm, keyBytes, mode) {
  if (algorithm === 'aes') return [16, 24, 32].includes(keyBytes) ? `aes-${keyBytes * 8}-${mode}` : null;
  if (algorithm === 'sm4') return keyBytes === 16 ? `sm4-${mode}` : null;
  return null;
}

function ivValid(mode, iv) {
  if (mode === 'ecb') return iv == null;
  if (!iv) return false;
  if (mode === 'gcm') return iv.length >= 8 && iv.length <= 16;
  return iv.length === 16;
}

function decryptOne({ algorithm, mode, key, iv, tag, ciphertext }) {
  const name = cipherName(algorithm, key.length, mode);
  if (!name || !crypto.getCiphers().includes(name)) return null;
  if (!ivValid(mode, iv)) return null;

  try {
    const decipher = crypto.createDecipheriv(name, key, mode === 'ecb' ? null : iv);
    if (mode === 'gcm') {
      if (!tag) return null;
      decipher.setAuthTag(tag);
    }
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return { plaintext, cipher: name, padding: ['cbc', 'ecb'].includes(mode) ? 'pkcs7/auto' : 'none' };
  } catch {
    if (!['cbc', 'ecb'].includes(mode) || ciphertext.length % 16 !== 0) return null;
    try {
      const decipher = crypto.createDecipheriv(name, key, mode === 'ecb' ? null : iv);
      decipher.setAutoPadding(false);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return { plaintext, cipher: name, padding: 'raw-blocks' };
    } catch {
      return null;
    }
  }
}

function scorePlaintext(buffer) {
  const direct = scoreBuffer(buffer);
  let nested = null;
  try { nested = autoDecode(buffer.toString('utf8'), { maxDepth: 2 }); } catch {}
  const flags = uniq([...(direct.flags || []), ...(nested?.foundFlag ? [nested.foundFlag] : [])], (item) => item);
  let score = direct.score + (nested?.foundFlag ? 900 : 0);
  if (buffer.length && direct.printable < 0.45 && !direct.magic) score -= 100;
  return { direct, nested, flags, score };
}

function decryptCryptoContext(input) {
  const context = extractCryptoContext(input);
  const raw = context._raw;
  let tried = 0;
  const candidates = [];

  if (!context.algorithms.length || !context.modes.length || !raw.keys.length || !raw.ciphertexts.length) {
    const { _raw, ...publicContext } = context;
    return {
      context: publicContext,
      tried,
      bestCandidates: [],
      foundFlag: null,
      bestAction: `条件还不够：${context.missing.join(', ') || 'unknown'}。先从源码、配置或日志补齐。`
    };
  }

  outer: for (const algorithm of context.algorithms) {
    for (const mode of context.modes) {
      const ivPool = mode === 'ecb' ? [null] : raw.ivs.map((item) => item.buffer);
      const tagPool = mode === 'gcm' ? raw.tags.map((item) => item.buffer) : [null];
      for (const keyItem of raw.keys) {
        if (!cipherName(algorithm, keyItem.buffer.length, mode)) continue;
        for (const ctItem of raw.ciphertexts) {
          for (const iv of ivPool) {
            for (const tag of tagPool) {
              if (tried >= MAX_TRIES) break outer;
              tried += 1;
              const result = decryptOne({ algorithm, mode, key: keyItem.buffer, iv, tag, ciphertext: ctItem.buffer });
              if (!result) continue;

              const quality = scorePlaintext(result.plaintext);
              const hash = crypto.createHash('sha256').update(result.plaintext).digest('hex');
              const artifact = quality.direct.magic ? createBinaryArtifact({
                name: `decrypted-${quality.direct.magic.toLowerCase()}-${hash.slice(0, 12)}.bin`,
                buffer: result.plaintext,
                completeness: 'complete',
                provenance: [{ source: 'context-crypto', cipher: result.cipher, keyEncoding: keyItem.encoding, ciphertextEncoding: ctItem.encoding }],
                metadata: { kind: 'crypto-decrypted-candidate', cipher: result.cipher, mode }
              }) : null;

              candidates.push({
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
                printableRatio: Number(quality.direct.printable.toFixed(3)),
                magic: quality.direct.magic,
                flags: quality.flags,
                preview: result.plaintext.toString('utf8').replace(/\0/g, '␀').slice(0, 320),
                hexPreview: result.plaintext.subarray(0, 96).toString('hex'),
                nestedPath: quality.nested?.flagHits?.[0]?.path || null,
                score: quality.score,
                artifact
              });
            }
          }
        }
      }
    }
  }

  candidates.sort((a, b) => b.score - a.score || b.printableRatio - a.printableRatio);
  const hit = candidates.find((item) => item.flags.length);
  const { _raw, ...publicContext } = context;
  return {
    context: publicContext,
    tried,
    bestCandidates: candidates.slice(0, 12),
    foundFlag: hit?.flags?.[0] || null,
    bestAction: hit
      ? `发现 Flag 候选：${hit.flags[0]}；${hit.cipher} / key=${hit.keyEncoding}。回原题环境验证。`
      : candidates[0]?.magic
        ? `最高候选解出 ${candidates[0].magic} 文件，可导出继续分析。`
        : candidates.length
          ? `完成 ${tried} 个上下文约束内的尝试；优先检查 ${candidates[0].cipher} 最高分结果。`
          : `没有形成有效解密结果；检查 key 长度、IV/nonce、mode、auth tag 或本机 OpenSSL 支持。`
  };
}

module.exports = { extractCryptoContext, decryptCryptoContext, decodeLiteral, cipherName, MAX_TRIES };
