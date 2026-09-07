const crypto = require('crypto');
const zlib = require('zlib');
const { createBinaryArtifact } = require('./artifacts');

const MAX_INPUT_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_NODES = 600;
const MAX_DEPTH = 3;

const FLAG_RE = /(?:flag|ctf|[A-Za-z0-9_]{2,24})\{[^{}\r\n]{1,200}\}/gi;
const KEYWORD_RE = /\b(?:flag|ctf|key|secret|password|token|admin|success|accepted)\b/i;

const MAGIC = [
  ['PNG', Buffer.from('89504e470d0a1a0a', 'hex')],
  ['ZIP', Buffer.from('504b0304', 'hex')],
  ['ELF', Buffer.from('7f454c46', 'hex')],
  ['PDF', Buffer.from('25504446', 'hex')],
  ['GZIP', Buffer.from('1f8b', 'hex')],
  ['SQLite', Buffer.from('53514c69746520666f726d6174203300', 'hex')],
  ['JPEG', Buffer.from('ffd8ff', 'hex')],
  ['GIF', Buffer.from('47494638', 'hex')],
  ['7Z', Buffer.from('377abcaf271c', 'hex')],
  ['RAR', Buffer.from('526172211a07', 'hex')]
];

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function printableRatio(buffer) {
  if (!buffer.length) return 0;
  let printable = 0;
  for (const byte of buffer) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable += 1;
  }
  return printable / buffer.length;
}

function utf8Quality(buffer) {
  if (!buffer.length) return 0;
  const text = buffer.toString('utf8');
  const replacement = (text.match(/\uFFFD/g) || []).length;
  return Math.max(0, 1 - replacement / Math.max(text.length, 1));
}

function magicName(buffer) {
  for (const [name, prefix] of MAGIC) {
    if (buffer.length >= prefix.length && buffer.subarray(0, prefix.length).equals(prefix)) return name;
  }
  return null;
}

function flagsIn(buffer) {
  const text = buffer.toString('utf8');
  FLAG_RE.lastIndex = 0;
  return [...text.matchAll(FLAG_RE)].map((match) => match[0]).slice(0, 8);
}

function scoreBuffer(buffer) {
  const text = buffer.toString('utf8');
  const printable = printableRatio(buffer);
  const utf8 = utf8Quality(buffer);
  const flags = flagsIn(buffer);
  const magic = magicName(buffer);
  let score = Math.round(printable * 100 + utf8 * 20);
  if (flags.length) score += 1200 + flags.length * 50;
  if (KEYWORD_RE.test(text)) score += 100;
  if (magic) score += 320;
  if (/^\s*[\[{][\s\S]*[\]}]\s*$/.test(text) && printable > 0.9) score += 60;
  return { score, printable, utf8, flags, magic };
}

function preview(buffer, max = 240) {
  const text = buffer.toString('utf8').replace(/\0/g, '␀');
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function cleanEncodedText(buffer) {
  return buffer.toString('utf8').trim();
}

function decodeHex(text) {
  const compact = text.replace(/^0x/i, '').replace(/[\s,:-]/g, '');
  if (compact.length < 4 || compact.length % 2 || !/^[0-9a-f]+$/i.test(compact)) return null;
  return Buffer.from(compact, 'hex');
}

function decodeBase64(text) {
  const compact = text.replace(/\s+/g, '');
  if (compact.length < 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return null;
  if (compact.length % 4 === 1) return null;
  try {
    const padded = compact.padEnd(Math.ceil(compact.length / 4) * 4, '=');
    const out = Buffer.from(padded, 'base64');
    return out.length ? out : null;
  } catch { return null; }
}

function decodeBase64Url(text) {
  const compact = text.replace(/\s+/g, '');
  if (compact.length < 4 || !/^[A-Za-z0-9_-]+={0,2}$/.test(compact) || !/[-_]/.test(compact)) return null;
  try {
    const normalized = compact.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    return decodeBase64(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
  } catch { return null; }
}

function decodeBase32(text) {
  const compact = text.replace(/[\s=-]/g, '').toUpperCase();
  if (compact.length < 8 || !/^[A-Z2-7]+$/.test(compact)) return null;
  let bits = '';
  for (const char of compact) {
    const value = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
    if (value < 0) return null;
    bits += value.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return bytes.length ? Buffer.from(bytes) : null;
}

function decodeBase58(text) {
  const compact = text.trim();
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  if (compact.length < 4 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(compact)) return null;
  try {
    let value = 0n;
    for (const char of compact) value = value * 58n + BigInt(alphabet.indexOf(char));
    let hex = value.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    let body = value === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
    const leading = compact.match(/^1+/)?.[0].length || 0;
    if (leading) body = Buffer.concat([Buffer.alloc(leading), body]);
    return body.length ? body : null;
  } catch { return null; }
}

function decodeUrl(text) {
  if (!/%[0-9a-f]{2}/i.test(text)) return null;
  try {
    const decoded = decodeURIComponent(text.replace(/\+/g, '%20'));
    return decoded !== text ? Buffer.from(decoded, 'utf8') : null;
  } catch { return null; }
}

function decodeEscapes(text) {
  if (!/(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4})/i.test(text)) return null;
  try {
    const decoded = text
      .replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
      .replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    return Buffer.from(decoded, 'utf8');
  } catch { return null; }
}

function decodeBits(text) {
  const compact = text.replace(/[\s,_-]/g, '');
  if (compact.length < 16 || compact.length % 8 || !/^[01]+$/.test(compact)) return null;
  const bytes = [];
  for (let i = 0; i < compact.length; i += 8) bytes.push(parseInt(compact.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function decodeDecimalBytes(text) {
  const trimmed = text.trim();
  if (!/^(?:\d{1,3}[\s,;:]+){3,}\d{1,3}$/.test(trimmed)) return null;
  const values = trimmed.split(/[\s,;:]+/).map(Number);
  if (values.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null;
  return Buffer.from(values);
}

function reverseText(text) {
  if (text.length < 4) return null;
  return Buffer.from([...text].reverse().join(''), 'utf8');
}

function rot13(text) {
  return Buffer.from(text.replace(/[A-Za-z]/g, (char) => {
    const base = char <= 'Z' ? 65 : 97;
    return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
  }), 'utf8');
}

function caesar(text, shift) {
  return Buffer.from(text.replace(/[A-Za-z]/g, (char) => {
    const base = char <= 'Z' ? 65 : 97;
    return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26) + base);
  }), 'utf8');
}

function atbash(text) {
  return Buffer.from(text.replace(/[A-Za-z]/g, (char) => {
    const upper = char <= 'Z';
    const base = upper ? 65 : 97;
    return String.fromCharCode(base + (25 - (char.charCodeAt(0) - base)));
  }), 'utf8');
}

function singleByteXor(buffer, key) {
  const out = Buffer.alloc(buffer.length);
  for (let i = 0; i < buffer.length; i += 1) out[i] = buffer[i] ^ key;
  return out;
}

function pushTransform(list, name, buffer) {
  if (!buffer || !Buffer.isBuffer(buffer) || !buffer.length || buffer.length > MAX_OUTPUT_BYTES) return;
  list.push({ name, buffer });
}

function transformsFor(node) {
  const list = [];
  const text = cleanEncodedText(node.buffer);
  const printable = printableRatio(node.buffer);

  pushTransform(list, 'Hex decode', decodeHex(text));
  pushTransform(list, 'Base64 decode', decodeBase64(text));
  pushTransform(list, 'Base64URL decode', decodeBase64Url(text));
  pushTransform(list, 'Base32 decode', decodeBase32(text));
  pushTransform(list, 'Base58 decode', decodeBase58(text));
  pushTransform(list, 'URL decode', decodeUrl(text));
  pushTransform(list, 'Escape decode', decodeEscapes(text));
  pushTransform(list, 'Binary bits decode', decodeBits(text));
  pushTransform(list, 'Decimal bytes decode', decodeDecimalBytes(text));

  if (printable >= 0.72 && text.length >= 4 && node.depth <= 2) {
    pushTransform(list, 'Reverse text', reverseText(text));
    pushTransform(list, 'ROT13', rot13(text));
    pushTransform(list, 'Atbash', atbash(text));
    if (node.depth <= 1 && /[A-Za-z]/.test(text)) {
      for (let shift = 1; shift < 26; shift += 1) pushTransform(list, `Caesar +${shift}`, caesar(text, shift));
    }
  }

  const allowXor = node.depth === 0 || /decode$/.test(node.path[node.path.length - 1] || '');
  if (allowXor && node.buffer.length >= 2 && node.buffer.length <= 8192) {
    for (let key = 1; key <= 255; key += 1) {
      const out = singleByteXor(node.buffer, key);
      const scored = scoreBuffer(out);
      if (scored.flags.length || scored.magic || scored.printable >= 0.82) pushTransform(list, `XOR 0x${key.toString(16).padStart(2, '0')}`, out);
    }
  }

  if (node.buffer.length >= 2 && node.buffer[0] === 0x1f && node.buffer[1] === 0x8b) {
    try { pushTransform(list, 'Gzip decompress', zlib.gunzipSync(node.buffer, { maxOutputLength: MAX_OUTPUT_BYTES })); } catch {}
  }
  if (node.buffer.length >= 2 && node.buffer[0] === 0x78) {
    try { pushTransform(list, 'Zlib inflate', zlib.inflateSync(node.buffer, { maxOutputLength: MAX_OUTPUT_BYTES })); } catch {}
  }

  return list;
}

function candidateFromNode(node) {
  const scored = scoreBuffer(node.buffer);
  const artifact = scored.magic && node.depth > 0 ? createBinaryArtifact({
    name: `decoded-${scored.magic.toLowerCase()}-${node.hash.slice(0, 12)}.bin`,
    buffer: node.buffer,
    completeness: 'complete',
    provenance: [{ source: 'auto-decode', transformPath: node.path.join(' → ') }],
    metadata: { kind: 'decoded-candidate', magic: scored.magic, transformPath: node.path }
  }) : null;
  return {
    depth: node.depth,
    path: node.path,
    score: scored.score,
    printableRatio: Number(scored.printable.toFixed(3)),
    utf8Quality: Number(scored.utf8.toFixed(3)),
    flags: scored.flags,
    magic: scored.magic,
    preview: preview(node.buffer),
    hexPreview: node.buffer.subarray(0, 96).toString('hex'),
    size: node.buffer.length,
    sha256: node.hash,
    artifact
  };
}

function autoDecode(input, options = {}) {
  const raw = Buffer.from(String(input ?? ''), 'utf8');
  if (!raw.length) throw new Error('请输入可疑数据');
  if (raw.length > MAX_INPUT_BYTES) throw new Error(`自动解码输入上限 ${MAX_INPUT_BYTES} bytes`);

  const maxDepth = Math.max(1, Math.min(Number(options.maxDepth) || MAX_DEPTH, MAX_DEPTH));
  const seen = new Set();
  const queue = [];
  const candidates = [];
  const initial = { buffer: raw, depth: 0, path: [], hash: sha256(raw) };
  seen.add(initial.hash);
  queue.push(initial);
  candidates.push(candidateFromNode(initial));

  while (queue.length && seen.size < MAX_NODES) {
    const node = queue.shift();
    if (node.depth >= maxDepth) continue;
    const generated = transformsFor(node)
      .map((item) => ({ ...item, score: scoreBuffer(item.buffer).score }))
      .sort((a, b) => b.score - a.score);

    for (const item of generated) {
      if (seen.size >= MAX_NODES) break;
      const hash = sha256(item.buffer);
      if (seen.has(hash)) continue;
      seen.add(hash);
      const next = { buffer: item.buffer, depth: node.depth + 1, path: [...node.path, item.name], hash };
      queue.push(next);
      candidates.push(candidateFromNode(next));
    }
  }

  const ranked = candidates
    .filter((item) => item.depth > 0)
    .sort((a, b) => b.score - a.score || a.depth - b.depth || a.path.join('>').localeCompare(b.path.join('>')));
  const flagHits = ranked.filter((item) => item.flags.length);
  const topCandidates = ranked.slice(0, 20);

  return {
    inputBytes: raw.length,
    triedCandidates: candidates.length - 1,
    uniqueStates: seen.size,
    maxDepth,
    flagHits: flagHits.slice(0, 12),
    bestCandidates: topCandidates,
    foundFlag: flagHits[0]?.flags?.[0] || null,
    bestAction: flagHits.length
      ? `发现 Flag 候选：${flagHits[0].flags[0]}，先回到原题环境验证。`
      : topCandidates[0]?.magic
        ? `最高候选像 ${topCandidates[0].magic} 文件，可导出后继续分析。`
        : topCandidates.length
          ? `先检查最高分路径：${topCandidates[0].path.join(' → ')}。`
          : '没有找到高质量结果，可能需要题目提供的 key、IV、算法参数或更具体的上下文。',
    note: '自动解码只尝试高收益确定性变换，不会声称破解未知强加密。AES/RSA/SM4 等需要 key/IV/模式时，应结合题目上下文继续。'
  };
}

module.exports = { autoDecode, scoreBuffer, decodeBase32, decodeBase58, MAX_DEPTH, MAX_NODES };
