const crypto = require('crypto');
const zlib = require('zlib');
const { createBinaryArtifact } = require('./artifacts');

const MAX_INPUT_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_NODES = 600;
const MAX_DEPTH = 3;

const PROFILE_PRESETS = {
  fast: { maxDepth: 1, maxNodes: 140, classical: false, caesar: false, xor: false },
  normal: { maxDepth: 2, maxNodes: 320, classical: true, caesar: false, xor: false },
  enhanced: { maxDepth: 3, maxNodes: MAX_NODES, classical: true, caesar: true, xor: true }
};

const FLAG_RE = /(?:flag|ctf|[A-Za-z][A-Za-z0-9_]{2,23})\{[\x20-\x7a\x7c\x7e]{1,200}\}/gi;
const KEYWORD_RE = /\b(?:flag|ctf|key|secret|password|token|admin|success|accepted)\b/i;

const MAGIC = [
  ['PNG', Buffer.from('89504e470d0a1a0a', 'hex')],
  ['ZIP', Buffer.from('504b0304', 'hex')],
  ['ELF', Buffer.from('7f454c46', 'hex')],
  ['PDF', Buffer.from('25504446', 'hex')],
  ['GZIP', Buffer.from('1f8b', 'hex')],
  ['PCAPNG', Buffer.from('0a0d0d0a', 'hex')],
  ['PCAP', Buffer.from('d4c3b2a1', 'hex')],
  ['PCAP', Buffer.from('a1b2c3d4', 'hex')],
  ['PCAP', Buffer.from('4d3cb2a1', 'hex')],
  ['PCAP', Buffer.from('a1b23c4d', 'hex')],
  ['UIMAGE', Buffer.from('27051956', 'hex')],
  ['SQUASHFS', Buffer.from('68737173', 'hex')],
  ['SQUASHFS', Buffer.from('73717368', 'hex')],
  ['SQLite', Buffer.from('53514c69746520666f726d6174203300', 'hex')],
  ['JPEG', Buffer.from('ffd8ff', 'hex')],
  ['GIF', Buffer.from('47494638', 'hex')],
  ['7Z', Buffer.from('377abcaf271c', 'hex')],
  ['RAR', Buffer.from('526172211a07', 'hex')]
];

const BASE91_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
const MORSE = {
  '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
  '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'
};

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

function decodeAscii85(text) {
  let compact = text.trim();
  const wrapped = compact.startsWith('<~') && compact.endsWith('~>');
  if (wrapped) compact = compact.slice(2, -2);
  compact = compact.replace(/\s+/g, '');
  if (compact.length < 5) return null;
  if (!wrapped && (!/^[!-u]+$/.test(compact) || !/[^A-Za-z0-9]/.test(compact))) return null;
  if (wrapped && !/^[!-u]*$/.test(compact.replace(/z/g, '!!!!!'))) return null;
  const out = [];
  let group = [];
  const flush = (final = false) => {
    if (!group.length) return true;
    const original = group.length;
    if (!final && original !== 5) return false;
    if (final && original === 1) return false;
    while (group.length < 5) group.push('u'.charCodeAt(0));
    let value = 0;
    for (const code of group) value = value * 85 + (code - 33);
    if (value > 0xffffffff) return false;
    const bytes = [value >>> 24, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
    out.push(...bytes.slice(0, final ? original - 1 : 4));
    group = [];
    return true;
  };
  for (const char of compact) {
    if (char === 'z') {
      if (group.length) return null;
      out.push(0, 0, 0, 0);
      continue;
    }
    const code = char.charCodeAt(0);
    if (code < 33 || code > 117) return null;
    group.push(code);
    if (group.length === 5 && !flush(false)) return null;
  }
  if (group.length && !flush(true)) return null;
  return out.length ? Buffer.from(out) : null;
}

function decodeBase91(text) {
  const compact = text.trim();
  if (compact.length < 8 || /\s/.test(compact)) return null;
  let punctuation = 0;
  for (const ch of compact) {
    if (BASE91_ALPHABET.indexOf(ch) < 0) return null;
    if (!/[A-Za-z0-9]/.test(ch)) punctuation += 1;
  }
  if (punctuation < 2) return null;
  const out = [];
  let b = 0;
  let n = 0;
  let v = -1;
  for (const ch of compact) {
    const c = BASE91_ALPHABET.indexOf(ch);
    if (v < 0) v = c;
    else {
      v += c * 91;
      b |= v << n;
      n += (v & 8191) > 88 ? 13 : 14;
      do {
        out.push(b & 255);
        b >>= 8;
        n -= 8;
      } while (n > 7);
      v = -1;
    }
  }
  if (v >= 0) out.push((b | (v << n)) & 255);
  return out.length ? Buffer.from(out) : null;
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

function decodeQuotedPrintable(text) {
  if (!/=[0-9a-f]{2}/i.test(text)) return null;
  try {
    const joined = text.replace(/=\r?\n/g, '');
    const decoded = joined.replace(/=([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    return decoded !== text ? Buffer.from(decoded, 'latin1') : null;
  } catch { return null; }
}

function decodeHtmlEntities(text) {
  if (!/&(?:#\d+|#x[0-9a-f]+|amp|lt|gt|quot|apos);/i.test(text)) return null;
  const named = { amp:'&', lt:'<', gt:'>', quot:'"', apos:"'" };
  const decoded = text.replace(/&(?:#(\d+)|#x([0-9a-f]+)|(amp|lt|gt|quot|apos));/gi, (whole, dec, hex, name) => {
    if (dec) return String.fromCodePoint(Number(dec));
    if (hex) return String.fromCodePoint(parseInt(hex, 16));
    return named[String(name).toLowerCase()] || whole;
  });
  return decoded !== text ? Buffer.from(decoded, 'utf8') : null;
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

function decodeA1Z26(text) {
  const trimmed = text.trim();
  if (!/^(?:\d{1,2}[\s,;:\/-]+){3,}\d{1,2}$/.test(trimmed)) return null;
  const values = trimmed.split(/[\s,;:\/-]+/).map(Number);
  if (values.some((value) => !Number.isInteger(value) || value < 1 || value > 26)) return null;
  return Buffer.from(values.map((value) => String.fromCharCode(64 + value)).join(''), 'utf8');
}

function decodeMorse(text) {
  const normalized = text.trim().replace(/[|]/g, '/');
  if (!/^[.\-\s/]+$/.test(normalized) || !/[.-]{1,5}\s+[.-]{1,5}/.test(normalized)) return null;
  const words = normalized.split(/\s*\/\s*/);
  const decoded = [];
  for (const word of words) {
    const letters = word.trim().split(/\s+/).filter(Boolean);
    if (!letters.length) continue;
    const out = letters.map((item) => MORSE[item]);
    if (out.some((item) => !item)) return null;
    decoded.push(out.join(''));
  }
  return decoded.length ? Buffer.from(decoded.join(' '), 'utf8') : null;
}

function decodeJwt(text) {
  const compact = text.trim();
  const parts = compact.split('.');
  if (parts.length !== 3 || parts[0].length < 4 || parts[1].length < 4) return null;
  if (!parts.every((part) => /^[A-Za-z0-9_-]*$/.test(part))) return null;
  const decodePart = (part) => {
    const normalized = part.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='), 'base64').toString('utf8');
  };
  try {
    const header = decodePart(parts[0]);
    const payload = decodePart(parts[1]);
    if (!header || !payload) return null;
    return Buffer.from(`${header}\n${payload}`, 'utf8');
  } catch { return null; }
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

function rot47(text) {
  if (!/[!-~]/.test(text)) return null;
  return Buffer.from([...text].map((char) => {
    const code = char.charCodeAt(0);
    if (code < 33 || code > 126) return char;
    return String.fromCharCode(33 + ((code - 33 + 47) % 94));
  }).join(''), 'utf8');
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

function transformsFor(node, settings) {
  const list = [];
  const text = cleanEncodedText(node.buffer);
  const printable = printableRatio(node.buffer);

  pushTransform(list, 'Hex decode', decodeHex(text));
  pushTransform(list, 'Base64 decode', decodeBase64(text));
  pushTransform(list, 'Base64URL decode', decodeBase64Url(text));
  pushTransform(list, 'Base32 decode', decodeBase32(text));
  pushTransform(list, 'Base58 decode', decodeBase58(text));
  pushTransform(list, 'Ascii85 decode', decodeAscii85(text));
  pushTransform(list, 'Base91 decode', decodeBase91(text));
  pushTransform(list, 'JWT decode', decodeJwt(text));
  pushTransform(list, 'URL decode', decodeUrl(text));
  pushTransform(list, 'Escape decode', decodeEscapes(text));
  pushTransform(list, 'Quoted-printable decode', decodeQuotedPrintable(text));
  pushTransform(list, 'HTML entity decode', decodeHtmlEntities(text));
  pushTransform(list, 'Binary bits decode', decodeBits(text));
  pushTransform(list, 'Decimal bytes decode', decodeDecimalBytes(text));
  pushTransform(list, 'A1Z26 decode', decodeA1Z26(text));
  pushTransform(list, 'Morse decode', decodeMorse(text));

  if (settings.classical && printable >= 0.72 && text.length >= 4 && node.depth <= 2) {
    pushTransform(list, 'Reverse text', reverseText(text));
    pushTransform(list, 'ROT13', rot13(text));
    pushTransform(list, 'ROT47', rot47(text));
    pushTransform(list, 'Atbash', atbash(text));
    if (settings.caesar && node.depth <= 1 && /[A-Za-z]/.test(text)) {
      for (let shift = 1; shift < 26; shift += 1) pushTransform(list, `Caesar +${shift}`, caesar(text, shift));
    }
  }

  const allowXor = settings.xor && (node.depth === 0 || /decode$/.test(node.path[node.path.length - 1] || ''));
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

  const profileName = PROFILE_PRESETS[options.profile] ? options.profile : 'enhanced';
  const preset = PROFILE_PRESETS[profileName];
  const maxDepth = Math.max(1, Math.min(Number(options.maxDepth) || preset.maxDepth, MAX_DEPTH));
  const maxNodes = Math.max(16, Math.min(Number(options.maxNodes) || preset.maxNodes, MAX_NODES));
  const settings = {
    classical: options.classical ?? preset.classical,
    caesar: options.caesar ?? preset.caesar,
    xor: options.xor ?? preset.xor
  };
  const seen = new Set();
  const queue = [];
  const candidates = [];
  const initial = { buffer: raw, depth: 0, path: [], hash: sha256(raw) };
  seen.add(initial.hash);
  queue.push(initial);
  candidates.push(candidateFromNode(initial));

  while (queue.length && seen.size < maxNodes) {
    const node = queue.shift();
    if (node.depth >= maxDepth) continue;
    const generated = transformsFor(node, settings)
      .map((item) => ({ ...item, score: scoreBuffer(item.buffer).score }))
      .sort((a, b) => b.score - a.score);

    for (const item of generated) {
      if (seen.size >= maxNodes) break;
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
    profile: profileName,
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
    note: '自动解码采用分层预算：先跑 Base/转义/信号等确定性解码，再按 profile 放开古典变换和单字节 XOR；不会把未知强加密冒充成已破解。'
  };
}

module.exports = {
  autoDecode,
  scoreBuffer,
  magicName,
  printableRatio,
  decodeBase32,
  decodeBase58,
  decodeAscii85,
  decodeBase91,
  decodeQuotedPrintable,
  decodeHtmlEntities,
  decodeMorse,
  decodeA1Z26,
  decodeJwt,
  PROFILE_PRESETS,
  MAX_DEPTH,
  MAX_NODES
};
