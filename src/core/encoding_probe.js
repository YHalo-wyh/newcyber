const { autoDecode } = require('./auto_decode');

const MAX_VALUE = 4096;
const DEFAULT_LIMIT = 80;

function normalizeValue(value) {
  return String(value || '').trim().replace(/^(["'`])([\s\S]*)\1$/, '$2').trim();
}

function detectEncodingKinds(value) {
  const text = normalizeValue(value);
  if (text.length < 4 || text.length > MAX_VALUE) return [];
  const compact = text.replace(/\s+/g, '');
  const hits = [];
  const add = (kind, confidence, rank = 2) => hits.push({ kind, confidence, rank });

  if (/^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$/.test(compact)) add('jwt', 0.99, 1);
  if (/^(?:0x)?[0-9A-Fa-f]{16,}$/.test(compact) && compact.replace(/^0x/i, '').length % 2 === 0) add('hex', 0.98, 1);
  if (/(?:%[0-9A-Fa-f]{2}){3,}/.test(text)) add('percent', 0.99, 1);
  if (/(?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}){3,}/.test(text)) add('escape', 0.99, 1);
  if (/^(?:[01]{8}[\s,_-]?){4,}$/.test(text.trim())) add('bits', 0.99, 1);
  if (/^(?:\d{1,3}[\s,;:]+){4,}\d{1,3}$/.test(text) && text.split(/[\s,;:]+/).every((x) => Number(x) <= 255)) add('decimal-bytes', 0.94, 1);
  if (/(?:=[0-9A-Fa-f]{2}){3,}/.test(text)) add('quoted-printable', 0.98, 1);
  if (/(?:&(?:#\d+|#x[0-9A-Fa-f]+|amp|lt|gt|quot|apos);){3,}/i.test(text)) add('html-entity', 0.99, 1);
  if (/^[.\-\s/|]+$/.test(text) && (text.match(/[.-]{1,5}/g) || []).length >= 4) add('morse', 0.96, 1);
  if (/^(?:\d{1,2}[\s,;:\/-]+){3,}\d{1,2}$/.test(text) && text.split(/[\s,;:\/-]+/).every((x) => Number(x) >= 1 && Number(x) <= 26)) add('a1z26', 0.86, 2);
  if (/^<~[!-u\s]*~>$/.test(text)) add('ascii85', 0.99, 2);

  if (/^[A-Z2-7]+=*$/.test(compact) && compact.length >= 8) {
    const signal = /[2-7=]/.test(compact) ? 0.94 : 0.78;
    add('base32', signal, 1);
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(compact) && compact.length >= 12 && compact.length % 4 !== 1) {
    const signal = /[+/=]/.test(compact) || /[A-Z]/.test(compact) && /[a-z]/.test(compact) && /\d/.test(compact) ? 0.92 : 0.76;
    add('base64', signal, 1);
  }
  if (/^[A-Za-z0-9_-]+={0,2}$/.test(compact) && compact.length >= 12 && /[-_]/.test(compact)) add('base64url', 0.94, 1);
  if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(compact) && compact.length >= 16 && /\d/.test(compact) && /[A-Za-z]/.test(compact)) add('base58', compact.startsWith('1') ? 0.86 : 0.78, 2);
  if (/^[!-u]+$/.test(compact) && compact.length >= 10 && /[^A-Za-z0-9]/.test(compact)) add('ascii85', 0.82, 2);

  const base91Alphabet = /^[A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_`{|}~"]+$/;
  if (base91Alphabet.test(compact) && compact.length >= 16) {
    const punctuation = (compact.match(/[^A-Za-z0-9]/g) || []).length;
    if (punctuation >= 3) add('base91', 0.76, 3);
  }

  return hits.sort((a, b) => b.confidence - a.confidence || a.rank - b.rank || a.kind.localeCompare(b.kind));
}

function extractSuspiciousEncodings(text, options = {}) {
  const source = String(text || '');
  const limit = Math.max(1, Math.min(Number(options.limit) || DEFAULT_LIMIT, 200));
  const items = [];
  const push = (kind, value, index, confidence = 0.9, rank = 1) => {
    const normalized = normalizeValue(value);
    if (normalized.length < 4 || normalized.length > MAX_VALUE) return;
    items.push({ kind, value: normalized, index: Math.max(0, index || 0), confidence, rank });
  };
  const pushMatches = (kind, regex, confidence = 0.95, rank = 1) => {
    regex.lastIndex = 0;
    for (const match of source.matchAll(regex)) {
      push(kind, match[0], match.index || 0, confidence, rank);
      if (items.length >= limit * 3) break;
    }
  };

  pushMatches('jwt', /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])/g, 0.99, 1);
  pushMatches('hex', /(?<![A-Za-z0-9])(?:0x)?(?:[0-9A-Fa-f]{2}[\s,:-]?){8,512}(?![A-Za-z0-9])/g, 0.98, 1);
  pushMatches('base64', /(?<![A-Za-z0-9+/_-])(?:[A-Za-z0-9+/]{4}){3,256}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/_-])/g, 0.9, 1);
  pushMatches('base64url', /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,1024}={0,2}(?![A-Za-z0-9_-])/g, 0.82, 1);
  pushMatches('base32', /(?<![A-Z2-7])[A-Z2-7]{8,1024}={0,6}(?![A-Z2-7])/g, 0.86, 1);
  pushMatches('percent', /(?:%[0-9A-Fa-f]{2}){4,256}/g, 0.99, 1);
  pushMatches('escape', /(?:(?:\\x[0-9A-Fa-f]{2})|(?:\\u[0-9A-Fa-f]{4})){4,256}/g, 0.99, 1);
  pushMatches('bits', /(?<![01])(?:[01]{8}[\s,_-]?){4,256}(?![01])/g, 0.99, 1);
  pushMatches('decimal-bytes', /(?<!\d)(?:\d{1,3}[\s,;:]+){5,255}\d{1,3}(?!\d)/g, 0.92, 1);
  pushMatches('quoted-printable', /(?:=[0-9A-Fa-f]{2}){4,256}/g, 0.98, 1);
  pushMatches('html-entity', /(?:(?:&#\d+;|&#x[0-9A-Fa-f]+;|&(?:amp|lt|gt|quot|apos);)){3,256}/gi, 0.99, 1);
  pushMatches('morse', /(?<![.\-])(?:[.\-]{1,5}[ \t/|]+){3,80}[.\-]{1,5}(?![.\-])/g, 0.95, 1);
  pushMatches('ascii85', /<~[!-u\s]{5,4090}~>/g, 0.99, 2);

  const contextual = [];
  for (const match of source.matchAll(/["'`]([^"'`\r\n]{8,2048})["'`]/g)) contextual.push({ value: match[1], index: (match.index || 0) + 1 });
  for (const match of source.matchAll(/(?:^|[\r\n])[^\r\n]{0,80}?[=:]\s*([^\r\n]{8,2048})/g)) contextual.push({ value: match[1].replace(/[;,]\s*$/, ''), index: (match.index || 0) + match[0].indexOf(match[1]) });
  for (const candidate of contextual.slice(0, 120)) {
    const kinds = detectEncodingKinds(candidate.value);
    if (kinds[0] && kinds[0].confidence >= 0.76) push(kinds[0].kind, candidate.value, candidate.index, kinds[0].confidence, kinds[0].rank);
  }

  const seen = new Set();
  const accepted = [];
  for (const item of items.sort((a, b) => a.index - b.index || a.rank - b.rank || b.confidence - a.confidence || b.value.length - a.value.length)) {
    const key = item.value.replace(/\s+/g, ' ');
    if (seen.has(key)) continue;
    const end = item.index + item.value.length;
    const covered = accepted.some((prior) => prior.index <= item.index && prior.index + prior.value.length >= end && prior.confidence >= item.confidence);
    if (covered) continue;
    seen.add(key);
    accepted.push(item);
    if (accepted.length >= limit) break;
  }
  return accepted;
}

function decodeSuspiciousEncoding(source, options = {}) {
  const input = typeof source === 'string' ? { value: source, kind: null, confidence: 0 } : source || {};
  const profile = options.profile || (Number(input.confidence) >= 0.9 ? 'fast' : 'normal');
  return autoDecode(input.value, {
    profile,
    maxDepth: options.maxDepth || 2,
    maxNodes: options.maxNodes,
    caesar: options.caesar,
    xor: options.xor
  });
}

module.exports = { detectEncodingKinds, extractSuspiciousEncodings, decodeSuspiciousEncoding };
