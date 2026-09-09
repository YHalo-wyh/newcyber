'use strict';

const MAX_VOCAB_BYTES = 32 * 1024 * 1024;
const MAX_MERGES_BYTES = 16 * 1024 * 1024;
const MAX_TEXT_BYTES = 4 * 1024 * 1024;
const MAX_TOKENS = 262144;

function bytesToUnicodeMaps() {
  const bs = [];
  for (let i = 33; i <= 126; i += 1) bs.push(i);
  for (let i = 161; i <= 172; i += 1) bs.push(i);
  for (let i = 174; i <= 255; i += 1) bs.push(i);
  const cs = bs.slice();
  let extra = 0;
  for (let b = 0; b < 256; b += 1) {
    if (bs.includes(b)) continue;
    bs.push(b);
    cs.push(256 + extra);
    extra += 1;
  }
  const encoder = new Map();
  const decoder = new Map();
  for (let i = 0; i < bs.length; i += 1) {
    const ch = String.fromCodePoint(cs[i]);
    encoder.set(bs[i], ch);
    decoder.set(ch, bs[i]);
  }
  return { encoder, decoder };
}

const BYTE_MAPS = bytesToUnicodeMaps();
const TOKEN_PATTERN = /'s|'t|'re|'ve|'m|'ll|'d| ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+(?!\S)|\s+/gu;

function parseVocab(input) {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_VOCAB_BYTES) throw new Error('vocab.json 超过大小上限');
  let object;
  try { object = JSON.parse(text); } catch { throw new Error('vocab.json 不是合法 JSON'); }
  if (!object || Array.isArray(object) || typeof object !== 'object') throw new Error('vocab.json 必须是 token→id 对象');
  const tokenToId = new Map();
  const idToToken = new Map();
  for (const [token, rawId] of Object.entries(object)) {
    const id = Number(rawId);
    if (!Number.isSafeInteger(id) || id < 0 || id > 10_000_000) throw new Error(`vocab token ${token.slice(0,32)} 的 id 非法`);
    if (idToToken.has(id)) throw new Error(`vocab 出现重复 id ${id}`);
    tokenToId.set(token, id);
    idToToken.set(id, token);
  }
  if (!tokenToId.size) throw new Error('vocab.json 为空');
  return { tokenToId, idToToken };
}

function parseMerges(input) {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_MERGES_BYTES) throw new Error('merges.txt 超过大小上限');
  const ranks = new Map();
  let rank = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    if (parts.length !== 2) continue;
    const key = `${parts[0]}\u0000${parts[1]}`;
    if (!ranks.has(key)) ranks.set(key, rank++);
  }
  return ranks;
}

function pairsOf(symbols) {
  const out = [];
  for (let i = 0; i + 1 < symbols.length; i += 1) out.push([symbols[i], symbols[i + 1]]);
  return out;
}

function bpe(token, ranks, cache) {
  if (cache.has(token)) return cache.get(token);
  let word = Array.from(token);
  if (word.length <= 1) { cache.set(token, word); return word; }
  while (true) {
    let best = null;
    let bestRank = Infinity;
    for (const [left, right] of pairsOf(word)) {
      const rank = ranks.get(`${left}\u0000${right}`);
      if (rank != null && rank < bestRank) { bestRank = rank; best = [left, right]; }
    }
    if (!best) break;
    const merged = [];
    for (let i = 0; i < word.length;) {
      if (i + 1 < word.length && word[i] === best[0] && word[i + 1] === best[1]) {
        merged.push(best[0] + best[1]); i += 2;
      } else { merged.push(word[i]); i += 1; }
    }
    word = merged;
    if (word.length === 1) break;
  }
  cache.set(token, word);
  return word;
}

function createGpt2Bpe(vocabInput, mergesInput = '') {
  const { tokenToId, idToToken } = parseVocab(vocabInput);
  const ranks = parseMerges(mergesInput);
  const cache = new Map();

  function encode(textInput) {
    const text = String(textInput ?? '');
    if (Buffer.byteLength(text, 'utf8') > MAX_TEXT_BYTES) throw new Error('待编码文本超过大小上限');
    const ids = [];
    for (const match of text.matchAll(TOKEN_PATTERN)) {
      const bytes = Buffer.from(match[0], 'utf8');
      let encoded = '';
      for (const byte of bytes) encoded += BYTE_MAPS.encoder.get(byte);
      const pieces = bpe(encoded, ranks, cache);
      for (const piece of pieces) {
        const id = tokenToId.get(piece);
        if (id == null) throw new Error(`tokenizer vocab 缺少 BPE piece: ${JSON.stringify(piece.slice(0,32))}`);
        ids.push(id);
        if (ids.length > MAX_TOKENS) throw new Error(`token 数超过 ${MAX_TOKENS} 上限`);
      }
    }
    return ids;
  }

  function decode(idsInput) {
    const ids = Array.from(idsInput || [], Number);
    if (ids.length > MAX_TOKENS) throw new Error(`token 数超过 ${MAX_TOKENS} 上限`);
    let symbols = '';
    for (const id of ids) {
      if (!Number.isSafeInteger(id) || id < 0) throw new Error(`非法 token id ${id}`);
      const token = idToToken.get(id);
      if (token == null) throw new Error(`vocab 不包含 token id ${id}`);
      symbols += token;
    }
    const bytes = [];
    for (const ch of Array.from(symbols)) {
      const byte = BYTE_MAPS.decoder.get(ch);
      if (byte == null) throw new Error(`token 中出现非 GPT-2 byte-unicode 字符 ${JSON.stringify(ch)}`);
      bytes.push(byte);
    }
    return Buffer.from(bytes).toString('utf8');
  }

  return {
    schema: 'newcyber.gpt2-bpe.v1',
    vocabSize: tokenToId.size,
    mergeCount: ranks.size,
    encode,
    decode,
    tokenToId,
    idToToken
  };
}

module.exports = {
  MAX_TOKENS,
  bytesToUnicodeMaps,
  parseVocab,
  parseMerges,
  createGpt2Bpe
};
