const common = require('./common');
const vehicle = require('./vehicle');
const lowalt = require('./lowalt');
const lowaltMatrix = require('./lowalt_matrix');
const ai = require('./ai');
const web3 = require('./web3');
const examDirections = require('./exam_directions');

const ENTRIES = [...common, ...vehicle, ...lowalt, ...lowaltMatrix, ...ai, ...web3, ...examDirections];

const TRACK_ALIASES = new Map([
  ['common', 'common'], ['通用', 'common'], ['misc', 'common'], ['crypto', 'common'],
  ['vehicle', 'vehicle'], ['car', 'vehicle'], ['can', 'vehicle'], ['车联网', 'vehicle'], ['汽车', 'vehicle'],
  ['lowalt', 'lowalt'], ['uav', 'lowalt'], ['drone', 'lowalt'], ['低空', 'lowalt'], ['低空经济', 'lowalt'], ['无人机', 'lowalt'],
  ['ai', 'ai'], ['人工智能', 'ai'], ['模型', 'ai'], ['llm', 'ai'],
  ['web3', 'web3'], ['blockchain', 'web3'], ['evm', 'web3'], ['solidity', 'web3'], ['区块链', 'web3']
]);

function normalize(value) {
  return String(value || '').trim().toLowerCase();
}

function resolveTrack(value) {
  const raw = String(value || '').trim();
  return TRACK_ALIASES.get(raw) || TRACK_ALIASES.get(raw.toLowerCase()) || null;
}

function haystack(entry) {
  return [
    entry.id, entry.title, entry.domain, entry.track,
    ...(entry.tags || []), entry.summary,
    ...(entry.evidence || []), ...(entry.prerequisites || []),
    ...(entry.verify || []), ...(entry.falsePositives || []),
    ...(entry.actions || []), ...(entry.mutations || [])
  ].join(' ').toLowerCase();
}

function scoreEntry(entry, query) {
  const q = normalize(query);
  if (!q) return 1;
  const words = q.split(/\s+/).filter(Boolean);
  const title = normalize(entry.title);
  const id = normalize(entry.id);
  const tags = (entry.tags || []).map(normalize);
  const body = haystack(entry);
  let score = 0;
  if (id === q) score += 100;
  if (title === q) score += 90;
  if (id.includes(q)) score += 45;
  if (title.includes(q)) score += 40;
  if (tags.includes(q)) score += 35;
  for (const word of words) {
    if (id.includes(word)) score += 12;
    if (title.includes(word)) score += 10;
    if (tags.some((tag) => tag.includes(word))) score += 8;
    if (body.includes(word)) score += 2;
  }
  return score;
}

function publicEntry(entry, score = null) {
  return {
    id: entry.id,
    term: entry.title,
    title: entry.title,
    domain: entry.domain,
    track: entry.track,
    tags: entry.tags || [],
    text: entry.summary,
    summary: entry.summary,
    evidence: entry.evidence || [],
    prerequisites: entry.prerequisites || [],
    verify: entry.verify || [],
    falsePositives: entry.falsePositives || [],
    actions: entry.actions || [],
    mutations: entry.mutations || [],
    ...(score == null ? {} : { score })
  };
}

function searchKnowledge(query, domain = null, options = {}) {
  const track = resolveTrack(domain) || resolveTrack(options.track);
  const limit = Number.isInteger(options.limit) ? Math.max(1, Math.min(options.limit, 50)) : 12;
  return ENTRIES
    .filter((entry) => !track || entry.track === track)
    .map((entry) => ({ entry, score: scoreEntry(entry, query) }))
    .filter((item) => !normalize(query) || item.score > 0)
    .sort((a, b) => b.score - a.score || a.entry.title.localeCompare(b.entry.title, 'zh-CN'))
    .slice(0, limit)
    .map((item) => publicEntry(item.entry, item.score));
}

function matchKnowledgeByEvidence(track, evidenceIds = [], text = '', options = {}) {
  const resolvedTrack = resolveTrack(track) || track;
  const tokens = [
    ...evidenceIds.map((item) => normalize(item).replace(/[^a-z0-9_-]+/g, ' ')),
    normalize(text)
  ].join(' ').split(/\s+/).filter((item) => item.length >= 3);
  const tokenSet = new Set(tokens);
  const limit = Number.isInteger(options.limit) ? Math.max(1, Math.min(options.limit, 20)) : 5;

  return ENTRIES
    .filter((entry) => !resolvedTrack || entry.track === resolvedTrack)
    .map((entry) => {
      const entryTokens = new Set([
        entry.id,
        ...(entry.tags || []),
        ...entry.id.split(/[._-]/)
      ].map(normalize));
      let score = 0;
      for (const token of tokenSet) {
        for (const candidate of entryTokens) {
          if (candidate === token) score += 8;
          else if (candidate.includes(token) || token.includes(candidate)) score += 3;
        }
        if (haystack(entry).includes(token)) score += 1;
      }
      return { entry, score };
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score || a.entry.id.localeCompare(b.entry.id))
    .slice(0, limit)
    .map((item) => publicEntry(item.entry, item.score));
}

function knowledgeStats() {
  const tracks = {};
  for (const entry of ENTRIES) tracks[entry.track] = (tracks[entry.track] || 0) + 1;
  return { total: ENTRIES.length, tracks };
}

module.exports = {
  ENTRIES,
  TRACK_ALIASES,
  resolveTrack,
  searchKnowledge,
  matchKnowledgeByEvidence,
  knowledgeStats
};
