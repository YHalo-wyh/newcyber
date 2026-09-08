const fsp = require('fs/promises');
const path = require('path');

const SOURCE_REPOSITORY = 'nomi-sec/PoC-in-GitHub';
const INDEX_SCHEMA = 'newcyber.poc-reference-index.v1';
const DEFAULT_MAX_REPOS_PER_CVE = 6;
const DEFAULT_MAX_CVES = 50000;
const MAX_DESCRIPTION = 360;
const MAX_WORKSPACE_QUERY = 2 * 1024 * 1024;

const STOPWORDS = new Set([
  'the','and','for','with','from','this','that','into','when','where','which','while','have','has','had','are','was','were','will','can','could','would','should','may','might','not','but','all','any','use','using','used','via','under','over','after','before','through','about','your','their','our','its','app','application','service','server','client','system','software','project','test','tests','demo','example','sample','code','source','github','repository','repo','security','secure','vulnerability','vulnerable','exploit','poc','proof','concept','cve','issue','bug','attack','attacker','remote','local','allows','allow','arbitrary','version','versions','ctf','challenge','flag','file','files','data','input','output','http','https','www','com','org','net','api','json','txt','log','main','readme'
]);

const VULN_ALIASES = Object.freeze([
  ['rce', /\b(?:rce|remote\s+code\s+(?:execution|injection))\b/i],
  ['command-injection', /\b(?:command\s+injection|os\s+command|shell\s+injection)\b/i],
  ['sql-injection', /\b(?:sqli|sql\s+injection)\b/i],
  ['xss', /\b(?:xss|cross[- ]site\s+scripting)\b/i],
  ['ssrf', /\b(?:ssrf|server[- ]side\s+request\s+forgery)\b/i],
  ['ssti', /\b(?:ssti|server[- ]side\s+template\s+injection)\b/i],
  ['deserialization', /\b(?:deseriali[sz]ation|unsafe\s+pickle|object\s+injection)\b/i],
  ['path-traversal', /\b(?:path\s+traversal|directory\s+traversal|\.\.\/)\b/i],
  ['auth-bypass', /\b(?:auth(?:entication|orization)?\s+bypass|unauthenticated|broken\s+access\s+control)\b/i],
  ['file-upload', /\b(?:file\s+upload|unrestricted\s+upload|arbitrary\s+file\s+upload)\b/i],
  ['lfi', /\b(?:lfi|local\s+file\s+inclusion)\b/i],
  ['xxe', /\b(?:xxe|xml\s+external\s+entity)\b/i],
  ['request-smuggling', /\b(?:request\s+smuggling|http\s+smuggling)\b/i],
  ['prototype-pollution', /\bprototype\s+pollution\b/i],
  ['buffer-overflow', /\b(?:buffer\s+overflow|stack\s+overflow|heap\s+overflow|out[- ]of[- ]bounds)\b/i],
  ['use-after-free', /\b(?:use[- ]after[- ]free|\buaf\b)\b/i],
  ['privilege-escalation', /\b(?:privilege\s+escalation|priv[- ]esc|elevation\s+of\s+privilege)\b/i],
  ['information-disclosure', /\b(?:information\s+disclosure|information\s+leak|info\s+leak|sensitive\s+data\s+exposure)\b/i],
  ['dos', /\b(?:denial\s+of\s+service|\bdos\b)\b/i]
]);

function normalizeText(value = '') {
  return String(value)
    .normalize('NFKC')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase();
}

function tokenize(value = '') {
  const text = normalizeText(value);
  const out = new Set();
  for (const match of text.matchAll(/[a-z][a-z0-9._+-]{1,47}|\d{1,4}(?:\.\d{1,4}){1,3}/g)) {
    const token = match[0].replace(/^[._+-]+|[._+-]+$/g, '');
    if (!token || STOPWORDS.has(token)) continue;
    if (/^\d+$/.test(token)) continue;
    if (/^cve[-_]?\d/i.test(token)) continue;
    out.add(token);
  }
  for (const [name, regex] of VULN_ALIASES) if (regex.test(text)) out.add(name);
  return [...out];
}

function cveIds(value = '') {
  return [...new Set((String(value).match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map((x) => x.toUpperCase()))];
}

function cveSourceUrl(cve) {
  const match = String(cve || '').toUpperCase().match(/^CVE-(\d{4})-(\d{4,7})$/);
  return match ? `https://github.com/${SOURCE_REPOSITORY}/blob/master/${match[1]}/${match[0]}.json` : null;
}

function repoScore(record = {}) {
  const stars = Math.max(0, Number(record.stargazers_count) || 0);
  const forks = Math.max(0, Number(record.forks_count) || 0);
  const description = String(record.description || '').trim();
  return Math.log2(stars + 1) * 12 + Math.log2(forks + 1) * 4 + (description ? 8 : 0) + (record.full_name ? 2 : 0);
}

function compactRepo(record = {}) {
  const description = String(record.description || '').replace(/\s+/g, ' ').trim().slice(0, MAX_DESCRIPTION);
  return {
    name: String(record.name || '').slice(0, 180),
    fullName: String(record.full_name || '').slice(0, 240),
    url: /^https:\/\/github\.com\//i.test(String(record.html_url || '')) ? String(record.html_url) : null,
    description: description || null,
    stars: Math.max(0, Number(record.stargazers_count) || 0),
    forks: Math.max(0, Number(record.forks_count) || 0),
    topics: Array.isArray(record.topics) ? record.topics.map((x) => String(x).slice(0, 80)).slice(0, 24) : []
  };
}

function normalizeCveEntry(cve, records, options = {}) {
  const maxRepos = Math.max(1, Math.min(Number(options.maxReposPerCve) || DEFAULT_MAX_REPOS_PER_CVE, 20));
  const all = Array.isArray(records) ? records.filter((x) => x && typeof x === 'object') : [];
  const repos = all
    .filter((x) => x.full_name || x.html_url || x.description)
    .sort((a, b) => repoScore(b) - repoScore(a))
    .slice(0, maxRepos)
    .map(compactRepo);
  const corpus = [cve, ...repos.flatMap((repo) => [repo.name, repo.fullName, repo.description, ...(repo.topics || [])])].filter(Boolean).join('\n');
  const keywords = tokenize(corpus).slice(0, 96);
  const bestDescription = repos.find((repo) => repo.description)?.description || null;
  return {
    cve,
    year: Number(String(cve).slice(4, 8)) || null,
    sourceUrl: cveSourceUrl(cve),
    referenceCount: all.length,
    summary: bestDescription,
    keywords,
    repos
  };
}

async function mapLimit(items, limit, worker) {
  const out = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.max(1, Math.min(limit, items.length || 1)) }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= items.length) break;
      out[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return out;
}

async function buildPocIndexFromDirectory(rootPath, options = {}) {
  const root = path.resolve(String(rootPath || ''));
  const rootStat = await fsp.stat(root);
  if (!rootStat.isDirectory()) throw new Error('PoC-in-GitHub 索引源必须是目录');
  const maxCves = Math.max(1, Math.min(Number(options.maxCves) || DEFAULT_MAX_CVES, 100000));
  const rootEntries = await fsp.readdir(root, { withFileTypes: true });
  const years = rootEntries.filter((entry) => entry.isDirectory() && /^(?:19|20)\d{2}$/.test(entry.name)).map((entry) => entry.name).sort();
  if (!years.length) throw new Error('未找到年份目录；请选择 nomi-sec/PoC-in-GitHub 仓库根目录');

  const files = [];
  for (const year of years) {
    if (files.length >= maxCves) break;
    let entries;
    try { entries = await fsp.readdir(path.join(root, year), { withFileTypes: true }); }
    catch { continue; }
    for (const entry of entries) {
      if (files.length >= maxCves) break;
      if (!entry.isFile()) continue;
      const match = entry.name.match(/^(CVE-\d{4}-\d{4,7})\.json$/i);
      if (!match) continue;
      files.push({ cve:match[1].toUpperCase(), filePath:path.join(root, year, entry.name) });
    }
  }

  let parseErrors = 0;
  const parsed = await mapLimit(files, Number(options.concurrency) || 24, async (item) => {
    try {
      const raw = await fsp.readFile(item.filePath, 'utf8');
      const records = JSON.parse(raw);
      return normalizeCveEntry(item.cve, records, options);
    } catch {
      parseErrors += 1;
      return null;
    }
  });
  const entries = parsed.filter(Boolean).sort((a, b) => a.cve.localeCompare(b.cve));
  const refs = entries.reduce((sum, item) => sum + item.referenceCount, 0);
  return {
    schema: INDEX_SCHEMA,
    source: {
      repository: SOURCE_REPOSITORY,
      branch: 'master',
      importedFrom: root,
      note: '仅索引仓库元数据（CVE、仓库名、说明、topics、stars/forks）；NewCyber 不自动下载或执行任何 PoC。'
    },
    generatedAt: new Date().toISOString(),
    stats: { years:years.length, cves:entries.length, references:refs, parseErrors },
    entries
  };
}

function validateIndex(index) {
  if (!index || index.schema !== INDEX_SCHEMA || !Array.isArray(index.entries)) throw new Error('PoC 索引格式不受支持');
  return index;
}

async function loadPocIndexFile(filePath) {
  const raw = await fsp.readFile(filePath, 'utf8');
  return validateIndex(JSON.parse(raw));
}

function buildKeywordIndex(index) {
  validateIndex(index);
  const cveMap = new Map();
  const postings = new Map();
  index.entries.forEach((entry, entryIndex) => {
    cveMap.set(entry.cve, entryIndex);
    for (const keyword of entry.keywords || []) {
      if (!postings.has(keyword)) postings.set(keyword, []);
      postings.get(keyword).push(entryIndex);
    }
  });
  return { cveMap, postings };
}

function analysisText(analysis = {}, extraText = '') {
  const chunks = [analysis.workspaceName || '', extraText];
  for (const file of (analysis.files || []).slice(0, 6000)) {
    chunks.push(file.path || '', file.name || '', file.type || '');
    for (const finding of (file.findings || []).slice(0, 24)) chunks.push(finding.title || '', finding.evidence || '');
    const m = file.metadata || {};
    if (m.firmware?.clues) chunks.push(JSON.stringify(m.firmware.clues).slice(0, 8000));
    if (m.captureIntelligence?.network?.protocolCounts) chunks.push(Object.keys(m.captureIntelligence.network.protocolCounts).join(' '));
    if (m.aiAudit?.findings) chunks.push((m.aiAudit.findings || []).map((x) => `${x.title || ''} ${x.evidence || ''}`).join(' '));
  }
  for (const finding of (analysis.findings || []).slice(0, 240)) chunks.push(finding.title || '', finding.evidence || '');
  for (const item of (analysis.recommendations || []).slice(0, 80)) chunks.push(item);
  return chunks.join('\n').slice(0, MAX_WORKSPACE_QUERY);
}

function querySignals(analysis, extraText = '') {
  const text = analysisText(analysis, extraText);
  return { text, cves:cveIds(text), tokens:tokenize(text) };
}

function postingWeight(length) {
  if (length <= 2) return 24;
  if (length <= 8) return 16;
  if (length <= 30) return 10;
  if (length <= 120) return 5;
  if (length <= 400) return 2;
  return 0;
}

function rankIndexMatches(index, signals, options = {}) {
  const topK = Math.max(1, Math.min(Number(options.topK) || 12, 40));
  const { cveMap, postings } = buildKeywordIndex(index);
  const scores = new Map();
  const reasons = new Map();
  const add = (entryIndex, score, reason) => {
    scores.set(entryIndex, (scores.get(entryIndex) || 0) + score);
    if (!reasons.has(entryIndex)) reasons.set(entryIndex, []);
    if (reason && !reasons.get(entryIndex).includes(reason)) reasons.get(entryIndex).push(reason);
  };

  for (const cve of signals.cves || []) {
    const entryIndex = cveMap.get(cve);
    if (entryIndex != null) add(entryIndex, 1000, `题目/附件直接出现 ${cve}`);
  }
  for (const token of signals.tokens || []) {
    const hits = postings.get(token) || [];
    const weight = postingWeight(hits.length);
    if (!weight) continue;
    for (const entryIndex of hits) add(entryIndex, weight, `关键词：${token}`);
  }

  return [...scores.entries()]
    .map(([entryIndex, score]) => {
      const entry = index.entries[entryIndex];
      const matchedKeywords = (reasons.get(entryIndex) || []).filter((x) => x.startsWith('关键词：')).map((x) => x.slice(4));
      const exact = (reasons.get(entryIndex) || []).some((x) => x.startsWith('题目/附件直接出现'));
      return { ...entry, score, exactCve:exact, matchedKeywords:matchedKeywords.slice(0, 12), reasons:(reasons.get(entryIndex) || []).slice(0, 12) };
    })
    .filter((item) => item.exactCve || item.score >= 18 || item.matchedKeywords.length >= 2)
    .sort((a, b) => b.score - a.score || b.referenceCount - a.referenceCount || a.cve.localeCompare(b.cve))
    .slice(0, topK);
}

function fallbackExactCves(signals) {
  return (signals.cves || []).slice(0, 20).map((cve) => ({
    cve,
    year:Number(cve.slice(4, 8)) || null,
    sourceUrl:cveSourceUrl(cve),
    referenceCount:null,
    summary:null,
    keywords:[],
    repos:[],
    score:1000,
    exactCve:true,
    matchedKeywords:[],
    reasons:[`题目/附件直接出现 ${cve}`],
    metadataPending:true
  }));
}

function matchPocReferences(analysis, index, options = {}) {
  const signals = querySignals(analysis, options.extraText || '');
  const available = Boolean(index?.schema === INDEX_SCHEMA && Array.isArray(index.entries));
  const matches = available ? rankIndexMatches(index, signals, options) : fallbackExactCves(signals);
  return {
    source: SOURCE_REPOSITORY,
    indexAvailable: available,
    indexGeneratedAt: available ? index.generatedAt : null,
    indexStats: available ? index.stats : null,
    query: { exactCves:signals.cves.slice(0, 40), keywords:signals.tokens.slice(0, 80) },
    matches,
    note: available
      ? '只做离线元数据关联：根据 CVE/产品/漏洞类型关键词筛选 PoC 参考，不自动下载、不执行、不验证远程目标。'
      : '尚未导入本地 PoC-in-GitHub 元数据索引；直接出现的 CVE 仍可定位到对应源文件，关键词关联需先导入索引。'
  };
}

module.exports = {
  SOURCE_REPOSITORY,
  INDEX_SCHEMA,
  tokenize,
  cveIds,
  cveSourceUrl,
  normalizeCveEntry,
  buildPocIndexFromDirectory,
  loadPocIndexFile,
  buildKeywordIndex,
  querySignals,
  matchPocReferences
};