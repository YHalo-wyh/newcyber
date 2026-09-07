const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer_batch4');
const { autoDecode } = require('./auto_decode');

const TEXT_EXTENSIONS = new Set([
  '.txt', '.md', '.log', '.json', '.jsonl', '.xml', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg',
  '.csv', '.tsv', '.py', '.js', '.ts', '.rs', '.c', '.cpp', '.h', '.hpp', '.go', '.java', '.php', '.sh', '.ps1'
]);
const MAX_TEXT_BYTES = 512 * 1024;
const MAX_FILES = 40;
const MAX_CANDIDATES_PER_FILE = 6;

function extractSuspiciousStrings(text) {
  const items = [];
  const pushMatches = (kind, regex) => {
    regex.lastIndex = 0;
    for (const match of text.matchAll(regex)) {
      const value = match[0].trim();
      if (value.length < 8 || value.length > 4096) continue;
      items.push({ kind, value, index: match.index || 0 });
      if (items.length >= 80) break;
    }
  };

  pushMatches('hex', /(?<![A-Za-z0-9])(?:0x)?(?:[0-9A-Fa-f]{2}[\s,:-]?){8,512}(?![A-Za-z0-9])/g);
  pushMatches('base64', /(?<![A-Za-z0-9+/_-])(?:[A-Za-z0-9+/]{4}){3,256}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/_-])/g);
  pushMatches('base64url', /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,1024}={0,2}(?![A-Za-z0-9_-])/g);
  pushMatches('percent', /(?:%[0-9A-Fa-f]{2}){4,256}/g);
  pushMatches('escape', /(?:(?:\\x[0-9A-Fa-f]{2})|(?:\\u[0-9A-Fa-f]{4})){4,256}/g);
  pushMatches('bits', /(?<![01])(?:[01]{8}[\s,_-]?){4,256}(?![01])/g);
  pushMatches('decimal-bytes', /(?<!\d)(?:\d{1,3}[\s,;:]+){5,255}\d{1,3}(?!\d)/g);

  const seen = new Set();
  return items
    .sort((a, b) => a.index - b.index || b.value.length - a.value.length)
    .filter((item) => {
      const key = item.value.replace(/\s+/g, ' ');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

async function readTextBounded(fullPath) {
  const stat = await fsp.stat(fullPath);
  if (stat.size > MAX_TEXT_BYTES) return null;
  const buffer = await fsp.readFile(fullPath);
  if (buffer.includes(0)) return null;
  return buffer.toString('utf8');
}

function summarizeCandidate(source, result) {
  const best = result.flagHits?.[0] || result.bestCandidates?.[0] || null;
  if (!best) return null;
  return {
    sourceKind: source.kind,
    sourcePreview: source.value.slice(0, 180),
    sourceOffset: source.index,
    foundFlag: result.foundFlag || null,
    path: best.path || [],
    score: best.score || 0,
    magic: best.magic || null,
    preview: best.preview || '',
    size: best.size || 0,
    sha256: best.sha256 || null,
    artifact: best.artifact || null
  };
}

function shouldKeep(summary) {
  if (!summary) return false;
  if (summary.foundFlag || summary.magic) return true;
  return summary.score >= 230 && /(?:flag|ctf|key|secret|password|token|admin|success|accepted)/i.test(summary.preview || '');
}

async function enrichAutoDecode(rootPath, file) {
  if (!TEXT_EXTENSIONS.has(file.extension) || file.size > MAX_TEXT_BYTES) return false;
  const text = await readTextBounded(path.join(rootPath, file.path));
  if (!text) return false;
  const suspicious = extractSuspiciousStrings(text).slice(0, MAX_CANDIDATES_PER_FILE);
  if (!suspicious.length) return false;

  const kept = [];
  for (const source of suspicious) {
    try {
      const result = autoDecode(source.value, { maxDepth: 2 });
      const summary = summarizeCandidate(source, result);
      if (shouldKeep(summary)) kept.push(summary);
    } catch {}
  }
  if (!kept.length) return false;

  file.metadata = {
    ...(file.metadata || {}),
    autoDecode: {
      attempted: suspicious.length,
      candidates: kept
    }
  };
  file.flags ||= [];
  file.findings ||= [];

  for (const candidate of kept) {
    if (candidate.foundFlag && !file.flags.includes(candidate.foundFlag)) file.flags.push(candidate.foundFlag);
    const id = `auto-decode:${file.path}:${candidate.sha256 || candidate.sourceOffset}`;
    if (file.findings.some((item) => item.id === id)) continue;
    file.findings.push({
      id,
      severity: candidate.foundFlag ? 'high' : candidate.magic ? 'medium' : 'info',
      title: candidate.foundFlag ? '自动解码命中 Flag 候选' : candidate.magic ? `自动解码得到 ${candidate.magic} 文件候选` : '可疑数据存在高质量解码路径',
      file: file.path,
      count: 1,
      evidence: `${candidate.path.join(' → ')} => ${candidate.foundFlag || candidate.magic || candidate.preview.slice(0, 120)}`
    });
  }
  return true;
}

function refresh(analysis) {
  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  analysis.findings = analysis.files
    .flatMap((file) => file.findings || [])
    .sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9) || String(a.file).localeCompare(String(b.file)));
  analysis.stats.findings = analysis.findings.length;
  analysis.stats.flags = analysis.files.reduce((sum, file) => sum + (file.flags?.length || 0), 0);
}

async function scanWorkspace(rootPath) {
  const analysis = await base.scanWorkspace(rootPath);
  let inspectedFiles = 0;
  let usefulFiles = 0;
  for (const file of analysis.files) {
    if (inspectedFiles >= MAX_FILES) break;
    if (!TEXT_EXTENSIONS.has(file.extension) || file.size > MAX_TEXT_BYTES) continue;
    inspectedFiles += 1;
    try {
      if (await enrichAutoDecode(rootPath, file)) usefulFiles += 1;
    } catch (error) {
      file.metadata = { ...(file.metadata || {}), autoDecodeError: error.message };
    }
  }
  if (usefulFiles) {
    analysis.recommendations ||= [];
    const text = '发现疑似编码/轻量加密数据并自动试解；比赛模式会优先显示解出的 Flag、文件头和高质量文本。未知 AES/RSA/SM4 等仍需结合 key/IV/模式。';
    if (!analysis.recommendations.includes(text)) analysis.recommendations.push(text);
  }
  refresh(analysis);
  analysis.version = Math.max(Number(analysis.version) || 1, 6);
  return analysis;
}

function oneLine(value) {
  return String(value ?? '').replace(/\s+/g, ' ').replace(/`/g, "'").trim();
}

function buildAutoDecodeSection(analysis) {
  const lines = [];
  for (const file of analysis.files || []) {
    const candidates = file.metadata?.autoDecode?.candidates || [];
    if (!candidates.length) continue;
    lines.push(`### 自动试解：\`${oneLine(file.path)}\``, '');
    for (const item of candidates.slice(0, 10)) {
      lines.push(`- ${oneLine(item.path.join(' → '))}：${oneLine(item.foundFlag || item.magic || item.preview)}`);
    }
    lines.push('');
  }
  return lines.length ? ['## 可疑数据自动试解', '', ...lines].join('\n') : '';
}

function buildMarkdownReport(analysis, notes = '') {
  let report = base.buildMarkdownReport(analysis, notes);
  const section = buildAutoDecodeSection(analysis);
  if (!section) return report;
  const marker = '\n## Flag 候选\n';
  if (report.includes(marker)) return report.replace(marker, `\n${section}\n${marker}`);
  return `${report.trim()}\n\n${section}\n`;
}

module.exports = {
  ...base,
  scanWorkspace,
  buildMarkdownReport,
  enrichAutoDecode,
  extractSuspiciousStrings,
  buildAutoDecodeSection
};
