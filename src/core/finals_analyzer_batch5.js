const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer_batch4');
const { decodeSuspiciousEncoding, extractSuspiciousEncodings } = require('./encoding_probe');

const TEXT_EXTENSIONS = new Set([
  '.txt', '.md', '.log', '.json', '.jsonl', '.xml', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg',
  '.csv', '.tsv', '.py', '.js', '.ts', '.rs', '.c', '.cpp', '.h', '.hpp', '.go', '.java', '.php', '.sh', '.ps1'
]);
const MAX_TEXT_BYTES = 512 * 1024;
const MAX_FILES = 40;
const MAX_CANDIDATES_PER_FILE = 8;

function extractSuspiciousStrings(text) {
  return extractSuspiciousEncodings(text, { limit: 80 });
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
    sourceConfidence: source.confidence || 0,
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
      const result = decodeSuspiciousEncoding(source, { maxDepth: 2 });
      const summary = summarizeCandidate(source, result);
      if (shouldKeep(summary)) kept.push(summary);
    } catch {}
  }
  if (!kept.length) return false;

  file.metadata = {
    ...(file.metadata || {}),
    autoDecode: {
      attempted: suspicious.length,
      detectors: suspicious.slice(0, 16).map((x) => ({ kind:x.kind, confidence:x.confidence, offset:x.index })),
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
      evidence: `${candidate.sourceKind || 'unknown'}(${Number(candidate.sourceConfidence || 0).toFixed(2)}) · ${candidate.path.join(' → ')} => ${candidate.foundFlag || candidate.magic || candidate.preview.slice(0, 120)}`
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
    const text = '发现疑似编码并按指纹优先自动试解：Base64/32/58/85/91、Hex、URL/HTML/QP/Unicode、JWT、Morse、A1Z26、二进制/十进制字节等先走低成本确定性路径；多层套娃继续递归，未知 AES/RSA/SM4 仍需题目给出的 key/IV/模式。';
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
      lines.push(`- ${oneLine(item.sourceKind || 'encoding')} → ${oneLine(item.path.join(' → '))}：${oneLine(item.foundFlag || item.magic || item.preview)}`);
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
