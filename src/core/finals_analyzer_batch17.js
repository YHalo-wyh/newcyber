const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer_batch16');
const { matchPocReferences } = require('./poc_reference_index');

const TEXT_EXTENSIONS = new Set(['.txt','.md','.json','.jsonl','.xml','.yaml','.yml','.toml','.ini','.conf','.cfg','.log','.csv','.tsv','.py','.js','.ts','.java','.php','.go','.rs','.c','.cc','.cpp','.h','.hpp','.sh','.ps1','.bat','.sql','.html','.htm','.properties','.env']);
const MAX_EXTRA_TEXT_BYTES = 1024 * 1024;
const MAX_FILE_TEXT_BYTES = 192 * 1024;
const MAX_TEXT_FILES = 24;

async function collectReferenceText(rootPath, analysis) {
  const chunks = [];
  let bytes = 0;
  let filesRead = 0;
  const candidates = (analysis.files || [])
    .filter((file) => TEXT_EXTENSIONS.has(file.extension) && file.size > 0 && file.size <= 2 * 1024 * 1024)
    .sort((a, b) => {
      const score = (file) => (file.findings?.length || 0) * 20 + (file.flags?.length || 0) * 50 + (/readme|description|challenge|题目|说明|docker|compose|package|requirements/i.test(file.path || '') ? 30 : 0) - Math.log2((file.size || 1) + 1);
      return score(b) - score(a);
    });
  for (const file of candidates) {
    if (filesRead >= MAX_TEXT_FILES || bytes >= MAX_EXTRA_TEXT_BYTES) break;
    const remaining = Math.min(MAX_FILE_TEXT_BYTES, MAX_EXTRA_TEXT_BYTES - bytes);
    if (remaining <= 0) break;
    try {
      const handle = await fsp.open(path.join(rootPath, file.path), 'r');
      try {
        const buffer = Buffer.alloc(Math.min(remaining, file.size));
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        const data = buffer.subarray(0, bytesRead);
        if (data.includes(0)) continue;
        chunks.push(`FILE:${file.path}\n${data.toString('utf8')}`);
        bytes += bytesRead;
        filesRead += 1;
      } finally { await handle.close(); }
    } catch {}
  }
  return { text:chunks.join('\n\n'), bytes, filesRead };
}

async function scanWorkspace(rootPath, options = {}) {
  const analysis = await base.scanWorkspace(rootPath);
  let extra = { text:'', bytes:0, filesRead:0 };
  try { extra = await collectReferenceText(rootPath, analysis); }
  catch (error) { analysis.pocReferenceTextError = error.message; }
  analysis.pocReferences = matchPocReferences(analysis, options.pocIndex || null, { extraText:extra.text, topK:12 });
  analysis.pocReferences.queryEvidence = { textFilesRead:extra.filesRead, textBytes:extra.bytes };
  analysis.recommendations ||= [];
  const refs = analysis.pocReferences.matches || [];
  if (refs.length) {
    const exact = refs.filter((item) => item.exactCve).length;
    analysis.recommendations.unshift(`漏洞参考：从 PoC-in-GitHub 元数据筛出 ${refs.length} 个相关 CVE/PoC 参考${exact ? `，其中 ${exact} 个为题目直接出现的 CVE` : ''}；仅作线索对照，不自动下载或执行 PoC。`);
  } else if (!analysis.pocReferences.indexAvailable) {
    analysis.recommendations.push('PoC 参考索引尚未导入：可一次性选择本地 nomi-sec/PoC-in-GitHub 仓库生成离线关键词索引，之后所有赛题自动筛选相关 CVE/PoC 元数据。');
  }
  analysis.version = Math.max(Number(analysis.version) || 1, 17);
  analysis.batch17Counts = {
    pocIndexAvailable:analysis.pocReferences.indexAvailable,
    pocMatches:refs.length,
    exactCves:analysis.pocReferences.query?.exactCves?.length || 0,
    referenceTextFiles:extra.filesRead
  };
  return analysis;
}

function buildBatch17Section(analysis) {
  const refs = analysis.pocReferences;
  if (!refs) return '';
  const lines = ['## Batch 17 · PoC Reference Intelligence', '', `- source=${refs.source}`, `- index=${refs.indexAvailable ? 'loaded' : 'not-loaded'}, matches=${refs.matches?.length || 0}, exactCves=${refs.query?.exactCves?.length || 0}`, `- ${refs.note}`, ''];
  for (const item of (refs.matches || []).slice(0, 12)) {
    lines.push(`### ${item.cve} · score=${item.score}`, '');
    if (item.summary) lines.push(`- 参考说明：${item.summary.replace(/\s+/g, ' ').slice(0, 360)}`);
    if (item.matchedKeywords?.length) lines.push(`- 匹配关键词：${item.matchedKeywords.join(', ')}`);
    if (item.reasons?.length) lines.push(`- 命中原因：${item.reasons.join('；')}`);
    lines.push(`- PoC-in-GitHub 元数据：${item.sourceUrl}`);
    const top = (item.repos || []).slice(0, 3).map((repo) => `${repo.fullName || repo.name}${repo.stars ? ` ★${repo.stars}` : ''}`).filter(Boolean);
    if (top.length) lines.push(`- 代表参考：${top.join('；')}`);
    lines.push('');
  }
  return lines.join('\n');
}

function buildMarkdownReport(analysis, notes = '') {
  const report = base.buildMarkdownReport(analysis, notes);
  const section = buildBatch17Section(analysis);
  return section ? `${report.trim()}\n\n${section}\n` : report;
}

module.exports = { ...base, scanWorkspace, buildMarkdownReport, collectReferenceText, buildBatch17Section };