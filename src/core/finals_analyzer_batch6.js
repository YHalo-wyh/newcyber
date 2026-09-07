const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer_batch5');
const { decryptCryptoContext } = require('./context_crypto');

const TEXT_EXTENSIONS = new Set([
  '.txt', '.md', '.log', '.json', '.jsonl', '.xml', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg',
  '.csv', '.tsv', '.py', '.js', '.ts', '.rs', '.c', '.cpp', '.h', '.hpp', '.go', '.java', '.php', '.sh', '.ps1'
]);
const MAX_TEXT_BYTES = 512 * 1024;
const MAX_FILES = 50;

async function readText(fullPath) {
  const stat = await fsp.stat(fullPath);
  if (stat.size > MAX_TEXT_BYTES) return null;
  const buffer = await fsp.readFile(fullPath);
  if (buffer.includes(0)) return null;
  return buffer.toString('utf8');
}

function summarizeResult(result) {
  return {
    context: result.context,
    tried: result.tried,
    foundFlag: result.foundFlag,
    bestAction: result.bestAction,
    bestCandidates: (result.bestCandidates || []).slice(0, 6).map((item) => ({
      algorithm: item.algorithm,
      mode: item.mode,
      cipher: item.cipher,
      keyEncoding: item.keyEncoding,
      keyBytes: item.keyBytes,
      ciphertextEncoding: item.ciphertextEncoding,
      ciphertextBytes: item.ciphertextBytes,
      ivHex: item.ivHex,
      tagHex: item.tagHex,
      padding: item.padding,
      plaintextBytes: item.plaintextBytes,
      printableRatio: item.printableRatio,
      magic: item.magic,
      flags: item.flags,
      preview: item.preview,
      nestedPath: item.nestedPath,
      score: item.score,
      artifact: item.artifact || null
    }))
  };
}

async function enrichContextCrypto(rootPath, file) {
  if (!TEXT_EXTENSIONS.has(file.extension) || file.size > MAX_TEXT_BYTES) return false;
  const text = await readText(path.join(rootPath, file.path));
  if (!text || !/\bAES\b|\bSM4\b|aes-(?:128|192|256)-(?:cbc|ecb|ctr|gcm)|sm4-(?:cbc|ecb|ctr|gcm)|CryptoJS\.(?:AES|SM4)/i.test(text)) return false;

  const result = decryptCryptoContext(text);
  if (!result.context?.algorithms?.length) return false;
  const summary = summarizeResult(result);
  file.metadata = { ...(file.metadata || {}), contextCrypto: summary };
  file.flags ||= [];
  file.findings ||= [];

  if (summary.foundFlag && !file.flags.includes(summary.foundFlag)) file.flags.push(summary.foundFlag);

  if (summary.foundFlag) {
    file.findings.push({
      id: `context-crypto-flag:${file.path}:${summary.foundFlag}`,
      severity: 'high',
      title: '上下文强加密解密命中 Flag 候选',
      file: file.path,
      count: 1,
      evidence: summary.bestAction
    });
  } else if (summary.bestCandidates.some((item) => item.magic)) {
    const item = summary.bestCandidates.find((candidate) => candidate.magic);
    file.findings.push({
      id: `context-crypto-artifact:${file.path}:${item.cipher}:${item.magic}`,
      severity: 'medium',
      title: `上下文解密得到 ${item.magic} 文件候选`,
      file: file.path,
      count: 1,
      evidence: `${item.cipher}; key=${item.keyEncoding}; ciphertext=${item.ciphertextEncoding}`
    });
  } else if (summary.context.missing?.length) {
    file.findings.push({
      id: `context-crypto-incomplete:${file.path}`,
      severity: 'info',
      title: '发现强加密上下文但参数不完整',
      file: file.path,
      count: 1,
      evidence: `缺少：${summary.context.missing.join(', ')}`
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
  let inspected = 0;
  let matched = 0;
  for (const file of analysis.files) {
    if (inspected >= MAX_FILES) break;
    if (!TEXT_EXTENSIONS.has(file.extension) || file.size > MAX_TEXT_BYTES) continue;
    inspected += 1;
    try {
      if (await enrichContextCrypto(rootPath, file)) matched += 1;
    } catch (error) {
      file.metadata = { ...(file.metadata || {}), contextCryptoError: error.message };
    }
  }
  if (matched) {
    analysis.recommendations ||= [];
    const message = '发现 AES/SM4 强加密上下文：优先使用源码中明确的 key / IV / nonce / mode / tag 解密；成功结果会继续进入自动试解链，缺参数时保持 unknown。';
    if (!analysis.recommendations.includes(message)) analysis.recommendations.push(message);
  }
  refresh(analysis);
  analysis.version = Math.max(Number(analysis.version) || 1, 7);
  return analysis;
}

function oneLine(value) {
  return String(value ?? '').replace(/\s+/g, ' ').replace(/`/g, "'").trim();
}

function buildCryptoSection(analysis) {
  const lines = [];
  for (const file of analysis.files || []) {
    const item = file.metadata?.contextCrypto;
    if (!item) continue;
    lines.push(`### 强加密上下文：\`${oneLine(file.path)}\``, '');
    lines.push(`- 算法：${oneLine((item.context.algorithms || []).join(', ') || 'unknown')}`);
    lines.push(`- 模式：${oneLine((item.context.modes || []).join(', ') || 'unknown')}`);
    if (item.context.missing?.length) lines.push(`- 缺少参数：${oneLine(item.context.missing.join(', '))}`);
    if (item.foundFlag) lines.push(`- Flag 候选：\`${oneLine(item.foundFlag)}\``);
    const best = item.bestCandidates?.[0];
    if (best) lines.push(`- 最佳解密：${oneLine(best.cipher)}；key=${oneLine(best.keyEncoding)}；ciphertext=${oneLine(best.ciphertextEncoding)}；preview=${oneLine(best.preview)}`);
    lines.push('');
  }
  return lines.length ? ['## 上下文强加密试解', '', ...lines].join('\n') : '';
}

function buildMarkdownReport(analysis, notes = '') {
  const report = base.buildMarkdownReport(analysis, notes);
  const section = buildCryptoSection(analysis);
  if (!section) return report;
  const marker = '\n## Flag 候选\n';
  if (report.includes(marker)) return report.replace(marker, `\n${section}\n${marker}`);
  return `${report.trim()}\n\n${section}\n`;
}

module.exports = {
  ...base,
  scanWorkspace,
  buildMarkdownReport,
  enrichContextCrypto,
  buildCryptoSection
};
