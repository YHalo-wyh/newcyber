const fsp = require('fs/promises');
const path = require('path');
const base = require('./analyzer');
const { parsePcapng } = require('./pcapng');
const { inspectPytorchZip, auditPytorchAgainstTrainingLog } = require('./model');

const DEEP_INSPECTION_LIMIT = 64 * 1024 * 1024;
const TEXT_CONTEXT_LIMIT = 1024 * 1024;

async function readFileBounded(filePath, limit) {
  const stat = await fsp.stat(filePath);
  if (stat.size > limit) return { buffer: null, skipped: true, size: stat.size };
  return { buffer: await fsp.readFile(filePath), skipped: false, size: stat.size };
}

async function readTextBounded(filePath, limit = TEXT_CONTEXT_LIMIT) {
  try {
    const handle = await fsp.open(filePath, 'r');
    try {
      const stat = await handle.stat();
      const size = Math.min(stat.size, limit);
      const buffer = Buffer.alloc(size);
      const { bytesRead } = await handle.read(buffer, 0, size, 0);
      return buffer.subarray(0, bytesRead).toString('utf8');
    } finally {
      await handle.close();
    }
  } catch {
    return '';
  }
}

function findTrainingLog(files, modelPath) {
  const modelDir = path.dirname(modelPath);
  const candidates = files.filter((file) => {
    const lower = file.path.toLowerCase();
    return file.extension === '.log' && (lower.includes('train') || lower.includes('training'));
  });
  return candidates.sort((a, b) => {
    const aSame = path.dirname(a.path) === modelDir ? 0 : 1;
    const bSame = path.dirname(b.path) === modelDir ? 0 : 1;
    return aSame - bSame || a.path.localeCompare(b.path);
  })[0] || null;
}

async function enrichPcapng(rootPath, file) {
  const fullPath = path.join(rootPath, file.path);
  const read = await readFileBounded(fullPath, DEEP_INSPECTION_LIMIT);
  if (read.skipped) {
    file.metadata = {
      ...(file.metadata || {}),
      pcapng: { skipped: true, reason: '文件超过深度解析上限', size: read.size, limit: DEEP_INSPECTION_LIMIT }
    };
    return;
  }
  const parsed = parsePcapng(read.buffer);
  if (parsed) file.metadata = { ...(file.metadata || {}), pcapng: parsed };
}

async function enrichPytorch(rootPath, files, file) {
  const fullPath = path.join(rootPath, file.path);
  const read = await readFileBounded(fullPath, DEEP_INSPECTION_LIMIT);
  if (read.skipped) {
    file.metadata = {
      ...(file.metadata || {}),
      model: { skipped: true, reason: '模型超过安全深度解析上限', size: read.size, limit: DEEP_INSPECTION_LIMIT }
    };
    return;
  }
  const inspection = inspectPytorchZip(read.buffer);
  if (!inspection) return;

  const trainingLogFile = findTrainingLog(files, file.path);
  let audit = null;
  if (trainingLogFile) {
    const trainingLog = await readTextBounded(path.join(rootPath, trainingLogFile.path));
    audit = auditPytorchAgainstTrainingLog(inspection, trainingLog);
  }

  file.metadata = {
    ...(file.metadata || {}),
    model: inspection,
    modelAudit: audit,
    trainingLog: trainingLogFile?.path || null
  };

  if (audit?.findings?.length) {
    const existingIds = new Set((file.findings || []).map((item) => item.id));
    for (const finding of audit.findings) {
      const id = `model-${finding.type}:${file.path}`;
      if (existingIds.has(id)) continue;
      file.findings.push({
        id,
        severity: finding.severity,
        title: finding.type === 'unexpected-parameter' ? '模型参数与训练日志不一致' : finding.type === 'storage-size-outlier' ? '模型存在异常大的 tensor storage' : 'Checkpoint 体积异常增长',
        file: file.path,
        count: 1,
        evidence: finding.message
      });
    }
  }
}

async function scanWorkspace(rootPath) {
  const analysis = await base.scanWorkspace(rootPath);
  for (const file of analysis.files) {
    try {
      if (file.extension === '.pcapng') await enrichPcapng(rootPath, file);
      if (file.extension === '.pth' || file.extension === '.pt') await enrichPytorch(rootPath, analysis.files, file);
    } catch (error) {
      file.metadata = { ...(file.metadata || {}), deepInspectionError: error.message };
    }
  }

  const severityOrder = { high: 0, medium: 1, low: 2 };
  analysis.findings = analysis.files
    .flatMap((file) => file.findings || [])
    .sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));
  analysis.stats.findings = analysis.findings.length;
  return analysis;
}

function oneLine(value) {
  return String(value ?? '').replace(/\s+/g, ' ').replace(/`/g, "'").trim();
}

function findingEvidence(item) {
  const value = item.evidence ?? item.description ?? item.patterns;
  if (value == null || value === '') return '';
  if (typeof value === 'string') return oneLine(value);
  try { return oneLine(JSON.stringify(value)); } catch { return oneLine(value); }
}

function changeSummary(changes = []) {
  return changes.map((change) => {
    const from = Number.isInteger(change.from) ? change.from.toString(16).padStart(2, '0') : '--';
    const to = Number.isInteger(change.to) ? change.to.toString(16).padStart(2, '0') : '--';
    const setBits = Number.isInteger(change.setBits) && change.setBits ? ` +${change.setBits.toString(16).padStart(2, '0')}` : '';
    const clearedBits = Number.isInteger(change.clearedBits) && change.clearedBits ? ` -${change.clearedBits.toString(16).padStart(2, '0')}` : '';
    return `b${change.byteIndex}:${from}->${to}${setBits}${clearedBits}`;
  }).join('; ');
}

function buildDeepEvidenceSection(analysis) {
  const lines = [];

  for (const file of analysis.files || []) {
    const can = file.metadata?.pcapng?.can;
    if (can) {
      lines.push(`### CAN / PCAPNG：\`${oneLine(file.path)}\``, '');
      lines.push(`- 解析 CAN 帧：${can.parsedFrames || 0}`);
      lines.push(`- CAN ID 数量：${can.uniqueIds || 0}`);
      const candidates = (can.eventCandidates || []).slice(0, 100);
      if (candidates.length) {
        lines.push('', '| ID | frame | packet | payload | 变化 | raw frame |', '| --- | ---: | ---: | --- | --- | --- |');
        for (const event of candidates) {
          lines.push(`| ${oneLine(event.id)} | ${event.frameIndex ?? '—'} | ${event.packetIndex ?? '—'} | \`${oneLine(event.payload)}\` | ${oneLine(changeSummary(event.changes))} | \`${oneLine(event.rawFrameHex || '—')}\` |`);
        }
      }
      lines.push('');
    }

    const audit = file.metadata?.modelAudit;
    const model = file.metadata?.model;
    if (model || audit) {
      lines.push(`### 模型供应链：\`${oneLine(file.path)}\``, '');
      if (Number.isFinite(model?.storageCount)) lines.push(`- tensor storage 数量：${model.storageCount}`);
      if (audit?.unexpectedParameters?.length) lines.push(`- 训练日志未声明参数：\`${audit.unexpectedParameters.map(oneLine).join('`, `')}\``);
      if (audit?.suspiciousMappings?.length) {
        lines.push('- 可疑参数/storage 映射：');
        for (const item of audit.suspiciousMappings) {
          lines.push(`  - \`${oneLine(item.parameter)}\` -> \`${oneLine(item.storage)}\` (${item.storageBytes} bytes, ${oneLine(item.mapping)})`);
        }
      }
      if (audit?.storageOutliers?.length) {
        lines.push('- 异常 storage：');
        for (const item of audit.storageOutliers) lines.push(`  - \`${oneLine(item.name)}\`：${item.uncompressedSize} bytes`);
      }
      if (audit?.baselineBytes && audit?.exportedBytes) lines.push(`- checkpoint 体积：baseline ${audit.baselineBytes} bytes -> exported ${audit.exportedBytes} bytes`);
      lines.push('');
    }
  }

  if (!lines.length) return '';
  return ['## 深度解析证据', '', ...lines].join('\n');
}

function buildMarkdownReport(analysis, notes = '') {
  let report = base.buildMarkdownReport(analysis, notes);
  const detailLines = [];
  for (const [index, item] of (analysis.findings || []).entries()) {
    detailLines.push(`### ${index + 1}. ${oneLine(item.title || item.id || '未命名线索')}`, '');
    detailLines.push(`- 严重度：${oneLine(item.severity || 'unknown')}`);
    detailLines.push(`- 文件：\`${oneLine(item.file || 'workspace')}\``);
    const evidence = findingEvidence(item);
    if (evidence) detailLines.push(`- 证据：${evidence}`);
    detailLines.push('');
  }

  const sections = [];
  if (detailLines.length) sections.push(['## 发现证据明细', '', ...detailLines].join('\n'));
  const deep = buildDeepEvidenceSection(analysis);
  if (deep) sections.push(deep);
  if (!sections.length) return report;

  const marker = '\n## Flag 候选\n';
  const block = `\n${sections.join('\n\n')}\n`;
  if (report.includes(marker)) report = report.replace(marker, `${block}${marker}`);
  else report = `${report.trim()}${block}\n`;
  return report;
}

module.exports = { ...base, scanWorkspace, buildMarkdownReport, DEEP_INSPECTION_LIMIT };
