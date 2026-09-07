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

module.exports = { ...base, scanWorkspace, DEEP_INSPECTION_LIMIT };
