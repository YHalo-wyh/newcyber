const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer');
const { inspectModelArtifact } = require('./model_artifacts');

const MODEL_EXTENSIONS = new Set(['.pt', '.pth', '.safetensors', '.npy']);
const MODEL_INSPECTION_LIMIT = 64 * 1024 * 1024;

async function readBounded(filePath, limit = MODEL_INSPECTION_LIMIT) {
  const stat = await fsp.stat(filePath);
  if (stat.size > limit) return { skipped: true, size: stat.size, buffer: null };
  return { skipped: false, size: stat.size, buffer: await fsp.readFile(filePath) };
}

function appendFinding(file, finding) {
  file.findings ||= [];
  const suffix = finding.tensor || finding.global || finding.pc || finding.message || 'evidence';
  const id = `model-structure-${finding.id}:${file.path}:${String(suffix).slice(0, 80)}`;
  if (file.findings.some((item) => item.id === id)) return;
  file.findings.push({
    id,
    severity: finding.severity || 'info',
    title: finding.id === 'pickle-dangerous-global'
      ? 'Checkpoint pickle 引用高风险 global'
      : finding.id === 'pickle-external-global'
        ? 'Checkpoint pickle 引用非典型模块'
        : finding.id === 'npy-object-dtype'
          ? 'NPY 使用 object dtype / pickle 语义'
          : finding.id?.startsWith('tensor-') || finding.id?.includes('offset')
            ? '模型 tensor 结构不一致'
            : '模型文件结构审计线索',
    file: file.path,
    count: 1,
    evidence: finding.message || JSON.stringify(finding)
  });
}

function upsertCategory(analysis, name, score) {
  const existing = analysis.categories.find((item) => item.name === name);
  if (existing) existing.score = Math.max(existing.score || 0, score);
  else analysis.categories.push({ name, score });
}

function appendRecommendation(analysis, text) {
  analysis.recommendations ||= [];
  if (!analysis.recommendations.includes(text)) analysis.recommendations.push(text);
}

async function enrichModelArtifact(rootPath, file) {
  if (!MODEL_EXTENSIONS.has(file.extension)) return false;
  const read = await readBounded(path.join(rootPath, file.path));
  if (read.skipped) {
    file.metadata = {
      ...(file.metadata || {}),
      model: {
        ...(file.metadata?.model || {}),
        skipped: true,
        reason: '模型超过安全深度解析上限',
        size: read.size,
        limit: MODEL_INSPECTION_LIMIT
      }
    };
    return true;
  }

  const inspection = inspectModelArtifact(read.buffer, file.extension);
  if (!inspection) return false;
  file.metadata = { ...(file.metadata || {}), model: inspection };
  for (const finding of inspection.securityFindings || []) appendFinding(file, finding);
  return true;
}

function refreshFindings(analysis) {
  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  analysis.findings = analysis.files
    .flatMap((file) => file.findings || [])
    .sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9) || String(a.file).localeCompare(String(b.file)));
  analysis.stats.findings = analysis.findings.length;
}

async function scanWorkspace(rootPath) {
  const analysis = await base.scanWorkspace(rootPath);
  let modelArtifacts = 0;
  let highFindings = 0;
  for (const file of analysis.files) {
    try {
      if (!await enrichModelArtifact(rootPath, file)) continue;
      modelArtifacts += 1;
      highFindings += (file.metadata?.model?.securityFindings || []).filter((item) => item.severity === 'high').length;
    } catch (error) {
      file.metadata = { ...(file.metadata || {}), modelStructureInspectionError: error.message };
    }
  }
  if (modelArtifacts) {
    upsertCategory(analysis, '人工智能', 8 + Math.min(modelArtifacts + highFindings * 2, 10));
    appendRecommendation(analysis, '模型工件已做离线结构审计：SafeTensors 核对 shape/dtype/data_offsets，NPY 检查 object dtype，PyTorch ZIP 静态审计 data.pkl global/opcode；不要直接加载不可信模型。');
  }
  analysis.categories.sort((a, b) => (b.score || 0) - (a.score || 0) || a.name.localeCompare(b.name, 'zh-CN'));
  refreshFindings(analysis);
  analysis.version = Math.max(Number(analysis.version) || 1, 5);
  return analysis;
}

function oneLine(value) {
  return String(value ?? '').replace(/\s+/g, ' ').replace(/`/g, "'").trim();
}

function buildModelArtifactSection(analysis) {
  const lines = [];
  for (const file of analysis.files || []) {
    const model = file.metadata?.model;
    if (!model || !MODEL_EXTENSIONS.has(file.extension)) continue;
    lines.push(`### 模型结构：\`${oneLine(file.path)}\``, '');
    lines.push(`- Format：${oneLine(model.format || file.extension)}`);
    if (Number.isFinite(model.tensorCount)) lines.push(`- Tensors：${model.tensorCount}`);
    if (Number.isFinite(model.storageCount)) lines.push(`- Storages：${model.storageCount}`);
    if (model.valid != null) lines.push(`- Structural valid：${Boolean(model.valid)}`);
    if (model.objectDtype) lines.push('- NPY object dtype：yes（不要对不可信文件启用 allow_pickle）');
    if (model.pickleAudit) {
      lines.push(`- Pickle protocol：${model.pickleAudit.protocol || 0} / complete=${Boolean(model.pickleAudit.complete)}`);
      if (model.pickleAudit.globals?.length) lines.push(`- Pickle globals：${model.pickleAudit.globals.slice(0, 20).map((item) => `${oneLine(item.qualifiedName)}[${item.severity}]`).join(', ')}`);
      if (model.pickleAudit.parseError) lines.push(`- Pickle parser stop：${oneLine(model.pickleAudit.parseError)}`);
    }
    if (model.overlaps?.length) lines.push(`- Tensor overlaps：${model.overlaps.length}`);
    const findings = model.securityFindings || [];
    if (findings.length) {
      lines.push('- Structure findings：');
      for (const finding of findings.slice(0, 30)) lines.push(`  - [${oneLine(finding.severity)}] ${oneLine(finding.id)}：${oneLine(finding.message)}`);
    }
    lines.push('');
  }
  return lines.length ? ['## 模型文件结构审计', '', ...lines].join('\n') : '';
}

function buildMarkdownReport(analysis, notes = '') {
  let report = base.buildMarkdownReport(analysis, notes);
  const section = buildModelArtifactSection(analysis);
  if (!section) return report;
  const marker = '\n## Flag 候选\n';
  if (report.includes(marker)) return report.replace(marker, `\n${section}\n${marker}`);
  return `${report.trim()}\n\n${section}\n`;
}

module.exports = {
  ...base,
  scanWorkspace,
  buildMarkdownReport,
  enrichModelArtifact,
  buildModelArtifactSection,
  MODEL_INSPECTION_LIMIT
};
