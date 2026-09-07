const fsp = require('fs/promises');
const path = require('path');
const base = require('./workbench_analyzer');
const { auditAiChallengeSource } = require('./ai_source');
const { auditSolanaAnchor, inspectAnchorToml } = require('./solana');

const TEXT_LIMIT = 2 * 1024 * 1024;
const AI_SOURCE_EXTENSIONS = new Set(['.py', '.pyw', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);

async function readTextBounded(filePath, limit = TEXT_LIMIT) {
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
}

function upsertCategory(analysis, name, score) {
  if (!score) return;
  const existing = analysis.categories.find((item) => item.name === name);
  if (existing) existing.score = Math.max(existing.score || 0, score);
  else analysis.categories.push({ name, score });
}

function appendRecommendation(analysis, text) {
  analysis.recommendations ||= [];
  if (!analysis.recommendations.includes(text)) analysis.recommendations.push(text);
}

function appendFinding(file, finding, prefix) {
  file.findings ||= [];
  const id = `${prefix}-${finding.id}:${file.path}:${finding.line || 0}`;
  if (file.findings.some((item) => item.id === id)) return;
  file.findings.push({
    id,
    severity: finding.severity || 'info',
    title: finding.title || finding.id,
    file: file.path,
    count: finding.count || 1,
    evidence: finding.message ? `${finding.message}${finding.evidence ? `\n${Array.isArray(finding.evidence) ? finding.evidence.join('\n---\n') : finding.evidence}` : ''}` : finding.evidence,
    line: finding.line || null
  });
}

function looksLikeAiSource(source) {
  return /\b(?:torch|tensorflow|transformers|whisper|sklearn|xgboost|openai|llm|chat\/completions|system_prompt|retriever|vectorstore|faiss|chroma|tool_call|function_call)\b/i.test(source);
}

async function enrichAiSource(rootPath, file) {
  if (!AI_SOURCE_EXTENSIONS.has(file.extension)) return false;
  const source = await readTextBounded(path.join(rootPath, file.path));
  if (!source.trim() || !looksLikeAiSource(source)) return false;
  const audit = auditAiChallengeSource(source);
  const meaningful = audit.llmCrypto || audit.surfaces?.model || audit.surfaces?.rag || audit.surfaces?.agent || audit.findings?.some((item) => item.id.startsWith('llm-'));
  if (!meaningful) return false;
  file.metadata = { ...(file.metadata || {}), aiAudit: audit };
  for (const finding of audit.findings || []) appendFinding(file, finding, 'ai');
  return true;
}

async function enrichSolana(rootPath, file) {
  if (file.extension !== '.rs') return false;
  const source = await readTextBounded(path.join(rootPath, file.path));
  const audit = auditSolanaAnchor(source);
  if (!audit) return false;
  file.metadata = { ...(file.metadata || {}), solanaAudit: audit };
  for (const finding of audit.findings || []) appendFinding(file, finding, 'solana');
  return true;
}

async function enrichAnchorConfig(rootPath, file) {
  if (path.basename(file.path).toLowerCase() !== 'anchor.toml') return false;
  const source = await readTextBounded(path.join(rootPath, file.path));
  const config = inspectAnchorToml(source);
  if (!config) return false;
  file.metadata = { ...(file.metadata || {}), anchorConfig: config };
  file.findings ||= [];
  file.findings.push({
    id: `solana-anchor-config:${file.path}`,
    severity: 'info',
    title: 'Anchor / Solana 工具链配置',
    file: file.path,
    count: 1,
    evidence: `cluster=${config.cluster || 'unknown'}, solana=${config.solanaVersion || 'unknown'}, anchor=${config.anchorVersion || 'unknown'}`
  });
  return true;
}

function refreshCategoriesAndRecommendations(analysis) {
  const canFiles = analysis.files.filter((file) => file.metadata?.pcapng?.can);
  if (canFiles.length) {
    upsertCategory(analysis, '车联网', 8 + Math.min(canFiles.length, 3));
    appendRecommendation(analysis, '检测到 SocketCAN/PCAPNG：优先查看 CAN ID 状态跃迁、原始帧映射，并对 0x7DF/0x7E8 等诊断流量继续做 ISO-TP/UDS 重组。');
  }

  const aiFiles = analysis.files.filter((file) => file.metadata?.aiAudit);
  if (aiFiles.length) {
    const high = aiFiles.reduce((sum, file) => sum + (file.metadata.aiAudit.findings || []).filter((item) => item.severity === 'high').length, 0);
    upsertCategory(analysis, '人工智能', 7 + Math.min(high * 2, 10));
    if (aiFiles.some((file) => file.metadata.aiAudit.llmCrypto)) {
      appendRecommendation(analysis, '发现 LLM 输出参与密钥派生：固定 model/prompt/temperature，枚举模型输出候选，并用 PKCS#7 padding、明文格式或校验值作为本地 oracle。');
    } else {
      appendRecommendation(analysis, 'AI 源码已进入专项审计：沿 prompt/RAG/model output 到 tool、shell、文件与密码学 sink 追踪数据流。');
    }
  }

  const solanaFiles = analysis.files.filter((file) => file.metadata?.solanaAudit || file.metadata?.anchorConfig);
  if (solanaFiles.length) {
    const medium = solanaFiles.reduce((sum, file) => sum + (file.metadata.solanaAudit?.summary?.medium || 0), 0);
    upsertCategory(analysis, '区块链', 7 + Math.min(medium * 2, 8));
    appendRecommendation(analysis, '检测到 Solana/Anchor：先固定 program ID、cluster、instruction、PDA seeds，再逐个核对 AccountInfo 的 owner/address/PDA/signer 约束和交易日志。');
  }

  analysis.categories.sort((a, b) => (b.score || 0) - (a.score || 0) || a.name.localeCompare(b.name, 'zh-CN'));
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
  for (const file of analysis.files) {
    try {
      await enrichAiSource(rootPath, file);
      await enrichSolana(rootPath, file);
      await enrichAnchorConfig(rootPath, file);
    } catch (error) {
      file.metadata = { ...(file.metadata || {}), finalsInspectionError: error.message };
    }
  }
  refreshFindings(analysis);
  refreshCategoriesAndRecommendations(analysis);
  analysis.version = Math.max(Number(analysis.version) || 1, 3);
  return analysis;
}

function oneLine(value) {
  return String(value ?? '').replace(/\s+/g, ' ').replace(/`/g, "'").trim();
}

function buildFinalsEvidenceSection(analysis) {
  const lines = [];
  for (const file of analysis.files || []) {
    const ai = file.metadata?.aiAudit;
    if (ai) {
      lines.push(`### AI 源码：\`${oneLine(file.path)}\``, '');
      lines.push(`- Surfaces：model=${Boolean(ai.surfaces?.model)}, rag=${Boolean(ai.surfaces?.rag)}, agent=${Boolean(ai.surfaces?.agent)}, shell=${Boolean(ai.surfaces?.shell)}`);
      if (ai.llmCrypto) {
        lines.push(`- LLM→Crypto：${oneLine(ai.llmCrypto.outputEvidence)} → ${oneLine(ai.llmCrypto.keyDerivationEvidence)} → ${oneLine(ai.llmCrypto.encryptionEvidence)}`);
        if (ai.llmCrypto.temperatures?.length) lines.push(`- temperature：${ai.llmCrypto.temperatures.join(', ')}`);
      }
      lines.push('');
    }

    const solana = file.metadata?.solanaAudit;
    if (solana) {
      lines.push(`### Solana / Anchor：\`${oneLine(file.path)}\``, '');
      if (solana.programId) lines.push(`- Program ID：\`${oneLine(solana.programId)}\``);
      if (solana.instructions?.length) lines.push(`- Instructions：${solana.instructions.map((item) => `\`${oneLine(item)}\``).join(', ')}`);
      if (solana.pdaSeeds?.length) lines.push(`- PDA seeds：${solana.pdaSeeds.map((item) => `\`${oneLine(item)}\``).join(', ')}`);
      if (solana.rawAccountInfos?.length) lines.push(`- Raw AccountInfo：${solana.rawAccountInfos.map((item) => `\`${oneLine(item.name)}@L${item.line}\``).join(', ')}`);
      lines.push('');
    }

    const anchor = file.metadata?.anchorConfig;
    if (anchor) {
      lines.push(`### Anchor 配置：\`${oneLine(file.path)}\``, '');
      lines.push(`- cluster：${oneLine(anchor.cluster || 'unknown')}`);
      lines.push(`- Solana：${oneLine(anchor.solanaVersion || 'unknown')} / Anchor：${oneLine(anchor.anchorVersion || 'unknown')}`, '');
    }
  }
  return lines.length ? ['## 决赛专项证据', '', ...lines].join('\n') : '';
}

function buildMarkdownReport(analysis, notes = '') {
  let report = base.buildMarkdownReport(analysis, notes);
  const section = buildFinalsEvidenceSection(analysis);
  if (!section) return report;
  const marker = '\n## Flag 候选\n';
  if (report.includes(marker)) return report.replace(marker, `\n${section}\n${marker}`);
  return `${report.trim()}\n\n${section}\n`;
}

module.exports = { ...base, scanWorkspace, buildMarkdownReport, TEXT_LIMIT };
