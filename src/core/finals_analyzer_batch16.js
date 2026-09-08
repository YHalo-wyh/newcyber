const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer_batch15');
const { analyzeArtifactTree } = require('./recursive_artifact_analysis');
const { analyzeFirmwareBuffer } = require('./firmware_workbench');
const { buildInvestigationGraph } = require('./investigation_graph');
const { buildWorkspaceAutopilot } = require('./workspace_autopilot');

const MAX_SEED_BYTES = 8 * 1024 * 1024;
const MAX_SEEDS_PER_FILE = 16;
const MAX_FIRMWARE_REANALYZE = 64 * 1024 * 1024;

function pushSeed(out, seen, artifact) {
  if (!artifact || artifact.completeness !== 'complete' || !artifact.sha256 || seen.has(artifact.sha256)) return;
  if (!Number.isFinite(artifact.size) || artifact.size <= 0 || artifact.size > MAX_SEED_BYTES) return;
  seen.add(artifact.sha256);
  out.push(artifact);
}

function collectMetadataSeeds(file) {
  const out = [];
  const seen = new Set();
  const m = file.metadata || {};
  for (const artifact of file.artifacts || []) pushSeed(out, seen, artifact);

  const programming = m.pcapng?.can?.udsProgramming || m.captureIntelligence?.can?.udsProgramming;
  for (const transfer of programming?.transfers || []) pushSeed(out, seen, transfer?.artifact);

  const ftp = m.lowAltitude?.ftpReassembly || m.mavlink?.ftpReassembly;
  for (const item of ftp?.files || []) pushSeed(out, seen, item?.artifact);

  for (const item of m.autoDecode?.candidates || []) pushSeed(out, seen, item?.artifact);
  for (const item of m.contextCrypto?.bestCandidates || []) pushSeed(out, seen, item?.artifact);
  for (const artifact of m.captureIntelligence?.video?.artifacts || []) pushSeed(out, seen, artifact);
  for (const session of m.captureIntelligence?.video?.sessions || []) pushSeed(out, seen, session?.artifact);
  return out.slice(0, MAX_SEEDS_PER_FILE);
}

async function recoverFirmwareSeeds(rootPath, file, existing) {
  const summaries = file.metadata?.firmware?.artifactSummaries || [];
  if (!summaries.length || file.size <= 0 || file.size > MAX_FIRMWARE_REANALYZE) return [];
  const wanted = new Set(summaries.filter((x) => x.size > 0 && x.size <= MAX_SEED_BYTES).map((x) => x.sha256));
  if (!wanted.size) return [];
  const buffer = await fsp.readFile(path.join(rootPath, file.path));
  const result = analyzeFirmwareBuffer(buffer, { tryDecompress: false });
  const seen = new Set(existing.map((x) => x.sha256));
  const out = [];
  for (const artifact of result.artifacts || []) {
    if (out.length >= MAX_SEEDS_PER_FILE) break;
    if (!wanted.has(artifact.sha256)) continue;
    if (artifact.completeness !== 'complete' || artifact.size > MAX_SEED_BYTES || seen.has(artifact.sha256)) continue;
    seen.add(artifact.sha256);
    out.push(artifact);
  }
  return out;
}

function compactArtifact(artifact) {
  if (!artifact) return null;
  return { name:artifact.name, size:artifact.size, sha256:artifact.sha256, mediaType:artifact.mediaType, completeness:artifact.completeness, metadata:artifact.metadata };
}

function compactRecursive(tree) {
  return {
    schema: tree.schema,
    maxDepth: tree.maxDepth,
    stats: tree.stats,
    flags: tree.flags,
    findings: tree.findings,
    artifacts: tree.artifacts,
    nodes: (tree.nodes || []).map((node) => ({
      ...node,
      decode: node.decode ? {
        attempted: node.decode.attempted,
        candidates: (node.decode.candidates || []).map((item) => ({
          ...item,
          artifact: undefined,
          artifactSummary: compactArtifact(item.artifact)
        }))
      } : null,
      capture: node.capture ? {
        ...node.capture,
        video: node.capture.video ? {
          sessions: (node.capture.video.sessions || []).map((session) => ({ ...session, artifact: undefined, artifactSummary:compactArtifact(session.artifact) })),
          artifacts: (node.capture.video.artifacts || []).map(compactArtifact).filter(Boolean)
        } : null
      } : null,
      decompressed: (node.decompressed || []).map((item) => ({ transform:item.transform, artifact:compactArtifact(item.artifact) }))
    }))
  };
}

async function enrichRecursiveArtifacts(rootPath, file) {
  const seeds = collectMetadataSeeds(file);
  try { seeds.push(...await recoverFirmwareSeeds(rootPath, file, seeds)); }
  catch (error) { file.metadata = { ...(file.metadata || {}), recursiveFirmwareSeedError:error.message }; }
  if (!seeds.length) return false;

  const tree = analyzeArtifactTree(seeds, { maxDepth: 2, maxNodes: 24 });
  if (!tree.nodes.length) return false;
  const compact = compactRecursive(tree);
  file.metadata = { ...(file.metadata || {}), recursiveArtifacts: compact };
  file.flags ||= [];
  file.findings ||= [];
  for (const flag of compact.flags || []) if (!file.flags.includes(flag)) file.flags.push(flag);
  const existing = new Set(file.findings.map((x) => String(x.id || '')));
  for (const finding of compact.findings || []) {
    const id = `recursive-artifact:${file.path}:${finding.id}`;
    if (existing.has(id)) continue;
    file.findings.push({ ...finding, id, file:file.path, count:1 });
    existing.add(id);
  }
  if ((compact.artifacts || []).length > seeds.length) {
    const id = `recursive-artifact-derived:${file.path}`;
    if (!existing.has(id)) file.findings.push({
      id,
      severity: 'info',
      title: '恢复产物已继续递归解析',
      file: file.path,
      count: compact.artifacts.length - seeds.length,
      evidence: `seed=${seeds.length}, artifacts=${compact.artifacts.length}, nodes=${compact.stats?.analyzedNodes || 0}`
    });
  }
  return true;
}

function refresh(analysis) {
  const order = { high:0, medium:1, low:2, info:3 };
  analysis.findings = analysis.files.flatMap((file) => file.findings || []).sort((a,b) =>
    (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || String(a.file || '').localeCompare(String(b.file || '')) || (a.line || 0) - (b.line || 0));
  analysis.stats.findings = analysis.findings.length;
  analysis.stats.flags = analysis.files.reduce((sum, file) => sum + (file.flags?.length || 0), 0);
  analysis.investigation = buildInvestigationGraph(analysis);
  analysis.autopilot = buildWorkspaceAutopilot(analysis);
}

async function scanWorkspace(rootPath) {
  const analysis = await base.scanWorkspace(rootPath);
  const counts = { files:0, nodes:0, artifacts:0, flags:0, decodedCandidates:0, captures:0, firmwareSeedFiles:0 };
  for (const file of analysis.files || []) {
    try {
      if (!await enrichRecursiveArtifacts(rootPath, file)) continue;
      counts.files += 1;
      const r = file.metadata?.recursiveArtifacts;
      counts.nodes += r?.stats?.analyzedNodes || 0;
      counts.artifacts += r?.artifacts?.length || 0;
      counts.flags += r?.flags?.length || 0;
      counts.decodedCandidates += (r?.nodes || []).reduce((sum, node) => sum + (node.decode?.candidates?.length || 0), 0);
      counts.captures += (r?.nodes || []).filter((node) => node.capture).length;
      if (file.metadata?.firmware?.artifactSummaries?.length) counts.firmwareSeedFiles += 1;
    } catch (error) {
      file.metadata = { ...(file.metadata || {}), recursiveArtifactError:error.message };
    }
  }
  analysis.recommendations ||= [];
  if (counts.files) analysis.recommendations.push(`递归产物分析：${counts.files} 个源文件的恢复产物继续自动检查，共遍历 ${counts.nodes} 个节点、保留 ${counts.artifacts} 个完整 artifact；疑似编码继续试解，不再要求“导出后再拖回来”。`);
  if (counts.captures) analysis.recommendations.push(`递归抓包：从解码/恢复产物中自动识别并解析 ${counts.captures} 个 PCAP/PCAPNG 节点，继续提取协议、凭据、MAVLink/CAN/图传证据。`);
  if (counts.flags) analysis.recommendations.unshift(`递归恢复链新增 ${counts.flags} 个 Flag 候选；优先核对 transform lineage 与原始文件偏移。`);
  refresh(analysis);
  analysis.version = Math.max(Number(analysis.version) || 1, 16);
  analysis.batch16Counts = counts;
  return analysis;
}

function buildBatch16Section(analysis) {
  const lines = [];
  for (const file of analysis.files || []) {
    const r = file.metadata?.recursiveArtifacts;
    if (!r) continue;
    const decoded = (r.nodes || []).reduce((sum, node) => sum + (node.decode?.candidates?.length || 0), 0);
    const captures = (r.nodes || []).filter((node) => node.capture).length;
    lines.push(`### 递归产物：\`${file.path}\``, '', `- nodes=${r.stats?.analyzedNodes || 0}, artifacts=${r.artifacts?.length || 0}, decoded=${decoded}, captures=${captures}, flags=${r.flags?.length || 0}`);
    for (const flag of (r.flags || []).slice(0, 6)) lines.push(`- Flag: ${flag}`);
    lines.push('');
  }
  return lines.length ? ['## Batch 16 · Recursive Artifact / Encoding Intelligence', '', ...lines].join('\n') : '';
}

function buildMarkdownReport(analysis, notes = '') {
  const report = base.buildMarkdownReport(analysis, notes);
  const section = buildBatch16Section(analysis);
  return section ? `${report.trim()}\n\n${section}\n` : report;
}

module.exports = { ...base, scanWorkspace, buildMarkdownReport, enrichRecursiveArtifacts, collectMetadataSeeds, compactRecursive, buildBatch16Section };
