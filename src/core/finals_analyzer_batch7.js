const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer_batch6');
const { analyzeFirmwareBuffer } = require('./firmware_unpack');
const { analyzeUavChallengeEvidence } = require('./uav_challenge_matrix');

const FIRMWARE_EXTENSIONS = new Set(['.bin','.img','.fw','.rom','.trx','.chk','.ubi','.squashfs','.jffs2']);
const UAV_TEXT_EXTENSIONS = new Set(['.txt','.log','.hex','.mavlink','.nmea','.csv','.json','.md','.conf','.cfg']);
const MAX_FIRMWARE_SCAN = 96 * 1024 * 1024;
const MAX_UAV_TEXT = 1024 * 1024;

function stripArtifacts(result) {
  return {
    size: result.size,
    entropy: result.entropy,
    headerHex: result.headerHex,
    headerAscii: result.headerAscii,
    vendor: result.vendor ? {
      ...result.vendor,
      segments: (result.vendor.segments || []).map((x) => ({
        name: x.name, offset: x.offset, offsetHex: x.offsetHex, length: x.length,
        complete: x.complete, source: x.source, entropy: x.entropy, error: x.error
      }))
    } : null,
    magic: (result.magic || []).slice(0, 80),
    structures: (result.structures || []).map((x) => ({
      type: x.type || x.name, offset: x.offset, offsetHex: x.offsetHex, length: x.length,
      dataSize: x.dataSize, totalSize: x.totalSize, bytesUsed: x.bytesUsed,
      blockSize: x.blockSize, inodes: x.inodes, complete: x.complete,
      extractor: x.extractor, error: x.error
    })),
    artifactSummaries: (result.artifacts || []).map((a) => ({ name: a.name, size: a.size, sha256: a.sha256, metadata: a.metadata })),
    findings: result.findings,
    backends: result.backends,
    nextActions: result.nextActions
  };
}

async function enrichFirmware(rootPath, file) {
  if (!FIRMWARE_EXTENSIONS.has(file.extension) || file.size <= 0 || file.size > MAX_FIRMWARE_SCAN) return false;
  const buffer = await fsp.readFile(path.join(rootPath, file.path));
  const result = analyzeFirmwareBuffer(buffer, { tryDecompress: false });
  const summary = stripArtifacts(result);
  file.metadata = { ...(file.metadata || {}), firmware: summary };
  file.findings ||= [];
  for (const finding of summary.findings || []) {
    file.findings.push({ ...finding, file: file.path, count: 1, id: `${finding.id}:${file.path}` });
  }
  if (summary.magic.length || summary.vendor) {
    file.findings.push({
      id: `firmware-structure:${file.path}`,
      severity: 'info',
      title: '固件结构候选已识别',
      file: file.path,
      count: 1,
      evidence: [summary.vendor ? `${summary.vendor.vendor} ${summary.vendor.version}` : null, ...summary.magic.slice(0, 6).map((x) => `${x.name}@${x.offsetHex}`)].filter(Boolean).join(', ')
    });
  }
  return true;
}

async function enrichUavText(rootPath, file) {
  if (!UAV_TEXT_EXTENSIONS.has(file.extension) || file.size <= 0 || file.size > MAX_UAV_TEXT) return false;
  const buffer = await fsp.readFile(path.join(rootPath, file.path));
  if (buffer.includes(0)) return false;
  const text = buffer.toString('utf8');
  if (!/(mavlink|ardupilot|px4|gps|nmea|rtsp|ftp|gcs|param_|mission_|attitude|vfr_hud|deauth|ssid|bssid|nmap|prearm|battery|ulog|dataflash)/i.test(text) && !/^(?:fe|fd)[0-9a-f\s]+$/i.test(text.trim())) return false;
  const result = analyzeUavChallengeEvidence(text);
  if (!result.hits.length) return false;
  file.metadata = { ...(file.metadata || {}), uavChallenge: { coverage: result.coverage, hits: result.hits.slice(0, 12) } };
  file.findings ||= [];
  for (const hit of result.hits.filter((x) => x.confidence >= 0.6).slice(0, 8)) {
    file.findings.push({
      id: `uav-${hit.scenarioId}:${file.path}`,
      severity: hit.confidence >= 0.8 ? 'medium' : 'info',
      title: `低空题型候选：${hit.title}`,
      file: file.path,
      count: 1,
      evidence: (hit.evidence || []).join(', '),
      message: hit.action
    });
  }
  return true;
}

function refresh(analysis) {
  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  analysis.findings = analysis.files.flatMap((file) => file.findings || [])
    .sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9) || String(a.file).localeCompare(String(b.file)));
  analysis.stats.findings = analysis.findings.length;
  analysis.stats.flags = analysis.files.reduce((sum, file) => sum + (file.flags?.length || 0), 0);
}

async function scanWorkspace(rootPath) {
  const analysis = await base.scanWorkspace(rootPath);
  let firmwareCount = 0;
  let uavCount = 0;
  for (const file of analysis.files) {
    try { if (await enrichFirmware(rootPath, file)) firmwareCount += 1; }
    catch (error) { file.metadata = { ...(file.metadata || {}), firmwareError: error.message }; }
    try { if (await enrichUavText(rootPath, file)) uavCount += 1; }
    catch (error) { file.metadata = { ...(file.metadata || {}), uavChallengeError: error.message }; }
  }
  analysis.recommendations ||= [];
  if (firmwareCount) analysis.recommendations.push(`识别到 ${firmwareCount} 个固件候选：优先恢复 kernel/rootfs/bootloader，解包后检查启动脚本、Web/API、默认凭据、密钥和升级校验。`);
  if (uavCount) analysis.recommendations.push(`识别到 ${uavCount} 个低空证据文件：按侦查→欺骗/注入→状态变化→泄露/产物恢复建立时间线，不以单个 msgid 直接下漏洞结论。`);
  refresh(analysis);
  analysis.version = Math.max(Number(analysis.version) || 1, 8);
  return analysis;
}

function buildUavSection(analysis) {
  const lines = [];
  for (const file of analysis.files || []) {
    const fw = file.metadata?.firmware;
    const uav = file.metadata?.uavChallenge;
    if (fw) {
      lines.push(`### 固件：\`${file.path}\``, '');
      if (fw.vendor) lines.push(`- 厂商头：${fw.vendor.vendor} ${fw.vendor.version}`);
      if (fw.magic?.length) lines.push(`- 结构：${fw.magic.slice(0, 10).map((x) => `${x.name}@${x.offsetHex}`).join(', ')}`);
      for (const action of fw.nextActions || []) lines.push(`- 下一步：${action}`);
      lines.push('');
    }
    if (uav?.hits?.length) {
      lines.push(`### 低空题型：\`${file.path}\``, '');
      for (const hit of uav.hits.slice(0, 8)) lines.push(`- ${hit.title} (${Math.round(hit.confidence * 100)}%)：${hit.action}`);
      lines.push('');
    }
  }
  return lines.length ? ['## 低空经济攻击面', '', ...lines].join('\n') : '';
}

function buildMarkdownReport(analysis, notes = '') {
  const report = base.buildMarkdownReport(analysis, notes);
  const section = buildUavSection(analysis);
  if (!section) return report;
  const marker = '\n## Flag 候选\n';
  if (report.includes(marker)) return report.replace(marker, `\n${section}\n${marker}`);
  return `${report.trim()}\n\n${section}\n`;
}

module.exports = { ...base, scanWorkspace, buildMarkdownReport, enrichFirmware, enrichUavText, buildUavSection };
