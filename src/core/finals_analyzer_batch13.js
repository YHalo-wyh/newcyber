const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer_batch12');
const { analyzeCaptureIntelligence } = require('./capture_intelligence_v2');
const { buildInvestigationGraph } = require('./investigation_graph');

const CAPTURE_EXTENSIONS = new Set(['.pcap','.pcapng','.cap']);
const MAX_CAPTURE = 192 * 1024 * 1024;

function compactCapture(result) {
  return {
    format:result.format,
    packetCount:result.packetCount,
    linkTypes:result.linkTypes,
    truncated:result.truncated,
    highlights:(result.highlights||[]).slice(0,30),
    findings:(result.findings||[]).slice(0,120),
    nextActions:(result.nextActions||[]).slice(0,30),
    wifi:result.wifi ? {
      networks:(result.wifi.networks||[]).slice(0,120),
      handshakes:(result.wifi.handshakes||[]).slice(0,800),
      pmkids:(result.wifi.pmkids||[]).slice(0,300),
      deauth:(result.wifi.deauth||[]).slice(0,800)
    } : null,
    network:result.network ? {
      ethernetPackets:result.network.ethernetPackets,
      protocolCounts:result.network.protocolCounts,
      topFlows:(result.network.topFlows||[]).slice(0,80),
      dnsQueries:(result.network.dnsQueries||[]).slice(0,300),
      httpRequests:(result.network.httpRequests||[]).slice(0,200),
      rtspEndpoints:(result.network.rtspEndpoints||[]).slice(0,100),
      credentials:(result.network.credentials||[]).slice(0,100),
      plaintextEvidence:(result.network.plaintextEvidence||[]).slice(0,240),
      mavlink:result.network.mavlink || null
    } : null,
    can:result.can ? {
      parsedFrames:result.can.parsedFrames,
      uniqueIds:result.can.uniqueIds,
      eventCandidates:(result.can.eventCandidates||[]).slice(0,160),
      isoTpSessions:(result.can.isoTpSessions||[]).slice(0,120),
      udsProgramming:result.can.udsProgramming || null
    } : null,
    video:result.video ? {
      sessions:(result.video.sessions||[]).slice(0,40),
      artifacts:(result.video.artifacts||[]).slice(0,20),
      findings:(result.video.findings||[]).slice(0,80),
      notes:(result.video.notes||[]).slice(0,20)
    } : null
  };
}

async function enrichCapture(rootPath, file) {
  if (!CAPTURE_EXTENSIONS.has(file.extension) || file.size <= 0 || file.size > MAX_CAPTURE) return false;
  const buffer = await fsp.readFile(path.join(rootPath, file.path));
  const result = analyzeCaptureIntelligence(buffer);
  if (result.format === 'unknown') return false;
  file.metadata = { ...(file.metadata||{}), captureIntelligence:compactCapture(result) };
  file.findings ||= [];
  const existing = new Set(file.findings.map((finding)=>String(finding.id || '')));
  for (const finding of result.findings || []) {
    const id = `capture-intel:${finding.id}:${file.path}`;
    if (existing.has(id)) continue;
    file.findings.push({ ...finding, id, file:file.path, count:1 });
  }
  if (result.video?.artifacts?.length) {
    file.artifacts ||= [];
    const seen=new Set(file.artifacts.map((a)=>a.sha256));
    for (const artifact of result.video.artifacts) if (artifact?.sha256&&!seen.has(artifact.sha256)) { file.artifacts.push(artifact); seen.add(artifact.sha256); }
  }
  return true;
}

function refresh(analysis) {
  const order={high:0,medium:1,low:2,info:3};
  analysis.findings=analysis.files.flatMap((file)=>file.findings||[]).sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)||String(a.file||'').localeCompare(String(b.file||''))||(a.line||0)-(b.line||0));
  analysis.stats.findings=analysis.findings.length;
  analysis.investigation=buildInvestigationGraph(analysis);
}

async function scanWorkspace(rootPath) {
  const analysis = await base.scanWorkspace(rootPath);
  let captures = 0;
  let credentials = 0;
  let rtsp = 0;
  let mavlink = 0;
  let can = 0;
  let videoSessions=0;
  for (const file of analysis.files) {
    try {
      if (!(await enrichCapture(rootPath, file))) continue;
      captures += 1;
      const intel = file.metadata.captureIntelligence;
      credentials += intel.network?.credentials?.length || 0;
      rtsp += intel.network?.rtspEndpoints?.length || 0;
      mavlink += intel.network?.mavlink?.parsedFrames || 0;
      can += intel.can?.parsedFrames || 0;
      videoSessions += intel.video?.sessions?.length || 0;
    } catch (error) {
      file.metadata={...(file.metadata||{}),captureIntelligenceError:error.message};
    }
  }
  if (captures) analysis.recommendations.push(`抓包自动解析：${captures} 个 PCAP/PCAPNG 已进入协议链；明文认证材料 ${credentials}、RTSP endpoint ${rtsp}、MAVLink ${mavlink} 帧、CAN ${can} 帧、RTP/H264 session ${videoSessions}。`);
  refresh(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,13);
  return analysis;
}

function buildCaptureSection(analysis) {
  const lines=[];
  for (const file of analysis.files||[]) {
    const intel=file.metadata?.captureIntelligence;
    if (!intel) continue;
    lines.push(`### Capture：\`${file.path}\``,'',`- format=${intel.format}, packets=${intel.packetCount}, linkTypes=${(intel.linkTypes||[]).join(',')||'unknown'}`);
    for (const item of intel.highlights||[]) lines.push(`- ${item}`);
    if (intel.network?.credentials?.length) {
      lines.push('- 明文认证材料：');
      for (const item of intel.network.credentials.slice(0,20)) lines.push(`  - packet=${item.packetIndex}, type=${item.type}, value=\`${String(item.value||'').replace(/`/g,"'")}\`, flow=${item.flow}`);
    }
    if (intel.network?.rtspEndpoints?.length) lines.push(`- RTSP：${intel.network.rtspEndpoints.slice(0,20).join(', ')}`);
    if (intel.video?.sessions?.length) lines.push(`- RTP/H264：sessions=${intel.video.sessions.length}, artifacts=${intel.video.artifacts?.length||0}, frames=${intel.video.sessions.reduce((sum,x)=>sum+(x.frames||0),0)}`);
    lines.push('');
  }
  return lines.length ? ['## Capture Intelligence','',...lines].join('\n') : '';
}

function buildMarkdownReport(analysis, notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildCaptureSection(analysis);
  return section ? `${report.trim()}\n\n${section}\n` : report;
}

module.exports={ ...base, scanWorkspace, buildMarkdownReport, enrichCapture, buildCaptureSection };
