const fsp = require('fs/promises');
const path = require('path');
const base = require('./finals_analyzer_batch11');
const { analyzeWifiCapture } = require('./uav_wifi_pcap');
const { analyzeFlightLog } = require('./uav_flight_log');
const { buildInvestigationGraph } = require('./investigation_graph');

const CAPTURE_EXTENSIONS = new Set(['.pcap','.pcapng','.cap']);
const ULOG_EXTENSIONS = new Set(['.ulg']);
const MAX_CAPTURE = 192 * 1024 * 1024;
const MAX_ULOG = 128 * 1024 * 1024;

function wifiSummary(result) {
  return {
    format:result.format,
    packetCount:result.packetCount,
    linkTypes:result.linkTypes,
    supportedPackets:result.supportedPackets,
    truncated:result.truncated,
    networks:(result.networks||[]).slice(0,120),
    clients:(result.clients||[]).slice(0,300),
    handshakes:(result.handshakes||[]).slice(0,1000),
    pmkids:(result.pmkids||[]).slice(0,300),
    deauth:(result.deauth||[]).slice(0,1000),
    auth:(result.auth||[]).slice(0,1000),
    events:(result.events||[]).slice(0,1200),
    findings:result.findings||[],
    notes:result.notes||[]
  };
}

function ulogSummary(result) {
  return {
    format:result.format,
    size:result.size,
    version:result.version,
    startTimestamp:result.startTimestamp,
    messageCount:result.messageCount,
    messageCounts:result.messageCounts||{},
    formatCount:result.formatCount,
    subscriptionCount:result.subscriptionCount,
    topics:(result.topics||[]).slice(0,200),
    timeRange:result.timeRange||null,
    modes:(result.modes||[]).slice(0,500),
    params:(result.params||[]).slice(0,1000),
    gps:(result.gps||[]).slice(0,1200),
    attitude:(result.attitude||[]).slice(0,1200),
    events:(result.events||[]).slice(0,800),
    battery:(result.battery||[]).slice(0,500),
    estimator:(result.estimator||[]).slice(0,500),
    dropouts:(result.dropouts||[]).slice(0,500),
    parseErrors:(result.parseErrors||[]).slice(0,80),
    findings:result.findings||[],
    notes:result.notes||[]
  };
}

async function enrichBatch12(rootPath, file) {
  const full = path.join(rootPath, file.path);
  let changed = false;

  if (CAPTURE_EXTENSIONS.has(file.extension) && file.size > 0 && file.size <= MAX_CAPTURE) {
    const buffer = await fsp.readFile(full);
    const wifi = analyzeWifiCapture(buffer);
    if (wifi.supported || wifi.findings?.length) {
      file.metadata = { ...(file.metadata||{}), uavWifiCapture:wifiSummary(wifi) };
      file.findings ||= [];
      for (const finding of wifi.findings||[]) file.findings.push({ ...finding, id:`${finding.id}:${file.path}`, title:finding.id==='wifi-deauth-evidence'?'802.11 断链/重连证据':'802.11 认证材料', file:file.path, count:1 });
      changed = true;
    }
  }

  if (ULOG_EXTENSIONS.has(file.extension) && file.size > 0 && file.size <= MAX_ULOG) {
    const buffer = await fsp.readFile(full);
    const log = analyzeFlightLog(buffer);
    if (log.format === 'px4-ulog') {
      file.metadata = { ...(file.metadata||{}), uavFlightLog:ulogSummary(log) };
      file.findings ||= [];
      const existing = new Set(file.findings.map((x)=>String(x.id||'').split(':')[0]));
      for (const finding of log.findings||[]) if (!existing.has(finding.id)) file.findings.push({ ...finding, id:`${finding.id}:${file.path}`, title:'PX4 ULog 时间线证据', file:file.path, count:1 });
      changed = true;
    }
  }
  return changed;
}

function refresh(analysis) {
  const order={high:0,medium:1,low:2,info:3};
  analysis.findings=analysis.files.flatMap((f)=>f.findings||[]).sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)||String(a.file||'').localeCompare(String(b.file||''))||(a.line||0)-(b.line||0));
  analysis.stats.findings=analysis.findings.length;
  analysis.investigation=buildInvestigationGraph(analysis);
}

async function scanWorkspace(rootPath) {
  const analysis = await base.scanWorkspace(rootPath);
  let wifiFiles=0; let ulogFiles=0;
  for (const file of analysis.files) {
    try {
      const beforeWifi=Boolean(file.metadata?.uavWifiCapture);
      const beforeUlog=file.metadata?.uavFlightLog?.format==='px4-ulog' && Boolean(file.metadata?.uavFlightLog?.topics?.length);
      if (await enrichBatch12(rootPath,file)) {
        if (!beforeWifi && file.metadata?.uavWifiCapture) wifiFiles+=1;
        if (!beforeUlog && file.metadata?.uavFlightLog?.format==='px4-ulog') ulogFiles+=1;
      }
    } catch (error) { file.metadata={...(file.metadata||{}),uavBatch12Error:error.message}; }
  }
  if (wifiFiles) analysis.recommendations.push(`802.11：${wifiFiles} 个抓包已恢复 AP/客户端、EAPOL/PMKID 与 Deauth 证据；优先按 BSSID/STA 和时间分组判断握手完整性与断链→重连关系。`);
  if (ulogFiles) analysis.recommendations.push(`PX4 ULog：${ulogFiles} 个日志已按文件内 F/A/D 定义恢复 topic；优先对齐 vehicle_status、GPS、attitude、battery、estimator 与外部 MAVLink 控制时间线。`);
  refresh(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,12);
  return analysis;
}

function buildBatch12Section(analysis) {
  const lines=[];
  for (const file of analysis.files||[]) {
    const wifi=file.metadata?.uavWifiCapture;
    const log=file.metadata?.uavFlightLog;
    if (wifi) {
      lines.push(`### 802.11 Capture：\`${file.path}\``,'',`- format=${wifi.format}, packets=${wifi.packetCount}, supported=${wifi.supportedPackets}`);
      if (wifi.networks?.length) lines.push(`- AP：${wifi.networks.slice(0,12).map((x)=>`${x.ssid||'<hidden>'}@${x.bssid||'?'}${x.security?`[${x.security}]`:''}`).join(', ')}`);
      if (wifi.handshakes?.length) lines.push(`- EAPOL-Key：${wifi.handshakes.length}，messages=${[...new Set(wifi.handshakes.map((x)=>x.message).filter(Boolean))].join('/')||'unknown'}`);
      if (wifi.pmkids?.length) lines.push(`- PMKID：${wifi.pmkids.length}`);
      if (wifi.deauth?.length) lines.push(`- Deauth/Disassociation：${wifi.deauth.length}`);
      lines.push('');
    }
    if (log?.format==='px4-ulog' && log.topics) {
      lines.push(`### PX4 ULog：\`${file.path}\``,'',`- messages=${log.messageCount||0}, formats=${log.formatCount||0}, subscriptions=${log.subscriptionCount||0}`);
      if (log.timeRange) lines.push(`- duration=${log.timeRange.durationSec.toFixed(3)}s`);
      lines.push(`- topics：${log.topics.slice(0,20).map((x)=>`${x.name}(${x.samples})`).join(', ')||'none'}`);
      lines.push(`- GPS=${log.gps?.length||0}, attitude=${log.attitude?.length||0}, status transitions=${log.modes?.length||0}, dropouts=${log.dropouts?.length||0}`,'');
    }
  }
  return lines.length ? ['## 802.11 / PX4 ULog 深度证据','',...lines].join('\n') : '';
}

function buildMarkdownReport(analysis, notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildBatch12Section(analysis);
  return section ? `${report.trim()}\n\n${section}\n` : report;
}

module.exports={ ...base, scanWorkspace, buildMarkdownReport, enrichBatch12, buildBatch12Section };
