const fsp=require('fs/promises');
const path=require('path');
const base=require('./finals_analyzer_batch7');
const { parseWifiEvidence }=require('./uav_wifi');
const { analyzeFlightLog }=require('./uav_flight_log');

const TEXT_EXTENSIONS=new Set(['.txt','.log','.csv','.md','.conf','.cfg']);
const ULOG_EXTENSIONS=new Set(['.ulg']);
const MAX_TEXT=2*1024*1024;
const MAX_LOG=64*1024*1024;

function flightSummary(result) {
  return {
    format:result.format,
    size:result.size,
    lineCount:result.lineCount,
    messageCounts:result.messageCounts||{},
    timeRange:result.timeRange||null,
    modes:(result.modes||[]).slice(0,100),
    params:(result.params||[]).slice(0,300),
    gps:(result.gps||[]).slice(0,500),
    attitude:(result.attitude||[]).slice(0,500),
    events:(result.events||[]).slice(0,300),
    findings:result.findings||[],
    notes:result.notes||[]
  };
}

async function enrichBatch8(rootPath,file) {
  let changed=false;
  const full=path.join(rootPath,file.path);

  if (ULOG_EXTENSIONS.has(file.extension) && file.size>0 && file.size<=MAX_LOG) {
    const buffer=await fsp.readFile(full);
    const log=analyzeFlightLog(buffer);
    if (log.format!=='unknown') {
      file.metadata={...(file.metadata||{}),uavFlightLog:flightSummary(log)};
      file.findings||=[];
      for (const finding of log.findings||[]) file.findings.push({ ...finding, id:`${finding.id}:${file.path}`, title:'飞行日志容器/轨迹证据', file:file.path, count:1 });
      changed=true;
    }
  }

  if (TEXT_EXTENSIONS.has(file.extension) && file.size>0 && file.size<=MAX_TEXT) {
    const buffer=await fsp.readFile(full);
    if (!buffer.includes(0)) {
      const text=buffer.toString('utf8');
      const wifi=parseWifiEvidence(text);
      if (wifi.networks.length||wifi.handshakes.length||wifi.deauth.length||wifi.crackResults.length) {
        file.metadata={...(file.metadata||{}),uavWifi:wifi};
        file.findings||=[];
        for (const finding of wifi.findings||[]) file.findings.push({ ...finding, id:`${finding.id}:${file.path}`, title:'Wi-Fi 攻击面证据', file:file.path, count:1 });
        changed=true;
      }
      const log=analyzeFlightLog(text);
      if (log.format!=='unknown') {
        file.metadata={...(file.metadata||{}),uavFlightLog:flightSummary(log)};
        file.findings||=[];
        for (const finding of log.findings||[]) file.findings.push({ ...finding, id:`${finding.id}:${file.path}`, title:'飞行日志提取证据', file:file.path, count:1 });
        changed=true;
      }
    }
  }
  return changed;
}

function refresh(analysis) {
  const order={high:0,medium:1,low:2,info:3};
  analysis.findings=analysis.files.flatMap((f)=>f.findings||[]).sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)||String(a.file||'').localeCompare(String(b.file||'')));
  analysis.stats.findings=analysis.findings.length;
}

async function scanWorkspace(rootPath) {
  const analysis=await base.scanWorkspace(rootPath);
  let enriched=0;
  for (const file of analysis.files) {
    try { if (await enrichBatch8(rootPath,file)) enriched++; }
    catch (error) { file.metadata={...(file.metadata||{}),uavBatch8Error:error.message}; }
  }
  if (enriched) analysis.recommendations.push(`Batch 8 进一步解析 ${enriched} 个无线/飞行日志证据文件：优先把 Wi-Fi 身份、GCS 控制源、围栏参数和飞行状态按时间线关联。`);
  refresh(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,9);
  return analysis;
}

function buildBatch8Section(analysis) {
  const lines=[];
  for (const file of analysis.files||[]) {
    const wifi=file.metadata?.uavWifi;
    const log=file.metadata?.uavFlightLog;
    if (wifi) {
      lines.push(`### Wi-Fi：\`${file.path}\``,'');
      if (wifi.networks?.length) lines.push(`- 网络：${wifi.networks.slice(0,10).map((x)=>`${x.ssid||'?'}@${x.bssid||'?'}`).join(', ')}`);
      if (wifi.handshakes?.length) lines.push(`- 离线认证材料：${wifi.handshakes.map((x)=>x.id).join(', ')}`);
      if (wifi.deauth?.length) lines.push(`- Deauth/Disassociation：${wifi.deauth.length} 条`);
      if (wifi.crackResults?.length) lines.push(`- 口令/PSK 候选：${wifi.crackResults.length} 条（仍需验证）`);
      lines.push('');
    }
    if (log) {
      lines.push(`### 飞行日志：\`${file.path}\``,'',`- 格式：${log.format}`);
      if (log.timeRange) lines.push(`- 时长：${log.timeRange.durationSec.toFixed(3)}s`);
      lines.push(`- GPS=${log.gps?.length||0}，姿态=${log.attitude?.length||0}，参数=${log.params?.length||0}，事件=${log.events?.length||0}`,'');
    }
  }
  return lines.length ? ['## Wi-Fi 与飞行日志证据','',...lines].join('\n') : '';
}

function buildMarkdownReport(analysis,notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildBatch8Section(analysis);
  return section ? `${report.trim()}\n\n${section}\n` : report;
}

module.exports={ ...base, scanWorkspace, buildMarkdownReport, enrichBatch8, buildBatch8Section };
