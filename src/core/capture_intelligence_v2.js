const base=require('./capture_intelligence');
const { parseClassicPcap,parsePcapngPackets }=require('./uav_wifi_pcap');
const { analyzeVideoCapture }=require('./uav_video_v2');
const { analyzeDatalinkCapture }=require('./uav_datalink');
const { analyzeTcpReassembly }=require('./tcp_reassembly');

function compactVideo(video) {
  return {
    sessions:(video.sessions||[]).map((x)=>({
      key:x.key,codec:x.codec||'H264',ssrc:x.ssrc,payloadType:x.payloadType,frames:x.frames,firstPacket:x.firstPacket,lastPacket:x.lastPacket,completeNal:x.completeNal,nalTypes:x.nalTypes,gaps:x.gaps,incompleteFragment:x.incompleteFragment,artifact:x.artifact
    })).slice(0,40),
    artifacts:(video.artifacts||[]).slice(0,20),
    findings:video.findings||[],
    notes:video.notes||[]
  };
}

function compactDatalink(result) {
  return {
    format:result.format,
    flows:(result.flows||[]).slice(0,120),
    vendorEvidence:(result.vendorEvidence||[]).slice(0,120),
    pairedFlows:(result.pairedFlows||[]).slice(0,80),
    findings:result.findings||[],
    nextActions:result.nextActions||[],
    notes:result.notes||[]
  };
}

function uniqueMerge(left,right,keyOf,limit=400) {
  const out=[]; const seen=new Set();
  for (const item of [...(left||[]),...(right||[])]) {
    const key=keyOf(item);
    if (!key||seen.has(key)) continue;
    seen.add(key); out.push(item);
    if (out.length>=limit) break;
  }
  return out;
}

function mergeTcpNetwork(network,tcp) {
  const baseNetwork=network||{};
  if (!tcp) return baseNetwork;
  return {
    ...baseNetwork,
    credentials:uniqueMerge(baseNetwork.credentials,tcp.credentials,(x)=>`${x.type||''}:${x.value||''}:${x.flow||''}`,160),
    httpRequests:uniqueMerge(baseNetwork.httpRequests,tcp.httpRequests,(x)=>`${x.method||''}:${x.host||''}:${x.path||''}:${x.flow||''}`,280),
    rtspEndpoints:[...new Set([...(baseNetwork.rtspEndpoints||[]),...(tcp.rtspEndpoints||[])])].slice(0,160),
    plaintextEvidence:uniqueMerge(baseNetwork.plaintextEvidence,tcp.plaintextEvidence,(x)=>`${x.flow||''}:${x.text||''}`,360),
    tcpReassembly:{
      stats:tcp.stats,
      streams:(tcp.streams||[]).slice(0,120),
      recoveredCredentials:(tcp.credentials||[]).length,
      recoveredHttpRequests:(tcp.httpRequests||[]).length,
      recoveredRtspEndpoints:(tcp.rtspEndpoints||[]).length,
      findings:tcp.findings||[]
    }
  };
}

function analyzeCaptureIntelligence(buffer) {
  const result=base.analyzeCaptureIntelligence(buffer);
  if (result.format==='unknown') return result;
  const container=parseClassicPcap(buffer)||parsePcapngPackets(buffer);
  if (!container) return result;
  let video=null;
  let datalink=null;
  let tcp=null;
  try { video=analyzeVideoCapture(container.packets||[]); }
  catch (error) { video={sessions:[],artifacts:[],findings:[],error:error.message}; }
  try { datalink=compactDatalink(analyzeDatalinkCapture(buffer)); }
  catch (error) { datalink={flows:[],vendorEvidence:[],pairedFlows:[],findings:[],nextActions:[],error:error.message}; }
  try { tcp=analyzeTcpReassembly(container.packets||[]); }
  catch (error) { tcp={streams:[],stats:{},credentials:[],httpRequests:[],rtspEndpoints:[],plaintextEvidence:[],findings:[],error:error.message}; }
  const compact=compactVideo(video);
  const network=mergeTcpNetwork(result.network,tcp);
  const findings=[...(result.findings||[]),...(compact.findings||[]),...(datalink.findings||[]),...(tcp.findings||[])];
  if ((tcp.credentials||[]).length) findings.push({
    severity:'high',
    id:'capture-tcp-reassembled-credentials',
    title:'TCP 重组后恢复明文认证材料',
    evidence:`credentials=${tcp.credentials.length}; 证据包含 directional flow 与 packet 范围`
  });
  const highlights=[...(result.highlights||[])];
  const nextActions=[...(result.nextActions||[]),...(datalink.nextActions||[])];
  if (tcp.stats?.streams) {
    highlights.push(`TCP：重组 ${tcp.stats.streams} 个单向流、${tcp.stats.contiguousRuns||0} 个连续区段，恢复 HTTP ${tcp.httpRequests?.length||0} 条 / RTSP ${tcp.rtspEndpoints?.length||0} 个 / 认证材料 ${tcp.credentials?.length||0} 条。`);
    if (tcp.stats.gaps) nextActions.push(`TCP 重组存在 ${tcp.stats.gaps} 个 sequence gap；跨 gap 的应用层内容不会强行拼接，优先核对抓包完整性。`);
    if (tcp.stats.overlapConflicts) nextActions.push(`TCP 存在 ${tcp.stats.overlapConflicts} 个重叠内容冲突；检查重传、抓包异常或 overlap/evasion 线索。`);
  }
  if (compact.sessions.length) {
    const frames=compact.sessions.reduce((sum,x)=>sum+(x.frames||0),0);
    const gaps=compact.sessions.reduce((sum,x)=>sum+(x.gaps?.length||0),0);
    const codecs=[...new Set(compact.sessions.map((x)=>x.codec))].join('/');
    highlights.push(`图传：恢复 ${compact.sessions.length} 个 RTP/${codecs} session、${frames} 个 RTP 包，生成 ${compact.artifacts.length} 个 Annex-B artifact。`);
    if (gaps) nextActions.push(`RTP/${codecs} 存在 ${gaps} 个 sequence gap；先区分抓包丢包与真实视频链路中断。`);
    else nextActions.push(`RTP/${codecs} 已重组为 Annex-B artifact，可直接交给 ffplay/ffmpeg 或视频取证继续检查。`);
  }
  if (datalink.vendorEvidence?.length) {
    const vendors=[...new Set(datalink.vendorEvidence.map((x)=>x.vendor))];
    highlights.push(`数据链：发现厂商/协议指纹 ${vendors.join(', ')}；已保留 packet/flow 证据。`);
  }
  if (datalink.pairedFlows?.length) highlights.push(`数据链：识别 ${datalink.pairedFlows.length} 组控制/遥测 ↔ 高带宽媒体流候选。`);
  return { ...result,network,video:compact,datalink,findings,highlights,nextActions:[...new Set(nextActions)] };
}

function scanEmbeddedCaptures(input,options={}) {
  const buffer=Buffer.isBuffer(input)?input:Buffer.from(input||[]);
  const segments=base.scanEmbeddedCaptures(buffer,options);
  for (const segment of segments) {
    try {
      const data=buffer.subarray(segment.offset,segment.endOffset);
      segment.analysis=analyzeCaptureIntelligence(data);
      segment.videoArtifacts=segment.analysis.video?.artifacts||[];
    } catch (error) {
      segment.videoError=error.message;
    }
  }
  return segments;
}

module.exports={ ...base,analyzeCaptureIntelligence,scanEmbeddedCaptures,mergeTcpNetwork };
