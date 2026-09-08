const base=require('./capture_intelligence');
const { parseClassicPcap,parsePcapngPackets }=require('./uav_wifi_pcap');
const { analyzeVideoCapture }=require('./uav_video_v2');

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

function analyzeCaptureIntelligence(buffer) {
  const result=base.analyzeCaptureIntelligence(buffer);
  if (result.format==='unknown') return result;
  const container=parseClassicPcap(buffer)||parsePcapngPackets(buffer);
  if (!container) return result;
  let video=null;
  try { video=analyzeVideoCapture(container.packets||[]); }
  catch (error) { video={sessions:[],artifacts:[],findings:[],error:error.message}; }
  const compact=compactVideo(video);
  const findings=[...(result.findings||[]),...(compact.findings||[])];
  const highlights=[...(result.highlights||[])];
  const nextActions=[...(result.nextActions||[])];
  if (compact.sessions.length) {
    const frames=compact.sessions.reduce((sum,x)=>sum+(x.frames||0),0);
    const gaps=compact.sessions.reduce((sum,x)=>sum+(x.gaps?.length||0),0);
    const codecs=[...new Set(compact.sessions.map((x)=>x.codec))].join('/');
    highlights.push(`图传：恢复 ${compact.sessions.length} 个 RTP/${codecs} session、${frames} 个 RTP 包，生成 ${compact.artifacts.length} 个 Annex-B artifact。`);
    if (gaps) nextActions.push(`RTP/${codecs} 存在 ${gaps} 个 sequence gap；先区分抓包丢包与真实视频链路中断。`);
    else nextActions.push(`RTP/${codecs} 已重组为 Annex-B artifact，可直接交给 ffplay/ffmpeg 或视频取证继续检查。`);
  }
  return { ...result,video:compact,findings,highlights,nextActions };
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

module.exports={ ...base,analyzeCaptureIntelligence,scanEmbeddedCaptures };
