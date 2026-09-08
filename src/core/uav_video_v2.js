const base=require('./uav_video');
const { createBinaryArtifact,MAX_ARTIFACT_BYTES }=require('./artifacts');

const LINKTYPE_ETHERNET=1;
const MAX_VIDEO_BYTES=Math.min(MAX_ARTIFACT_BYTES,64*1024*1024);

function h265Info(payload) {
  if (!payload||payload.length<2) return null;
  if (payload[0]&0x80) return null;
  const nalType=(payload[0]>>1)&0x3f;
  const temporalIdPlus1=payload[1]&0x07;
  if (!temporalIdPlus1) return null;
  if (nalType===48) return {type:'ap',nalType,strong:true};
  if (nalType===49&&payload.length>=3) return {type:'fu',nalType,fuType:payload[2]&0x3f,start:Boolean(payload[2]&0x80),end:Boolean(payload[2]&0x40),strong:true};
  if (nalType===50) return {type:'paci',nalType,strong:false};
  return {type:'single',nalType,strong:nalType>=32&&nalType<=40};
}

function annexb(nal) { return Buffer.concat([Buffer.from([0,0,0,1]),nal]); }

function collectRtp(packets) {
  const sessions=new Map();
  for (const packet of packets||[]) {
    if (packet.linkType!==LINKTYPE_ETHERNET) continue;
    const udp=base.parseUdp(packet.data); if (!udp) continue;
    const rtp=base.parseRtp(udp.payload); if (!rtp) continue;
    const info=h265Info(rtp.payload); if (!info) continue;
    const key=`${rtp.ssrc}:${rtp.payloadType}:${udp.srcPort}->${udp.dstPort}`;
    const list=sessions.get(key)||[];
    if (list.length<250000) list.push({...rtp,packetIndex:packet.index,srcPort:udp.srcPort,dstPort:udp.dstPort,h265:info});
    sessions.set(key,list);
  }
  return sessions;
}

function sortFrames(frames) {
  if (!frames.length) return frames;
  const first=frames[0].sequence;
  return [...frames].sort((a,b)=>{
    const da=(a.sequence-first+65536)%65536;
    const db=(b.sequence-first+65536)%65536;
    return da-db||a.timestamp-b.timestamp;
  });
}

function depacketizeH265(frames) {
  const chunks=[]; const gaps=[]; const nalTypes={};
  let bytes=0; let completeNal=0; let previousSeq=null; let fu=null; let strongEvidence=0;
  for (const frame of sortFrames(frames)) {
    if (previousSeq!=null) {
      const expected=(previousSeq+1)&0xffff;
      if (frame.sequence!==expected) gaps.push({expected,actual:frame.sequence,packetIndex:frame.packetIndex});
    }
    previousSeq=frame.sequence;
    const info=frame.h265||h265Info(frame.payload); if (!info) continue;
    nalTypes[info.nalType]=(nalTypes[info.nalType]||0)+1;
    if (info.strong) strongEvidence+=1;

    if (info.type==='single') {
      const out=annexb(frame.payload);
      if (bytes+out.length>MAX_VIDEO_BYTES) break;
      chunks.push(out); bytes+=out.length; completeNal+=1; fu=null;
      continue;
    }

    if (info.type==='ap') {
      let p=2;
      while (p+2<=frame.payload.length) {
        const len=frame.payload.readUInt16BE(p); p+=2;
        if (!len||p+len>frame.payload.length) break;
        const nal=frame.payload.subarray(p,p+len); p+=len;
        if (!h265Info(nal)) continue;
        const out=annexb(nal);
        if (bytes+out.length>MAX_VIDEO_BYTES) break;
        chunks.push(out); bytes+=out.length; completeNal+=1;
      }
      fu=null;
      continue;
    }

    if (info.type==='fu') {
      if (info.start) {
        const first=(frame.payload[0]&0x81)|((info.fuType&0x3f)<<1);
        const second=frame.payload[1];
        fu={timestamp:frame.timestamp,startSeq:frame.sequence,parts:[Buffer.from([first,second]),frame.payload.subarray(3)]};
      } else if (fu&&fu.timestamp===frame.timestamp) fu.parts.push(frame.payload.subarray(3));
      else { fu=null; continue; }
      if (info.end&&fu) {
        const out=annexb(Buffer.concat(fu.parts));
        if (bytes+out.length<=MAX_VIDEO_BYTES) { chunks.push(out); bytes+=out.length; completeNal+=1; }
        fu=null;
      }
    }
  }
  return {buffer:chunks.length?Buffer.concat(chunks):Buffer.alloc(0),bytes,completeNal,nalTypes,gaps,incompleteFragment:Boolean(fu),strongEvidence};
}

function analyzeH265(packets) {
  const sessions=[]; const artifacts=[];
  for (const [key,rawFrames] of collectRtp(packets)) {
    if (rawFrames.length<2) continue;
    const frames=sortFrames(rawFrames);
    const dep=depacketizeH265(frames);
    if (!dep.strongEvidence||!dep.completeNal||!dep.buffer.length) continue;
    const first=frames[0];
    const completeness=dep.gaps.length||dep.incompleteFragment?'partial':'complete';
    const artifact=createBinaryArtifact({
      name:`rtp-${first.ssrc.toString(16)}-pt${first.payloadType}.h265`,mediaType:'video/H265',buffer:dep.buffer,completeness,
      gaps:dep.gaps.slice(0,500),provenance:[{source:'pcap-rtp',parser:'uav-video-h265',ssrc:first.ssrc,payloadType:first.payloadType,frames:frames.length}],metadata:{kind:'rtp-h265-annexb',ssrc:first.ssrc,payloadType:first.payloadType,nalTypes:dep.nalTypes}
    });
    artifacts.push(artifact);
    sessions.push({key,codec:'H265',ssrc:`0x${first.ssrc.toString(16)}`,payloadType:first.payloadType,frames:frames.length,firstPacket:frames[0].packetIndex,lastPacket:frames[frames.length-1].packetIndex,completeNal:dep.completeNal,nalTypes:dep.nalTypes,gaps:dep.gaps.slice(0,120),incompleteFragment:dep.incompleteFragment,strongEvidence:dep.strongEvidence,artifact});
  }
  return {sessions,artifacts};
}

function analyzeVideoCapture(packets) {
  const h264=base.analyzeVideoCapture(packets);
  const h265=analyzeH265(packets);
  const h265Keys=new Set(h265.sessions.map((x)=>x.key));
  const h264Sessions=(h264.sessions||[]).filter((x)=>!h265Keys.has(x.key)).map((x)=>({...x,codec:'H264'}));
  const h264Artifacts=h264Sessions.map((x)=>x.artifact).filter(Boolean);
  const sessions=[...h264Sessions,...h265.sessions];
  const artifacts=[...h264Artifacts,...h265.artifacts];
  const findings=[];
  if (h264Sessions.length) findings.push({id:'rtp-h264-session',severity:'info',title:'恢复 RTP/H264 图传会话',evidence:`sessions=${h264Sessions.length}`});
  if (h265.sessions.length) findings.push({id:'rtp-h265-session',severity:'info',title:'恢复 RTP/H265 图传会话',evidence:`sessions=${h265.sessions.length}`});
  const lossy=sessions.filter((x)=>x.gaps?.length);
  if (lossy.length) findings.push({id:'rtp-sequence-gaps',severity:'medium',title:'RTP 图传存在序列缺口',evidence:lossy.slice(0,10).map((x)=>`${x.codec}/${x.ssrc}: gaps=${x.gaps.length}`),meaning:'可能是抓包丢包、无线链路丢包或视频中断；需结合时间窗和 RTSP 控制面判断。'});
  return {sessions,artifacts,findings,notes:['H264 支持 single NAL/STAP-A/FU-A；H265 支持 single NAL/AP/FU。','H265 仅在 VPS/SPS/PPS/AP/FU 等强结构证据出现后成立，避免把动态 RTP payload 猜成 H265。','存在 sequence gap 或未闭合 FU 时 artifact 标为 partial，不冒充完整视频。']};
}

module.exports={...base,h265Info,depacketizeH265,analyzeH265,analyzeVideoCapture};
