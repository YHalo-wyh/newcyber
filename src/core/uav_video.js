const { createBinaryArtifact, MAX_ARTIFACT_BYTES }=require('./artifacts');

const LINKTYPE_ETHERNET=1;
const MAX_VIDEO_BYTES=Math.min(MAX_ARTIFACT_BYTES,64*1024*1024);

function parseUdp(packet) {
  if (!packet||packet.length<42) return null;
  let l2=14; let etherType=packet.readUInt16BE(12);
  if (etherType===0x8100&&packet.length>=46) { etherType=packet.readUInt16BE(16); l2=18; }
  if (etherType!==0x0800||packet.length<l2+20) return null;
  const ihl=(packet[l2]&0x0f)*4;
  if ((packet[l2]>>4)!==4||ihl<20||packet[l2+9]!==17||packet.length<l2+ihl+8) return null;
  const ipTotal=packet.readUInt16BE(l2+2);
  const udp=l2+ihl;
  const srcPort=packet.readUInt16BE(udp),dstPort=packet.readUInt16BE(udp+2),len=packet.readUInt16BE(udp+4);
  const end=Math.min(packet.length,l2+Math.max(ipTotal,ihl+8),udp+Math.max(len,8));
  return { srcPort,dstPort,payload:packet.subarray(udp+8,end) };
}

function parseRtp(payload) {
  if (!payload||payload.length<12||(payload[0]>>6)!==2) return null;
  const cc=payload[0]&0x0f;
  const extension=Boolean(payload[0]&0x10);
  const padding=Boolean(payload[0]&0x20);
  let offset=12+cc*4;
  if (offset>payload.length) return null;
  if (extension) {
    if (offset+4>payload.length) return null;
    const words=payload.readUInt16BE(offset+2);
    offset+=4+words*4;
    if (offset>payload.length) return null;
  }
  let end=payload.length;
  if (padding) {
    const pad=payload[payload.length-1];
    if (!pad||pad>end-offset) return null;
    end-=pad;
  }
  if (end<=offset) return null;
  return {
    marker:Boolean(payload[1]&0x80),payloadType:payload[1]&0x7f,sequence:payload.readUInt16BE(2),timestamp:payload.readUInt32BE(4),ssrc:payload.readUInt32BE(8),payload:payload.subarray(offset,end)
  };
}

function annexb(nal) { return Buffer.concat([Buffer.from([0,0,0,1]),nal]); }

function classifyH264(payload) {
  if (!payload?.length) return null;
  const type=payload[0]&0x1f;
  if (type>=1&&type<=23) return { type:'single',nalType:type };
  if (type===24) return { type:'stap-a',nalType:type };
  if (type===28&&payload.length>=2) return { type:'fu-a',nalType:payload[1]&0x1f,start:Boolean(payload[1]&0x80),end:Boolean(payload[1]&0x40) };
  return null;
}

function depacketizeSession(frames) {
  const chunks=[]; const gaps=[]; const nalTypes={};
  let bytes=0; let previousSeq=null; let fu=null; let completeNal=0;
  for (const frame of frames) {
    if (previousSeq!=null) {
      const expected=(previousSeq+1)&0xffff;
      if (frame.sequence!==expected) gaps.push({ expected,actual:frame.sequence,packetIndex:frame.packetIndex });
    }
    previousSeq=frame.sequence;
    const info=classifyH264(frame.payload);
    if (!info) continue;
    nalTypes[info.nalType]=(nalTypes[info.nalType]||0)+1;
    if (info.type==='single') {
      const out=annexb(frame.payload); if (bytes+out.length>MAX_VIDEO_BYTES) break;
      chunks.push(out); bytes+=out.length; completeNal+=1; fu=null;
    } else if (info.type==='stap-a') {
      let p=1;
      while (p+2<=frame.payload.length) {
        const len=frame.payload.readUInt16BE(p); p+=2;
        if (!len||p+len>frame.payload.length) break;
        const out=annexb(frame.payload.subarray(p,p+len)); p+=len;
        if (bytes+out.length>MAX_VIDEO_BYTES) break;
        chunks.push(out); bytes+=out.length; completeNal+=1;
      }
      fu=null;
    } else if (info.type==='fu-a') {
      if (info.start) {
        const header=(frame.payload[0]&0xe0)|info.nalType;
        fu={ timestamp:frame.timestamp,parts:[Buffer.from([header]),frame.payload.subarray(2)],startSeq:frame.sequence };
      } else if (fu&&fu.timestamp===frame.timestamp) fu.parts.push(frame.payload.subarray(2));
      else { fu=null; continue; }
      if (info.end&&fu) {
        const nal=Buffer.concat(fu.parts); const out=annexb(nal);
        if (bytes+out.length<=MAX_VIDEO_BYTES) { chunks.push(out); bytes+=out.length; completeNal+=1; }
        fu=null;
      }
    }
  }
  const buffer=chunks.length?Buffer.concat(chunks):Buffer.alloc(0);
  return { buffer,bytes,completeNal,nalTypes,gaps,incompleteFragment:Boolean(fu) };
}

function analyzeVideoCapture(packets) {
  const sessions=new Map();
  for (const packet of packets||[]) {
    if (packet.linkType!==LINKTYPE_ETHERNET) continue;
    const udp=parseUdp(packet.data); if (!udp) continue;
    const rtp=parseRtp(udp.payload); if (!rtp) continue;
    const info=classifyH264(rtp.payload); if (!info) continue;
    const key=`${rtp.ssrc}:${rtp.payloadType}:${udp.srcPort}->${udp.dstPort}`;
    const list=sessions.get(key)||[];
    if (list.length<250000) list.push({ ...rtp,packetIndex:packet.index,srcPort:udp.srcPort,dstPort:udp.dstPort });
    sessions.set(key,list);
  }

  const results=[]; const artifacts=[]; const findings=[];
  for (const [key,frames] of sessions) {
    if (frames.length<2) continue;
    frames.sort((a,b)=>a.timestamp-b.timestamp||((a.sequence-b.sequence+65536)%65536));
    const dep=depacketizeSession(frames);
    const ssrc=frames[0].ssrc; const payloadType=frames[0].payloadType;
    const artifact=dep.buffer.length?createBinaryArtifact({
      name:`rtp-${ssrc.toString(16)}-pt${payloadType}.h264`,mediaType:'video/H264',buffer:dep.buffer,completeness:dep.gaps.length||dep.incompleteFragment?'partial':'complete',
      gaps:dep.gaps.slice(0,500),provenance:[{source:'pcap-rtp',parser:'uav-video',ssrc,payloadType,frames:frames.length}],metadata:{kind:'rtp-h264-annexb',ssrc,payloadType,nalTypes:dep.nalTypes}
    }):null;
    if (artifact) artifacts.push(artifact);
    results.push({ key,ssrc:`0x${ssrc.toString(16)}`,payloadType,frames:frames.length,firstPacket:frames[0].packetIndex,lastPacket:frames[frames.length-1].packetIndex,completeNal:dep.completeNal,nalTypes:dep.nalTypes,gaps:dep.gaps.slice(0,120),incompleteFragment:dep.incompleteFragment,artifact });
  }
  if (results.length) findings.push({id:'rtp-h264-session',severity:'info',title:'恢复 RTP/H264 图传会话',evidence:`sessions=${results.length}, artifacts=${artifacts.length}`});
  const lossy=results.filter((x)=>x.gaps.length);
  if (lossy.length) findings.push({id:'rtp-sequence-gaps',severity:'medium',title:'RTP 图传存在序列缺口',evidence:lossy.slice(0,10).map((x)=>`${x.ssrc}: gaps=${x.gaps.length}`),meaning:'可能是抓包丢包、无线链路丢包或视频中断；需结合时间窗和 RTSP 控制面判断。'});
  return { sessions:results,artifacts,findings,notes:['只在 RTP payload 符合 H264 single NAL/STAP-A/FU-A 结构时重组 Annex-B；未知 payload 不强行解释。','存在 sequence gap 或未闭合 FU-A 时 artifact 标为 partial，不冒充完整视频。'] };
}

module.exports={ parseUdp,parseRtp,classifyH264,depacketizeSession,analyzeVideoCapture };
