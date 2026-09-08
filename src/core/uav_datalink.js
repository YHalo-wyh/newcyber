const { parseClassicPcap,parsePcapngPackets }=require('./uav_wifi_pcap');
const { parseEthernetIp }=require('./capture_intelligence');

const VENDOR_PATTERNS=Object.freeze([
  ['DJI',/\bDJI\b/i],
  ['Lightbridge',/\bLightbridge\b/i],
  ['OcuSync',/\bOcuSync\b/i],
  ['QGroundControl',/\bQGroundControl\b/i],
  ['ArduPilot',/\bArduPilot\b/i],
  ['PX4',/\bPX4\b/i],
  ['MAVLink',/\bMAVLink\b/i]
]);

function endpointPair(transport) {
  const a=transport.src<transport.dst?transport.src:transport.dst;
  const b=transport.src<transport.dst?transport.dst:transport.src;
  return `${a}<->${b}`;
}

function asciiPreview(payload) {
  if (!payload?.length) return '';
  return payload.subarray(0,Math.min(payload.length,512)).toString('latin1').replace(/[^\x20-\x7e]/g,' ');
}

function analyzeDatalinkCapture(buffer) {
  const container=parseClassicPcap(buffer)||parsePcapngPackets(buffer);
  if (!container) return {format:'unknown',flows:[],findings:[],nextActions:[]};
  const flows=new Map();
  const vendorEvidence=[];

  for (const packet of container.packets||[]) {
    if (packet.linkType!==1) continue;
    const t=parseEthernetIp(packet.data);
    if (!t||!['UDP','TCP'].includes(t.protocol)) continue;
    const key=`${t.protocol} ${t.src}:${t.srcPort??'*'} -> ${t.dst}:${t.dstPort??'*'}`;
    const item=flows.get(key)||{key,protocol:t.protocol,src:t.src,dst:t.dst,srcPort:t.srcPort,dstPort:t.dstPort,pair:endpointPair(t),packets:0,payloadBytes:0,firstTimestamp:null,lastTimestamp:null,vendors:new Set()};
    item.packets+=1;
    item.payloadBytes+=t.payload?.length||0;
    if (Number.isFinite(packet.timestamp)) {
      if (item.firstTimestamp==null||packet.timestamp<item.firstTimestamp) item.firstTimestamp=packet.timestamp;
      if (item.lastTimestamp==null||packet.timestamp>item.lastTimestamp) item.lastTimestamp=packet.timestamp;
    }
    const preview=asciiPreview(t.payload);
    for (const [name,regex] of VENDOR_PATTERNS) {
      if (!regex.test(preview)) continue;
      item.vendors.add(name);
      if (vendorEvidence.length<120) vendorEvidence.push({packetIndex:packet.index,flow:key,vendor:name,text:preview.trim().slice(0,240)});
    }
    flows.set(key,item);
  }

  const list=[...flows.values()].map((item)=>{
    const durationSec=item.firstTimestamp!=null&&item.lastTimestamp!=null?Math.max(0,item.lastTimestamp-item.firstTimestamp):null;
    const avgPayload=item.packets?item.payloadBytes/item.packets:0;
    const pps=durationSec>0?item.packets/durationSec:null;
    let role='other'; let confidence=0.2;
    if (item.protocol==='UDP'&&item.packets>=20&&avgPayload>=700&&(pps==null||pps>=8)) { role='media/high-rate-data-candidate'; confidence=0.78; }
    else if (item.protocol==='UDP'&&item.packets>=20&&avgPayload<=320&&(pps==null||pps>=3)) { role='control/telemetry-candidate'; confidence=0.66; }
    if (item.vendors.size) confidence=Math.max(confidence,0.9);
    return {...item,vendors:[...item.vendors],durationSec,avgPayload,pps,role,confidence};
  }).sort((a,b)=>b.payloadBytes-a.payloadBytes||b.packets-a.packets);

  const pairMap=new Map();
  for (const flow of list) {
    const rows=pairMap.get(flow.pair)||[]; rows.push(flow); pairMap.set(flow.pair,rows);
  }
  const paired=[];
  for (const [pair,rows] of pairMap) {
    const media=rows.filter((x)=>x.role==='media/high-rate-data-candidate');
    const control=rows.filter((x)=>x.role==='control/telemetry-candidate');
    if (media.length&&control.length) paired.push({pair,media:media.slice(0,6).map((x)=>x.key),control:control.slice(0,6).map((x)=>x.key),confidence:0.82});
  }

  const findings=[];
  const proprietary=vendorEvidence.filter((x)=>['DJI','Lightbridge','OcuSync'].includes(x.vendor));
  if (proprietary.length) findings.push({
    id:'uav-proprietary-link-fingerprint',severity:'info',title:'抓包中出现无人机专有数据链标识',
    evidence:proprietary.slice(0,12),meaning:'仅作为离线指纹证据；具体帧格式、加密和认证仍需结合协议样本/固件实现复核。'
  });
  if (paired.length) findings.push({
    id:'uav-control-media-flow-pair',severity:'info',title:'识别控制/遥测与高带宽媒体流组合候选',
    evidence:paired.slice(0,12),meaning:'同一主机对同时存在小包控制/遥测流与大包高带宽流，适合继续关联图传、遥测和断链事件。'
  });
  const unknownHigh=list.filter((x)=>x.role==='media/high-rate-data-candidate'&&!x.vendors.length&&![554,8554,5004,5005].includes(x.srcPort)&&![554,8554,5004,5005].includes(x.dstPort));
  if (unknownHigh.length) findings.push({
    id:'uav-unknown-high-rate-datalink',severity:'info',title:'发现未知高带宽 UDP 数据链候选',
    evidence:unknownHigh.slice(0,10).map((x)=>`${x.key}; packets=${x.packets}; avg=${x.avgPayload.toFixed(1)}B${x.pps==null?'':`; pps=${x.pps.toFixed(1)}`}`),
    meaning:'可能是厂商私有图传/数据链，也可能是普通媒体/遥测；不根据端口或流量形态直接声称 Lightbridge/OcuSync。'
  });

  const nextActions=[];
  if (proprietary.length) nextActions.push('按 vendor evidence 所在 packet/flow 回看前后握手、版本、会话 ID 和密钥协商线索；保持被动分析，不主动向真实链路注入。');
  if (paired.length) nextActions.push('将控制候选流、媒体候选流与 Wi-Fi Deauth、MAVLink 命令、RTSP/RTP sequence gap 放到同一时间线。');
  if (unknownHigh.length) nextActions.push('对未知高带宽 UDP 流做长度分布、固定头/计数器/熵和重传模式分析，再决定是否需要厂商协议适配器。');

  return {
    format:container.format,
    packetCount:container.packets?.length||0,
    flows:list.slice(0,160).map((x)=>({...x,vendors:x.vendors})),
    vendorEvidence,
    pairedFlows:paired,
    findings,
    nextActions,
    notes:['本模块只做离线抓包流量画像和厂商字符串指纹，不发送 Deauth、控制帧、干扰或协议注入。','Lightbridge/OcuSync 只有出现明确厂商/协议证据时才标记；高带宽 UDP 本身保持 unknown candidate。']
  };
}

module.exports={VENDOR_PATTERNS,analyzeDatalinkCapture};
