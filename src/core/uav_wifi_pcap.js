const LINKTYPE_IEEE802_11 = 105;
const LINKTYPE_IEEE802_11_RADIOTAP = 127;
const MAX_PACKETS = 250000;

function mac(buffer, offset) {
  if (!buffer || offset < 0 || offset + 6 > buffer.length) return null;
  return [...buffer.subarray(offset, offset + 6)].map((x) => x.toString(16).padStart(2, '0')).join(':');
}

function parseClassicPcap(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 24) return null;
  const magic = buffer.subarray(0, 4).toString('hex');
  let endian = null; let ns = false;
  if (magic === 'd4c3b2a1') endian = 'little';
  else if (magic === 'a1b2c3d4') endian = 'big';
  else if (magic === '4d3cb2a1') { endian = 'little'; ns = true; }
  else if (magic === 'a1b23c4d') { endian = 'big'; ns = true; }
  else return null;
  const r32 = (o) => endian === 'little' ? buffer.readUInt32LE(o) : buffer.readUInt32BE(o);
  const linkType = r32(20);
  const packets = [];
  let offset = 24; let index = 0; let truncated = false;
  while (offset + 16 <= buffer.length && index < MAX_PACKETS) {
    const sec = r32(offset); const frac = r32(offset + 4); const incl = r32(offset + 8); const orig = r32(offset + 12);
    offset += 16;
    if (incl > buffer.length - offset) { truncated = true; break; }
    index += 1;
    packets.push({ index, linkType, timestamp: sec + frac / (ns ? 1e9 : 1e6), capturedLength: incl, originalLength: orig, data: buffer.subarray(offset, offset + incl) });
    offset += incl;
  }
  if (index >= MAX_PACKETS && offset < buffer.length) truncated = true;
  return { format:'PCAP', endian, linkTypes:[linkType], packets, truncated };
}

function align4(value) { return (value + 3) & ~3; }

function parsePcapngPackets(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 28 || buffer.readUInt32BE(0) !== 0x0a0d0d0a) return null;
  let offset = 0; let endian = null; let section = -1; let index = 0; let truncated = false;
  let interfaces = [];
  const packets = []; const linkTypes = new Set();
  const r16 = (o) => endian === 'little' ? buffer.readUInt16LE(o) : buffer.readUInt16BE(o);
  const r32 = (o) => endian === 'little' ? buffer.readUInt32LE(o) : buffer.readUInt32BE(o);

  while (offset + 12 <= buffer.length && index < MAX_PACKETS) {
    if (buffer.readUInt32BE(offset) === 0x0a0d0d0a) {
      if (offset + 12 > buffer.length) break;
      const le = buffer.readUInt32LE(offset + 8); const be = buffer.readUInt32BE(offset + 8);
      if (le === 0x1a2b3c4d) endian = 'little';
      else if (be === 0x1a2b3c4d) endian = 'big';
      else break;
      section += 1; interfaces = [];
    }
    if (!endian) break;
    const type = r32(offset); const total = r32(offset + 4);
    if (total < 12 || total % 4 || offset + total > buffer.length || r32(offset + total - 4) !== total) { truncated = true; break; }
    if (type === 1 && total >= 20) {
      const linkType = r16(offset + 8); const snapLen = r32(offset + 12);
      let tsResolution = 1e-6; let p = offset + 16; const end = offset + total - 4;
      while (p + 4 <= end) {
        const code = r16(p); const len = r16(p + 2); if (!code) break;
        const start = p + 4; if (start + len > end) break;
        if (code === 9 && len >= 1) { const raw = buffer[start]; tsResolution = raw & 0x80 ? 2 ** -(raw & 0x7f) : 10 ** -raw; }
        p = start + align4(len);
      }
      interfaces.push({ id:interfaces.length, section, linkType, snapLen, tsResolution }); linkTypes.add(linkType);
    } else if (type === 6 && total >= 32) {
      const ifaceId = r32(offset + 8); const hi = r32(offset + 12); const lo = r32(offset + 16); const cap = r32(offset + 20); const orig = r32(offset + 24);
      const start = offset + 28; const end = start + cap; const iface = interfaces[ifaceId] || null;
      if (end <= offset + total - 4) {
        index += 1; const rawTs = (BigInt(hi) << 32n) | BigInt(lo);
        packets.push({ index, linkType:iface?.linkType ?? null, timestamp:iface ? Number(rawTs) * iface.tsResolution : null, capturedLength:cap, originalLength:orig, data:buffer.subarray(start, end) });
      }
    } else if (type === 3 && total >= 16 && interfaces[0]) {
      const orig = r32(offset + 8); const cap = Math.min(orig, total - 16); const start = offset + 12;
      index += 1; packets.push({ index, linkType:interfaces[0].linkType, timestamp:null, capturedLength:cap, originalLength:orig, data:buffer.subarray(start, start + cap) });
    }
    offset += total;
  }
  if (index >= MAX_PACKETS && offset < buffer.length) truncated = true;
  return { format:'PCAPNG', endian, linkTypes:[...linkTypes], packets, truncated };
}

function stripRadiotap(packet, linkType) {
  if (linkType === LINKTYPE_IEEE802_11) return { frame:packet, radiotapLength:0 };
  if (linkType !== LINKTYPE_IEEE802_11_RADIOTAP || packet.length < 8 || packet[0] !== 0) return null;
  const length = packet.readUInt16LE(2);
  if (length < 8 || length > packet.length) return null;
  return { frame:packet.subarray(length), radiotapLength:length };
}

function parseIes(buffer, offset) {
  const out = []; let p = offset;
  while (p + 2 <= buffer.length) {
    const id = buffer[p]; const len = buffer[p + 1]; p += 2;
    if (p + len > buffer.length) break;
    out.push({ id, data:buffer.subarray(p, p + len) }); p += len;
  }
  return out;
}

function decodeRsn(data) {
  if (!data || data.length < 8) return null;
  let p = 0; const read16 = () => { if (p + 2 > data.length) return null; const v = data.readUInt16LE(p); p += 2; return v; };
  const suite = () => { if (p + 4 > data.length) return null; const oui = data.subarray(p, p + 3).toString('hex'); const type = data[p + 3]; p += 4; return { oui, type }; };
  const version = read16(); const group = suite(); const pairCount = read16(); if (version == null || !group || pairCount == null || pairCount > 64) return null;
  const pairwise = []; for (let i=0;i<pairCount;i+=1) { const s=suite(); if (!s) return null; pairwise.push(s); }
  const akmCount = read16(); if (akmCount == null || akmCount > 64) return null;
  const akms=[]; for (let i=0;i<akmCount;i+=1) { const s=suite(); if (!s) return null; akms.push(s); }
  const labels = akms.map((x) => x.type === 8 ? 'SAE' : x.type === 2 ? 'PSK' : x.type === 1 ? '802.1X' : `AKM-${x.type}`);
  return { version, group, pairwise, akms, security: labels.includes('SAE') ? 'WPA3-SAE' : labels.includes('PSK') ? 'WPA2-PSK' : labels.includes('802.1X') ? 'WPA2-Enterprise' : 'RSN' };
}

function networkFromMgmt(frame, subtype) {
  if (frame.length < 24) return null;
  const bssid = mac(frame, 16); const transmitter = mac(frame, 10); const receiver = mac(frame, 4);
  let ieOffset = null;
  if (subtype === 8 || subtype === 5) ieOffset = 36;
  else if (subtype === 4) ieOffset = 24;
  if (ieOffset == null || frame.length < ieOffset) return { bssid, transmitter, receiver, ies:[] };
  const ies = parseIes(frame, ieOffset);
  const ssidIe = ies.find((x)=>x.id===0); const channelIe = ies.find((x)=>x.id===3); const rsnIe = ies.find((x)=>x.id===48);
  return {
    bssid,
    transmitter,
    receiver,
    ssid:ssidIe ? ssidIe.data.toString('utf8').replace(/[\u0000-\u001f\u007f]/g,'') : null,
    hidden:ssidIe ? ssidIe.data.length===0 : null,
    channel:channelIe?.data?.[0] ?? null,
    rsn:rsnIe ? decodeRsn(rsnIe.data) : null,
    ies
  };
}

function dataHeaderLength(fc, subtype) {
  const toDs = Boolean(fc & 0x0100); const fromDs = Boolean(fc & 0x0200);
  let len = toDs && fromDs ? 30 : 24;
  if (subtype & 0x08) len += 2;
  if (fc & 0x8000) len += 4;
  return len;
}

function eapolMessage(payload) {
  if (payload.length < 99 || payload[1] !== 3) return { kind:'EAPOL', keyMessage:null, pmkids:[] };
  const bodyLen = payload.readUInt16BE(2); if (bodyLen + 4 > payload.length) return { kind:'EAPOL', keyMessage:null, pmkids:[] };
  const descriptor = payload[4]; const keyInfo = payload.readUInt16BE(5);
  const ack = Boolean(keyInfo & 0x0080); const mic = Boolean(keyInfo & 0x0100); const secure = Boolean(keyInfo & 0x0200); const pairwise = Boolean(keyInfo & 0x0008);
  let keyMessage = null;
  if (pairwise && ack && !mic) keyMessage = 1;
  else if (pairwise && !ack && mic && !secure) keyMessage = 2;
  else if (pairwise && ack && mic) keyMessage = 3;
  else if (pairwise && !ack && mic && secure) keyMessage = 4;
  const pmkids=[];
  for (let i=0;i+22<=payload.length;i+=1) {
    if (payload[i]===0xdd && payload[i+1]===0x14 && payload[i+2]===0x00 && payload[i+3]===0x0f && payload[i+4]===0xac && payload[i+5]===0x04) pmkids.push(payload.subarray(i+6,i+22).toString('hex'));
  }
  return { kind:'EAPOL-Key', descriptor, keyInfo:`0x${keyInfo.toString(16).padStart(4,'0')}`, keyMessage, ack, mic, secure, pairwise, pmkids };
}

function parseDot11(packet, linkType, packetMeta) {
  const stripped = stripRadiotap(packet, linkType); if (!stripped || stripped.frame.length < 10) return null;
  const frame = stripped.frame; const fc = frame.readUInt16LE(0); const type=(fc>>2)&3; const subtype=(fc>>4)&15;
  const base={ packetIndex:packetMeta.index, timestamp:packetMeta.timestamp, type, subtype, fc:`0x${fc.toString(16).padStart(4,'0')}`, radiotapLength:stripped.radiotapLength, addr1:mac(frame,4), addr2:mac(frame,10), addr3:mac(frame,16) };
  if (type===0) {
    const mgmt=networkFromMgmt(frame,subtype);
    return { ...base, kind:'management', name:({0:'assoc-request',1:'assoc-response',4:'probe-request',5:'probe-response',8:'beacon',10:'disassociation',11:'authentication',12:'deauthentication'})[subtype] || `mgmt-${subtype}`, ...mgmt };
  }
  if (type===2) {
    const headerLen=dataHeaderLength(fc,subtype); if (frame.length < headerLen + 8) return { ...base, kind:'data' };
    const llc=frame.subarray(headerLen);
    if (llc.length>=8 && llc[0]===0xaa && llc[1]===0xaa && llc[2]===0x03) {
      const etherType=llc.readUInt16BE(6);
      if (etherType===0x888e) return { ...base, kind:'data', etherType:'0x888e', eapol:eapolMessage(llc.subarray(8)) };
    }
    return { ...base, kind:'data' };
  }
  return { ...base, kind:type===1?'control':'reserved' };
}

function mergeNetworks(events) {
  const map=new Map();
  for (const event of events) {
    if (!['beacon','probe-response'].includes(event.name) || !event.bssid) continue;
    const item=map.get(event.bssid)||{ bssid:event.bssid, ssid:null, hidden:false, channel:null, security:null, firstPacket:event.packetIndex, lastPacket:event.packetIndex, beacons:0 };
    if (event.ssid) item.ssid=event.ssid; if (event.hidden) item.hidden=true; if (event.channel!=null) item.channel=event.channel; if (event.rsn?.security) item.security=event.rsn.security;
    item.lastPacket=event.packetIndex; item.beacons+=event.name==='beacon'?1:0; map.set(event.bssid,item);
  }
  return [...map.values()].sort((a,b)=>a.firstPacket-b.firstPacket);
}

function analyzeWifiCapture(buffer) {
  const container=parseClassicPcap(buffer)||parsePcapngPackets(buffer);
  if (!container) return { format:'unknown', packetCount:0, linkTypes:[], supported:false, findings:[], notes:['未识别为 classic PCAP 或 PCAPNG。'] };
  const events=[]; const handshakes=[]; const deauth=[]; const auth=[]; const pmkids=[]; const clients=new Set(); let supportedPackets=0;
  for (const packet of container.packets) {
    if (![LINKTYPE_IEEE802_11,LINKTYPE_IEEE802_11_RADIOTAP].includes(packet.linkType)) continue;
    supportedPackets+=1; const event=parseDot11(packet.data,packet.linkType,packet); if (!event) continue;
    if (events.length<2500 && (event.kind==='management' || event.eapol)) events.push(event);
    if (event.addr2) clients.add(event.addr2); if (event.addr1) clients.add(event.addr1);
    if (event.name==='deauthentication' || event.name==='disassociation') deauth.push({ packetIndex:event.packetIndex,timestamp:event.timestamp,kind:event.name,source:event.addr2,target:event.addr1,bssid:event.addr3 });
    if (event.name==='authentication' || event.name==='assoc-request' || event.name==='assoc-response') auth.push({ packetIndex:event.packetIndex,timestamp:event.timestamp,kind:event.name,source:event.addr2,target:event.addr1,bssid:event.addr3 });
    if (event.eapol) {
      const h={ packetIndex:event.packetIndex,timestamp:event.timestamp,source:event.addr2,target:event.addr1,bssid:event.addr3,message:event.eapol.keyMessage,keyInfo:event.eapol.keyInfo };
      handshakes.push(h); for (const value of event.eapol.pmkids||[]) pmkids.push({ packetIndex:event.packetIndex,source:event.addr2,target:event.addr1,pmkid:value });
    }
  }
  const networks=mergeNetworks(events); const findings=[];
  if (handshakes.length) findings.push({ id:'wifi-eapol-handshake',severity:'info',evidence:`eapol=${handshakes.length}, messages=${[...new Set(handshakes.map((x)=>x.message).filter(Boolean))].join('/')||'unknown'}`,meaning:'抓包包含 EAPOL-Key 认证材料；先按 AP/客户端分组判断 4-Way Handshake 是否完整，再做离线口令验证。' });
  if (pmkids.length) findings.push({ id:'wifi-pmkid-evidence',severity:'info',evidence:`pmkid=${pmkids.length}`,meaning:'抓包中发现 PMKID KDE，可作为 WPA/WPA2 离线认证材料；仍需确认对应 AP/客户端与题目授权范围。' });
  if (deauth.length) findings.push({ id:'wifi-deauth-evidence',severity:'medium',evidence:`deauth/disassoc=${deauth.length}`,meaning:'抓包存在 Deauthentication/Disassociation；结合时间密度、来源地址与后续重连/EAPOL 判断是否为断链或诱导重连。' });
  if (!supportedPackets && container.packets.length) findings.push({ id:'wifi-linktype-unsupported',severity:'info',evidence:`linkTypes=${container.linkTypes.join(',')}`,meaning:'抓包容器可解析，但当前没有 IEEE 802.11 / Radiotap 接口。' });
  return {
    format:container.format,
    packetCount:container.packets.length,
    linkTypes:container.linkTypes,
    supportedPackets,
    truncated:container.truncated,
    supported:supportedPackets>0,
    networks:networks.slice(0,200),
    clients:[...clients].filter((x)=>x && x!=='ff:ff:ff:ff:ff:ff').slice(0,500),
    handshakes:handshakes.slice(0,4000),
    pmkids:pmkids.slice(0,1000),
    deauth:deauth.slice(0,4000),
    auth:auth.slice(0,4000),
    events,
    findings,
    notes:['802.11 解析只恢复帧结构与认证/管理证据；不会把握手存在解释为口令已破解。','Radiotap 只使用其 length 定位 802.11 frame，不依赖驱动私有字段。']
  };
}

module.exports={ LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP, parseClassicPcap, parsePcapngPackets, parseDot11, analyzeWifiCapture };
