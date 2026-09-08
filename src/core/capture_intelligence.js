const { parseClassicPcap, parsePcapngPackets, analyzeWifiCapture } = require('./uav_wifi_pcap');
const { parseCanSocketcan, LINKTYPE_CAN_SOCKETCAN } = require('./pcapng');
const { analyzeCanAdvanced } = require('./vehicle_final');
const { analyzeMavlinkAdvanced } = require('./low_altitude');
const { createBinaryArtifact, MAX_ARTIFACT_BYTES } = require('./artifacts');

const LINKTYPE_ETHERNET = 1;
const MAX_CAPTURE_CARVE_BYTES = 96 * 1024 * 1024;
const MAX_CAPTURE_ARTIFACT_BYTES = Math.min(MAX_ARTIFACT_BYTES, 32 * 1024 * 1024);
const MAX_NETWORK_PACKETS = 100000;
const MAX_MAVLINK_BYTES = 4 * 1024 * 1024;

const PCAP_MAGICS = Object.freeze([
  { hex:'d4c3b2a1', format:'PCAP' },
  { hex:'a1b2c3d4', format:'PCAP' },
  { hex:'4d3cb2a1', format:'PCAP' },
  { hex:'a1b23c4d', format:'PCAP' },
  { hex:'0a0d0d0a', format:'PCAPNG' }
]);

function endianReaders(buffer, endian) {
  return {
    u16: (offset) => endian === 'little' ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset),
    u32: (offset) => endian === 'little' ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset)
  };
}

function classicHeaderAt(buffer, offset) {
  if (!Buffer.isBuffer(buffer) || offset < 0 || offset + 24 > buffer.length) return null;
  const magic = buffer.subarray(offset, offset + 4).toString('hex');
  let endian = null;
  let ns = false;
  if (magic === 'd4c3b2a1') endian = 'little';
  else if (magic === 'a1b2c3d4') endian = 'big';
  else if (magic === '4d3cb2a1') { endian = 'little'; ns = true; }
  else if (magic === 'a1b23c4d') { endian = 'big'; ns = true; }
  else return null;
  const { u16, u32 } = endianReaders(buffer, endian);
  const major = u16(offset + 4);
  const minor = u16(offset + 6);
  const snapLen = u32(offset + 16);
  const linkType = u32(offset + 20);
  if (major !== 2 || minor > 4 || snapLen < 1 || snapLen > 16 * 1024 * 1024 || linkType > 0xffff) return null;
  return { endian, ns, major, minor, snapLen, linkType };
}

function carveClassicPcapAt(buffer, offset, maxBytes = MAX_CAPTURE_CARVE_BYTES) {
  const header = classicHeaderAt(buffer, offset);
  if (!header) return null;
  const { u32 } = endianReaders(buffer, header.endian);
  const limit = Math.min(buffer.length, offset + maxBytes);
  let cursor = offset + 24;
  let packetCount = 0;
  while (cursor + 16 <= limit && packetCount < MAX_NETWORK_PACKETS) {
    const inclLen = u32(cursor + 8);
    const origLen = u32(cursor + 12);
    const next = cursor + 16 + inclLen;
    if (inclLen > header.snapLen || inclLen > 16 * 1024 * 1024 || origLen < inclLen || next > limit || next > buffer.length) break;
    packetCount += 1;
    cursor = next;
  }
  if (!packetCount) return null;
  return {
    format:'PCAP',
    offset,
    endOffset:cursor,
    size:cursor - offset,
    packetCount,
    linkTypes:[header.linkType],
    boundary:'validated-packet-records'
  };
}

function pcapngEndianAt(buffer, offset) {
  if (offset + 12 > buffer.length || buffer.readUInt32BE(offset) !== 0x0a0d0d0a) return null;
  const le = buffer.readUInt32LE(offset + 8);
  const be = buffer.readUInt32BE(offset + 8);
  if (le === 0x1a2b3c4d) return 'little';
  if (be === 0x1a2b3c4d) return 'big';
  return null;
}

function carvePcapngAt(buffer, offset, maxBytes = MAX_CAPTURE_CARVE_BYTES) {
  let cursor = offset;
  const limit = Math.min(buffer.length, offset + maxBytes);
  let endian = null;
  let blockCount = 0;
  let packetCount = 0;
  let interfaceCount = 0;
  const linkTypes = new Set();
  while (cursor + 12 <= limit && blockCount < 500000) {
    if (buffer.readUInt32BE(cursor) === 0x0a0d0d0a) {
      endian = pcapngEndianAt(buffer, cursor);
      if (!endian) break;
    }
    if (!endian) break;
    const { u16, u32 } = endianReaders(buffer, endian);
    const blockType = u32(cursor);
    const totalLength = u32(cursor + 4);
    if (totalLength < 12 || totalLength % 4 || cursor + totalLength > limit || cursor + totalLength > buffer.length) break;
    if (u32(cursor + totalLength - 4) !== totalLength) break;
    if (blockType === 1 && totalLength >= 20) {
      interfaceCount += 1;
      linkTypes.add(u16(cursor + 8));
    } else if (blockType === 6 || blockType === 3) {
      packetCount += 1;
    }
    cursor += totalLength;
    blockCount += 1;
  }
  if (!packetCount || !interfaceCount) return null;
  return {
    format:'PCAPNG',
    offset,
    endOffset:cursor,
    size:cursor - offset,
    packetCount,
    linkTypes:[...linkTypes],
    blockCount,
    interfaceCount,
    boundary:'validated-block-chain'
  };
}

function candidateOffsets(buffer) {
  const candidates = [];
  for (const sig of PCAP_MAGICS) {
    const needle = Buffer.from(sig.hex, 'hex');
    let start = 0;
    let seen = 0;
    while (start < buffer.length && seen < 128) {
      const offset = buffer.indexOf(needle, start);
      if (offset < 0) break;
      candidates.push({ offset, format:sig.format });
      start = offset + 1;
      seen += 1;
    }
  }
  const unique = new Map();
  for (const item of candidates.sort((a,b)=>a.offset-b.offset || (a.format === 'PCAPNG' ? -1 : 1))) {
    if (!unique.has(item.offset)) unique.set(item.offset, item);
  }
  return [...unique.values()];
}

function ipv4(value) {
  return `${value[0]}.${value[1]}.${value[2]}.${value[3]}`;
}

function parseEthernetIp(packet) {
  if (!packet || packet.length < 14) return null;
  let offset = 14;
  let etherType = packet.readUInt16BE(12);
  let vlanDepth = 0;
  while ([0x8100,0x88a8,0x9100].includes(etherType) && vlanDepth < 2) {
    if (packet.length < offset + 4) return null;
    etherType = packet.readUInt16BE(offset + 2);
    offset += 4;
    vlanDepth += 1;
  }
  if (etherType !== 0x0800 || packet.length < offset + 20) return null;
  const versionIhl = packet[offset];
  if ((versionIhl >> 4) !== 4) return null;
  const ihl = (versionIhl & 0x0f) * 4;
  if (ihl < 20 || offset + ihl > packet.length) return null;
  const totalLength = packet.readUInt16BE(offset + 2);
  const ipEnd = Math.min(packet.length, offset + Math.max(totalLength, ihl));
  const protocol = packet[offset + 9];
  const src = ipv4(packet.subarray(offset + 12, offset + 16));
  const dst = ipv4(packet.subarray(offset + 16, offset + 20));
  const frag = packet.readUInt16BE(offset + 6);
  if (frag & 0x1fff) return { src, dst, protocol, fragmented:true, payload:Buffer.alloc(0), vlanDepth };
  const transportOffset = offset + ihl;
  if (transportOffset > ipEnd) return null;

  if (protocol === 6 && transportOffset + 20 <= ipEnd) {
    const srcPort = packet.readUInt16BE(transportOffset);
    const dstPort = packet.readUInt16BE(transportOffset + 2);
    const dataOffset = ((packet[transportOffset + 12] >> 4) & 0x0f) * 4;
    if (dataOffset < 20 || transportOffset + dataOffset > ipEnd) return null;
    return { src, dst, protocol:'TCP', srcPort, dstPort, payload:packet.subarray(transportOffset + dataOffset, ipEnd), vlanDepth };
  }
  if (protocol === 17 && transportOffset + 8 <= ipEnd) {
    const srcPort = packet.readUInt16BE(transportOffset);
    const dstPort = packet.readUInt16BE(transportOffset + 2);
    const udpLength = packet.readUInt16BE(transportOffset + 4);
    const end = Math.min(ipEnd, transportOffset + Math.max(udpLength, 8));
    return { src, dst, protocol:'UDP', srcPort, dstPort, payload:packet.subarray(transportOffset + 8, end), vlanDepth };
  }
  return { src, dst, protocol:`IP-${protocol}`, srcPort:null, dstPort:null, payload:packet.subarray(transportOffset, ipEnd), vlanDepth };
}

function serviceName(transport) {
  const ports = [transport.srcPort, transport.dstPort];
  if (ports.includes(21)) return 'FTP';
  if (ports.includes(22)) return 'SSH';
  if (ports.includes(53)) return 'DNS';
  if (ports.includes(80) || ports.includes(8080) || ports.includes(8000)) return 'HTTP';
  if (ports.includes(443)) return 'HTTPS';
  if (ports.includes(554) || ports.includes(8554)) return 'RTSP';
  if (ports.includes(1883)) return 'MQTT';
  if (ports.includes(8883)) return 'MQTTS';
  if (ports.includes(14540) || ports.includes(14550) || ports.includes(14555)) return 'MAVLink';
  const prefix = transport.payload?.subarray(0, 16).toString('latin1') || '';
  if (/^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s/i.test(prefix) || /^HTTP\/1\.[01]/i.test(prefix)) return 'HTTP';
  if (/^(?:OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN)\s/i.test(prefix) || /^RTSP\/1\.0/i.test(prefix)) return 'RTSP';
  if (/^SSH-/i.test(prefix)) return 'SSH';
  if (/^(?:USER|PASS|RETR|STOR|220 |230 |331 )/i.test(prefix)) return 'FTP';
  if (transport.payload?.length >= 8 && (transport.payload[0] === 0xfe || transport.payload[0] === 0xfd)) return 'MAVLink';
  return transport.protocol;
}

function parseDnsQuery(payload) {
  if (!payload || payload.length < 12 || payload.readUInt16BE(4) < 1) return null;
  let offset = 12;
  const labels = [];
  for (let i = 0; i < 64 && offset < payload.length; i += 1) {
    const len = payload[offset++];
    if (!len) break;
    if ((len & 0xc0) || len > 63 || offset + len > payload.length) return null;
    labels.push(payload.subarray(offset, offset + len).toString('ascii'));
    offset += len;
  }
  return labels.length ? labels.join('.') : null;
}

function printableLines(payload) {
  if (!payload?.length) return [];
  const text = payload.toString('latin1').replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '\n');
  return text.split(/\r?\n/).map((line)=>line.trim()).filter((line)=>line.length >= 4).slice(0, 80);
}

function analyzeIpTraffic(packets) {
  const flows = new Map();
  const protocolCounts = {};
  const dnsQueries = [];
  const plaintextEvidence = [];
  const credentials = [];
  const rtspEndpoints = [];
  const httpRequests = [];
  const mavlinkPayloads = [];
  let mavlinkBytes = 0;
  let ethernetPackets = 0;

  for (const packet of packets.slice(0, MAX_NETWORK_PACKETS)) {
    if (packet.linkType !== LINKTYPE_ETHERNET) continue;
    const transport = parseEthernetIp(packet.data);
    if (!transport || typeof transport.protocol !== 'string') continue;
    ethernetPackets += 1;
    const service = serviceName(transport);
    protocolCounts[service] = (protocolCounts[service] || 0) + 1;
    const flowKey = `${transport.protocol} ${transport.src}:${transport.srcPort ?? '*'} -> ${transport.dst}:${transport.dstPort ?? '*'}`;
    const flow = flows.get(flowKey) || { flow:flowKey, protocol:transport.protocol, service, packets:0, payloadBytes:0 };
    flow.packets += 1;
    flow.payloadBytes += transport.payload?.length || 0;
    flows.set(flowKey, flow);

    if (service === 'DNS' && transport.protocol === 'UDP') {
      const query = parseDnsQuery(transport.payload);
      if (query && !dnsQueries.includes(query) && dnsQueries.length < 500) dnsQueries.push(query);
    }

    if (service === 'MAVLink' && transport.payload?.length && mavlinkBytes < MAX_MAVLINK_BYTES) {
      const remaining = MAX_MAVLINK_BYTES - mavlinkBytes;
      const part = transport.payload.subarray(0, remaining);
      mavlinkPayloads.push(part);
      mavlinkBytes += part.length;
    }

    const lines = printableLines(transport.payload);
    if (!lines.length) continue;
    const joined = lines.join('\n');
    const interesting = lines.filter((line)=>/(?:rtsp:\/\/|https?:\/\/|authorization:|cookie:|token|api[_-]?key|^USER\s|^PASS\s|^RETR\s|^STOR\s|^SSH-|^GET\s|^POST\s|^PUT\s|^DELETE\s|^DESCRIBE\s|^SETUP\s|^PLAY\s|^TEARDOWN\s|host:)/i.test(line));
    for (const line of interesting) {
      if (plaintextEvidence.length >= 240) break;
      plaintextEvidence.push({ packetIndex:packet.index, flow:flowKey, service, text:line.slice(0, 320) });
    }

    for (const match of joined.matchAll(/\brtsp:\/\/[^\s"'<>]+/gi)) {
      const value = match[0].slice(0, 500);
      if (!rtspEndpoints.includes(value) && rtspEndpoints.length < 100) rtspEndpoints.push(value);
    }
    const request = joined.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP\/1\.[01]/im);
    const host = joined.match(/^Host:\s*([^\r\n]+)/im);
    if (request && httpRequests.length < 200) httpRequests.push({ packetIndex:packet.index, method:request[1].toUpperCase(), path:request[2], host:host?.[1]?.trim() || null, flow:flowKey });

    for (const line of lines) {
      let m = line.match(/^USER\s+(.+)/i);
      if (m && credentials.length < 100) credentials.push({ packetIndex:packet.index, type:'ftp-user', value:m[1].trim().slice(0,160), flow:flowKey });
      m = line.match(/^PASS\s+(.+)/i);
      if (m && credentials.length < 100) credentials.push({ packetIndex:packet.index, type:'ftp-password', value:m[1].trim().slice(0,160), flow:flowKey });
      m = line.match(/^Authorization:\s*Basic\s+([A-Za-z0-9+/=]{4,512})/i);
      if (m && credentials.length < 100) {
        let decoded = null;
        try { decoded = Buffer.from(m[1], 'base64').toString('utf8').replace(/[\u0000-\u001f\u007f]/g, ''); } catch {}
        credentials.push({ packetIndex:packet.index, type:'http-basic', value:decoded || m[1], flow:flowKey });
      }
    }
  }

  let mavlink = null;
  if (mavlinkPayloads.length) {
    try {
      const data = Buffer.concat(mavlinkPayloads).subarray(0, MAX_MAVLINK_BYTES);
      const parsed = analyzeMavlinkAdvanced(data.toString('hex'));
      mavlink = {
        parsedFrames:parsed.parsedFrames,
        messageCounts:parsed.messageCounts,
        findings:(parsed.findings||[]).slice(0,80),
        highRiskEvents:(parsed.highRiskEvents||[]).slice(0,160),
        securitySummary:parsed.securitySummary
      };
    } catch (error) { mavlink = { error:error.message }; }
  }

  const findings = [];
  if (credentials.length) findings.push({ severity:'high', id:'capture-plaintext-credentials', title:'抓包中发现明文认证材料', evidence:`credentials=${credentials.length}` });
  if (rtspEndpoints.length) findings.push({ severity:'medium', id:'capture-rtsp-endpoint', title:'抓包中发现 RTSP/图传端点', evidence:rtspEndpoints.slice(0,8).join(', ') });
  if (httpRequests.length) findings.push({ severity:'info', id:'capture-http-surface', title:'抓包中恢复 HTTP 请求', evidence:`requests=${httpRequests.length}` });
  if (mavlink?.parsedFrames) findings.push({ severity:'info', id:'capture-mavlink', title:'抓包中恢复 MAVLink 帧', evidence:`frames=${mavlink.parsedFrames}` });

  return {
    ethernetPackets,
    protocolCounts,
    topFlows:[...flows.values()].sort((a,b)=>b.payloadBytes-a.payloadBytes || b.packets-a.packets).slice(0,80),
    dnsQueries,
    httpRequests,
    rtspEndpoints,
    credentials,
    plaintextEvidence,
    mavlink,
    findings
  };
}

function analyzeCanTraffic(packets) {
  const frames = [];
  for (const packet of packets.slice(0, MAX_NETWORK_PACKETS)) {
    if (packet.linkType !== LINKTYPE_CAN_SOCKETCAN) continue;
    const frame = parseCanSocketcan(packet.data);
    if (frame) frames.push({ ...frame, packetIndex:packet.index, timestamp:packet.timestamp, frameIndex:frames.length + 1 });
  }
  if (!frames.length) return null;
  const candump = frames.map((frame)=>`(${Number.isFinite(frame.timestamp) ? frame.timestamp.toFixed(6) : frame.frameIndex}) can0 ${frame.idHex}#${frame.payload}`).join('\n');
  const summary = analyzeCanAdvanced(candump);
  return {
    parsedFrames:summary.parsedFrames,
    uniqueIds:summary.uniqueIds,
    ids:(summary.ids||[]).slice(0,120),
    eventCandidates:(summary.eventCandidates||[]).slice(0,160).map((event)=>{
      const source = frames[event.frameIndex - 1];
      return { ...event, packetIndex:source?.packetIndex ?? null };
    }),
    isoTpSessions:(summary.isoTpSessions||[]).slice(0,120),
    udsProgramming:summary.udsProgramming || null
  };
}

function wifiSummary(wifi) {
  if (!wifi || (!wifi.supported && !wifi.findings?.length)) return null;
  return {
    format:wifi.format,
    supportedPackets:wifi.supportedPackets,
    networks:(wifi.networks||[]).slice(0,120),
    clients:(wifi.clients||[]).slice(0,300),
    handshakes:(wifi.handshakes||[]).slice(0,800),
    pmkids:(wifi.pmkids||[]).slice(0,300),
    deauth:(wifi.deauth||[]).slice(0,800),
    findings:wifi.findings||[]
  };
}

function analyzeCaptureIntelligence(buffer) {
  const container = parseClassicPcap(buffer) || parsePcapngPackets(buffer);
  if (!container) return { format:'unknown', packetCount:0, linkTypes:[], findings:[], highlights:[], nextActions:[] };
  const wifi = wifiSummary(analyzeWifiCapture(buffer));
  const network = analyzeIpTraffic(container.packets || []);
  const can = analyzeCanTraffic(container.packets || []);
  const findings = [
    ...(wifi?.findings || []),
    ...(network.findings || [])
  ];
  const highlights = [];
  if (wifi?.networks?.length) highlights.push(`802.11：恢复 ${wifi.networks.length} 个 AP，${wifi.handshakes?.length || 0} 个 EAPOL-Key，${wifi.deauth?.length || 0} 个 Deauth/Disassociation。`);
  if (can?.parsedFrames) highlights.push(`CAN：恢复 ${can.parsedFrames} 帧、${can.uniqueIds || 0} 个 CAN ID。`);
  if (network.ethernetPackets) highlights.push(`IP：解析 ${network.ethernetPackets} 个 Ethernet/IPv4 包；协议 ${Object.entries(network.protocolCounts).map(([name,count])=>`${name}:${count}`).join(', ') || 'unknown'}。`);
  if (network.credentials.length) highlights.push(`敏感：发现 ${network.credentials.length} 条明文认证材料，已保留 packet/flow provenance。`);
  if (network.rtspEndpoints.length) highlights.push(`图传：发现 ${network.rtspEndpoints.length} 个 RTSP endpoint。`);
  if (network.mavlink?.parsedFrames) highlights.push(`MAVLink：从 IP 流量恢复 ${network.mavlink.parsedFrames} 帧并进入控制/签名/FTP 分析。`);
  const nextActions = [];
  if (network.credentials.length) nextActions.push('先按 flow/packetIndex 核对明文认证材料，再关联后续登录、文件下载或控制操作。');
  if (network.rtspEndpoints.length) nextActions.push('RTSP/图传端点已恢复：继续按 SSRC/sequence 重组 RTP/H264/H265。');
  if (network.mavlink?.parsedFrames) nextActions.push('MAVLink 已自动解析：优先查看 unsigned/signing、COMMAND、PARAM、MISSION、FTP 和高风险控制链。');
  if (wifi?.handshakes?.length || wifi?.pmkids?.length) nextActions.push('802.11 认证材料已识别：按 BSSID/STA 分组验证握手完整性或 PMKID，再进行离线候选验证。');
  if (can?.parsedFrames) nextActions.push('CAN 已自动进入状态跃迁 / ISO-TP / UDS 分析；优先检查高变化 ID 与可导出的刷写链。');
  return {
    format:container.format,
    packetCount:container.packets?.length || 0,
    linkTypes:container.linkTypes || [],
    truncated:Boolean(container.truncated),
    wifi,
    network,
    can,
    findings,
    highlights,
    nextActions
  };
}

function captureArtifact(segment, buffer, index, source) {
  if (segment.size > MAX_CAPTURE_ARTIFACT_BYTES) return null;
  const ext = segment.format === 'PCAPNG' ? 'pcapng' : 'pcap';
  const data = buffer.subarray(segment.offset, segment.endOffset);
  return createBinaryArtifact({
    name:`embedded-capture-${String(index + 1).padStart(2,'0')}.${ext}`,
    mediaType:'application/vnd.tcpdump.pcap',
    buffer:data,
    completeness:'complete',
    provenance:[{ source:source || 'firmware', offset:segment.offset, length:segment.size, parser:'capture-intelligence' }],
    metadata:{ kind:'embedded-capture', format:segment.format, offset:segment.offset, packetCount:segment.packetCount, boundary:segment.boundary }
  });
}

function scanEmbeddedCaptures(input, options = {}) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  const segments = [];
  let coveredUntil = -1;
  for (const candidate of candidateOffsets(buffer)) {
    if (candidate.offset < coveredUntil) continue;
    const segment = candidate.format === 'PCAPNG'
      ? carvePcapngAt(buffer, candidate.offset, options.maxBytes || MAX_CAPTURE_CARVE_BYTES)
      : carveClassicPcapAt(buffer, candidate.offset, options.maxBytes || MAX_CAPTURE_CARVE_BYTES);
    if (!segment) continue;
    const data = buffer.subarray(segment.offset, segment.endOffset);
    let analysis = null;
    try { analysis = analyzeCaptureIntelligence(data); }
    catch (error) { analysis = { format:segment.format, packetCount:segment.packetCount, linkTypes:segment.linkTypes, error:error.message, findings:[], highlights:[], nextActions:[] }; }
    const artifact = captureArtifact(segment, buffer, segments.length, options.source || 'firmware');
    segments.push({
      ...segment,
      offsetHex:`0x${segment.offset.toString(16)}`,
      endOffsetHex:`0x${segment.endOffset.toString(16)}`,
      artifact,
      exportDeferred:artifact ? null : { reason:'embedded-capture-artifact-size-limit', size:segment.size, limit:MAX_CAPTURE_ARTIFACT_BYTES },
      analysis
    });
    coveredUntil = segment.endOffset;
    if (segments.length >= (options.maxCaptures || 16)) break;
  }
  return segments;
}

module.exports = {
  LINKTYPE_ETHERNET,
  MAX_CAPTURE_CARVE_BYTES,
  MAX_CAPTURE_ARTIFACT_BYTES,
  classicHeaderAt,
  carveClassicPcapAt,
  carvePcapngAt,
  parseEthernetIp,
  analyzeCaptureIntelligence,
  scanEmbeddedCaptures
};
