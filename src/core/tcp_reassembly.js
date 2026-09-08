const LINKTYPE_ETHERNET = 1;
const MAX_STREAMS = 200;
const MAX_STREAM_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 12 * 1024 * 1024;
const MAX_SEGMENTS_PER_STREAM = 20000;

function ipv4(bytes) { return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`; }

function parseEthernetTcp(packet) {
  if (!packet || packet.length < 14) return null;
  let offset = 14;
  let etherType = packet.readUInt16BE(12);
  let vlanDepth = 0;
  while ([0x8100,0x88a8,0x9100].includes(etherType) && vlanDepth < 2) {
    if (offset + 4 > packet.length) return null;
    etherType = packet.readUInt16BE(offset + 2);
    offset += 4;
    vlanDepth += 1;
  }
  if (etherType !== 0x0800 || offset + 20 > packet.length) return null;
  const versionIhl = packet[offset];
  if ((versionIhl >> 4) !== 4) return null;
  const ihl = (versionIhl & 0x0f) * 4;
  if (ihl < 20 || offset + ihl > packet.length) return null;
  const totalLength = packet.readUInt16BE(offset + 2);
  const ipEnd = Math.min(packet.length, offset + Math.max(totalLength, ihl));
  if (packet[offset + 9] !== 6) return null;
  const frag = packet.readUInt16BE(offset + 6);
  if (frag & 0x1fff) return null;
  const tcp = offset + ihl;
  if (tcp + 20 > ipEnd) return null;
  const dataOffset = ((packet[tcp + 12] >> 4) & 0x0f) * 4;
  if (dataOffset < 20 || tcp + dataOffset > ipEnd) return null;
  return {
    src:ipv4(packet.subarray(offset + 12, offset + 16)),
    dst:ipv4(packet.subarray(offset + 16, offset + 20)),
    srcPort:packet.readUInt16BE(tcp),
    dstPort:packet.readUInt16BE(tcp + 2),
    seq:packet.readUInt32BE(tcp + 4),
    ack:packet.readUInt32BE(tcp + 8),
    flags:packet[tcp + 13],
    payload:packet.subarray(tcp + dataOffset, ipEnd),
    vlanDepth
  };
}

function directionalKey(segment) {
  return `${segment.src}:${segment.srcPort} -> ${segment.dst}:${segment.dstPort}`;
}

function signedDistance(seq, base) { return (seq - base) | 0; }

function buildRuns(segments, maxBytes = MAX_STREAM_BYTES) {
  if (!segments.length) return { runs:[], gaps:[], retransmissions:0, overlapConflicts:0, bytes:0, truncated:false };
  const baseSeq = segments[0].seq >>> 0;
  const ordered = [...segments]
    .map((segment) => ({ ...segment, rel:signedDistance(segment.seq >>> 0, baseSeq) }))
    .sort((a, b) => a.rel - b.rel || a.packetIndex - b.packetIndex)
    .slice(0, MAX_SEGMENTS_PER_STREAM);
  const minRel = ordered[0].rel;
  for (const segment of ordered) segment.pos = segment.rel - minRel;

  const runs = [];
  const gaps = [];
  let retransmissions = 0;
  let overlapConflicts = 0;
  let written = 0;
  let truncated = false;
  let current = null;

  for (const segment of ordered) {
    if (!segment.payload?.length) continue;
    if (segment.pos >= maxBytes) { truncated = true; continue; }
    let data = segment.payload;
    let start = segment.pos;
    const allowed = maxBytes - start;
    if (data.length > allowed) { data = data.subarray(0, allowed); truncated = true; }
    if (!data.length) continue;

    if (!current || start > current.end) {
      if (current && start > current.end) gaps.push({ from:current.end, to:start, bytes:start - current.end, afterPacket:current.lastPacket, beforePacket:segment.packetIndex });
      current = { start, end:start + data.length, chunks:[Buffer.from(data)], firstPacket:segment.packetIndex, lastPacket:segment.packetIndex, packetIndexes:[segment.packetIndex] };
      runs.push(current);
      written += data.length;
      continue;
    }

    const overlap = current.end - start;
    if (overlap >= data.length) {
      retransmissions += 1;
      const currentData = Buffer.concat(current.chunks);
      const local = start - current.start;
      if (local >= 0 && local + data.length <= currentData.length && !currentData.subarray(local, local + data.length).equals(data)) overlapConflicts += 1;
      current.lastPacket = segment.packetIndex;
      if (!current.packetIndexes.includes(segment.packetIndex)) current.packetIndexes.push(segment.packetIndex);
      continue;
    }

    if (overlap > 0) {
      const currentData = Buffer.concat(current.chunks);
      const local = start - current.start;
      const compareLength = Math.min(overlap, data.length, Math.max(0, currentData.length - local));
      if (compareLength > 0 && local >= 0 && !currentData.subarray(local, local + compareLength).equals(data.subarray(0, compareLength))) overlapConflicts += 1;
      data = data.subarray(overlap);
      start += overlap;
    }
    if (!data.length) continue;
    current.chunks.push(Buffer.from(data));
    current.end = start + data.length;
    current.lastPacket = segment.packetIndex;
    if (!current.packetIndexes.includes(segment.packetIndex)) current.packetIndexes.push(segment.packetIndex);
    written += data.length;
  }

  return {
    runs:runs.map((run) => ({ ...run, data:Buffer.concat(run.chunks), chunks:undefined, packetCount:run.packetIndexes.length })),
    gaps,
    retransmissions,
    overlapConflicts,
    bytes:written,
    truncated
  };
}

function serviceForPorts(srcPort, dstPort) {
  const ports = [srcPort, dstPort];
  if (ports.includes(21)) return 'FTP';
  if (ports.includes(80) || ports.includes(8000) || ports.includes(8080)) return 'HTTP';
  if (ports.includes(554) || ports.includes(8554)) return 'RTSP';
  if (ports.includes(1883)) return 'MQTT';
  if (ports.includes(22)) return 'SSH';
  return 'TCP';
}

function safeText(buffer) {
  return buffer.toString('latin1').replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '\n');
}

function pushUnique(out, seen, key, value, limit) {
  if (out.length >= limit || seen.has(key)) return;
  seen.add(key); out.push(value);
}

function scanRun(run, stream, accumulators) {
  const text = safeText(run.data);
  const flow = stream.flow;
  const provenance = { flow, firstPacket:run.firstPacket, lastPacket:run.lastPacket, packetCount:run.packetCount, reassembled:true };
  const { credentials, credentialSeen, httpRequests, httpSeen, rtspEndpoints, rtspSeen, plaintextEvidence, evidenceSeen } = accumulators;

  for (const match of text.matchAll(/(?:^|\r?\n)USER\s+([^\r\n]{1,200})/gi)) {
    const value = match[1].trim();
    pushUnique(credentials, credentialSeen, `ftp-user:${flow}:${value}`, { type:'ftp-user', value, ...provenance }, 120);
  }
  for (const match of text.matchAll(/(?:^|\r?\n)PASS\s+([^\r\n]{1,200})/gi)) {
    const value = match[1].trim();
    pushUnique(credentials, credentialSeen, `ftp-password:${flow}:${value}`, { type:'ftp-password', value, ...provenance }, 120);
  }
  for (const match of text.matchAll(/(?:^|\r?\n)Authorization:\s*Basic\s+([A-Za-z0-9+/=]{4,512})/gi)) {
    let decoded = null;
    try { decoded = Buffer.from(match[1], 'base64').toString('utf8').replace(/[\u0000-\u001f\u007f]/g, ''); } catch {}
    const value = decoded || match[1];
    pushUnique(credentials, credentialSeen, `http-basic:${flow}:${value}`, { type:'http-basic', value, ...provenance }, 120);
  }

  const requestRe = /(?:^|\r?\n)(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s\r\n]+)\s+HTTP\/1\.[01]\r?\n/gi;
  for (const match of text.matchAll(requestRe)) {
    const headerEnd = text.indexOf('\r\n\r\n', match.index);
    const altEnd = text.indexOf('\n\n', match.index);
    const end = [headerEnd >= 0 ? headerEnd : Infinity, altEnd >= 0 ? altEnd : Infinity, match.index + 8192].reduce((a, b) => Math.min(a, b));
    const header = text.slice(match.index, Number.isFinite(end) ? end : match.index + 8192);
    const host = header.match(/(?:^|\r?\n)Host:\s*([^\r\n]+)/i)?.[1]?.trim() || null;
    const item = { method:match[1].toUpperCase(), path:match[2], host, ...provenance };
    pushUnique(httpRequests, httpSeen, `${item.method}:${item.host || ''}:${item.path}:${flow}`, item, 240);
  }

  for (const match of text.matchAll(/\brtsp:\/\/[^\s"'<>]+/gi)) {
    const value = match[0].slice(0, 500);
    pushUnique(rtspEndpoints, rtspSeen, value, value, 120);
  }
  const rtspMethod = /(?:^|\r?\n)(OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|ANNOUNCE|RECORD)\s+([^\s\r\n]+)\s+RTSP\/1\.0/gi;
  for (const match of text.matchAll(rtspMethod)) {
    const value = match[2];
    if (/^rtsp:\/\//i.test(value)) pushUnique(rtspEndpoints, rtspSeen, value, value, 120);
  }

  const interesting = text.split(/\r?\n/).map((x) => x.trim()).filter((line) => /^(?:USER|PASS|GET|POST|PUT|DELETE|OPTIONS|DESCRIBE|SETUP|PLAY|TEARDOWN)\s|^(?:Authorization|Host|Cookie|X-Api-Key):|\brtsp:\/\//i.test(line));
  for (const line of interesting.slice(0, 80)) {
    const key = `${flow}:${line}`;
    pushUnique(plaintextEvidence, evidenceSeen, key, { text:line.slice(0, 360), service:stream.service, ...provenance }, 320);
  }
}

function analyzeTcpReassembly(packets, options = {}) {
  const maxStreams = Math.max(1, Math.min(Number(options.maxStreams) || MAX_STREAMS, 1000));
  const maxStreamBytes = Math.max(4096, Math.min(Number(options.maxStreamBytes) || MAX_STREAM_BYTES, 16 * 1024 * 1024));
  const maxTotalBytes = Math.max(maxStreamBytes, Math.min(Number(options.maxTotalBytes) || MAX_TOTAL_BYTES, 64 * 1024 * 1024));
  const groups = new Map();
  for (const packet of packets || []) {
    if (packet.linkType !== LINKTYPE_ETHERNET) continue;
    const parsed = parseEthernetTcp(packet.data);
    if (!parsed?.payload?.length) continue;
    const flow = directionalKey(parsed);
    if (!groups.has(flow)) {
      if (groups.size >= maxStreams) continue;
      groups.set(flow, { flow, src:parsed.src, dst:parsed.dst, srcPort:parsed.srcPort, dstPort:parsed.dstPort, service:serviceForPorts(parsed.srcPort, parsed.dstPort), segments:[] });
    }
    const stream = groups.get(flow);
    if (stream.segments.length < MAX_SEGMENTS_PER_STREAM) stream.segments.push({ ...parsed, packetIndex:packet.index ?? stream.segments.length + 1 });
  }

  const credentials = []; const credentialSeen = new Set();
  const httpRequests = []; const httpSeen = new Set();
  const rtspEndpoints = []; const rtspSeen = new Set();
  const plaintextEvidence = []; const evidenceSeen = new Set();
  const streams = [];
  let totalBytes = 0;
  let totalRuns = 0;
  let totalGaps = 0;
  let retransmissions = 0;
  let overlapConflicts = 0;

  for (const stream of groups.values()) {
    const budget = Math.min(maxStreamBytes, Math.max(0, maxTotalBytes - totalBytes));
    if (budget < 1) break;
    const built = buildRuns(stream.segments, budget);
    totalBytes += built.bytes;
    totalRuns += built.runs.length;
    totalGaps += built.gaps.length;
    retransmissions += built.retransmissions;
    overlapConflicts += built.overlapConflicts;
    const summary = {
      flow:stream.flow,
      service:stream.service,
      segments:stream.segments.length,
      bytes:built.bytes,
      contiguousRuns:built.runs.length,
      gaps:built.gaps.length,
      retransmissions:built.retransmissions,
      overlapConflicts:built.overlapConflicts,
      truncated:built.truncated,
      firstPacket:Math.min(...stream.segments.map((x) => x.packetIndex)),
      lastPacket:Math.max(...stream.segments.map((x) => x.packetIndex))
    };
    streams.push(summary);
    const accumulators = { credentials, credentialSeen, httpRequests, httpSeen, rtspEndpoints, rtspSeen, plaintextEvidence, evidenceSeen };
    for (const run of built.runs) scanRun(run, stream, accumulators);
  }

  const findings = [];
  if (streams.some((stream) => stream.segments > 1) && (credentials.length || httpRequests.length || rtspEndpoints.length || plaintextEvidence.length)) findings.push({
    severity:'info',
    id:'capture-tcp-reassembly',
    title:'TCP 流已按 sequence 重组并恢复跨包应用层证据',
    evidence:`streams=${streams.length}, runs=${totalRuns}, gaps=${totalGaps}, credentials=${credentials.length}, http=${httpRequests.length}, rtsp=${rtspEndpoints.length}`
  });
  if (overlapConflicts) findings.push({
    severity:'medium',
    id:'capture-tcp-overlap-conflict',
    title:'TCP 重叠区存在内容冲突',
    evidence:`overlapConflicts=${overlapConflicts}; 需区分重传、抓包异常与刻意的 TCP overlap/evasion`
  });

  return {
    streams:streams.sort((a, b) => b.bytes - a.bytes).slice(0, 120),
    stats:{ streams:streams.length, contiguousRuns:totalRuns, gaps:totalGaps, bytes:totalBytes, retransmissions, overlapConflicts },
    credentials,
    httpRequests,
    rtspEndpoints,
    plaintextEvidence,
    findings
  };
}

module.exports = { parseEthernetTcp, buildRuns, analyzeTcpReassembly, MAX_STREAMS, MAX_STREAM_BYTES, MAX_TOTAL_BYTES };