const { analyzeCanAdvanced } = require('./vehicle_final');

const LINKTYPE_CAN_SOCKETCAN = 227;

function align4(value) {
  return (value + 3) & ~3;
}

function parseCanSocketcan(packet) {
  if (!packet || packet.length < 16) return null;

  const be = packet.readUInt32BE(0);
  const le = packet.readUInt32LE(0);
  const score = (raw) => {
    const eff = Boolean(raw & 0x80000000);
    const identifierBits = raw & 0x1fffffff;
    if (eff) return identifierBits <= 0x1fffffff ? 2 : -10;
    if ((raw & 0x1ffff800) === 0) return 5;
    return -5;
  };
  const canIdRaw = score(be) >= score(le) ? be : le;
  const endian = canIdRaw === be ? 'big' : 'little';
  const extended = Boolean(canIdRaw & 0x80000000);
  const remote = Boolean(canIdRaw & 0x40000000);
  const error = Boolean(canIdRaw & 0x20000000);
  const id = extended ? (canIdRaw & 0x1fffffff) : (canIdRaw & 0x7ff);
  const dlc = Math.min(packet[4], Math.max(packet.length - 8, 0), packet.length >= 72 ? 64 : 8);
  const data = packet.subarray(8, 8 + dlc);

  return {
    id,
    idHex: id.toString(16).toUpperCase().padStart(extended ? 8 : 3, '0'),
    canIdRaw: `0x${canIdRaw.toString(16).padStart(8, '0')}`,
    endian,
    extended,
    remote,
    error,
    dlc,
    data,
    payload: data.toString('hex'),
    rawFrameHex: packet.toString('hex')
  };
}

function parsePcapng(buffer) {
  if (!buffer || buffer.length < 28 || buffer.readUInt32BE(0) !== 0x0a0d0d0a) return null;

  let offset = 0;
  let endian = null;
  let sectionIndex = -1;
  const interfaces = [];
  const packets = [];
  const canFrames = [];
  let packetIndex = 0;

  const read16 = (position) => endian === 'little' ? buffer.readUInt16LE(position) : buffer.readUInt16BE(position);
  const read32 = (position) => endian === 'little' ? buffer.readUInt32LE(position) : buffer.readUInt32BE(position);

  while (offset + 12 <= buffer.length) {
    const typeBE = buffer.readUInt32BE(offset);
    if (typeBE === 0x0a0d0d0a) {
      if (offset + 12 > buffer.length) break;
      const bomLE = buffer.readUInt32LE(offset + 8);
      const bomBE = buffer.readUInt32BE(offset + 8);
      if (bomLE === 0x1a2b3c4d) endian = 'little';
      else if (bomBE === 0x1a2b3c4d) endian = 'big';
      else break;
      sectionIndex += 1;
      interfaces.length = 0;
    }

    if (!endian) break;
    const blockType = read32(offset);
    const totalLength = read32(offset + 4);
    if (totalLength < 12 || offset + totalLength > buffer.length || totalLength % 4 !== 0) break;
    if (read32(offset + totalLength - 4) !== totalLength) break;

    if (blockType === 0x00000001 && totalLength >= 20) {
      const linkType = read16(offset + 8);
      const snapLen = read32(offset + 12);
      let tsResolution = 1e-6;
      let optionOffset = offset + 16;
      const optionEnd = offset + totalLength - 4;
      while (optionOffset + 4 <= optionEnd) {
        const code = read16(optionOffset);
        const length = read16(optionOffset + 2);
        if (code === 0) break;
        const valueStart = optionOffset + 4;
        if (valueStart + length > optionEnd) break;
        if (code === 9 && length >= 1) {
          const raw = buffer[valueStart];
          tsResolution = raw & 0x80 ? 2 ** -(raw & 0x7f) : 10 ** -raw;
        }
        optionOffset = valueStart + align4(length);
      }
      interfaces.push({ id: interfaces.length, sectionIndex, linkType, snapLen, tsResolution });
    } else if (blockType === 0x00000006 && totalLength >= 32) {
      const interfaceId = read32(offset + 8);
      const timestampHigh = read32(offset + 12);
      const timestampLow = read32(offset + 16);
      const capturedLength = read32(offset + 20);
      const originalLength = read32(offset + 24);
      const packetStart = offset + 28;
      const packetEnd = packetStart + capturedLength;
      if (packetEnd <= offset + totalLength - 4) {
        packetIndex += 1;
        const iface = interfaces[interfaceId] || null;
        const rawTimestamp = (BigInt(timestampHigh) << 32n) | BigInt(timestampLow);
        const timestamp = iface ? Number(rawTimestamp) * iface.tsResolution : null;
        const packet = buffer.subarray(packetStart, packetEnd);
        packets.push({ packetIndex, interfaceId, linkType: iface?.linkType ?? null, capturedLength, originalLength, timestamp });
        if (iface?.linkType === LINKTYPE_CAN_SOCKETCAN) {
          const can = parseCanSocketcan(packet);
          if (can) canFrames.push({ ...can, packetIndex, timestamp, frameIndex: canFrames.length + 1 });
        }
      }
    }

    offset += totalLength;
  }

  let can = null;
  if (canFrames.length) {
    const candump = canFrames.map((frame) => {
      const time = Number.isFinite(frame.timestamp) ? frame.timestamp.toFixed(6) : frame.frameIndex;
      return `(${time}) can0 ${frame.idHex}#${frame.payload}`;
    }).join('\n');
    const summary = analyzeCanAdvanced(candump);
    const byFrameIndex = new Map(canFrames.map((frame) => [frame.frameIndex, frame]));
    const attachSource = (event) => {
      const source = byFrameIndex.get(event.frameIndex);
      return source ? { ...event, packetIndex: source.packetIndex, rawFrameHex: source.rawFrameHex } : event;
    };
    summary.ids = summary.ids.map((item) => ({ ...item, transitions: item.transitions.map(attachSource) }));
    summary.eventCandidates = summary.eventCandidates.map(attachSource);
    can = {
      linkType: LINKTYPE_CAN_SOCKETCAN,
      frames: canFrames.slice(0, 300).map((frame) => ({
        frameIndex: frame.frameIndex,
        packetIndex: frame.packetIndex,
        timestamp: frame.timestamp,
        id: `0x${frame.idHex}`,
        dlc: frame.dlc,
        payload: frame.payload,
        rawFrameHex: frame.rawFrameHex
      })),
      ...summary
    };
  }

  return {
    format: 'PCAPNG',
    endian,
    sectionCount: sectionIndex + 1,
    interfaces: interfaces.map((item) => ({ id: item.id, linkType: item.linkType, snapLen: item.snapLen, tsResolution: item.tsResolution })),
    packetCountInPreview: packets.length,
    can
  };
}

module.exports = { parsePcapng, parseCanSocketcan, LINKTYPE_CAN_SOCKETCAN };
