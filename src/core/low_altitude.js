const crypto = require('crypto');

const ARDUPILOT_SIGNING_MAGIC = 0x3852fcd1;
const DEFAULT_STORAGE_KEYS_OFFSET = 0x1f80;
const MAVLINK_MESSAGES = {
  0: 'HEARTBEAT',
  24: 'GPS_RAW_INT',
  30: 'ATTITUDE',
  33: 'GLOBAL_POSITION_INT',
  76: 'COMMAND_LONG',
  126: 'SERIAL_CONTROL',
  253: 'STATUSTEXT'
};
const MAV_CMD_COMPONENT_ARM_DISARM = 400;

function nonZeroRegions(buffer, minimumGap = 32) {
  const regions = [];
  let start = -1;
  let lastNonZero = -1;
  for (let i = 0; i < buffer.length; i += 1) {
    if (buffer[i] !== 0) {
      if (start < 0) start = i;
      lastNonZero = i;
      continue;
    }
    if (start >= 0 && i - lastNonZero >= minimumGap) {
      regions.push({ start, end: lastNonZero + 1, size: lastNonZero + 1 - start });
      start = -1;
      lastNonZero = -1;
    }
  }
  if (start >= 0) regions.push({ start, end: lastNonZero + 1, size: lastNonZero + 1 - start });
  return regions;
}

function findSigningStruct(buffer) {
  const needle = Buffer.alloc(4);
  needle.writeUInt32LE(ARDUPILOT_SIGNING_MAGIC, 0);
  const found = buffer.indexOf(needle);
  const offset = found >= 0 ? found : (buffer.length >= DEFAULT_STORAGE_KEYS_OFFSET + 48 ? DEFAULT_STORAGE_KEYS_OFFSET : -1);
  if (offset < 0 || offset + 48 > buffer.length) return null;
  const magic = buffer.readUInt32LE(offset);
  const pad = buffer.readUInt32LE(offset + 4);
  const timestamp = buffer.readBigUInt64LE(offset + 8);
  const key = buffer.subarray(offset + 16, offset + 48);
  return {
    offset,
    offsetHex: `0x${offset.toString(16)}`,
    magic: `0x${magic.toString(16).padStart(8, '0')}`,
    magicValid: magic === ARDUPILOT_SIGNING_MAGIC,
    pad: `0x${pad.toString(16).padStart(8, '0')}`,
    timestamp: timestamp.toString(),
    signingKeyHex: key.toString('hex'),
    signingKeySha256: crypto.createHash('sha256').update(key).digest('hex'),
    keyLength: key.length
  };
}

function inspectArduPilotEeprom(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  if (buffer.length < 4) throw new Error('EEPROM 数据过短');
  const header = buffer.subarray(0, 2).toString('latin1');
  const signing = findSigningStruct(buffer);
  const findings = [];
  if (header === 'PA') findings.push({ severity: 'info', title: '识别为 ArduPilot AP_Param EEPROM', evidence: "header='PA'" });
  if (signing?.magicValid) findings.push({ severity: 'high', title: '发现 MAVLink 2 signing key 结构', evidence: `${signing.offsetHex}, key=${signing.signingKeyHex}` });
  return {
    format: header === 'PA' ? 'ArduPilot AP_Param EEPROM' : 'Unknown EEPROM/Binary',
    size: buffer.length,
    header,
    headerHex: buffer.subarray(0, Math.min(16, buffer.length)).toString('hex'),
    revisionCandidate: buffer.length >= 3 ? buffer[2] : null,
    nonZeroRegions: nonZeroRegions(buffer),
    signing,
    findings,
    notes: [
      'MAVLink 2 signing key 结构按 ArduPilot StorageKeys 的 48-byte 布局解析。',
      '签名密钥属于赛题/实验数据时可用于离线验证；真实设备密钥应按敏感凭据处理。'
    ]
  };
}

function parseHexBuffer(input) {
  const compact = String(input || '').replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '');
  if (!compact || compact.length % 2) throw new Error('MAVLink 十六进制流长度必须为偶数');
  return Buffer.from(compact, 'hex');
}

function decodeHeartbeat(payload) {
  if (payload.length < 9) return null;
  return {
    customMode: payload.readUInt32LE(0),
    type: payload[4],
    autopilot: payload[5],
    baseMode: payload[6],
    systemStatus: payload[7],
    mavlinkVersion: payload[8],
    armed: Boolean(payload[6] & 0x80)
  };
}

function decodeCommandLong(payload) {
  if (payload.length < 33) return null;
  const params = [];
  for (let i = 0; i < 7; i += 1) params.push(payload.readFloatLE(i * 4));
  return {
    params,
    command: payload.readUInt16LE(28),
    targetSystem: payload[30],
    targetComponent: payload[31],
    confirmation: payload[32]
  };
}

function decodeSerialControl(payload) {
  if (payload.length < 9) return null;
  const count = Math.min(payload[8], 70, Math.max(payload.length - 9, 0));
  const data = payload.subarray(9, 9 + count);
  return {
    baudrate: payload.readUInt32LE(0),
    timeout: payload.readUInt16LE(4),
    device: payload[6],
    flags: payload[7],
    count,
    dataHex: data.toString('hex'),
    dataText: data.toString('utf8').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '.')
  };
}

function decodeStatusText(payload) {
  if (payload.length < 2) return null;
  const raw = payload.subarray(1, Math.min(payload.length, 51));
  const end = raw.indexOf(0);
  return {
    severity: payload[0],
    text: raw.subarray(0, end >= 0 ? end : raw.length).toString('utf8')
  };
}

function parseMavlinkFrames(input) {
  const buffer = parseHexBuffer(input);
  const frames = [];
  let offset = 0;
  while (offset < buffer.length && frames.length < 3000) {
    const magic = buffer[offset];
    if (magic !== 0xfe && magic !== 0xfd) {
      offset += 1;
      continue;
    }

    if (magic === 0xfe) {
      if (offset + 8 > buffer.length) break;
      const payloadLength = buffer[offset + 1];
      const frameLength = 6 + payloadLength + 2;
      if (offset + frameLength > buffer.length) break;
      const payloadOffset = offset + 6;
      frames.push({
        version: 1,
        offset,
        frameLength,
        payloadLength,
        seq: buffer[offset + 2],
        sysid: buffer[offset + 3],
        compid: buffer[offset + 4],
        msgid: buffer[offset + 5],
        signed: false,
        payload: buffer.subarray(payloadOffset, payloadOffset + payloadLength)
      });
      offset += frameLength;
      continue;
    }

    if (offset + 12 > buffer.length) break;
    const payloadLength = buffer[offset + 1];
    const incompatFlags = buffer[offset + 2];
    const signed = Boolean(incompatFlags & 0x01);
    const frameLength = 10 + payloadLength + 2 + (signed ? 13 : 0);
    if (offset + frameLength > buffer.length) break;
    const payloadOffset = offset + 10;
    frames.push({
      version: 2,
      offset,
      frameLength,
      payloadLength,
      seq: buffer[offset + 4],
      sysid: buffer[offset + 5],
      compid: buffer[offset + 6],
      msgid: buffer[offset + 7] | (buffer[offset + 8] << 8) | (buffer[offset + 9] << 16),
      signed,
      incompatFlags,
      payload: buffer.subarray(payloadOffset, payloadOffset + payloadLength)
    });
    offset += frameLength;
  }
  return frames;
}

function analyzeMavlinkAdvanced(input) {
  const rawFrames = parseMavlinkFrames(input);
  const findings = [];
  const highRiskEvents = [];
  const messageCounts = {};
  const sequenceState = new Map();
  const sequenceGaps = [];
  let unsignedV2Frames = 0;

  const frames = rawFrames.map((frame, index) => {
    const name = MAVLINK_MESSAGES[frame.msgid] || 'UNKNOWN';
    messageCounts[`${frame.msgid} ${name}`] = (messageCounts[`${frame.msgid} ${name}`] || 0) + 1;
    if (frame.version === 2 && !frame.signed) unsignedV2Frames += 1;

    const key = `${frame.sysid}:${frame.compid}`;
    if (sequenceState.has(key)) {
      const expected = (sequenceState.get(key) + 1) & 0xff;
      if (frame.seq !== expected) sequenceGaps.push({ frameIndex: index + 1, sysid: frame.sysid, compid: frame.compid, expected, actual: frame.seq });
    }
    sequenceState.set(key, frame.seq);

    let decoded = null;
    if (frame.msgid === 0) decoded = decodeHeartbeat(frame.payload);
    else if (frame.msgid === 76) decoded = decodeCommandLong(frame.payload);
    else if (frame.msgid === 126) decoded = decodeSerialControl(frame.payload);
    else if (frame.msgid === 253) decoded = decodeStatusText(frame.payload);

    if (frame.msgid === 76 && decoded) {
      const event = { frameIndex: index + 1, type: 'COMMAND_LONG', command: decoded.command, targetSystem: decoded.targetSystem, targetComponent: decoded.targetComponent, params: decoded.params };
      if (decoded.command === MAV_CMD_COMPONENT_ARM_DISARM) {
        event.commandName = 'MAV_CMD_COMPONENT_ARM_DISARM';
        event.action = decoded.params[0] >= 0.5 ? 'arm' : 'disarm';
        highRiskEvents.push(event);
        findings.push({ severity: 'medium', id: 'mavlink-arm-disarm', title: '发现飞控 ARM/DISARM 命令', frameIndex: index + 1, evidence: `param1=${decoded.params[0]}, target=${decoded.targetSystem}:${decoded.targetComponent}` });
      }
    }

    if (frame.msgid === 126 && decoded && decoded.count > 0) {
      const shellCandidate = decoded.device === 10;
      const event = { frameIndex: index + 1, type: 'SERIAL_CONTROL', device: decoded.device, flags: decoded.flags, baudrate: decoded.baudrate, dataText: decoded.dataText, dataHex: decoded.dataHex, shellCandidate };
      highRiskEvents.push(event);
      findings.push({
        severity: shellCandidate ? 'high' : 'medium',
        id: shellCandidate ? 'mavlink-px4-debug-serial' : 'mavlink-serial-control',
        title: shellCandidate ? 'SERIAL_CONTROL device 10：PX4 debug shell 候选' : '发现 MAVLink SERIAL_CONTROL 数据',
        frameIndex: index + 1,
        evidence: `device=${decoded.device}, flags=0x${decoded.flags.toString(16)}, data=${JSON.stringify(decoded.dataText)}`
      });
    }

    if (frame.msgid === 253 && decoded && /debug|serial|shell|armed|preflight/i.test(decoded.text)) {
      highRiskEvents.push({ frameIndex: index + 1, type: 'STATUSTEXT', severity: decoded.severity, text: decoded.text });
    }

    return {
      version: frame.version,
      offset: frame.offset,
      payloadLength: frame.payloadLength,
      seq: frame.seq,
      sysid: frame.sysid,
      compid: frame.compid,
      msgid: frame.msgid,
      name,
      signed: frame.signed,
      decoded
    };
  });

  if (unsignedV2Frames) findings.push({ severity: 'info', id: 'mavlink2-unsigned', title: '检测到未签名 MAVLink 2 帧', count: unsignedV2Frames, evidence: `${unsignedV2Frames}/${frames.filter((item) => item.version === 2).length} MAVLink2 frames unsigned` });
  if (sequenceGaps.length) findings.push({ severity: 'info', id: 'mavlink-sequence-gaps', title: 'MAVLink sequence 存在跳号', count: sequenceGaps.length, evidence: sequenceGaps.slice(0, 8) });

  const armBeforeSerial = highRiskEvents.some((event, index) => event.type === 'SERIAL_CONTROL' && highRiskEvents.slice(0, index).some((prev) => prev.type === 'COMMAND_LONG' && prev.action === 'arm'));
  if (armBeforeSerial) findings.push({ severity: 'high', id: 'mavlink-arm-to-serial-chain', title: 'ARM → SERIAL_CONTROL 高风险控制链', evidence: '观察到 ARM 命令后出现 SERIAL_CONTROL 数据；应核对是否解锁调试串口、shell 或其他受保护接口。' });

  return {
    parsedFrames: frames.length,
    messageCounts,
    frames: frames.slice(0, 500),
    findings,
    highRiskEvents,
    securitySummary: {
      mavlink1Frames: frames.filter((item) => item.version === 1).length,
      mavlink2Frames: frames.filter((item) => item.version === 2).length,
      unsignedV2Frames,
      sequenceGapCount: sequenceGaps.length,
      armToSerialChain: armBeforeSerial
    },
    note: '结构解析不执行不可信数据；CRC 仍依赖具体 dialect/CRC extra。安全事件只提供协议证据，不等价于真实设备漏洞成立。'
  };
}

module.exports = {
  inspectArduPilotEeprom,
  findSigningStruct,
  nonZeroRegions,
  analyzeMavlinkAdvanced,
  parseMavlinkFrames,
  ARDUPILOT_SIGNING_MAGIC,
  DEFAULT_STORAGE_KEYS_OFFSET,
  MAV_CMD_COMPONENT_ARM_DISARM
};
