const crypto = require('crypto');

const UDS_SERVICES = {
  0x10: 'DiagnosticSessionControl', 0x11: 'ECUReset', 0x14: 'ClearDiagnosticInformation',
  0x19: 'ReadDTCInformation', 0x22: 'ReadDataByIdentifier', 0x23: 'ReadMemoryByAddress',
  0x27: 'SecurityAccess', 0x28: 'CommunicationControl', 0x2e: 'WriteDataByIdentifier',
  0x31: 'RoutineControl', 0x34: 'RequestDownload', 0x35: 'RequestUpload',
  0x36: 'TransferData', 0x37: 'RequestTransferExit', 0x3e: 'TesterPresent',
  0x85: 'ControlDTCSetting'
};

const UDS_NRCS = {
  0x10: 'generalReject', 0x11: 'serviceNotSupported', 0x12: 'subFunctionNotSupported',
  0x13: 'incorrectMessageLengthOrInvalidFormat', 0x21: 'busyRepeatRequest',
  0x22: 'conditionsNotCorrect', 0x24: 'requestSequenceError', 0x31: 'requestOutOfRange',
  0x33: 'securityAccessDenied', 0x35: 'invalidKey', 0x36: 'exceedNumberOfAttempts',
  0x37: 'requiredTimeDelayNotExpired', 0x70: 'uploadDownloadNotAccepted',
  0x71: 'transferDataSuspended', 0x72: 'generalProgrammingFailure', 0x73: 'wrongBlockSequenceCounter',
  0x78: 'responsePending'
};

const MAVLINK_MESSAGES = {
  0: 'HEARTBEAT', 1: 'SYS_STATUS', 2: 'SYSTEM_TIME', 24: 'GPS_RAW_INT', 30: 'ATTITUDE',
  33: 'GLOBAL_POSITION_INT', 39: 'MISSION_ITEM', 44: 'MISSION_COUNT', 47: 'MISSION_ACK',
  65: 'RC_CHANNELS', 73: 'MISSION_ITEM_INT', 74: 'VFR_HUD', 76: 'COMMAND_LONG',
  77: 'COMMAND_ACK', 105: 'HIGHRES_IMU', 147: 'BATTERY_STATUS', 253: 'STATUSTEXT'
};

const COMMON_SELECTORS = {
  a9059cbb: 'transfer(address,uint256)',
  '095ea7b3': 'approve(address,uint256)',
  '23b872dd': 'transferFrom(address,address,uint256)',
  '70a08231': 'balanceOf(address)',
  dd62ed3e: 'allowance(address,address)',
  '18160ddd': 'totalSupply()',
  '313ce567': 'decimals()',
  '06fdde03': 'name()',
  '95d89b41': 'symbol()',
  '8da5cb5b': 'owner()',
  f2fde38b: 'transferOwnership(address)'
};

const EVM_OPCODES = (() => {
  const map = {
    0x00: 'STOP', 0x01: 'ADD', 0x02: 'MUL', 0x03: 'SUB', 0x04: 'DIV', 0x05: 'SDIV',
    0x06: 'MOD', 0x07: 'SMOD', 0x08: 'ADDMOD', 0x09: 'MULMOD', 0x0a: 'EXP', 0x0b: 'SIGNEXTEND',
    0x10: 'LT', 0x11: 'GT', 0x12: 'SLT', 0x13: 'SGT', 0x14: 'EQ', 0x15: 'ISZERO',
    0x16: 'AND', 0x17: 'OR', 0x18: 'XOR', 0x19: 'NOT', 0x1a: 'BYTE', 0x1b: 'SHL', 0x1c: 'SHR', 0x1d: 'SAR',
    0x20: 'SHA3', 0x30: 'ADDRESS', 0x31: 'BALANCE', 0x32: 'ORIGIN', 0x33: 'CALLER',
    0x34: 'CALLVALUE', 0x35: 'CALLDATALOAD', 0x36: 'CALLDATASIZE', 0x37: 'CALLDATACOPY',
    0x38: 'CODESIZE', 0x39: 'CODECOPY', 0x3a: 'GASPRICE', 0x3b: 'EXTCODESIZE', 0x3c: 'EXTCODECOPY',
    0x3d: 'RETURNDATASIZE', 0x3e: 'RETURNDATACOPY', 0x3f: 'EXTCODEHASH',
    0x40: 'BLOCKHASH', 0x41: 'COINBASE', 0x42: 'TIMESTAMP', 0x43: 'NUMBER', 0x44: 'PREVRANDAO',
    0x45: 'GASLIMIT', 0x46: 'CHAINID', 0x47: 'SELFBALANCE', 0x48: 'BASEFEE',
    0x50: 'POP', 0x51: 'MLOAD', 0x52: 'MSTORE', 0x53: 'MSTORE8', 0x54: 'SLOAD', 0x55: 'SSTORE',
    0x56: 'JUMP', 0x57: 'JUMPI', 0x58: 'PC', 0x59: 'MSIZE', 0x5a: 'GAS', 0x5b: 'JUMPDEST',
    0x5f: 'PUSH0', 0xf0: 'CREATE', 0xf1: 'CALL', 0xf2: 'CALLCODE', 0xf3: 'RETURN', 0xf4: 'DELEGATECALL',
    0xf5: 'CREATE2', 0xfa: 'STATICCALL', 0xfd: 'REVERT', 0xfe: 'INVALID', 0xff: 'SELFDESTRUCT'
  };
  for (let i = 0; i < 32; i += 1) map[0x60 + i] = `PUSH${i + 1}`;
  for (let i = 0; i < 16; i += 1) map[0x80 + i] = `DUP${i + 1}`;
  for (let i = 0; i < 16; i += 1) map[0x90 + i] = `SWAP${i + 1}`;
  for (let i = 0; i < 5; i += 1) map[0xa0 + i] = `LOG${i}`;
  return map;
})();

const KNOWLEDGE = [
  ['Prompt Injection', '人工智能', '检查不可信输入是否直接进入 system/user prompt、RAG context 或工具参数；重点追踪模型输出到 shell/文件/网络等敏感 sink。'],
  ['torch.load', '人工智能', '对不可信 .pt/.pth 直接 torch.load 可能触发 pickle 反序列化。静态检查 ZIP/pickle 结构优先。'],
].map(([term, domain, text]) => ({ term, domain, text }));

function cleanHex(input) {
  const value = String(input || '').replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '');
  if (value.length % 2) throw new Error('十六进制长度必须为偶数');
  return value.toLowerCase();
}

function parseBytes(input) {
  const hex = cleanHex(input);
  return Buffer.from(hex, 'hex');
}

function runCodec(operation, input, key = '') {
  const text = String(input ?? '');
  switch (operation) {
    case 'text-to-hex': return { output: Buffer.from(text, 'utf8').toString('hex') };
    case 'hex-to-text': return { output: parseBytes(text).toString('utf8') };
    case 'text-to-base64': return { output: Buffer.from(text, 'utf8').toString('base64') };
    case 'base64-to-text': return { output: Buffer.from(text.trim(), 'base64').toString('utf8') };
    case 'url-encode': return { output: encodeURIComponent(text) };
    case 'url-decode': return { output: decodeURIComponent(text) };
    case 'sha256': return { output: crypto.createHash('sha256').update(text).digest('hex') };
    case 'md5': return { output: crypto.createHash('md5').update(text).digest('hex') };
    case 'xor-hex': {
      const data = parseBytes(text);
      const keyBytes = parseBytes(key);
      if (!keyBytes.length) throw new Error('XOR key 不能为空');
      const out = Buffer.alloc(data.length);
      for (let i = 0; i < data.length; i += 1) out[i] = data[i] ^ keyBytes[i % keyBytes.length];
      return { output: out.toString('hex'), utf8: out.toString('utf8') };
    }
    default: throw new Error(`未知编码操作：${operation}`);
  }
}

function parseCanLine(line) {
  const raw = line.trim();
  if (!raw || raw.startsWith('#')) return null;
  let timestamp = null;
  let id = null;
  let payload = null;
  let match = raw.match(/^\(([-\d.]+)\)\s+\S+\s+([0-9A-Fa-f]{3,8})#([0-9A-Fa-f]*)/);
  if (match) {
    timestamp = Number(match[1]); id = match[2]; payload = match[3];
  } else {
    match = raw.match(/^(?:\S+\s+)?([0-9A-Fa-f]{3,8})#([0-9A-Fa-f]*)/);
    if (match) { id = match[1]; payload = match[2]; }
    else {
      match = raw.match(/^(?:\(([-\d.]+)\)\s+)?\S*\s*([0-9A-Fa-f]{3,8})\s+\[(\d+)\]\s+(.+)$/);
      if (match) {
        timestamp = match[1] ? Number(match[1]) : null;
        id = match[2];
        payload = match[4].replace(/[^0-9A-Fa-f]/g, '');
      }
    }
  }
  if (!id || payload == null || payload.length % 2) return null;
  return { timestamp: Number.isFinite(timestamp) ? timestamp : null, id: id.toUpperCase(), bytes: [...Buffer.from(payload, 'hex')] };
}

function analyzeCan(text) {
  const frames = String(text || '').split(/\r?\n/).map(parseCanLine).filter(Boolean);
  const groups = new Map();
  for (const frame of frames) {
    if (!groups.has(frame.id)) groups.set(frame.id, []);
    groups.get(frame.id).push(frame);
  }
  const ids = [...groups.entries()].map(([id, list]) => {
    const maxDlc = Math.max(...list.map((frame) => frame.bytes.length), 0);
    const changingBytes = [];
    const counterCandidates = [];
    for (let index = 0; index < maxDlc; index += 1) {
      const values = list.map((frame) => frame.bytes[index]).filter((value) => Number.isInteger(value));
      if (new Set(values).size > 1) changingBytes.push(index);
      if (values.length >= 4) {
        let matches = 0;
        for (let i = 1; i < values.length; i += 1) if (((values[i - 1] + 1) & 0xff) === values[i]) matches += 1;
        if (matches / (values.length - 1) >= 0.75) counterCandidates.push(index);
      }
    }
    const times = list.map((frame) => frame.timestamp).filter(Number.isFinite);
    let averageIntervalMs = null;
    if (times.length >= 2) {
      let sum = 0;
      for (let i = 1; i < times.length; i += 1) sum += times[i] - times[i - 1];
      averageIntervalMs = Number(((sum / (times.length - 1)) * 1000).toFixed(3));
    }
    return {
      id: `0x${id}`, count: list.length, dlc: [...new Set(list.map((frame) => frame.bytes.length))],
      changingBytes, counterCandidates, averageIntervalMs,
      firstPayload: Buffer.from(list[0]?.bytes || []).toString('hex'),
      lastPayload: Buffer.from(list[list.length - 1]?.bytes || []).toString('hex')
    };
  }).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
  return { parsedFrames: frames.length, uniqueIds: ids.length, ids, hints: ['优先观察低频事件帧与状态切换前后的 byte 差分。', 'counterCandidates 只是启发式结果，需结合周期和协议语义人工确认。'] };
}

function decodeUds(input) {
  let bytes = [...parseBytes(input)];
  const notes = [];
  if (!bytes.length) throw new Error('请输入 UDS 十六进制数据');
  const pciType = bytes[0] >> 4;
  if (pciType === 0 && bytes.length >= 2) {
    const length = bytes[0] & 0x0f;
    bytes = bytes.slice(1, 1 + length);
    notes.push(`检测到 ISO-TP Single Frame，payload 长度 ${length}`);
  } else if (pciType === 1 && bytes.length >= 3) {
    const length = ((bytes[0] & 0x0f) << 8) | bytes[1];
    bytes = bytes.slice(2);
    notes.push(`检测到 ISO-TP First Frame，总 payload 长度 ${length}；当前仅解析首帧数据。`);
  }
  const sid = bytes[0];
  if (sid === 0x7f && bytes.length >= 3) {
    return { type: 'negative-response', requestService: `0x${bytes[1].toString(16).padStart(2, '0')}`, serviceName: UDS_SERVICES[bytes[1]] || 'Unknown', nrc: `0x${bytes[2].toString(16).padStart(2, '0')}`, nrcName: UDS_NRCS[bytes[2]] || 'Unknown', data: Buffer.from(bytes.slice(3)).toString('hex'), notes };
  }
  const isPositive = sid >= 0x40 && UDS_SERVICES[sid - 0x40];
  const requestSid = isPositive ? sid - 0x40 : sid;
  const result = { type: isPositive ? 'positive-response' : 'request', service: `0x${sid.toString(16).padStart(2, '0')}`, serviceName: UDS_SERVICES[requestSid] || 'Unknown', data: Buffer.from(bytes.slice(1)).toString('hex'), notes };
  if (requestSid === 0x27 && bytes.length >= 2) result.securityAccess = { subFunction: bytes[1], meaning: bytes[1] % 2 ? 'requestSeed' : 'sendKey' };
  if (requestSid === 0x22 && bytes.length >= 3) result.did = `0x${bytes[1].toString(16).padStart(2, '0')}${bytes[2].toString(16).padStart(2, '0')}`;
  return result;
}

function parseNmeaCoord(value, hemi) {
  if (!value) return null;
  const raw = Number(value);
  if (!Number.isFinite(raw)) return null;
  const degrees = Math.floor(raw / 100);
  const minutes = raw - degrees * 100;
  let result = degrees + minutes / 60;
  if (hemi === 'S' || hemi === 'W') result *= -1;
  return result;
}

function haversine(a, b) {
  const rad = (value) => value * Math.PI / 180;
  const dLat = rad(b.lat - a.lat);
  const dLon = rad(b.lon - a.lon);
  const x = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 6371000 * 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1 - x));
}

function analyzeNmea(text) {
  const points = [];
  let invalid = 0;
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!line.startsWith('$')) continue;
    const sentence = line.split('*')[0];
    const fields = sentence.split(',');
    const type = fields[0].slice(-3);
    if (type === 'RMC') {
      const lat = parseNmeaCoord(fields[3], fields[4]);
      const lon = parseNmeaCoord(fields[5], fields[6]);
      if (fields[2] !== 'A' || lat == null || lon == null) { invalid += 1; continue; }
      points.push({ source: 'RMC', time: fields[1] || null, date: fields[9] || null, lat, lon, speedKnots: Number(fields[7]) || 0 });
    } else if (type === 'GGA') {
      const lat = parseNmeaCoord(fields[2], fields[3]);
      const lon = parseNmeaCoord(fields[4], fields[5]);
      if (!Number(fields[6]) || lat == null || lon == null) { invalid += 1; continue; }
      points.push({ source: 'GGA', time: fields[1] || null, lat, lon, fixQuality: Number(fields[6]), satellites: Number(fields[7]) || null, altitudeM: Number(fields[9]) || null });
    }
  }
  let distanceM = 0;
  for (let i = 1; i < points.length; i += 1) distanceM += haversine(points[i - 1], points[i]);
  const latitudes = points.map((point) => point.lat);
  const longitudes = points.map((point) => point.lon);
  return {
    validPoints: points.length, invalidSentences: invalid, distanceM: Number(distanceM.toFixed(2)),
    bounds: points.length ? { minLat: Math.min(...latitudes), maxLat: Math.max(...latitudes), minLon: Math.min(...longitudes), maxLon: Math.max(...longitudes) } : null,
    points: points.slice(0, 500)
  };
}

function analyzeMavlinkHex(input) {
  const buffer = parseBytes(input);
  const frames = [];
  let offset = 0;
  while (offset < buffer.length && frames.length < 1000) {
    const magic = buffer[offset];
    if (magic !== 0xfe && magic !== 0xfd) { offset += 1; continue; }
    if (magic === 0xfe) {
      if (offset + 8 > buffer.length) break;
      const payloadLength = buffer[offset + 1];
      const frameLength = 6 + payloadLength + 2;
      if (offset + frameLength > buffer.length) break;
      const msgid = buffer[offset + 5];
      frames.push({ version: 1, offset, payloadLength, seq: buffer[offset + 2], sysid: buffer[offset + 3], compid: buffer[offset + 4], msgid, name: MAVLINK_MESSAGES[msgid] || 'UNKNOWN' });
      offset += frameLength;
    } else {
      if (offset + 12 > buffer.length) break;
      const payloadLength = buffer[offset + 1];
      const incompatFlags = buffer[offset + 2];
      const signed = Boolean(incompatFlags & 0x01);
      const frameLength = 10 + payloadLength + 2 + (signed ? 13 : 0);
      if (offset + frameLength > buffer.length) break;
      const msgid = buffer[offset + 7] | (buffer[offset + 8] << 8) | (buffer[offset + 9] << 16);
      frames.push({ version: 2, offset, payloadLength, seq: buffer[offset + 4], sysid: buffer[offset + 5], compid: buffer[offset + 6], msgid, name: MAVLINK_MESSAGES[msgid] || 'UNKNOWN', signed });
      offset += frameLength;
    }
  }
  const counts = {};
  for (const frame of frames) counts[`${frame.msgid} ${frame.name}`] = (counts[`${frame.msgid} ${frame.name}`] || 0) + 1;
  return { parsedFrames: frames.length, messageCounts: counts, frames: frames.slice(0, 300), note: '仅做帧结构解析；CRC 校验依赖具体 MAVLink dialect/CRC extra，当前不判定合法性。' };
}

const AI_RULES = [
  ['high', 'unsafe-deserialization', '不可信模型反序列化', /\b(?:pickle\.loads?|joblib\.load|torch\.load)\s*\(/gi],
  ['high', 'shell-sink', '模型/用户输入可能进入 Shell', /(?:os\.system|subprocess\.(?:run|Popen|call)|create_subprocess_shell|child_process\.exec)\s*\(/gi],
  ['high', 'dynamic-code', '动态代码执行入口', /\b(?:eval|exec)\s*\(/gi],
  ['medium', 'prompt-concat', 'Prompt 由动态输入拼接', /(?:system|prompt|messages?|context)\s*=.{0,80}(?:\+|f["']|format\()/gi],
  ['medium', 'rag-context', '发现 RAG / 检索上下文拼接线索', /\b(?:retriever|vectorstore|similarity_search|faiss|chroma|rag|context)\b/gi],
  ['medium', 'tool-call', '发现 Agent / Tool 调用面', /\b(?:tool_calls?|function_call|mcp|invoke|run_tool|execute_tool)\b/gi],
  ['medium', 'hardcoded-secret', '疑似硬编码凭据', /(?:api[_-]?key|secret|token|password)\s*[=:]\s*["'][^"'\r\n]{6,}/gi]
];

function scanAiSource(source) {
  const text = String(source || '');
  const findings = [];
  for (const [severity, id, title, regex] of AI_RULES) {
    regex.lastIndex = 0;
    const matches = [...text.matchAll(regex)];
    if (!matches.length) continue;
    findings.push({ severity, id, title, count: matches.length, evidence: matches.slice(0, 5).map((match) => match[0].slice(0, 180)) });
  }
  const surfaces = {
    model: /\b(?:torch|tensorflow|transformers|onnx|sklearn|xgboost|whisper)\b/i.test(text),
    rag: /\b(?:faiss|chroma|retriever|vectorstore|embedding|rag)\b/i.test(text),
    agent: /\b(?:agent|tool_call|function_call|mcp|langchain|autogen)\b/i.test(text),
    shell: /\b(?:subprocess|os\.system|child_process\.exec|create_subprocess_shell)\b/i.test(text)
  };
  return { findings, surfaces, hints: ['优先人工追踪：不可信输入 → prompt/RAG → 模型输出 → tool/shell/file/network。', '正则命中只代表审计线索，不等价于漏洞成立。'] };
}

function decodeCalldata(input) {
  const hex = cleanHex(input);
  if (hex.length < 8) throw new Error('calldata 至少需要 4 字节 selector');
  const selector = hex.slice(0, 8);
  const body = hex.slice(8);
  const words = [];
  for (let i = 0; i < body.length; i += 64) {
    const word = body.slice(i, i + 64).padEnd(64, '0');
    if (!word) continue;
    const bigint = BigInt(`0x${word}`);
    const address = word.slice(24);
    words.push({ index: words.length, hex: `0x${word}`, uint256: bigint.toString(), addressCandidate: `0x${address}` });
  }
  return { selector: `0x${selector}`, knownSignature: COMMON_SELECTORS[selector] || null, words };
}

function evmDisasm(input) {
  const bytes = [...parseBytes(input)];
  const instructions = [];
  let pc = 0;
  while (pc < bytes.length && instructions.length < 5000) {
    const opcode = bytes[pc];
    const name = EVM_OPCODES[opcode] || `UNKNOWN_0x${opcode.toString(16).padStart(2, '0')}`;
    const currentPc = pc;
    pc += 1;
    let immediate = null;
    if (opcode >= 0x60 && opcode <= 0x7f) {
      const size = opcode - 0x5f;
      immediate = Buffer.from(bytes.slice(pc, pc + size)).toString('hex');
      pc += size;
    }
    instructions.push({ pc: currentPc, opcode: `0x${opcode.toString(16).padStart(2, '0')}`, name, immediate: immediate ? `0x${immediate}` : null });
  }
  const risky = instructions.filter((item) => ['CALL', 'DELEGATECALL', 'CALLCODE', 'SELFDESTRUCT', 'CREATE2', 'ORIGIN'].includes(item.name));
  return { byteLength: bytes.length, instructions, riskyOpcodes: risky };
}

function searchKnowledge(query, domain = null) {
  const needle = String(query || '').trim().toLowerCase();
  if (!needle) return KNOWLEDGE.filter((item) => !domain || item.domain === domain);
  return KNOWLEDGE.filter((item) => (!domain || item.domain === domain) && `${item.term} ${item.domain} ${item.text}`.toLowerCase().includes(needle));
}

function runTool(tool, payload = {}) {
  switch (tool) {
    case 'codec': return runCodec(payload.operation, payload.input, payload.key);
    case 'can-analyze': return analyzeCan(payload.input);
    case 'uds-decode': return decodeUds(payload.input);
    case 'nmea-analyze': return analyzeNmea(payload.input);
    case 'mavlink-hex': return analyzeMavlinkHex(payload.input);
    case 'ai-source-scan': return scanAiSource(payload.input);
    case 'evm-calldata': return decodeCalldata(payload.input);
    case 'evm-disasm': return evmDisasm(payload.input);
    case 'knowledge-search': return { results: searchKnowledge(payload.input, payload.domain || null) };
    default: throw new Error(`未知工具：${tool}`);
  }
}

module.exports = {
  runTool, runCodec, analyzeCan, decodeUds, analyzeNmea, analyzeMavlinkHex,
  scanAiSource, decodeCalldata, evmDisasm, searchKnowledge, parseCanLine
};
