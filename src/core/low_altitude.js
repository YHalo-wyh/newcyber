const crypto = require('crypto');

const ARDUPILOT_SIGNING_MAGIC = 0x3852fcd1;
const DEFAULT_STORAGE_KEYS_OFFSET = 0x1f80;

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

module.exports = { inspectArduPilotEeprom, findSigningStruct, nonZeroRegions, ARDUPILOT_SIGNING_MAGIC, DEFAULT_STORAGE_KEYS_OFFSET };
