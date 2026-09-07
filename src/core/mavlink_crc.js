const COMMON_CRC_EXTRA = Object.freeze({
  0: 50,   // HEARTBEAT
  24: 24,  // GPS_RAW_INT
  30: 39,  // ATTITUDE
  33: 104, // GLOBAL_POSITION_INT
  76: 152, // COMMAND_LONG
  110: 84, // FILE_TRANSFER_PROTOCOL
  126: 220,// SERIAL_CONTROL
  253: 83  // STATUSTEXT
});

function crcAccumulate(byte, crc) {
  let tmp = (byte ^ (crc & 0xff)) & 0xff;
  tmp = (tmp ^ ((tmp << 4) & 0xff)) & 0xff;
  return (((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xffff) >>> 0;
}

function mavlinkCrcX25(buffer, crcExtra = null) {
  let crc = 0xffff;
  for (const byte of buffer || []) crc = crcAccumulate(byte, crc);
  if (Number.isInteger(crcExtra)) crc = crcAccumulate(crcExtra & 0xff, crc);
  return crc;
}

function verifyMavlinkFrameCrc(frame, crcExtras = COMMON_CRC_EXTRA) {
  if (!frame?.packetWithoutSignature || frame.packetWithoutSignature.length < 4) return { status: 'unavailable', valid: null };
  const extra = crcExtras[frame.msgid];
  const packet = frame.packetWithoutSignature;
  const checksumOffset = packet.length - 2;
  if (checksumOffset <= 1) return { status: 'unavailable', valid: null };
  const wire = packet.readUInt16LE(checksumOffset);
  if (!Number.isInteger(extra)) {
    return {
      status: 'unknown-crc-extra',
      valid: null,
      msgid: frame.msgid,
      wireCrc: `0x${wire.toString(16).padStart(4, '0')}`,
      crcExtra: null,
      dialect: 'unknown-or-unsupported'
    };
  }
  const body = packet.subarray(1, checksumOffset);
  const computed = mavlinkCrcX25(body, extra);
  return {
    status: computed === wire ? 'valid' : 'invalid',
    valid: computed === wire,
    msgid: frame.msgid,
    wireCrc: `0x${wire.toString(16).padStart(4, '0')}`,
    computedCrc: `0x${computed.toString(16).padStart(4, '0')}`,
    crcExtra: extra,
    dialect: 'common.xml-supported-subset'
  };
}

function analyzeMavlinkCrc(frames = [], crcExtras = COMMON_CRC_EXTRA) {
  const results = frames.map((frame, index) => ({ frameIndex: index + 1, ...verifyMavlinkFrameCrc(frame, crcExtras) }));
  const known = results.filter((item) => item.valid != null);
  const valid = known.filter((item) => item.valid).length;
  const invalid = known.length - valid;
  const unknown = results.filter((item) => item.valid == null).length;
  return {
    frames: results,
    summary: {
      totalFrames: results.length,
      knownCrcExtraFrames: known.length,
      validFrames: valid,
      invalidFrames: invalid,
      unknownCrcExtraFrames: unknown,
      allKnownFramesValid: known.length > 0 ? invalid === 0 : null
    },
    notes: [
      'CRC 按 MAVLink X.25 + CRC_EXTRA 校验；当前只内置本工具已经深度解析的 common.xml 消息子集。',
      'unknown-crc-extra 不代表坏帧，只表示需要对应 dialect 的消息定义。',
      'common.xml CRC mismatch 可能来自传输损坏、错误截帧或自定义/不匹配 dialect；不会自动声称是攻击。'
    ]
  };
}

module.exports = {
  COMMON_CRC_EXTRA,
  crcAccumulate,
  mavlinkCrcX25,
  verifyMavlinkFrameCrc,
  analyzeMavlinkCrc
};
