const { parseMavlinkFrames, verifyMavlink2Signature } = require('./low_altitude');

function parseVerifierInput(input) {
  const text = String(input || '').trim();
  if (!text) throw new Error('输入为空');
  let key = null;
  let frame = null;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const keyMatch = trimmed.match(/^(?:key|signing[_ -]?key)\s*[:=]\s*(?:0x)?([0-9a-f]{64})$/i);
    if (keyMatch) { key = keyMatch[1]; continue; }
    const frameMatch = trimmed.match(/^(?:frame|packet|mavlink)\s*[:=]\s*(?:0x)?([0-9a-f\s:.-]+)$/i);
    if (frameMatch) { frame = frameMatch[1].replace(/[^0-9a-f]/gi, ''); continue; }
    if (!key && /^(?:0x)?[0-9a-f]{64}$/i.test(trimmed)) { key = trimmed.replace(/^0x/i, ''); continue; }
    if (!frame && /^(?:0x)?[0-9a-f\s:.-]{20,}$/i.test(trimmed)) frame = trimmed.replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '');
  }
  if (!key) throw new Error('缺少 32-byte signing key（64 hex chars）');
  if (!frame) throw new Error('缺少 MAVLink2 signed frame hex');
  return { key, frame };
}

function verifyMavlinkSignatureInput(input) {
  const parsed = parseVerifierInput(input);
  const frames = parseMavlinkFrames(parsed.frame);
  const signed = frames.filter((frame) => frame.version === 2 && frame.signed);
  if (!signed.length) throw new Error('未解析到 signed MAVLink2 frame');
  const results = signed.map((frame, index) => ({
    index: index + 1,
    sysid: frame.sysid,
    compid: frame.compid,
    seq: frame.seq,
    msgid: frame.msgid,
    ...verifyMavlink2Signature(frame, parsed.key)
  }));
  return {
    frames: results,
    validFrames: results.filter((item) => item.valid).length,
    invalidFrames: results.filter((item) => !item.valid).length,
    allValid: results.every((item) => item.valid),
    keySha256: require('crypto').createHash('sha256').update(Buffer.from(parsed.key, 'hex')).digest('hex'),
    note: '离线验证公式：SHA-256(secret_key + MAVLink2 frame through CRC + link_id + 48-bit timestamp) 的前 6 字节。只验证签名匹配，不代表该密钥的使用/授权范围合理。'
  };
}

module.exports = { parseVerifierInput, verifyMavlinkSignatureInput };
