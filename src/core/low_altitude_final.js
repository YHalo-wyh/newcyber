const base = require('./low_altitude');
const { reconstructMavFtpFiles } = require('./mavlink_ftp_reassembly');
const { analyzeMavlinkCrc } = require('./mavlink_crc');

function analyzeMavlinkAdvanced(input) {
  const result = base.analyzeMavlinkAdvanced(input);
  const ftpReassembly = reconstructMavFtpFiles(result.ftpEvents || []);
  const rawFrames = base.parseMavlinkFrames(input);
  const crcEvidence = analyzeMavlinkCrc(rawFrames);
  const findings = [...(result.findings || [])];
  if (crcEvidence.summary.invalidFrames) findings.push({
    severity: 'medium',
    id: 'mavlink-common-crc-mismatch',
    title: 'MAVLink common.xml CRC 校验失败',
    count: crcEvidence.summary.invalidFrames,
    evidence: crcEvidence.frames.filter((item) => item.valid === false).slice(0, 12)
  });
  if (crcEvidence.summary.unknownCrcExtraFrames) findings.push({
    severity: 'info',
    id: 'mavlink-crc-extra-unknown',
    title: '部分 MAVLink 消息需要额外 dialect CRC 定义',
    count: crcEvidence.summary.unknownCrcExtraFrames,
    evidence: crcEvidence.frames.filter((item) => item.status === 'unknown-crc-extra').slice(0, 12).map((item) => ({ frameIndex: item.frameIndex, msgid: item.msgid, wireCrc: item.wireCrc }))
  });
  return {
    ...result,
    frames: (result.frames || []).map((frame, index) => ({ ...frame, crc: crcEvidence.frames[index] || null })),
    findings,
    ftpReassembly,
    crcEvidence: {
      summary: crcEvidence.summary,
      frames: crcEvidence.frames.slice(0, 500),
      notes: crcEvidence.notes
    },
    securitySummary: {
      ...(result.securitySummary || {}),
      ftpCompleteFiles: ftpReassembly.completeFiles,
      ftpExportableFiles: ftpReassembly.exportableFiles,
      crcKnownFrames: crcEvidence.summary.knownCrcExtraFrames,
      crcValidFrames: crcEvidence.summary.validFrames,
      crcInvalidFrames: crcEvidence.summary.invalidFrames,
      crcUnknownExtraFrames: crcEvidence.summary.unknownCrcExtraFrames
    },
    note: `${result.note || ''} 已对内置 common.xml 消息子集执行 X.25 + CRC_EXTRA 确定性校验；未知 dialect 不猜 CRC_EXTRA。`.trim()
  };
}

module.exports = { ...base, analyzeMavlinkAdvanced, reconstructMavFtpFiles, analyzeMavlinkCrc };
