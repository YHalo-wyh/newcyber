const base = require('./firmware_unpack');
const { scanEmbeddedCaptures } = require('./capture_intelligence');

function extractAscii(buffer, minLength = 6, maxItems = 6000) {
  const items = [];
  let start = -1;
  for (let i = 0; i <= buffer.length; i += 1) {
    const byte = i < buffer.length ? buffer[i] : 0;
    const printable = byte >= 0x20 && byte <= 0x7e;
    if (printable && start < 0) start = i;
    if (!printable && start >= 0) {
      if (i - start >= minLength) items.push({ offset: start, text: buffer.subarray(start, i).toString('ascii') });
      start = -1;
      if (items.length >= maxItems) break;
    }
  }
  return items;
}

const CLUE_RULES = Object.freeze([
  ['credential', /(?:password|passwd|username|admin|root|login|default[_ -]?pass)/i],
  ['wireless', /(?:ssid|wpa|wpa2|psk|wifi|wlan|hostapd)/i],
  ['secret', /(?:private[_ -]?key|signing[_ -]?key|secret|token|api[_ -]?key|mavlink[_ -]?key)/i],
  ['service', /(?:dropbear|sshd|telnetd|httpd|lighttpd|nginx|boa|uhttpd|rtsp|ftp|busybox)/i],
  ['startup', /(?:\/etc\/init\.d|rc\.local|inittab|systemd|procd|init\.rc)/i],
  ['update', /(?:firmware|upgrade|sysupgrade|bootloader|ota|flash|fw_update|image_check|verify_signature)/i],
  ['crypto', /(?:aes|sm4|rsa|ecdsa|sha256|md5|pbkdf2|hkdf|decrypt|encrypt)/i],
  ['uav', /(?:mavlink|ardupilot|px4|qgroundcontrol|mission planner|mavproxy|drone)/i],
  ['config', /(?:\/etc\/shadow|\/etc\/passwd|\/etc\/config\/|dropbear\/|hostapd\.conf|wpa_supplicant)/i]
]);

function classifyStrings(strings) {
  const clues = [];
  for (const item of strings) {
    for (const [kind, regex] of CLUE_RULES) {
      if (!regex.test(item.text)) continue;
      clues.push({ kind, offset: item.offset, offsetHex: `0x${item.offset.toString(16)}`, text: item.text.slice(0, 240) });
      break;
    }
    if (clues.length >= 400) break;
  }
  return clues;
}

function summarizeClues(clues) {
  const counts = {};
  for (const clue of clues) counts[clue.kind] = (counts[clue.kind] || 0) + 1;
  return counts;
}

function captureFinding(item, index) {
  const analysis = item.analysis || {};
  const highlights = analysis.highlights || [];
  const high = (analysis.findings || []).some((finding) => finding.severity === 'high');
  return {
    severity: high ? 'high' : 'medium',
    id: `firmware-embedded-capture-${index + 1}`,
    title: `固件内发现可验证 ${item.format} 抓包`,
    evidence: `${item.offsetHex}-${item.endOffsetHex}, packets=${analysis.packetCount || item.packetCount}, linkTypes=${(analysis.linkTypes || item.linkTypes || []).join(',')}${highlights.length ? `; ${highlights.slice(0, 3).join(' ')}` : ''}`
  };
}

function analyzeFirmwareBuffer(input, options = {}) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  const result = base.analyzeFirmwareBuffer(buffer, options);
  const strings = extractAscii(buffer.subarray(0, Math.min(buffer.length, 32 * 1024 * 1024)));
  const securityStrings = classifyStrings(strings);
  const clueSummary = summarizeClues(securityStrings);
  const nextActions = [...(result.nextActions || [])];

  let embeddedCaptures = [];
  if (options.scanEmbeddedCaptures !== false) {
    embeddedCaptures = scanEmbeddedCaptures(buffer, { source:'firmware-image' });
  }

  if (clueSummary.credential || clueSummary.secret) nextActions.push('发现凭据/密钥相关字符串：按 offset 回看配置与调用上下文，并用抓包/签名/登录证据验证，不直接把字符串当有效密钥。');
  if (clueSummary.service) nextActions.push('发现网络服务线索：解包后优先审计 Web/API、SSH/Telnet、FTP/RTSP 的认证、默认配置和命令执行边界。');
  if (clueSummary.update || clueSummary.crypto) nextActions.push('发现升级/密码学线索：追踪 image_check/verify/decrypt/KDF 到实际 flash 写入路径，重点判断签名校验是否覆盖最终写入内容。');
  if (clueSummary.uav) nextActions.push('发现 UAV/飞控组件字符串：把固件中的端口、参数、签名 key、服务配置与 MAVLink/无线抓包交叉关联。');

  if (embeddedCaptures.length) {
    const packetCount = embeddedCaptures.reduce((sum, item) => sum + (item.analysis?.packetCount || item.packetCount || 0), 0);
    const important = embeddedCaptures.flatMap((item) => item.analysis?.highlights || []).slice(0, 8);
    nextActions.unshift(`已从固件自动切出 ${embeddedCaptures.length} 个抓包（${packetCount} packets）并继续解析协议；优先查看其中的认证材料、MAVLink/CAN、HTTP/FTP/RTSP 和明文敏感信息。`);
    if (important.length) nextActions.unshift(...important);
  }

  const captureArtifacts = embeddedCaptures.map((item) => item.artifact).filter(Boolean);
  const artifacts = [];
  const seenArtifact = new Set();
  for (const artifact of [...(result.artifacts || []), ...captureArtifacts]) {
    if (!artifact?.sha256 || seenArtifact.has(artifact.sha256)) continue;
    seenArtifact.add(artifact.sha256);
    artifacts.push(artifact);
  }

  const findings = [
    ...(result.findings || []),
    ...embeddedCaptures.map(captureFinding),
    ...embeddedCaptures.flatMap((item, captureIndex) => (item.analysis?.findings || []).map((finding) => ({
      ...finding,
      id:`firmware-capture-${captureIndex + 1}:${finding.id}`,
      title:`内嵌抓包：${finding.title}`,
      evidence:`${item.offsetHex}; ${finding.evidence || ''}`
    })))
  ];

  return {
    ...result,
    artifacts,
    findings,
    securityStrings: securityStrings.slice(0, 160),
    clueSummary,
    embeddedCaptures,
    pipeline: {
      stages:[
        { id:'firmware-structure', status:'done', summary:`magic=${result.magic?.length || 0}, structures=${result.structures?.length || 0}` },
        { id:'security-strings', status:'done', summary:`clues=${securityStrings.length}` },
        { id:'embedded-captures', status:'done', summary:`captures=${embeddedCaptures.length}` },
        { id:'capture-intelligence', status:embeddedCaptures.length ? 'done' : 'idle', summary:embeddedCaptures.length ? `packets=${embeddedCaptures.reduce((sum,item)=>sum+(item.analysis?.packetCount || 0),0)}` : 'no validated capture carved' }
      ]
    },
    nextActions: [...new Set(nextActions)]
  };
}

module.exports = { ...base, extractAscii, classifyStrings, analyzeFirmwareBuffer };
