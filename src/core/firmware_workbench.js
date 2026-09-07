const base = require('./firmware_unpack');

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

function analyzeFirmwareBuffer(input, options = {}) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  const result = base.analyzeFirmwareBuffer(buffer, options);
  const strings = extractAscii(buffer.subarray(0, Math.min(buffer.length, 32 * 1024 * 1024)));
  const securityStrings = classifyStrings(strings);
  const clueSummary = summarizeClues(securityStrings);
  const nextActions = [...(result.nextActions || [])];

  if (clueSummary.credential || clueSummary.secret) nextActions.push('发现凭据/密钥相关字符串：按 offset 回看配置与调用上下文，并用抓包/签名/登录证据验证，不直接把字符串当有效密钥。');
  if (clueSummary.service) nextActions.push('发现网络服务线索：解包后优先审计 Web/API、SSH/Telnet、FTP/RTSP 的认证、默认配置和命令执行边界。');
  if (clueSummary.update || clueSummary.crypto) nextActions.push('发现升级/密码学线索：追踪 image_check/verify/decrypt/KDF 到实际 flash 写入路径，重点判断签名校验是否覆盖最终写入内容。');
  if (clueSummary.uav) nextActions.push('发现 UAV/飞控组件字符串：把固件中的端口、参数、签名 key、服务配置与 MAVLink/无线抓包交叉关联。');

  return {
    ...result,
    securityStrings: securityStrings.slice(0, 160),
    clueSummary,
    nextActions: [...new Set(nextActions)]
  };
}

module.exports = { ...base, extractAscii, classifyStrings, analyzeFirmwareBuffer };
