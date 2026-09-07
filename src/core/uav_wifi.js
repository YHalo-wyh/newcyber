const HANDSHAKE_PATTERNS = Object.freeze([
  { id:'wpa-handshake', regex:/\b(?:WPA(?:2)?\s+handshake|4-way\s+handshake|EAPOL)\b/i, confidence:0.95 },
  { id:'pmkid', regex:/\bPMKID\b/i, confidence:0.95 },
  { id:'sae', regex:/\b(?:SAE|WPA3)\b/i, confidence:0.8 }
]);

function normalizeMac(value) {
  const raw = String(value || '').replace(/[^0-9a-f]/gi,'').toLowerCase();
  return raw.length === 12 ? raw.match(/../g).join(':') : null;
}

function cleanSsid(value) {
  const text=String(value||'').trim();
  if (!text) return null;
  return text.split(/\s{2,}|\s+(?=(?:channel|ch)\b)|\s+(?=WPA3?\b)|\s+(?=WEP\b)|\s+(?=OPEN\b)/i)[0].trim() || null;
}

function parseWifiEvidence(input) {
  const text = String(input || '');
  const networks = [];
  const seen = new Set();
  const lines = text.split(/\r?\n/);

  for (const line of lines) {
    const bssidMatch = line.match(/(?:BSSID|AP|Access\s+Point)\s*[:=]?\s*([0-9a-f]{2}(?::|-)[0-9a-f]{2}(?:(?::|-)[0-9a-f]{2}){4})/i)
      || line.match(/\b([0-9a-f]{2}(?::|-)[0-9a-f]{2}(?:(?::|-)[0-9a-f]{2}){4})\b/i);
    const ssidMatch = line.match(/(?:ESSID|SSID)\s*[:=]\s*["']?([^"'\t,]+)["']?/i);
    const channelMatch = line.match(/(?:channel|ch)\s*[:=]?\s*(\d{1,3})/i);
    const cryptoMatch = line.match(/\b(WPA3|WPA2|WPA|WEP|OPN|OPEN)\b/i);
    if (!bssidMatch && !ssidMatch) continue;
    const bssid = normalizeMac(bssidMatch?.[1]);
    const ssid = cleanSsid(ssidMatch?.[1]);
    const key = `${bssid || '?'}|${ssid || '?'}`;
    if (seen.has(key)) continue;
    seen.add(key);
    networks.push({ bssid, ssid, channel: channelMatch ? Number(channelMatch[1]) : null, security: cryptoMatch?.[1]?.toUpperCase() || null, evidence: line.trim().slice(0,300) });
  }

  const handshakes = HANDSHAKE_PATTERNS
    .filter((rule)=>rule.regex.test(text))
    .map((rule)=>({ id:rule.id, confidence:rule.confidence }));

  const deauth = [];
  for (const [index,line] of lines.entries()) {
    if (/\b(?:deauth|deauthentication|disassoc|disassociation)\b/i.test(line)) {
      deauth.push({ line:index + 1, evidence:line.trim().slice(0,300) });
    }
  }

  const crackResults = [];
  for (const [index,line] of lines.entries()) {
    const keyMatch = line.match(/(?:KEY\s+FOUND|password|passphrase|psk)\s*[!:\]= -]+\s*[\["']?\s*([^\]"'\s]{4,128})/i);
    if (keyMatch) crackResults.push({ line:index + 1, candidate:keyMatch[1], evidence:line.trim().slice(0,300) });
  }

  const findings = [];
  if (handshakes.some((x)=>x.id==='wpa-handshake')) findings.push({ id:'wifi-handshake-captured', severity:'info', evidence:'WPA/EAPOL handshake evidence present', meaning:'已具备离线口令验证材料；下一步应先确认 BSSID/SSID/客户端与握手完整性。' });
  if (handshakes.some((x)=>x.id==='pmkid')) findings.push({ id:'wifi-pmkid-captured', severity:'info', evidence:'PMKID evidence present', meaning:'检测到 PMKID，可用于离线候选口令验证；不要把存在 PMKID 等同于已破解。' });
  if (deauth.length) findings.push({ id:'wifi-deauth-observed', severity:'medium', evidence:`events=${deauth.length}`, meaning:'发现 Deauthentication/Disassociation 证据；结合时间线判断是否用于强制重连或 DoS。' });
  if (crackResults.length) findings.push({ id:'wifi-key-candidate', severity:'medium', evidence:`candidates=${crackResults.length}`, meaning:'日志中出现口令/PSK 候选；仍需用握手或实际认证验证。' });

  return {
    networks,
    handshakes,
    deauth,
    crackResults,
    findings,
    notes:[
      '该工具只整理抓包/aircrack/hashcat/iw 等现有证据，不主动发射 Deauth，也不对真实无线网络执行在线攻击。',
      '候选密码必须通过离线握手或受控测试环境验证，日志文本本身不等同于真实密钥。'
    ]
  };
}

module.exports = { normalizeMac, cleanSsid, parseWifiEvidence };
