(() => {
  TOOL_META['uav-wifi-evidence'] = { domain:'lowalt', title:'Wi-Fi 破解 / 握手证据', placeholder:'粘贴 iw / airodump / aircrack / hashcat / 抓包摘要，例如 SSID、BSSID、EAPOL、PMKID、Deauth、KEY FOUND…', label:'无线证据 / 离线验证日志' };
  TOOL_META['uav-flight-log'] = { domain:'lowalt', title:'飞行日志提取 / 时间线', placeholder:'粘贴 ArduPilot DataFlash 文本日志（FMT/ATT/GPS/MODE/PARM/ERR/EV…）', label:'飞行日志' };

  const extraTools = [
    ['uav-wifi-evidence','Wi-Fi 破解 / 握手证据','整理 SSID/BSSID/认证方式、EAPOL/PMKID、Deauth 与离线口令候选；不主动发射无线攻击。'],
    ['uav-flight-log','飞行日志提取 / 时间线','解析 DataFlash 文本日志，提取模式、GPS、姿态、参数、错误/事件并建立时间线。']
  ];
  const existing = new Set((DOMAINS.lowalt.tools || []).map((x)=>x[0]));
  for (const row of extraTools) if (!existing.has(row[0])) DOMAINS.lowalt.tools.splice(Math.max(0,DOMAINS.lowalt.tools.length-1),0,row);

  const previousRenderResult = renderResult;

  function wifiResult(result) {
    const networks=result.networks||[], handshakes=result.handshakes||[], deauth=result.deauth||[], keys=result.crackResults||[];
    return `<div class="result-stats"><div><b>${networks.length}</b><span>无线网络</span></div><div><b>${handshakes.length}</b><span>握手/PMKID</span></div><div><b>${deauth.length}</b><span>Deauth</span></div><div><b>${keys.length}</b><span>口令候选</span></div></div>
      ${networks.length ? table(['SSID','BSSID','信道','认证'],networks.map(x=>[x.ssid||'—',x.bssid||'—',x.channel??'—',x.security||'—'])) : ''}
      ${handshakes.length ? `<div class="knowledge-list">${handshakes.map(x=>`<article><span>OFFLINE</span><b>${esc(x.id)}</b><p>置信度 ${Math.round(x.confidence*100)}%</p></article>`).join('')}</div>` : ''}
      ${keys.length ? `<details class="panel" open><summary><b>日志中的口令 / PSK 候选</b></summary>${table(['行','候选','原始证据'],keys.slice(0,30).map(x=>[x.line,x.candidate,x.evidence]))}<p class="notice">候选必须用握手或受控环境验证，不能仅凭日志文本宣称破解成功。</p></details>` : ''}
      ${deauth.length ? `<details class="panel"><summary><b>Deauth / Disassociation 时间点</b> · ${deauth.length}</summary>${table(['行','证据'],deauth.slice(0,60).map(x=>[x.line,x.evidence]))}</details>` : ''}`;
  }

  function flightLogResult(result) {
    const counts=Object.entries(result.messageCounts||{}).sort((a,b)=>b[1]-a[1]);
    const range=result.timeRange;
    return `<div class="result-stats"><div><b>${esc(result.format||'unknown')}</b><span>日志格式</span></div><div><b>${result.gps?.length||0}</b><span>GPS</span></div><div><b>${result.attitude?.length||0}</b><span>姿态</span></div><div><b>${result.events?.length||0}</b><span>事件/错误</span></div></div>
      ${range ? `<p class="notice"><b>时间范围：</b>${range.startSec.toFixed(3)}s → ${range.endSec.toFixed(3)}s，持续 ${range.durationSec.toFixed(3)}s</p>` : ''}
      ${counts.length ? table(['消息','数量'],counts.slice(0,40)) : ''}
      ${result.modes?.length ? `<details class="panel" open><summary><b>飞行模式变化</b> · ${result.modes.length}</summary><pre class="mini-pre">${esc(JSON.stringify(result.modes.slice(0,30),null,2))}</pre></details>` : ''}
      ${result.params?.length ? `<details class="panel"><summary><b>参数记录</b> · ${result.params.length}</summary><pre class="mini-pre">${esc(JSON.stringify(result.params.slice(0,50),null,2))}</pre></details>` : ''}
      ${result.events?.length ? `<details class="panel"><summary><b>错误 / 事件 / 状态文本</b> · ${result.events.length}</summary><pre class="mini-pre">${esc(JSON.stringify(result.events.slice(0,50),null,2))}</pre></details>` : ''}`;
  }

  function batch8Evidence(result) {
    const control=result?.controlFlow;
    let html='';
    if (control?.geofenceTransactions?.length) html += `<details class="panel" open><summary><b>地理围栏变更事务</b> · ${control.geofenceTransactions.length}</summary>${table(['参数','请求值','写入源','签名','回读','确认'],control.geofenceTransactions.slice(0,40).map(x=>[x.paramId,x.requestedValue,x.writer,x.signed?'signed':'unsigned',x.confirmation?.value??'无回读',x.confirmed===true?'一致':x.confirmed===false?'不一致':'未知']))}</details>`;
    if (control?.gcsProfiles?.length) html += `<details class="panel" open><summary><b>GCS 控制源画像</b> · ${control.gcsProfiles.length}</summary>${table(['控制源','控制事件','signed','unsigned','目标'],control.gcsProfiles.slice(0,30).map(x=>[x.stream,x.controlEvents,x.signed,x.unsigned,Object.keys(x.targets||{}).join(',')||'—']))}</details>`;
    if (result?.wifi) html += `<details class="panel"><summary><b>Wi-Fi 证据</b></summary>${wifiResult(result.wifi)}</details>`;
    if (result?.flightLog) html += `<details class="panel"><summary><b>飞行日志证据</b></summary>${flightLogResult(result.flightLog)}</details>`;
    return html;
  }

  renderResult = function batch8RenderResult(tool,result) {
    if (tool==='uav-wifi-evidence') return wifiResult(result);
    if (tool==='uav-flight-log') return flightLogResult(result);
    const html=previousRenderResult(tool,result);
    if (!['uav-recon-analyze','uav-spoof-analyze','uav-dos-analyze','uav-injection-analyze','uav-leak-analyze','uav-challenge-matrix'].includes(tool)) return html;
    return html + batch8Evidence(result);
  };

  render();
})();
