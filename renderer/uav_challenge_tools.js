(() => {
  const UAV_TOOLS = {
    'uav-recon-analyze': ['侦查与暴露面分析', '粘贴 nmap/iw/抓包摘要/服务 banner，归并 Wi-Fi、端口、指纹和嗅探线索。'],
    'uav-spoof-analyze': ['飞控遥测欺骗分析', '粘贴 MAVLink 十六进制流或分析日志，检查姿态/GPS/电池/状态/VFR_HUD 欺骗候选。'],
    'uav-dos-analyze': ['拒绝服务与状态阻断', '分析围栏、Deauth、GPS 偏移、终止飞行、视频中断、阻止起飞和链路洪泛证据。'],
    'uav-injection-analyze': ['控制注入与接管', '分析 GCS spoof、模式/返航点/云台/传感器/MAVLink/航点/机载主机注入链。'],
    'uav-leak-analyze': ['信息泄露与取证', '分析飞行日志、参数、Wi-Fi 客户端、FTP 和摄像机流泄露证据。']
  };

  for (const [id, [title, desc]] of Object.entries(UAV_TOOLS)) {
    TOOL_META[id] = { domain:'lowalt', title, placeholder:'粘贴抓包十六进制、日志、nmap/iw 输出或其他题目证据…', label:'题目证据 / 抓包 / 日志' };
  }
  TOOL_META['firmware-unpack'] = { domain:'lowalt', title:'固件结构分析 / 解包', placeholder:'', label:'固件文件' };

  DOMAINS.lowalt.desc = '飞控协议、无线链路、控制注入、信息泄露、飞行取证与固件。按攻击面恢复证据链，而不是只识别几个 MAVLink 消息。';
  DOMAINS.lowalt.tools = [
    ['uav-recon-analyze', ...UAV_TOOLS['uav-recon-analyze']],
    ['uav-spoof-analyze', ...UAV_TOOLS['uav-spoof-analyze']],
    ['uav-dos-analyze', ...UAV_TOOLS['uav-dos-analyze']],
    ['uav-injection-analyze', ...UAV_TOOLS['uav-injection-analyze']],
    ['uav-leak-analyze', ...UAV_TOOLS['uav-leak-analyze']],
    ['firmware-unpack', '固件结构分析 / 解包', '选固件文件，识别厂商头、kernel/rootfs/bootloader、文件系统、凭据/服务/更新线索并导出可验证 segment；可选调用本机 binwalk 递归解包。']
  ];

  const previousToolView = toolView;
  const previousRenderResult = renderResult;

  function firmwareView() {
    const selected = state.toolResult?.fileName;
    const result = state.toolResult?.analysis;
    return `<div class="page-head tool-head"><div><span class="kicker">FIRMWARE WORKBENCH</span><h1>固件结构分析 / 解包</h1><p>结构识别 → segment 恢复 → rootfs 解包 → 配置/密钥/服务/升级链审计。</p></div><button class="button ghost" data-view="lowalt">返回</button></div>
      <div class="workbench"><article class="panel input-panel"><div class="field grow"><label>固件文件</label><div class="result-empty">${selected ? `当前：${esc(selected)}` : '选择 .bin / .img / .fw / .rom / .trx / .ubi / squashfs 等文件。'}</div></div><div class="run-row"><span>按容器、文件系统和可验证 carve 结果组织证据</span><button class="button primary" data-action="choose-firmware">选择并分析</button></div></article>
      <article class="panel result-panel"><div class="result-title"><b>结果</b>${state.toolResult ? '<button class="text-button" data-action="firmware-binwalk">Binwalk 递归解包</button>' : ''}</div><div id="tool-result">${state.toolError ? `<div class="error-box">${esc(state.toolError)}</div>` : result ? renderFirmware(result) : '<div class="result-empty">等待选择固件。</div>'}</div></article></div>`;
  }

  toolView = function uavToolView(tool) {
    if (tool === 'firmware-unpack') return firmwareView();
    return previousToolView(tool);
  };

  function scenarioMatrix(result) {
    const groups = {};
    for (const row of result.matrix || []) (groups[row.categoryName] ||= []).push(row);
    return Object.entries(groups).map(([name, rows]) => `<details class="panel"><summary><b>${esc(name)}</b> · ${rows.filter(x=>x.matched).length}/${rows.length} 命中</summary><div class="knowledge-list">${rows.map(row=>`<article><span>${row.matched ? 'CHECK' : 'PLAYBOOK'}</span><b>${esc(row.title)}</b><p>${esc(row.action)}</p><small>${esc((row.evidence || []).join(' · '))}</small></article>`).join('')}</div></details>`).join('');
  }

  function telemetryEvidence(result) {
    const telemetry = result.telemetry;
    const control = result.controlFlow;
    let html = '';
    if (telemetry?.anomalies?.length) html += `<details class="panel" open><summary><b>遥测物理一致性</b> · ${telemetry.anomalies.length} 异常</summary><div class="knowledge-list">${telemetry.anomalies.slice(0,30).map(x=>`<article><span>${esc(x.severity)}</span><b>${esc(x.id)}</b><p>${esc(x.meaning)}</p><small>${esc(x.evidence)}</small></article>`).join('')}</div></details>`;
    if (control?.findings?.length) html += `<details class="panel" open><summary><b>MAVLink 控制状态机</b> · ${control.findings.length} 证据</summary><div class="knowledge-list">${control.findings.slice(0,30).map(x=>`<article><span>${esc(x.severity)}</span><b>${esc(x.id)}</b><p>${esc(x.message || '')}</p><small>${esc(x.evidence || '')}</small></article>`).join('')}</div></details>`;
    return html;
  }

  renderResult = function uavRenderResult(tool, result) {
    if (!Object.prototype.hasOwnProperty.call(UAV_TOOLS, tool) && tool !== 'uav-challenge-matrix') return previousRenderResult(tool, result);
    const hits = result.hits || [];
    return `<div class="result-stats"><div><b>${hits.length}</b><span>优先验证</span></div><div><b>${result.coverage?.total || 0}</b><span>题型覆盖</span></div></div>
      ${hits.length ? hits.slice(0,12).map(hit=>`<div class="finding ${hit.confidence >= .8 ? 'high' : hit.confidence >= .6 ? 'medium' : 'info'}"><span>${Math.round(hit.confidence*100)}%</span><div><b>${esc(hit.title)}</b><small>${esc((hit.evidence||[]).join(' · '))}</small><p>${esc(hit.action)}</p></div></div>`).join('') : '<div class="result-empty">当前证据没有形成高价值命中；可继续加入抓包、日志或服务扫描结果。</div>'}
      ${telemetryEvidence(result)}
      ${result.mavlink ? `<details><summary>MAVLink 统计</summary><pre class="mini-pre">${esc(JSON.stringify(result.mavlink.messageCounts,null,2))}</pre></details>` : ''}
      ${scenarioMatrix(result)}`;
  };

  function renderFirmware(result) {
    const vendor = result.vendor ? `${result.vendor.vendor} ${result.vendor.version}` : '未识别厂商头';
    const magic = (result.magic || []).slice(0,40);
    const artifacts = result.artifacts || [];
    const clues = result.securityStrings || [];
    return `<div class="result-stats"><div><b>${fmtBytes(result.size)}</b><span>固件大小</span></div><div><b>${result.entropy}</b><span>前 1MiB 熵</span></div><div><b>${magic.length}</b><span>Magic 命中</span></div><div><b>${artifacts.length}</b><span>可导出段</span></div></div>
      <p class="notice"><b>容器：</b>${esc(vendor)}</p>
      ${(result.findings||[]).map(x=>`<div class="finding ${x.severity}"><span>${esc(x.severity)}</span><div><b>${esc(x.title)}</b><small>${esc(x.evidence)}</small></div></div>`).join('')}
      ${table(['偏移','类型'], magic.map(x=>[x.offsetHex,x.name]))}
      ${clues.length ? `<details class="panel" open><summary><b>固件配置 / 凭据 / 服务线索</b> · ${clues.length}</summary>${table(['偏移','类型','字符串'], clues.slice(0,100).map(x=>[x.offsetHex,x.kind,x.text]))}</details>` : ''}
      ${artifacts.length ? `<div class="knowledge-list">${artifacts.map((a,i)=>`<article><span>ARTIFACT</span><b>${esc(a.name)}</b><p>${fmtBytes(a.size)} · SHA256 ${esc(a.sha256.slice(0,16))}…</p><button class="button" data-firmware-artifact="${i}">导出</button></article>`).join('')}</div>` : ''}
      ${(result.nextActions||[]).map(x=>`<p class="notice">${esc(x)}</p>`).join('')}`;
  }

  document.addEventListener('click', async (event) => {
    const choose = event.target.closest('[data-action="choose-firmware"]');
    if (choose) {
      choose.disabled = true;
      try { state.toolError = null; state.toolResult = await window.newcyber.chooseAndAnalyzeFirmware(); }
      catch (error) { state.toolResult = null; state.toolError = error?.message || String(error); }
      finally { choose.disabled = false; render(); }
      return;
    }
    const extract = event.target.closest('[data-action="firmware-binwalk"]');
    if (extract) {
      extract.disabled = true;
      try {
        const outcome = await window.newcyber.extractFirmwareWithBinwalk(state.toolResult?.filePath);
        if (outcome?.ok) toast(`已解包到 ${outcome.outputDir}`);
        else if (outcome) toast(outcome.error || '解包未完成', true);
      } catch (error) { toast(error?.message || '解包失败', true); }
      finally { extract.disabled = false; }
      return;
    }
    const artifactButton = event.target.closest('[data-firmware-artifact]');
    if (artifactButton) {
      const artifact = state.toolResult?.analysis?.artifacts?.[Number(artifactButton.dataset.firmwareArtifact)];
      if (!artifact) return;
      artifactButton.disabled = true;
      try { const saved = await window.newcyber.saveArtifact(artifact); if (saved?.filePath) toast(`已导出 ${artifact.name}`); }
      catch (error) { toast(error?.message || '导出失败', true); }
      finally { artifactButton.disabled = false; }
    }
  });

  render();
})();
