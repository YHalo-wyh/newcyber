(() => {
  const UAV_TOOLS = {
    'uav-recon-analyze': ['无线与服务侦查', '输入 nmap、iw、抓包摘要或服务 banner；输出 Wi-Fi、端口和服务线索。'],
    'uav-spoof-analyze': ['遥测异常', '输入 MAVLink 帧或分析日志；检查 GPS、姿态、电池和状态数据异常。'],
    'uav-dos-analyze': ['阻断 / DoS', '检查 Deauth、链路洪泛、飞行终止、围栏和视频中断证据。'],
    'uav-injection-analyze': ['控制注入', '检查 GCS、模式、返航点、航点、云台和 MAVLink 控制消息。'],
    'uav-leak-analyze': ['日志与泄露', '检查飞行日志、参数、FTP、摄像机流和无线客户端信息。']
  };

  for (const [id, [title, desc]] of Object.entries(UAV_TOOLS)) {
    TOOL_META[id] = { domain:'lowalt', title, placeholder:'粘贴抓包十六进制、日志、nmap/iw 输出或其他题目证据…', label:'输入数据' };
  }
  TOOL_META['firmware-unpack'] = { domain:'lowalt', title:'固件分析', placeholder:'', label:'固件文件' };

  DOMAINS.lowalt.desc = '802.11、MAVLink、GNSS、飞行日志、固件和控制链分析。';
  DOMAINS.lowalt.tools = [
    ['uav-recon-analyze', ...UAV_TOOLS['uav-recon-analyze']],
    ['uav-spoof-analyze', ...UAV_TOOLS['uav-spoof-analyze']],
    ['uav-dos-analyze', ...UAV_TOOLS['uav-dos-analyze']],
    ['uav-injection-analyze', ...UAV_TOOLS['uav-injection-analyze']],
    ['uav-leak-analyze', ...UAV_TOOLS['uav-leak-analyze']],
    ['firmware-unpack', '固件分析', '直接拖入固件：自动识别镜像结构、切出内嵌 PCAP/PCAPNG，并继续解析 Wi-Fi/CAN/MAVLink/HTTP/FTP/RTSP 等重要信息。']
  ];

  const previousToolView = toolView;
  const previousRenderResult = renderResult;

  function firmwareView() {
    const selected = state.toolResult?.fileName;
    const result = state.toolResult?.analysis;
    const recoveredCount = result?.artifacts?.length || 0;
    const captureCount = result?.embeddedCaptures?.length || 0;
    const exportStatus = state.toolResult?.lastFirmwareExport;
    const binwalkStatus = state.toolResult?.lastBinwalkExport;
    return `<div class="page-head tool-head"><div><span class="kicker">FIRMWARE → CAPTURE → EVIDENCE</span><h1>固件自动分析</h1><p>拖入一个固件，先拆结构；发现内嵌抓包后继续解析协议和敏感证据。全程只读，不执行固件。</p></div><button class="button ghost" data-view="lowalt">返回</button></div>
      <div class="workbench"><article class="panel input-panel"><div class="field grow"><label>固件文件</label><div class="file-slot" data-firmware-drop tabindex="0">${selected ? `<b>${esc(selected)}</b><span>${fmtBytes(result?.size)} · ${captureCount ? `已自动发现 ${captureCount} 个抓包` : '可再次拖入替换'}</span>` : '<b>把固件直接拖到这里</b><span>.bin / .img / .fw / .rom / .trx / .ubi / squashfs / 任意二进制；也可以点下面选择</span>'}</div></div><div class="run-row"><span>自动链：固件 → 内嵌文件/抓包 → 协议 → 高价值证据</span><button class="button primary" data-action="choose-firmware">选择固件</button></div></article>
      <article class="panel result-panel"><div class="result-title"><b>分析结果</b><div class="firmware-actions">${result ? `<button class="button" data-action="firmware-export-recovered" ${recoveredCount ? '' : 'disabled'}>导出恢复结果</button><button class="button" data-action="firmware-binwalk">Binwalk 解包到目录</button>` : ''}</div></div>
      ${exportStatus?.ok ? `<div class="export-status"><b>恢复结果已导出</b><span>${esc(exportStatus.outputDir)} · ${exportStatus.files?.length || 0} 个文件 · manifest 已生成</span></div>` : ''}
      ${binwalkStatus?.ok ? `<div class="export-status"><b>Binwalk 已完成</b><span>${esc(binwalkStatus.outputDir)}</span></div>` : ''}
      <div id="tool-result">${state.toolError ? `<div class="error-box">${esc(state.toolError)}</div>` : result ? renderFirmware(result) : '<div class="result-empty">拖入固件即可开始，不需要先选赛道或手动指定格式。</div>'}</div></article></div>`;
  }

  toolView = function uavToolView(tool) {
    if (tool === 'firmware-unpack') return firmwareView();
    return previousToolView(tool);
  };

  function scenarioMatrix(result) {
    const groups = {};
    for (const row of result.matrix || []) (groups[row.categoryName] ||= []).push(row);
    return Object.entries(groups).map(([name, rows]) => `<details class="panel"><summary><b>${esc(name)}</b> · ${rows.filter(x=>x.matched).length}/${rows.length}</summary><div class="knowledge-list">${rows.map(row=>`<article><span>${row.matched ? 'HIT' : 'CHECK'}</span><b>${esc(row.title)}</b><p>${esc(row.action)}</p><small>${esc((row.evidence || []).join(' · '))}</small></article>`).join('')}</div></details>`).join('');
  }

  function telemetryEvidence(result) {
    const telemetry = result.telemetry;
    const control = result.controlFlow;
    let html = '';
    if (telemetry?.anomalies?.length) html += `<details class="panel" open><summary><b>遥测一致性</b> · ${telemetry.anomalies.length}</summary><div class="knowledge-list">${telemetry.anomalies.slice(0,30).map(x=>`<article><span>${esc(x.severity)}</span><b>${esc(x.id)}</b><p>${esc(x.meaning)}</p><small>${esc(x.evidence)}</small></article>`).join('')}</div></details>`;
    if (control?.findings?.length) html += `<details class="panel" open><summary><b>MAVLink 控制链</b> · ${control.findings.length}</summary><div class="knowledge-list">${control.findings.slice(0,30).map(x=>`<article><span>${esc(x.severity)}</span><b>${esc(x.id)}</b><p>${esc(x.message || '')}</p><small>${esc(x.evidence || '')}</small></article>`).join('')}</div></details>`;
    return html;
  }

  renderResult = function uavRenderResult(tool, result) {
    if (!Object.prototype.hasOwnProperty.call(UAV_TOOLS, tool) && tool !== 'uav-challenge-matrix') return previousRenderResult(tool, result);
    const hits = result.hits || [];
    return `<div class="result-stats"><div><b>${hits.length}</b><span>命中</span></div><div><b>${result.coverage?.total || 0}</b><span>检查项</span></div></div>
      ${hits.length ? hits.slice(0,12).map(hit=>`<div class="finding ${hit.confidence >= .8 ? 'high' : hit.confidence >= .6 ? 'medium' : 'info'}"><span>${Math.round(hit.confidence*100)}%</span><div><b>${esc(hit.title)}</b><small>${esc((hit.evidence||[]).join(' · '))}</small><p>${esc(hit.action)}</p></div></div>`).join('') : '<div class="result-empty">未发现高优先级证据。</div>'}
      ${telemetryEvidence(result)}
      ${result.mavlink ? `<details><summary>MAVLink 统计</summary><pre class="mini-pre">${esc(JSON.stringify(result.mavlink.messageCounts,null,2))}</pre></details>` : ''}
      ${scenarioMatrix(result)}`;
  };

  function renderCapture(capture, index) {
    const analysis = capture.analysis || {};
    const network = analysis.network || {};
    const wifi = analysis.wifi || {};
    const can = analysis.can;
    const highlights = analysis.highlights || [];
    const credentials = network.credentials || [];
    const flows = network.topFlows || [];
    const protocolCounts = network.protocolCounts || {};
    const protocolText = Object.entries(protocolCounts).map(([name,count])=>`${name}:${count}`).join(' · ');
    return `<details class="panel" ${index === 0 ? 'open' : ''}><summary><b>${esc(capture.format)} @ ${esc(capture.offsetHex)}</b> · ${analysis.packetCount || capture.packetCount || 0} packets · ${fmtBytes(capture.size)}</summary>
      ${highlights.length ? `<div class="check-list">${highlights.map(x=>`<p>${esc(x)}</p>`).join('')}</div>` : ''}
      <div class="result-stats"><div><b>${analysis.packetCount || capture.packetCount || 0}</b><span>Packets</span></div><div><b>${(analysis.linkTypes || capture.linkTypes || []).join(',') || '—'}</b><span>LinkType</span></div><div><b>${credentials.length}</b><span>认证材料</span></div><div><b>${network.rtspEndpoints?.length || 0}</b><span>RTSP</span></div></div>
      ${protocolText ? `<p class="notice">协议：${esc(protocolText)}</p>` : ''}
      ${wifi.networks?.length ? `<details><summary>Wi-Fi / 802.11 · ${wifi.networks.length} AP</summary>${table(['SSID','BSSID','安全','信道'], wifi.networks.slice(0,80).map(x=>[x.ssid || '<hidden>',x.bssid || '—',x.security || '—',x.channel ?? '—']))}</details>` : ''}
      ${credentials.length ? `<details open><summary>明文认证材料 · ${credentials.length}</summary>${table(['Packet','类型','值','Flow'], credentials.slice(0,80).map(x=>[x.packetIndex,x.type,x.value,x.flow]))}</details>` : ''}
      ${network.rtspEndpoints?.length ? `<details open><summary>RTSP / 图传端点 · ${network.rtspEndpoints.length}</summary><div class="check-list">${network.rtspEndpoints.slice(0,80).map(x=>`<p>${esc(x)}</p>`).join('')}</div></details>` : ''}
      ${network.httpRequests?.length ? `<details><summary>HTTP 请求 · ${network.httpRequests.length}</summary>${table(['Packet','方法','Host','Path'], network.httpRequests.slice(0,100).map(x=>[x.packetIndex,x.method,x.host || '—',x.path]))}</details>` : ''}
      ${flows.length ? `<details><summary>Top flows · ${flows.length}</summary>${table(['服务','Flow','Packets','Payload'], flows.slice(0,60).map(x=>[x.service,x.flow,x.packets,fmtBytes(x.payloadBytes)]))}</details>` : ''}
      ${network.mavlink?.parsedFrames ? `<details open><summary>MAVLink · ${network.mavlink.parsedFrames} frames</summary><pre class="mini-pre">${esc(JSON.stringify({messageCounts:network.mavlink.messageCounts,securitySummary:network.mavlink.securitySummary,highRiskEvents:network.mavlink.highRiskEvents?.slice(0,20)},null,2))}</pre></details>` : ''}
      ${can?.parsedFrames ? `<details open><summary>CAN / ISO-TP / UDS · ${can.parsedFrames} frames</summary><p class="notice">CAN ID ${can.uniqueIds || 0} · 高变化候选 ${(can.eventCandidates || []).length}</p></details>` : ''}
      ${capture.artifact ? `<button class="button" data-capture-artifact="${index}">导出这个抓包</button>` : `<p class="notice">抓包已解析，但体积超过内置单文件导出上限；可用 Binwalk/外部 carving 按 offset 提取。</p>`}
    </details>`;
  }

  function renderFirmware(result) {
    const vendor = result.vendor ? `${result.vendor.vendor} ${result.vendor.version}` : '未识别';
    const magic = (result.magic || []).slice(0,40);
    const artifacts = result.artifacts || [];
    const clues = result.securityStrings || [];
    const actions = result.nextActions || [];
    const captures = result.embeddedCaptures || [];
    const pipeline = result.pipeline?.stages || [];
    return `<div class="result-stats"><div><b>${fmtBytes(result.size)}</b><span>大小</span></div><div><b>${result.entropy}</b><span>熵</span></div><div><b>${captures.length}</b><span>内嵌抓包</span></div><div><b>${artifacts.length}</b><span>可导出产物</span></div></div>
      <div class="firmware-meta"><span>容器</span><b>${esc(vendor)}</b></div>
      ${pipeline.length ? `<div class="check-list">${pipeline.map(stage=>`<p><b>${esc(stage.status === 'done' ? '✓' : '·')} ${esc(stage.id)}</b> · ${esc(stage.summary)}</p>`).join('')}</div>` : ''}
      ${(result.findings||[]).map(x=>`<div class="finding ${x.severity}"><span>${esc(x.severity)}</span><div><b>${esc(x.title)}</b><small>${esc(x.evidence)}</small></div></div>`).join('')}
      ${captures.length ? `<section><div class="result-title"><b>自动解析出的抓包</b><span>${captures.length} 个</span></div>${captures.map(renderCapture).join('')}</section>` : '<p class="notice">镜像中未直接切出可验证 PCAP/PCAPNG；如果抓包位于压缩 rootfs 内，可先点 Binwalk 解包，下一步会把解包目录继续自动递归扫描。</p>'}
      ${magic.length ? `<details class="panel"><summary><b>文件结构</b> · ${magic.length}</summary>${table(['偏移','类型'], magic.map(x=>[x.offsetHex,x.name]))}</details>` : ''}
      ${clues.length ? `<details class="panel"><summary><b>字符串线索</b> · ${clues.length}</summary>${table(['偏移','类型','字符串'], clues.slice(0,100).map(x=>[x.offsetHex,x.kind,x.text]))}</details>` : ''}
      ${artifacts.length ? `<details class="panel"><summary><b>可导出恢复段</b> · ${artifacts.length}</summary><div class="knowledge-list firmware-artifacts">${artifacts.map((a,i)=>`<article><span>${a.metadata?.kind === 'embedded-capture' ? 'CAPTURE' : 'SEGMENT'}</span><b>${esc(a.name)}</b><p>${fmtBytes(a.size)} · SHA-256 ${esc(a.sha256.slice(0,16))}…</p><button class="button" data-firmware-artifact="${i}">单独导出</button></article>`).join('')}</div></details>` : '<p class="notice">当前没有满足完整性条件的内置恢复段，可尝试 Binwalk 解包。</p>'}
      ${actions.length ? `<details class="panel" open><summary><b>下一步</b> · ${actions.length}</summary><div class="check-list">${actions.map(x=>`<p>${esc(x)}</p>`).join('')}</div></details>` : ''}`;
  }

  async function analyzeDroppedFirmware(file) {
    if (!file) return;
    state.toolError = null;
    state.toolResult = null;
    render();
    try {
      state.toolResult = await window.newcyber.analyzeDroppedFirmware(file);
      if (state.toolResult) toast(`已完成 ${state.toolResult.fileName} 自动分析`);
    } catch (error) {
      state.toolResult = null;
      state.toolError = error?.message || String(error);
    }
    render();
  }

  document.addEventListener('dragover', (event) => {
    const drop = event.target.closest?.('[data-firmware-drop]');
    if (!drop) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
    drop.classList.add('is-dragging');
  });

  document.addEventListener('dragleave', (event) => {
    const drop = event.target.closest?.('[data-firmware-drop]');
    if (drop) drop.classList.remove('is-dragging');
  });

  document.addEventListener('drop', (event) => {
    const drop = event.target.closest?.('[data-firmware-drop]');
    if (!drop) return;
    event.preventDefault();
    drop.classList.remove('is-dragging');
    const file = event.dataTransfer?.files?.[0];
    analyzeDroppedFirmware(file);
  });

  document.addEventListener('click', async (event) => {
    const choose = event.target.closest('[data-action="choose-firmware"]');
    if (choose) {
      choose.disabled = true;
      try { state.toolError = null; state.toolResult = await window.newcyber.chooseAndAnalyzeFirmware(); }
      catch (error) { state.toolResult = null; state.toolError = error?.message || String(error); }
      finally { choose.disabled = false; render(); }
      return;
    }

    const exportRecovered = event.target.closest('[data-action="firmware-export-recovered"]');
    if (exportRecovered) {
      exportRecovered.disabled = true;
      try {
        const outcome = await window.newcyber.exportFirmwareRecovered(state.toolResult?.filePath);
        if (outcome?.ok) {
          state.toolResult.lastFirmwareExport = outcome;
          toast(`已导出 ${outcome.files?.length || 0} 个恢复文件`);
          render();
        } else if (outcome) toast(outcome.error || '没有可导出的恢复结果', true);
      } catch (error) { toast(error?.message || '导出失败', true); }
      finally { if (exportRecovered.isConnected) exportRecovered.disabled = false; }
      return;
    }

    const extract = event.target.closest('[data-action="firmware-binwalk"]');
    if (extract) {
      extract.disabled = true;
      try {
        const outcome = await window.newcyber.extractFirmwareWithBinwalk(state.toolResult?.filePath);
        if (outcome?.ok) {
          state.toolResult.lastBinwalkExport = outcome;
          toast(`Binwalk 已解包到 ${outcome.outputDir}`);
          render();
        } else if (outcome) toast(outcome.error || '解包未完成', true);
      } catch (error) { toast(error?.message || '解包失败', true); }
      finally { if (extract.isConnected) extract.disabled = false; }
      return;
    }

    const captureArtifactButton = event.target.closest('[data-capture-artifact]');
    if (captureArtifactButton) {
      const capture = state.toolResult?.analysis?.embeddedCaptures?.[Number(captureArtifactButton.dataset.captureArtifact)];
      if (!capture?.artifact) return;
      captureArtifactButton.disabled = true;
      try { const saved = await window.newcyber.saveArtifact(capture.artifact); if (saved?.filePath) toast(`已导出 ${capture.artifact.name}`); }
      catch (error) { toast(error?.message || '导出失败', true); }
      finally { captureArtifactButton.disabled = false; }
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
