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
    ['firmware-unpack', '固件分析', '选择固件文件，识别镜像段和文件系统；完整恢复段可直接导出，也可调用本机 Binwalk 解包到目录。']
  ];

  const previousToolView = toolView;
  const previousRenderResult = renderResult;

  function firmwareView() {
    const selected = state.toolResult?.fileName;
    const result = state.toolResult?.analysis;
    const recoveredCount = result?.artifacts?.length || 0;
    const exportStatus = state.toolResult?.lastFirmwareExport;
    const binwalkStatus = state.toolResult?.lastBinwalkExport;
    return `<div class="page-head tool-head"><div><span class="kicker">FIRMWARE</span><h1>固件分析</h1><p>识别镜像结构、文件系统和可恢复段。不会执行固件。</p></div><button class="button ghost" data-view="lowalt">返回</button></div>
      <div class="workbench"><article class="panel input-panel"><div class="field grow"><label>固件文件</label><div class="file-slot">${selected ? `<b>${esc(selected)}</b><span>${fmtBytes(result?.size)}</span>` : '<span>支持 .bin / .img / .fw / .rom / .trx / .ubi / squashfs 等文件</span>'}</div></div><div class="run-row"><span>只读分析</span><button class="button primary" data-action="choose-firmware">选择固件</button></div></article>
      <article class="panel result-panel"><div class="result-title"><b>分析结果</b><div class="firmware-actions">${result ? `<button class="button" data-action="firmware-export-recovered" ${recoveredCount ? '' : 'disabled'}>导出恢复结果</button><button class="button" data-action="firmware-binwalk">Binwalk 解包到目录</button>` : ''}</div></div>
      ${exportStatus?.ok ? `<div class="export-status"><b>恢复结果已导出</b><span>${esc(exportStatus.outputDir)} · ${exportStatus.files?.length || 0} 个文件 · manifest 已生成</span></div>` : ''}
      ${binwalkStatus?.ok ? `<div class="export-status"><b>Binwalk 已完成</b><span>${esc(binwalkStatus.outputDir)}</span></div>` : ''}
      <div id="tool-result">${state.toolError ? `<div class="error-box">${esc(state.toolError)}</div>` : result ? renderFirmware(result) : '<div class="result-empty">请选择固件文件。</div>'}</div></article></div>`;
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

  function renderFirmware(result) {
    const vendor = result.vendor ? `${result.vendor.vendor} ${result.vendor.version}` : '未识别';
    const magic = (result.magic || []).slice(0,40);
    const artifacts = result.artifacts || [];
    const clues = result.securityStrings || [];
    const actions = result.nextActions || [];
    return `<div class="result-stats"><div><b>${fmtBytes(result.size)}</b><span>大小</span></div><div><b>${result.entropy}</b><span>熵</span></div><div><b>${magic.length}</b><span>Magic</span></div><div><b>${artifacts.length}</b><span>恢复段</span></div></div>
      <div class="firmware-meta"><span>容器</span><b>${esc(vendor)}</b></div>
      ${(result.findings||[]).map(x=>`<div class="finding ${x.severity}"><span>${esc(x.severity)}</span><div><b>${esc(x.title)}</b><small>${esc(x.evidence)}</small></div></div>`).join('')}
      ${magic.length ? `<details class="panel"><summary><b>文件结构</b> · ${magic.length}</summary>${table(['偏移','类型'], magic.map(x=>[x.offsetHex,x.name]))}</details>` : ''}
      ${clues.length ? `<details class="panel"><summary><b>字符串线索</b> · ${clues.length}</summary>${table(['偏移','类型','字符串'], clues.slice(0,100).map(x=>[x.offsetHex,x.kind,x.text]))}</details>` : ''}
      ${artifacts.length ? `<details class="panel" open><summary><b>可导出恢复段</b> · ${artifacts.length}</summary><div class="knowledge-list firmware-artifacts">${artifacts.map((a,i)=>`<article><span>SEGMENT</span><b>${esc(a.name)}</b><p>${fmtBytes(a.size)} · SHA-256 ${esc(a.sha256.slice(0,16))}…</p><button class="button" data-firmware-artifact="${i}">单独导出</button></article>`).join('')}</div></details>` : '<p class="notice">当前没有满足完整性条件的内置恢复段，可尝试 Binwalk 解包。</p>'}
      ${actions.length ? `<details class="panel"><summary><b>后续检查</b> · ${actions.length}</summary><div class="check-list">${actions.map(x=>`<p>${esc(x)}</p>`).join('')}</div></details>` : ''}`;
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
