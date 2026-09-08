(() => {
  const previousWorkspaceView = workspaceView;
  const baseRender = render;
  const SEVERITY_SCORE = { high: 40, medium: 18, low: 7, info: 2 };
  let selectedFilePath = null;
  let selectedInspection = null;
  let inspectionError = null;
  let inspectionBusy = false;
  let inspectionToken = 0;
  let workspaceArtifactRefs = [];

  function graph() {
    return state.workspace?.investigation || { summary:{}, focus:[], nextActions:[], artifacts:[] };
  }

  function flags(analysis) {
    const out = [];
    for (const file of analysis.files || []) {
      for (const value of file.flags || []) {
        if (!out.some((item) => item.value === value)) out.push({ value, file:file.path });
      }
    }
    return out.slice(0, 12);
  }

  function priorityFindings(analysis, limit = 12) {
    return [...(analysis.findings || [])]
      .sort((a,b) => (SEVERITY_SCORE[b.severity] || 0) - (SEVERITY_SCORE[a.severity] || 0))
      .filter((item,index,all) => all.findIndex((x) => `${x.id || x.title}:${x.file || ''}` === `${item.id || item.title}:${item.file || ''}`) === index)
      .slice(0, limit);
  }

  function priorityFiles(analysis) {
    return [...(analysis.files || [])].map((file) => {
      let score = (file.flags?.length || 0) * 120 + (file.findings || []).reduce((sum,f) => sum + (SEVERITY_SCORE[f.severity] || 0), 0);
      if (file.metadata?.firmware) score += 35;
      if (file.metadata?.pcapng?.can?.udsProgramming?.exportableTransfers) score += 60;
      if (file.metadata?.lowAltitude || file.metadata?.uavChallenge || file.metadata?.ulog) score += 25;
      if (file.metadata?.aiAudit || file.metadata?.aiSupplyChain || file.metadata?.model) score += 25;
      if (file.metadata?.web3Audit || file.metadata?.evmRuntime) score += 25;
      return { file, score };
    }).sort((a,b) => b.score - a.score || a.file.path.localeCompare(b.file.path));
  }

  function fileTypeMark(file) {
    const ext = String(file.extension || file.path?.match(/\.[^.\/]+$/)?.[0] || '').toLowerCase();
    if (['.pcap','.pcapng','.cap'].includes(ext)) return 'PC';
    if (['.bin','.img','.fw','.rom','.trx','.ubi','.squashfs'].includes(ext)) return 'FW';
    if (['.ulg','.tlog','.log'].includes(ext)) return 'LG';
    if (['.sol','.vy'].includes(ext)) return 'SC';
    if (['.py','.js','.ts','.rs','.c','.cpp'].includes(ext)) return '<>';
    if (['.pt','.pth','.pkl','.safetensors','.onnx','.npy'].includes(ext)) return 'ML';
    return '·';
  }

  function filteredFiles(analysis) {
    const q = String(state.fileFilter || '').trim().toLowerCase();
    const ranked = priorityFiles(analysis);
    const items = q ? ranked.filter(({file}) => `${file.name} ${file.path} ${file.type} ${file.extension || ''}`.toLowerCase().includes(q)) : ranked;
    return items.slice(0, 1200).map((x) => x.file);
  }

  function fileTree(analysis) {
    const files = filteredFiles(analysis);
    const groups = new Map();
    for (const file of files) {
      const parts = String(file.path || file.name || '').split(/[\\/]/).filter(Boolean);
      const key = parts.length > 1 ? parts[0] : '根目录';
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(file);
    }
    const groupHtml = [...groups.entries()].map(([name, items]) => {
      const open = groups.size <= 8 || name === '根目录' ? ' open' : '';
      return `<details class="ws-file-group"${open}><summary><span>${esc(name)}</span><b>${items.length}</b></summary><div>${items.map((file) => {
        const active = selectedFilePath === file.path ? ' active' : '';
        const depth = Math.max(0, String(file.path).split(/[\\/]/).length - 2);
        const signal = (file.flags?.length || 0) ? 'flag' : (file.findings || []).some((x) => x.severity === 'high') ? 'high' : (file.findings?.length || 0) ? 'finding' : '';
        return `<button class="ws-file-row${active}" data-ws-file="${esc(file.path)}" style="--depth:${Math.min(depth,5)}"><span class="ws-file-mark">${esc(fileTypeMark(file))}</span><span class="ws-file-name"><strong>${esc(file.name || file.path)}</strong><small>${esc(file.type || file.extension || '文件')} · ${fmtBytes(file.size)}</small></span>${signal ? `<i class="${signal}"></i>` : ''}</button>`;
      }).join('')}</div></details>`;
    }).join('');
    return `<div class="ws-file-toolbar"><input id="file-filter" placeholder="过滤文件 / 类型" value="${esc(state.fileFilter || '')}"/><span>${files.length}/${analysis.files.length}</span></div><div class="ws-file-tree">${groupHtml || '<div class="ws-empty-small">没有匹配文件</div>'}</div>`;
  }

  function resolveArtifact(ref) {
    const file = (state.workspace?.files || []).find((item) => item.path === ref?.sourceFile);
    if (!file) return null;
    if (ref.source === 'uds') return file.metadata?.pcapng?.can?.udsProgramming?.transfers?.[ref.index]?.artifact || null;
    if (ref.source === 'mavftp') {
      const ftp = file.metadata?.lowAltitude?.ftpReassembly || file.metadata?.mavlink?.ftpReassembly;
      return ftp?.files?.[ref.index]?.artifact || null;
    }
    if (ref.source === 'auto-decode') return file.metadata?.autoDecode?.candidates?.[ref.index]?.artifact || null;
    if (ref.source === 'context-crypto') return file.metadata?.contextCrypto?.bestCandidates?.[ref.index]?.artifact || null;
    return null;
  }

  function flagStrip(items) {
    if (!items.length) return '';
    return `<section class="ws-fixed-block flags"><div class="ws-block-title"><b>Flag</b><span>${items.length}</span></div><div class="ws-chip-list">${items.slice(0,4).map((item) => `<button class="ws-flag-chip" data-ws-copy="${esc(item.value)}"><code>${esc(item.value)}</code><small>${esc(item.file)}</small></button>`).join('')}</div></section>`;
  }

  function artifactStrip(data) {
    workspaceArtifactRefs = (data.artifacts || []).filter((item) => item.complete !== false).slice(0, 8);
    if (!workspaceArtifactRefs.length) return '';
    return `<section class="ws-fixed-block artifacts"><div class="ws-block-title"><b>Artifact</b><span>${workspaceArtifactRefs.length}</span></div><div class="ws-artifact-strip">${workspaceArtifactRefs.slice(0,4).map((item,index) => `<div><span>${esc(item.kind || 'artifact')}</span><strong>${esc(item.name || 'artifact.bin')}</strong><small>${fmtBytes(item.size || 0)} · ${esc((item.sha256 || '').slice(0,12))}</small><button class="button" data-ws-artifact="${index}">导出</button></div>`).join('')}</div></section>`;
  }

  function findingRows(items) {
    if (!items.length) return '<div class="ws-empty-small">没有高优先级线索</div>';
    return `<div class="ws-finding-list">${items.map((item) => `<button class="ws-finding-row ${esc(item.severity || 'info')}" ${item.file ? `data-ws-file="${esc(item.file)}"` : ''}><span>${esc(item.severity || 'info')}</span><span><strong>${esc(item.title || item.id || 'Finding')}</strong><small>${esc(item.file || 'workspace')}${item.line ? `:${Number(item.line)}` : ''}</small></span></button>`).join('')}</div>`;
  }

  function overviewCenter(analysis) {
    const items = priorityFindings(analysis, 10);
    return `<div class="ws-center-header"><div><span>关键结果</span><strong>${esc(analysis.workspaceName)}</strong></div><div class="ws-mini-stats"><span><b>${analysis.stats?.flags || 0}</b> Flag</span><span><b>${analysis.stats?.findings || 0}</b> Finding</span><span><b>${graph().summary?.artifacts || 0}</b> Artifact</span></div></div>
      ${flagStrip(flags(analysis))}${artifactStrip(graph())}
      <section class="ws-section"><div class="ws-section-title"><b>关键 Finding</b><span>按风险排序</span></div>${findingRows(items)}</section>`;
  }

  function metadataSummary(file) {
    const fw = file.metadata?.firmware;
    if (!fw) return '';
    return `<section class="ws-section"><div class="ws-section-title"><b>固件结构</b><span>${fw.artifactSummaries?.length || 0} 个可恢复段</span></div>
      <div class="ws-meta-grid"><span>Magic<strong>${fw.magic?.length || 0}</strong></span><span>结构<strong>${fw.structures?.length || 0}</strong></span><span>凭据/密钥<strong>${(fw.clueSummary?.credential || 0) + (fw.clueSummary?.secret || 0)}</strong></span></div>
      ${(fw.artifactSummaries || []).length ? `<div class="ws-compact-list">${fw.artifactSummaries.slice(0,8).map((a) => `<div><strong>${esc(a.name)}</strong><small>${fmtBytes(a.size)} · ${esc((a.sha256 || '').slice(0,12))}</small></div>`).join('')}</div><button class="button" data-tool="firmware-unpack">打开固件分析</button>` : ''}</section>`;
  }

  function selectedFileCenter(analysis) {
    const file = (analysis.files || []).find((item) => item.path === selectedFilePath);
    if (!file) return overviewCenter(analysis);
    const localFlags = file.flags || [];
    return `<div class="ws-center-header file"><div><button class="ws-back-overview" data-ws-overview>←</button><span>文件</span><strong>${esc(file.path)}</strong></div><div class="ws-mini-stats"><span>${fmtBytes(file.size)}</span><span>熵 ${esc(file.entropy)}</span><span>${esc(file.type || '')}</span></div></div>
      ${localFlags.length ? flagStrip(localFlags.map((value) => ({ value, file:file.path }))) : ''}
      ${metadataSummary(file)}
      ${(file.findings || []).length ? `<section class="ws-section"><div class="ws-section-title"><b>该文件的 Finding</b><span>${file.findings.length}</span></div>${findingRows([...file.findings].sort((a,b) => (SEVERITY_SCORE[b.severity]||0)-(SEVERITY_SCORE[a.severity]||0)).slice(0,12))}</section>` : ''}
      <section class="ws-section ws-preview"><div class="ws-section-title"><b>预览</b><span>${inspectionBusy ? '读取中' : selectedInspection?.binary ? '字符串视图' : '文本'}</span></div>
        ${inspectionBusy ? '<div class="ws-loading">读取文件…</div>' : inspectionError ? `<div class="error-box">${esc(inspectionError)}</div>` : selectedInspection ? `<pre>${esc(selectedInspection.text || '')}</pre>${selectedInspection.truncated ? '<small>文件较大，仅显示分析器返回的预览范围。</small>' : ''}` : '<div class="ws-empty-small">点击文件后加载预览</div>'}
      </section>
      <details class="ws-metadata"><summary>元数据</summary><pre>${esc(JSON.stringify(file.metadata || {}, null, 2))}</pre></details>`;
  }

  function investigationPane(data) {
    const actions = (data.nextActions || []).slice(0, 5);
    const focus = (data.focus || []).slice(0, 10);
    return `<div class="ws-investigation-head"><div><span>Investigation</span><strong>调查队列</strong></div><div><b>${data.summary?.high || 0}</b><small>High</small></div></div>
      <section class="ws-right-section"><div class="ws-section-title"><b>下一步</b><span>${actions.length}</span></div>
        <div class="ws-action-list">${actions.length ? actions.map((item,index) => `<div class="ws-action ${esc(item.severity || 'info')}"><b>${index+1}</b><div><strong>${esc(item.title)}</strong><p>${esc(item.text)}</p><div>${item.tool ? `<button class="text-button" data-tool="${esc(item.tool)}">打开工具</button>` : ''}${item.file ? `<button class="text-button" data-ws-file="${esc(item.file)}">定位文件</button>` : ''}${item.artifactId ? `<button class="text-button" data-ws-artifact-id="${esc(item.artifactId)}">导出</button>` : ''}</div></div></div>`).join('') : '<div class="ws-empty-small">暂无明确下一步</div>'}</div>
      </section>
      <section class="ws-right-section"><div class="ws-section-title"><b>证据</b><span>${focus.length}</span></div><div class="ws-evidence-list">${focus.length ? focus.map((node) => `<details class="ws-evidence ${esc(node.severity || 'info')}"><summary><span>${esc(node.severity || 'info')}</span><div><strong>${esc(node.title)}</strong><small>${esc(node.file || 'workspace')}</small></div></summary><div class="ws-evidence-body">${node.evidence ? `<p><b>证据</b>${esc(node.evidence)}</p>` : ''}${node.prerequisite ? `<p><b>前提</b>${esc(node.prerequisite)}</p>` : ''}${node.exploitability ? `<p><b>状态</b>${esc(node.exploitability)}</p>` : ''}${node.nextAction ? `<p><b>下一步</b>${esc(node.nextAction)}</p>` : ''}<div>${node.recommendedTool ? `<button class="button" data-tool="${esc(node.recommendedTool)}">打开工具</button>` : ''}${node.file ? `<button class="button ghost" data-ws-file="${esc(node.file)}">查看文件</button>` : ''}</div></div></details>`).join('') : '<div class="ws-empty-small">暂无结构化证据</div>'}</div></section>`;
  }

  workspaceView = function workspaceThreePaneView() {
    if (!state.workspace) return previousWorkspaceView();
    const analysis = state.workspace;
    return `<div class="workspace-three-pane">
      <header class="ws-topline"><div><strong>${esc(analysis.workspaceName)}</strong><small>${esc(analysis.workspacePath)}</small></div><div class="ws-top-actions"><span>${analysis.stats?.files || 0} files · ${fmtBytes(analysis.stats?.bytes || 0)}</span><button class="button" data-action="export-report">导出报告</button><button class="button" data-action="rescan-workspace">重新扫描</button></div></header>
      <div class="ws-columns">
        <aside class="ws-files-pane"><div class="ws-pane-title"><b>文件</b><span>${analysis.files?.length || 0}</span></div>${fileTree(analysis)}</aside>
        <main class="ws-main-pane">${selectedFilePath ? selectedFileCenter(analysis) : overviewCenter(analysis)}</main>
        <aside class="ws-investigation-pane">${investigationPane(graph())}</aside>
      </div>
    </div>`;
  };

  async function inspectFile(relativePath) {
    if (!state.workspace) return;
    selectedFilePath = relativePath;
    selectedInspection = null;
    inspectionError = null;
    inspectionBusy = true;
    const token = ++inspectionToken;
    render();
    try {
      const result = await window.newcyber.inspectFile(state.workspace.workspacePath, relativePath);
      if (token !== inspectionToken) return;
      selectedInspection = result;
    } catch (error) {
      if (token !== inspectionToken) return;
      inspectionError = error?.message || String(error);
    } finally {
      if (token === inspectionToken) {
        inspectionBusy = false;
        render();
      }
    }
  }

  function removeFloatingInvestigation() {
    if (!(state.view === 'workspace' && !state.tool && state.workspace)) return;
    document.body.classList.remove('investigation-open');
    document.getElementById('investigation-panel')?.remove();
    document.querySelector('.investigation-toggle')?.remove();
  }

  render = function workspaceThreePaneRender(...args) {
    const result = baseRender(...args);
    const active = state.view === 'workspace' && !state.tool && !!state.workspace;
    document.body.classList.toggle('workspace-task-mode', active);
    if (active) removeFloatingInvestigation();
    return result;
  };

  document.addEventListener('click', async (event) => {
    const fileButton = event.target.closest('[data-ws-file]');
    if (fileButton && state.workspace) {
      event.preventDefault();
      await inspectFile(fileButton.dataset.wsFile);
      return;
    }
    if (event.target.closest('[data-ws-overview]')) {
      selectedFilePath = null;
      selectedInspection = null;
      inspectionError = null;
      inspectionToken += 1;
      render();
      return;
    }
    const copy = event.target.closest('[data-ws-copy]');
    if (copy) {
      await navigator.clipboard.writeText(copy.dataset.wsCopy || '');
      toast('已复制');
      return;
    }
    const artifactButton = event.target.closest('[data-ws-artifact]');
    if (artifactButton) {
      const ref = workspaceArtifactRefs[Number(artifactButton.dataset.wsArtifact)];
      const artifact = resolveArtifact(ref);
      if (!artifact) return toast('未找到可导出的完整产物', true);
      artifactButton.disabled = true;
      try {
        const saved = await window.newcyber.saveArtifact(artifact);
        if (saved?.filePath) toast(`已导出 ${artifact.name}`);
      } catch (error) { toast(error?.message || '导出失败', true); }
      finally { artifactButton.disabled = false; }
      return;
    }
    const artifactById = event.target.closest('[data-ws-artifact-id]');
    if (artifactById) {
      const ref = (graph().artifacts || []).find((item) => item.id === artifactById.dataset.wsArtifactId);
      const artifact = resolveArtifact(ref);
      if (!artifact) return toast('未找到可导出的完整产物', true);
      try {
        const saved = await window.newcyber.saveArtifact(artifact);
        if (saved?.filePath) toast(`已导出 ${artifact.name}`);
      } catch (error) { toast(error?.message || '导出失败', true); }
    }
  });

  render();
})();
