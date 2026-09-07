(() => {
  const originalWorkspaceView = workspaceView;

  function evidenceText(value) {
    if (value == null) return '';
    if (typeof value === 'string') return value;
    try { return JSON.stringify(value, null, 2); } catch { return String(value); }
  }

  function renderFindings(analysis) {
    const findings = analysis.findings || [];
    if (!findings.length) return '';
    return `<article class="panel result-panel"><div class="result-title"><b>关键线索</b><span>${findings.length} 条</span></div>${findings.slice(0, 80).map((finding) => {
      const evidence = finding.evidence ?? finding.description ?? finding.patterns ?? '';
      return `<div class="finding ${esc(finding.severity || 'low')}"><span>${esc(finding.severity || 'info')}</span><div><b>${esc(finding.title || finding.id || '未命名线索')}</b><small>${esc(finding.file || 'workspace')} · ${Number(finding.count) || 1} 处</small>${evidence ? `<pre>${esc(evidenceText(evidence))}</pre>` : ''}</div></div>`;
    }).join('')}</article>`;
  }

  function changeSummary(changes = []) {
    return changes.map((change) => {
      const from = Number.isInteger(change.from) ? change.from.toString(16).padStart(2, '0') : '--';
      const to = Number.isInteger(change.to) ? change.to.toString(16).padStart(2, '0') : '--';
      const setBits = Number.isInteger(change.setBits) && change.setBits ? ` +${change.setBits.toString(16).padStart(2, '0')}` : '';
      const clearedBits = Number.isInteger(change.clearedBits) && change.clearedBits ? ` -${change.clearedBits.toString(16).padStart(2, '0')}` : '';
      return `b${change.byteIndex}:${from}→${to}${setBits}${clearedBits}`;
    }).join(' | ');
  }

  function renderCanEvidence(file) {
    const pcapng = file.metadata?.pcapng;
    const can = pcapng?.can;
    if (!can) return '';
    const candidates = can.eventCandidates || [];
    const idRows = (can.ids || []).map((item) => [
      item.id,
      item.count,
      item.changingBytes?.join(', ') || '—',
      item.counterCandidates?.join(', ') || '—',
      item.transitions?.length || 0,
      item.averageIntervalMs ?? '—'
    ]);
    const eventRows = candidates.slice(0, 100).map((event) => [
      event.id,
      event.frameIndex,
      event.packetIndex ?? '—',
      event.payload,
      changeSummary(event.changes),
      event.rawFrameHex || '—'
    ]);
    return `<article class="panel result-panel"><div class="result-title"><b>CAN / PCAPNG 深度解析 · ${esc(file.path)}</b><span>${can.parsedFrames || 0} 帧 / ${can.uniqueIds || 0} ID</span></div><p class="notice">SocketCAN 已离线解析。下面保留逐 ID 变化统计与原始帧映射；候选排序只是启发式，提交前仍应核对 raw frame。</p>${table(['CAN ID','帧数','变化字节','Counter','跃迁','平均周期(ms)'], idRows)}${eventRows.length ? `<div class="result-title"><b>状态跃迁候选</b><span>${candidates.length} 个候选</span></div>${table(['ID','frame','packet','payload','bit/byte 变化','raw frame'], eventRows)}` : ''}</article>`;
  }

  function renderModelEvidence(file) {
    const audit = file.metadata?.modelAudit;
    const model = file.metadata?.model;
    if (!audit && !model) return '';
    const mappings = audit?.suspiciousMappings || [];
    const outliers = audit?.storageOutliers || [];
    return `<article class="panel result-panel"><div class="result-title"><b>模型供应链深度解析 · ${esc(file.path)}</b><span>${model?.storageCount ?? 0} storages</span></div>${audit?.unexpectedParameters?.length ? `<p class="notice">训练日志未声明参数：${esc(audit.unexpectedParameters.join(', '))}</p>` : '<p class="notice">未发现可由训练日志直接证明的额外参数。</p>'}${mappings.length ? table(['异常参数','storage','大小(bytes)','映射依据'], mappings.map((item) => [item.parameter,item.storage,item.storageBytes,item.mapping])) : ''}${outliers.length ? table(['异常 storage','解压大小(bytes)','压缩大小(bytes)'], outliers.map((item) => [item.name,item.uncompressedSize,item.compressedSize])) : ''}</article>`;
  }

  function renderRecommendations(analysis) {
    const recommendations = analysis.recommendations || [];
    if (!recommendations.length) return '';
    return `<article class="panel"><div class="result-title"><b>建议路线</b><span>${recommendations.length} 条</span></div><div class="hint-list">${recommendations.slice(0, 30).map((item) => `<p>${esc(item)}</p>`).join('')}</div></article>`;
  }

  workspaceView = function workspaceViewWithEvidence() {
    const baseHtml = originalWorkspaceView();
    if (!state.workspace) return baseHtml;
    const analysis = state.workspace;
    const deepEvidence = (analysis.files || []).map((file) => `${renderCanEvidence(file)}${renderModelEvidence(file)}`).join('');
    const evidenceHtml = `${renderFindings(analysis)}${deepEvidence}${renderRecommendations(analysis)}`;
    if (!evidenceHtml) return baseHtml;
    return baseHtml.replace('<div class="workspace-actions">', `${evidenceHtml}<div class="workspace-actions">`);
  };
})();
