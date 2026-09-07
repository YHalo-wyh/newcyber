(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined') return;

  if (!DOMAINS.ai.tools.some(([id]) => id === 'ai-tabular-profile')) {
    DOMAINS.ai.tools.push([
      'ai-tabular-profile',
      '结构化模型数据画像',
      '分析 CSV/TSV 的分位数、标准差、强相关特征、中心样本与 NaN/Inf 边界，面向 Isolation Forest / XGBoost 等表格模型题。'
    ]);
  }

  TOOL_META['ai-tabular-profile'] = {
    domain: 'ai',
    title: '结构化模型数据画像',
    placeholder: 'amount,f1,f2,f3\n1200,0.12,4.2,8\n1350,0.18,4.8,9',
    label: 'CSV / TSV 数据'
  };

  const originalRenderResult = renderResult;
  renderResult = function renderAiTabularResult(tool, result) {
    if (tool !== 'ai-tabular-profile') return originalRenderResult(tool, result);

    const stats = (result.columnStats || []).map((column) => [
      column.name,
      column.type,
      column.count,
      column.missing,
      column.nonFinite,
      column.mean ?? '—',
      column.std ?? '—',
      column.q05 ?? '—',
      column.median ?? '—',
      column.q95 ?? '—'
    ]);
    const correlations = (result.strongestCorrelations || []).slice(0, 20).map((item) => [
      item.left,
      item.right,
      item.correlation
    ]);
    const centerRows = (result.centerRows || []).map((item) => [item.row, item.standardizedDistance]);
    const findings = (result.findings || []).map((item) => `<div class="finding ${esc(item.severity || 'info')}"><span>${esc(item.severity || 'info')}</span><div><b>${esc(item.title || item.id)}</b><small>${esc(item.id || '')}${item.count != null ? ` · ${esc(item.count)} 处` : ''}</small><p>${esc(item.message || '')}</p></div></div>`).join('');

    return `<div class="result-stats"><div><b>${esc(result.rows)}</b><span>样本</span></div><div><b>${esc(result.columns)}</b><span>列</span></div><div><b>${esc(result.numericColumns)}</b><span>数值列</span></div><div><b>${esc((result.nonFiniteCells || []).length)}</b><span>NaN/Inf</span></div></div>${findings}${table(['列','类型','有效','缺失','NaN/Inf','均值','Std','Q05','Median','Q95'], stats)}${correlations.length ? `<article class="panel"><div class="result-title"><b>最强相关特征</b><span>联合分布</span></div>${table(['特征 A','特征 B','Pearson r'], correlations)}</article>` : ''}${centerRows.length ? `<article class="panel"><div class="result-title"><b>中心样本索引</b><span>不直接复制</span></div>${table(['原始行','标准化距离'], centerRows)}</article>` : ''}<article class="panel"><div class="result-title"><b>中位中心 Profile</b><span>确定性</span></div><pre class="mini-pre">${esc(JSON.stringify(result.centerProfile || {}, null, 2))}</pre></article><div class="hint-list">${(result.hints || []).map((item) => `<p>${esc(item)}</p>`).join('')}</div>`;
  };

  const originalWorkspaceView = workspaceView;
  workspaceView = function workspaceViewWithTabularAi() {
    const baseHtml = originalWorkspaceView();
    if (!state.workspace) return baseHtml;
    const cards = [];
    for (const file of state.workspace.files || []) {
      const audit = file.metadata?.aiTabular;
      if (!audit) continue;
      const correlations = (audit.strongestCorrelations || []).slice(0, 8);
      cards.push(`<article class="panel result-panel"><div class="result-title"><b>AI 结构化数据 · ${esc(file.path)}</b><span>${audit.rows}×${audit.columns}</span></div>
        <div class="result-stats"><div><b>${audit.numericColumns}</b><span>数值列</span></div><div><b>${(audit.nonFiniteCells || []).length}</b><span>NaN/Inf</span></div></div>
        ${correlations.length ? table(['特征 A','特征 B','Pearson r'], correlations.map((item) => [item.left,item.right,item.correlation])) : ''}
        <p class="notice">高维异常检测题优先保持联合分布与强相关结构；中心样本只是构造参考，不应直接复制提交。</p>
      </article>`);
    }
    if (!cards.length) return baseHtml;
    return baseHtml.replace('<div class="workspace-actions">', `${cards.join('')}<div class="workspace-actions">`);
  };

  render();
})();
