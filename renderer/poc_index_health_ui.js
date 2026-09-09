(() => {
  if (typeof workspaceView !== 'function') return;
  const previousWorkspaceView = workspaceView;

  function healthBlock(stats = {}) {
    const legacy = stats.availableCves == null || !stats.importer;
    const truncated = Boolean(stats.truncated) || (!legacy && Number(stats.cves || 0) < Number(stats.availableCves || 0));
    const parseErrors = Number(stats.parseErrors || 0);
    const coverage = stats.coverage;
    const state = legacy ? 'legacy' : parseErrors > Math.max(10, Number(stats.cves || 0) * 0.01) ? 'degraded' : truncated || parseErrors ? 'partial' : 'healthy';
    const label = { healthy:'HEALTHY', partial:'PARTIAL', degraded:'DEGRADED', legacy:'LEGACY CACHE' }[state];
    const detail = legacy
      ? '旧缓存没有完整覆盖统计；点“更新本地索引”重新导入一次。'
      : `${stats.cves || 0}/${stats.availableCves || 0} CVE · ${stats.references || 0} references · parse errors ${parseErrors}${coverage ? ` · ${coverage.oldest}–${coverage.newest}` : ''}`;
    return `<div class="poc-index-health ${state}"><span>${label}</span><p>${esc(detail)}</p>${truncated ? '<b>索引受预算限制时优先保留最新年份。</b>' : ''}</div>`;
  }

  workspaceView = function pocHealthWorkspaceView(...args) {
    let html = previousWorkspaceView(...args);
    const stats = state.workspace?.pocReferences?.indexStats;
    if (!stats || !/poc-reference-panel/.test(html)) return html;
    const block = healthBlock(stats);
    return html.replace(/(<section class="panel next-actions poc-reference-panel">)/, `$1${block}`);
  };

  render();
})();