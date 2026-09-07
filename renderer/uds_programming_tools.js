(() => {
  if (typeof renderResult !== 'function') return;

  const originalRenderResult = renderResult;
  renderResult = function renderUdsProgrammingResult(tool, result) {
    const baseHtml = originalRenderResult(tool, result);
    if (tool !== 'can-analyze') return baseHtml;
    const programming = result?.udsProgramming;
    if (!programming?.transfers?.length) return baseHtml;

    const rows = programming.transfers.map((item, index) => [
      index + 1,
      item.canId,
      item.requestDownload?.address || '—',
      item.requestDownload?.size || '—',
      item.blockCount,
      item.blockSequenceCounters.join(', '),
      item.firmwareSize,
      item.complete ? 'complete' : 'incomplete',
      item.declaredSizeMatches == null ? 'unknown' : item.declaredSizeMatches ? 'yes' : 'no',
      item.confidence,
      item.firmwareSha256
    ]);
    const errors = programming.transfers.flatMap((item, transferIndex) => (item.errors || []).map((error) => [
      transferIndex + 1,
      error.id || 'unknown',
      error.expected ?? '—',
      error.actual ?? '—',
      error.sessionIndex ?? '—'
    ]));

    const panel = `<article class="panel"><div class="result-title"><b>UDS 刷写 / 固件重组</b><span>${programming.completeTransfers} complete</span></div>
      <p class="notice">按 RequestDownload(0x34) → TransferData(0x36) → RequestTransferExit(0x37) 串联。只有 high confidence 且无 block gap 的候选才适合直接导出继续逆向。</p>
      ${table(['#','CAN ID','地址','声明长度','Blocks','BSC','固件长度','状态','长度匹配','置信度','SHA-256'], rows)}
      ${errors.length ? table(['传输','错误','期望','实际','Session'], errors) : ''}
      <div class="hint-list">${(programming.hints || []).map((item) => `<p>${esc(item)}</p>`).join('')}</div>
    </article>`;
    return `${panel}${baseHtml}`;
  };

  render();
})();
