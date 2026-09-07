(() => {
  if (typeof renderResult !== 'function') return;

  const originalRenderResult = renderResult;
  renderResult = function renderEvmRuntimeResult(tool, result) {
    const baseHtml = originalRenderResult(tool, result);
    if (tool !== 'evm-disasm' || !result) return baseHtml;

    const selectors = result.dispatcherSelectors || [];
    const loose = (result.selectorCandidates || []).filter((item) => !item.looksLikeDispatcher);
    if (!selectors.length && !loose.length) return baseHtml;

    const rows = selectors.map((item) => [
      item.pc,
      item.selector,
      item.knownSignature || 'unknown',
      item.destination || '—',
      'dispatcher'
    ]);
    for (const item of loose.slice(0, 40)) {
      rows.push([item.pc, item.selector, item.knownSignature || 'unknown', item.destination || '—', 'PUSH4 constant']);
    }

    const panel = `<article class="panel"><div class="result-title"><b>EVM Runtime 入口恢复</b><span>${selectors.length} dispatcher selectors</span></div>
      <p class="notice">没有 ABI/源码时，先按 PUSH4 → EQ → JUMPI 汇总函数入口，再从 jump destination 回到反汇编/反编译结果恢复业务语义。孤立 PUSH4 只作为低置信度常量展示。</p>
      ${table(['PC','Selector','已知签名','Jump 目标','置信'], rows)}
      <div class="hint-list">${(result.notes || []).map((item) => `<p>${esc(item)}</p>`).join('')}</div>
    </article>`;
    return `${panel}${baseHtml}`;
  };

  render();
})();
