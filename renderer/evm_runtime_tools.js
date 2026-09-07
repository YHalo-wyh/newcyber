(() => {
  if (typeof renderResult !== 'function') return;

  const originalRenderResult = renderResult;
  renderResult = function renderEvmRuntimeResult(tool, result) {
    const baseHtml = originalRenderResult(tool, result);
    if (tool !== 'evm-disasm' || !result) return baseHtml;

    const selectors = result.dispatcherSelectors || [];
    const loose = (result.selectorCandidates || []).filter((item) => !item.looksLikeDispatcher);
    const storage = result.storage || { accesses: [], slots: [], reads: 0, writes: 0 };
    if (!selectors.length && !loose.length && !(storage.accesses || []).length) return baseHtml;

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

    const accessRows = (storage.accesses || []).slice(0, 160).map((item) => [
      item.pc,
      item.type,
      item.directSlot || '—',
      (item.slotCandidates || []).map((candidate) => `${candidate.slot} [${candidate.confidence}]@${candidate.sourcePc}`).join(', ') || '—'
    ]);
    const slotRows = (storage.slots || []).slice(0, 100).map((item) => [
      item.slot,
      item.reads,
      item.writes,
      item.highConfidenceReads,
      (item.evidencePcs || []).join(', ')
    ]);

    const selectorPanel = rows.length ? `<article class="panel"><div class="result-title"><b>EVM Runtime 入口恢复</b><span>${selectors.length} dispatcher selectors</span></div>
      <p class="notice">没有 ABI/源码时，先按 PUSH4 → EQ → JUMPI 汇总函数入口，再从 jump destination 回到反汇编/反编译结果恢复业务语义。孤立 PUSH4 只作为低置信度常量展示。</p>
      ${table(['PC','Selector','已知签名','Jump 目标','置信'], rows)}
    </article>` : '';

    const storagePanel = accessRows.length ? `<article class="panel"><div class="result-title"><b>EVM Storage / State 证据</b><span>${storage.reads || 0} reads · ${storage.writes || 0} writes</span></div>
      <p class="notice">紧邻 SLOAD/SSTORE 的 PUSH 才是高置信直接证据；复杂栈变换只展示同 basic block 候选。这里不是符号执行，低置信 slot 必须回到 TAC/反编译结果复核。</p>
      ${slotRows.length ? table(['Slot候选','SLOAD','SSTORE','高置信读','证据 PC'], slotRows) : ''}
      ${table(['PC','操作','Direct slot','同块候选'], accessRows)}
    </article>` : '';

    return `${selectorPanel}${storagePanel}<div class="hint-list">${(result.notes || []).map((item) => `<p>${esc(item)}</p>`).join('')}</div>${baseHtml}`;
  };

  render();
})();
