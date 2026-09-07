(() => {
  function renderModelStructureCard(file) {
    const model = file.metadata?.model;
    if (!model || !['.pt', '.pth', '.safetensors', '.npy'].includes(file.extension)) return '';
    const findings = model.securityFindings || [];
    const pickle = model.pickleAudit;
    const tensorRows = (model.tensors || []).slice(0, 80).map((item) => [
      item.name,
      item.dtype || '—',
      Array.isArray(item.shape) ? item.shape.join('×') : '—',
      item.expectedBytes ?? '—',
      item.actualBytes ?? '—',
      item.dataOffsets ? item.dataOffsets.join('..') : '—'
    ]);
    const findingRows = findings.slice(0, 80).map((item) => [
      item.severity || 'info',
      item.id || 'unknown',
      item.tensor || item.global || item.pc || '—',
      item.message || '—'
    ]);
    const globalRows = (pickle?.globals || []).slice(0, 80).map((item) => [
      item.pc,
      item.qualifiedName,
      item.dynamic ? 'STACK_GLOBAL' : 'GLOBAL',
      item.severity
    ]);
    const badges = [];
    if (model.valid != null) badges.push(`valid=${Boolean(model.valid)}`);
    if (model.objectDtype) badges.push('object dtype');
    if (pickle?.dangerousGlobals?.length) badges.push(`${pickle.dangerousGlobals.length} dangerous globals`);
    return `<article class="panel result-panel"><div class="result-title"><b>模型文件结构完整性 · ${esc(file.path)}</b><span>${esc(model.format || file.extension)}${badges.length ? ` · ${esc(badges.join(' · '))}` : ''}</span></div>
      <p class="notice">只读解析，不执行 torch.load / pickle.loads / numpy.load。结构不一致是优先复核证据，不直接等同于恶意模型。</p>
      ${tensorRows.length ? table(['Tensor','dtype','shape','期望bytes','实际bytes','data offsets'], tensorRows) : ''}
      ${globalRows.length ? `<div class="result-title"><b>Pickle globals</b><span>protocol ${pickle.protocol || 0}</span></div>${table(['PC','Global','Opcode','风险'], globalRows)}` : ''}
      ${findingRows.length ? `<div class="result-title"><b>结构线索</b><span>${findings.length}</span></div>${table(['级别','规则','对象','说明'], findingRows)}` : ''}
      ${pickle?.parseError ? `<p class="notice">静态 pickle parser 在 ${esc(pickle.parseError)} 停止；已解析部分仍保留，不继续猜测。</p>` : ''}
    </article>`;
  }

  if (typeof workspaceView === 'function') {
    const originalWorkspaceView = workspaceView;
    workspaceView = function workspaceViewBatch4() {
      const baseHtml = originalWorkspaceView();
      if (!state.workspace) return baseHtml;
      const cards = (state.workspace.files || []).map(renderModelStructureCard).join('');
      if (!cards) return baseHtml;
      return baseHtml.replace('<div class="workspace-actions">', `${cards}<div class="workspace-actions">`);
    };
  }

  if (typeof renderResult === 'function') {
    const originalRenderResult = renderResult;
    renderResult = function renderBatch4Result(tool, result) {
      const baseHtml = originalRenderResult(tool, result);
      if (!result) return baseHtml;

      if (tool === 'evm-disasm' && result.proxy) {
        const proxy = result.proxy;
        const slots = (proxy.slots || []).filter((item) => item.referenced || item.sloadPcs?.length || item.sstorePcs?.length || item.delegateCallPcs?.length);
        const slotRows = slots.map((item) => [
          item.kind,
          item.slot,
          (item.pushPcs || []).join(', ') || '—',
          (item.sloadPcs || []).join(', ') || '—',
          (item.sstorePcs || []).join(', ') || '—',
          (item.delegateCallPcs || []).join(', ') || '—'
        ]);
        const selectorRows = (proxy.selectorSurfaces || []).map((item) => [item.selector, item.signature, item.destination || '—', item.pc]);
        const writeRows = (proxy.upgradeWrites || []).map((item) => [item.slotKind, item.pc, item.valueExpr, (item.upgradeSelectorContext || []).map((ctx) => ctx.signature).join(', ') || '—']);
        const panel = proxy.isProxyCandidate || slotRows.length ? `<article class="panel"><div class="result-title"><b>EVM Proxy / Implementation 恢复</b><span>${esc(proxy.classification || 'slot evidence')} · ${esc(proxy.confidence || 'none')}</span></div>
          <p class="notice">EIP-1167 只有 canonical runtime 完整匹配才直接恢复 implementation；EIP-1967 只有 implementation slot 的读取确实流入 DELEGATECALL target 才给 high confidence。</p>
          ${proxy.minimalProxy ? table(['字段','值'], [['standard', proxy.minimalProxy.standard], ['implementation', proxy.minimalProxy.implementation], ['runtime offset', proxy.minimalProxy.runtimeOffsetBytes], ['runtime bytes', proxy.minimalProxy.runtimeLengthBytes]]) : ''}
          ${slotRows.length ? table(['Slot','常量','PUSH PC','SLOAD PC','SSTORE PC','→ DELEGATECALL'], slotRows) : ''}
          ${selectorRows.length ? table(['Selector','代理入口','Jump','PC'], selectorRows) : ''}
          ${writeRows.length ? table(['写入槽','PC','Value 来源','入口上下文'], writeRows) : ''}
        </article>` : '';
        if (panel) return `${panel}${baseHtml}`;
      }

      if (tool === 'mavlink-hex' && result.crcEvidence) {
        const crc = result.crcEvidence;
        const summary = crc.summary || {};
        const badRows = (crc.frames || []).filter((item) => item.valid === false).slice(0, 80).map((item) => [item.frameIndex, item.msgid, item.wireCrc, item.computedCrc, item.crcExtra]);
        const unknownRows = (crc.frames || []).filter((item) => item.status === 'unknown-crc-extra').slice(0, 40).map((item) => [item.frameIndex, item.msgid, item.wireCrc, item.dialect]);
        const panel = `<article class="panel"><div class="result-title"><b>MAVLink CRC / Dialect 证据</b><span>${summary.validFrames || 0} valid · ${summary.invalidFrames || 0} invalid · ${summary.unknownCrcExtraFrames || 0} unknown</span></div>
          <p class="notice">按 X.25 + CRC_EXTRA 校验当前内置 common.xml 消息子集。unknown 只代表缺对应 dialect 定义，不代表坏帧；CRC mismatch 也可能是截帧/损坏/方言不匹配。</p>
          ${table(['字段','值'], [['total frames', summary.totalFrames ?? 0], ['known CRC_EXTRA', summary.knownCrcExtraFrames ?? 0], ['valid', summary.validFrames ?? 0], ['invalid', summary.invalidFrames ?? 0], ['unknown extra', summary.unknownCrcExtraFrames ?? 0]])}
          ${badRows.length ? table(['Frame','MsgID','Wire CRC','Computed','CRC_EXTRA'], badRows) : ''}
          ${unknownRows.length ? table(['Frame','MsgID','Wire CRC','Dialect'], unknownRows) : ''}
        </article>`;
        return `${panel}${baseHtml}`;
      }

      return baseHtml;
    };
  }

  if (typeof render === 'function') render();
})();
