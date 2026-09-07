(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof renderResult !== 'function') return;

  if (!DOMAINS.ai.tools.some(([id]) => id === 'ai-tabular-candidate')) {
    DOMAINS.ai.tools.push([
      'ai-tabular-candidate',
      '表格模型候选验证',
      '用分位数、标准化距离与强相关残差检查候选是否贴近现有数据联合分布；不伪装成真实模型分数。'
    ]);
  }

  TOOL_META['ai-tabular-candidate'] = {
    domain: 'ai',
    title: '表格模型候选验证',
    placeholder: 'x,y,z\n0,0,10\n1,2,11\n2,4,12\n--- candidate ---\n{"x":1.5,"y":3,"z":11.5}',
    label: '数据集 + Candidate JSON'
  };

  function artifactButton(kind, index, artifact) {
    if (!artifact) return '<span class="muted">不可导出</span>';
    return `<button class="button primary" data-save-artifact data-artifact-kind="${esc(kind)}" data-artifact-index="${index}">导出 ${esc(artifact.name)}</button>`;
  }

  function renderUdsArtifacts(result) {
    const programming = result?.udsProgramming;
    if (!programming?.transfers?.length) return '';
    const cards = programming.transfers.map((item, index) => {
      const blockRows = (item.blockMap || []).slice(0, 80).map((block) => [block.counter, block.sessionIndex, block.offset, block.length, block.endOffset]);
      const raw = item.artifact?.metadata?.rawTransferPayload;
      return `<article class="panel result-panel"><div class="result-title"><b>UDS Artifact #${index + 1}</b><span>${item.artifactReady ? 'exportable' : item.confidence}</span></div>
        <div class="result-stats"><div><b>${item.firmwareSize}</b><span>bytes</span></div><div><b>${item.blockCount}</b><span>blocks</span></div><div><b>${item.errors?.length || 0}</b><span>errors</span></div></div>
        <p class="notice">${raw ? 'dataFormatIdentifier != 0：当前产物是 raw transfer payload，仍可能压缩或加密。' : 'dataFormatIdentifier=0：满足完整性条件时按 firmware candidate 导出。'}</p>
        ${blockRows.length ? table(['BSC','ISO-TP Session','Offset','Length','End'], blockRows) : ''}
        <div class="run-row"><span>${item.artifact ? `${esc(item.artifact.sha256)} · ${item.artifact.size} bytes` : '存在 gap/冲突/长度问题时只保留 block map，不落盘。'}</span>${artifactButton('uds', index, item.artifact)}</div>
      </article>`;
    });
    return `<section><div class="page-head"><span class="kicker">BINARY ARTIFACT</span><h2>UDS 固件产物</h2><p>从 TransferData block map 到经过 SHA-256 绑定的可保存二进制。</p></div>${cards.join('')}</section>`;
  }

  function renderFtpArtifacts(result) {
    const reassembly = result?.ftpReassembly;
    if (!reassembly?.files?.length) return '';
    const cards = reassembly.files.map((file, index) => {
      const chunkRows = (file.chunkMap || []).slice(0, 100).map((chunk) => [chunk.frameIndex, chunk.sequence, chunk.offset, chunk.length, chunk.endOffset]);
      const gapText = (file.gaps || []).map((gap) => `${gap.start}-${gap.end}`).join(', ') || 'none';
      return `<article class="panel result-panel"><div class="result-title"><b>MAVLink FTP · ${esc(file.path || `session ${file.session}`)}</b><span>${file.complete ? 'complete' : 'incomplete'}</span></div>
        <div class="result-stats"><div><b>${file.coveredBytes || 0}</b><span>covered</span></div><div><b>${file.expectedSize ?? '—'}</b><span>expected</span></div><div><b>${file.conflictingBytes || 0}</b><span>conflicts</span></div><div><b>${(file.gaps || []).length}</b><span>gaps</span></div></div>
        <p class="notice">Remote ${esc(`${file.remoteSystem}:${file.remoteComponent}`)} · session ${esc(file.session)} · gaps ${esc(gapText)}</p>
        ${chunkRows.length ? table(['帧','FTP SEQ','Offset','Length','End'], chunkRows) : ''}
        <div class="run-row"><span>${file.artifact ? `${esc(file.artifact.sha256)} · ${file.artifact.size} bytes` : '未达到完整覆盖条件，不生成下载产物。'}</span>${artifactButton('mavftp', index, file.artifact)}</div>
      </article>`;
    });
    return `<section><div class="page-head"><span class="kicker">FILE REASSEMBLY</span><h2>MAVLink FTP 文件重组</h2><p>按 remote/session/offset 聚合 ACK 数据，并区分重传、冲突和缺口。</p></div>${cards.join('')}</section>`;
  }

  function renderCandidate(result) {
    const dimensionRows = (result.dimensions || []).map((item) => [
      item.column,
      item.value ?? '—',
      item.status,
      item.zFromMedian ?? '—',
      item.withinQ05Q95 == null ? '—' : item.withinQ05Q95 ? 'yes' : 'no',
      item.q05 ?? '—',
      item.median ?? '—',
      item.q95 ?? '—'
    ]);
    const relationRows = (result.correlationChecks || []).map((item) => [
      item.left,
      item.right,
      item.correlation,
      item.predictedRight,
      item.actualRight,
      item.conditionalResidualStd,
      item.status
    ]);
    const findingHtml = (result.findings || []).map((item) => `<div class="finding ${esc(item.severity || 'info')}"><span>${esc(item.severity || 'info')}</span><div><b>${esc(item.title || item.id)}</b><p>${esc(item.message || '')}</p></div></div>`).join('');
    return `<div class="result-stats"><div><b>${esc(result.profileCompatibility)}</b><span>profile compatibility</span></div><div><b>${esc(result.standardizedProfileDistance ?? '—')}</b><span>RMS z-distance</span></div><div><b>${result.outsideCoreRangeCount || 0}</b><span>outside Q05-Q95</span></div><div><b>${result.nonFiniteValues || 0}</b><span>NaN/Inf</span></div></div>${findingHtml}${table(['Feature','Value','Status','|z|','Q05-Q95','Q05','Median','Q95'], dimensionRows)}${relationRows.length ? `<article class="panel"><div class="result-title"><b>强相关联合关系</b><span>conditional residual</span></div>${table(['A','B','r','预测 B','实际 B','残差 σ','状态'], relationRows)}</article>` : ''}<div class="hint-list">${(result.notes || []).map((item) => `<p>${esc(item)}</p>`).join('')}</div>`;
  }

  function renderEvmDataFlow(result) {
    const flow = result?.dataFlow;
    if (!flow || (!flow.storageFlows?.length && !flow.calls?.length && !flow.calldataLoads?.length)) return '';
    const storageRows = (flow.storageFlows || []).slice(0, 120).map((item) => [
      item.pc,
      item.type,
      item.selectorContext?.map((ctx) => ctx.knownSignature || ctx.selector).join(', ') || '—',
      item.slotExpr,
      item.valueExpr,
      (item.sources || []).join(' | ')
    ]);
    const callRows = (flow.calls || []).slice(0, 100).map((item) => [
      item.pc,
      item.type,
      item.selectorContext?.map((ctx) => ctx.knownSignature || ctx.selector).join(', ') || '—',
      item.toExpr,
      item.valueExpr || '—',
      item.inputOffsetExpr,
      item.inputSizeExpr,
      (item.inputSources || []).map((source) => `${source.kind}@${source.pc}:${source.expr}`).join(' | ') || '—'
    ]);
    return `<article class="panel"><div class="result-title"><b>EVM 局部状态流</b><span>${flow.linkedStorageWrites || 0} linked SSTORE · ${flow.linkedCalls || 0} linked CALL</span></div>
      <p class="notice">只做单 basic block 符号传播；跨 JUMP/JUMPI 不合并状态。unknown 比错误的“自动反编译”更可信。</p>
      ${storageRows.length ? table(['PC','类型','Selector Context','Slot','Value','Sources'], storageRows) : ''}
      ${callRows.length ? table(['PC','CALL','Selector Context','To','Value','Input Off','Input Size','Memory/Input 来源'], callRows) : ''}
      <div class="hint-list">${(flow.notes || []).map((item) => `<p>${esc(item)}</p>`).join('')}</div>
    </article>`;
  }

  const originalRenderResult = renderResult;
  renderResult = function renderBatch3Result(tool, result) {
    if (tool === 'ai-tabular-candidate') return renderCandidate(result);
    const baseHtml = originalRenderResult(tool, result);
    if (tool === 'can-analyze') return `${renderUdsArtifacts(result)}${baseHtml}`;
    if (tool === 'mavlink-hex') return `${renderFtpArtifacts(result)}${baseHtml}`;
    if (tool === 'evm-disasm') return `${renderEvmDataFlow(result)}${baseHtml}`;
    return baseHtml;
  };

  render();
})();
