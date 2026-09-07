(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined') return;

  if (!DOMAINS.web3.tools.some(([id]) => id === 'solana-source-scan')) {
    DOMAINS.web3.tools.push([
      'solana-source-scan',
      'Solana / Anchor 源码审计',
      '提取 Program ID、instruction、PDA seeds、Signer/AccountInfo 与链上日志线索。'
    ]);
  }

  TOOL_META['solana-source-scan'] = {
    domain: 'web3',
    title: 'Solana / Anchor 源码审计',
    placeholder: 'use anchor_lang::prelude::*;\ndeclare_id!("...");\n#[program]\npub mod challenge { ... }',
    label: 'Rust / Anchor 源码'
  };

  function findingEvidence(item) {
    if (!item) return '—';
    if (Array.isArray(item.evidence)) return item.evidence.join(' | ');
    if (typeof item.evidence === 'object' && item.evidence !== null) return JSON.stringify(item.evidence);
    return item.evidence || item.message || '—';
  }

  const originalRenderResult = renderResult;
  renderResult = function renderFinalsResult(tool, result) {
    if (tool === 'solana-source-scan') {
      if (!result || result.language === 'unknown') return '<div class="result-empty">未检测到 Anchor / Solana Rust 特征。</div>';
      const summary = result.summary || {};
      const overview = [
        ['Program ID', result.programId || '—'],
        ['Instructions', (result.instructions || []).join(', ') || '—'],
        ['PDA seeds', (result.pdaSeeds || []).join(', ') || '—'],
        ['Signers', (result.signers || []).join(', ') || '—'],
        ['Raw AccountInfo', (result.rawAccountInfos || []).map((item) => `${item.name}@L${item.line}`).join(', ') || '—']
      ];
      const findings = (result.findings || []).map((item) => [
        item.severity || 'info', item.line || '—', item.id || '—', item.title || '—', item.message || item.evidence || '—'
      ]);
      return `<div class="result-stats"><div><b>${summary.high || 0}</b><span>High</span></div><div><b>${summary.medium || 0}</b><span>Medium</span></div><div><b>${(result.rawAccountInfos || []).length}</b><span>Raw AccountInfo</span></div></div>${table(['字段','值'], overview)}${findings.length ? table(['级别','行','规则','发现','说明'], findings) : '<div class="result-empty">未命中约束审计规则。</div>'}<div class="hint-list">${(result.notes || []).map((item) => `<p>${esc(item)}</p>`).join('')}</div>`;
    }

    if (tool === 'can-analyze') {
      const baseHtml = originalRenderResult(tool, result);
      const canopen = result?.canopen;
      if (!canopen?.detected) return baseHtml;

      const objectRows = (canopen.objectValues || []).slice(0, 80).map((item) => [
        item.nodeId,
        item.index,
        item.subIndex,
        item.objectName || '—',
        item.direction || '—',
        item.value?.ascii || '—',
        item.value?.hex || '—',
        item.frameIndex || '—'
      ]);
      const transferRows = (canopen.transfers || []).slice(0, 80).map((item) => [
        item.nodeId,
        item.direction,
        item.index,
        item.objectName || '—',
        `${item.collectedLength}/${item.totalLength}`,
        item.complete ? 'complete' : item.error || 'incomplete',
        item.value?.ascii || item.value?.hex || '—',
        `${item.startFrameIndex}→${item.endFrameIndex}`
      ]);
      const panel = `<article class="panel"><div class="result-title"><b>CANopen / SDO 真题证据</b><span>${(canopen.events || []).length} events</span></div>
        <p class="notice">识别到标准 SDO COB-ID 与对象字典访问。优先看设备身份对象和 segmented upload/download 重组结果。</p>
        ${objectRows.length ? table(['Node','Index','Sub','对象','方向','ASCII','HEX','帧'], objectRows) : ''}
        ${transferRows.length ? table(['Node','方向','Index','对象','长度','状态','重组值','帧范围'], transferRows) : ''}
        <div class="hint-list">${(canopen.hints || []).map((item) => `<p>${esc(item)}</p>`).join('')}</div>
      </article>`;
      return `${panel}${baseHtml}`;
    }

    if (tool === 'mavlink-hex') {
      const baseHtml = originalRenderResult(tool, result);
      const summary = result?.securitySummary;
      const findings = result?.findings || [];
      const events = result?.highRiskEvents || [];
      if (!summary && !findings.length && !events.length) return baseHtml;

      const eventRows = events.slice(0, 100).map((item) => [
        item.frameIndex || '—',
        item.type || '—',
        item.commandName || item.command || item.device ?? '—',
        item.action || (item.shellCandidate ? 'PX4 shell candidate' : '—'),
        item.dataText || item.text || '—'
      ]);
      const findingRows = findings.slice(0, 100).map((item) => [
        item.severity || 'info',
        item.frameIndex || '—',
        item.id || '—',
        item.title || '—',
        findingEvidence(item)
      ]);
      const panel = `<article class="panel"><div class="result-title"><b>MAVLink 飞控安全证据</b><span>${summary?.armToSerialChain ? 'ARM → SERIAL' : 'telemetry'}</span></div>
        <div class="result-stats"><div><b>${summary?.mavlink1Frames || 0}</b><span>MAVLink 1</span></div><div><b>${summary?.mavlink2Frames || 0}</b><span>MAVLink 2</span></div><div><b>${summary?.unsignedV2Frames || 0}</b><span>Unsigned v2</span></div><div><b>${summary?.sequenceGapCount || 0}</b><span>SEQ gaps</span></div></div>
        ${summary?.armToSerialChain ? '<p class="notice">检测到 ARM 后出现 SERIAL_CONTROL。若 device=10 或伴随 debug/shell STATUSTEXT，优先核对 PX4 调试串口是否被解锁。</p>' : ''}
        ${eventRows.length ? table(['帧','事件','命令/设备','动作','数据/文本'], eventRows) : ''}
        ${findingRows.length ? table(['级别','帧','规则','发现','证据'], findingRows) : ''}
      </article>`;
      return `${panel}${baseHtml}`;
    }

    if (tool === 'ai-source-scan' && result?.llmCrypto) {
      const baseHtml = originalRenderResult(tool, result);
      const chain = result.llmCrypto;
      const evidence = `<article class="panel"><div class="result-title"><b>LLM → Crypto 攻击链</b><span>真题模式</span></div>${table(['节点','证据'], [
        ['模型调用', chain.modelCallDetected ? 'detected' : 'not proven'],
        ['模型输出', chain.outputEvidence || '—'],
        ['密钥派生', chain.keyDerivationEvidence || '—'],
        ['加密使用', chain.encryptionEvidence || '—'],
        ['temperature', (chain.temperatures || []).join(', ') || '—']
      ])}<p class="notice">固定 model / prompt / temperature 后，优先枚举模型输出候选，并用 padding、明文格式或业务校验作为本地 oracle。</p></article>`;
      return `${evidence}${baseHtml}`;
    }

    return originalRenderResult(tool, result);
  };

  const originalWorkspaceView = workspaceView;
  workspaceView = function workspaceViewWithFinalsEvidence() {
    const baseHtml = originalWorkspaceView();
    if (!state.workspace) return baseHtml;

    const cards = [];
    for (const file of state.workspace.files || []) {
      const ai = file.metadata?.aiAudit;
      if (ai?.llmCrypto) {
        cards.push(`<article class="panel result-panel"><div class="result-title"><b>AI 真题链 · ${esc(file.path)}</b><span>LLM → Crypto</span></div>${table(['节点','证据'], [
          ['模型输出', ai.llmCrypto.outputEvidence || '—'],
          ['KDF / Hash', ai.llmCrypto.keyDerivationEvidence || '—'],
          ['Crypto', ai.llmCrypto.encryptionEvidence || '—'],
          ['temperature', (ai.llmCrypto.temperatures || []).join(', ') || '—']
        ])}</article>`);
      }

      const can = file.metadata?.pcapng?.can;
      const canopen = can?.summary?.canopen;
      if (canopen?.detected) {
        const named = (canopen.objectValues || []).filter((item) => item.objectName || item.value?.ascii).slice(0, 24);
        cards.push(`<article class="panel result-panel"><div class="result-title"><b>CANopen / SDO · ${esc(file.path)}</b><span>${named.length} object values</span></div>${named.length ? table(['Node','Index','对象','值'], named.map((item) => [item.nodeId,item.index,item.objectName || '—',item.value?.ascii || item.value?.hex || '—'])) : '<p class="notice">检测到 SDO 会话，可在 CAN 工具中查看完整分段重组。</p>'}</article>`);
      }

      const solana = file.metadata?.solanaAudit;
      if (solana) {
        cards.push(`<article class="panel result-panel"><div class="result-title"><b>Solana / Anchor · ${esc(file.path)}</b><span>${esc(solana.programId || 'Anchor')}</span></div>${table(['字段','值'], [
          ['Program ID', solana.programId || '—'],
          ['Instructions', (solana.instructions || []).join(', ') || '—'],
          ['PDA seeds', (solana.pdaSeeds || []).join(', ') || '—'],
          ['Signer', (solana.signers || []).join(', ') || '—'],
          ['Raw AccountInfo', (solana.rawAccountInfos || []).map((item) => `${item.name}@L${item.line}`).join(', ') || '—'],
          ['msg!', (solana.messages || []).join(', ') || '—']
        ])}</article>`);
      }

      const anchor = file.metadata?.anchorConfig;
      if (anchor) {
        cards.push(`<article class="panel result-panel"><div class="result-title"><b>Anchor 环境 · ${esc(file.path)}</b><span>${esc(anchor.cluster || 'unknown')}</span></div>${table(['配置','值'], [
          ['Solana', anchor.solanaVersion || '—'],
          ['Anchor', anchor.anchorVersion || '—'],
          ['Cluster', anchor.cluster || '—']
        ])}</article>`);
      }
    }

    if (!cards.length) return baseHtml;
    return baseHtml.replace('<div class="workspace-actions">', `${cards.join('')}<div class="workspace-actions">`);
  };

  render();
})();
