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
