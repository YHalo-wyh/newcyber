(() => {
  TOOL_META['context-crypto'] = {
    domain: 'common',
    title: '上下文强加密试解',
    placeholder: '粘贴包含 AES/SM4、key、IV/nonce、mode、ciphertext 的源码 / 配置 / 日志…',
    label: '源码 / 配置 / 日志上下文'
  };

  const previousHomeView = homeView;
  const previousCommonView = commonView;
  const previousRenderResult = renderResult;

  homeView = function contextCryptoHomeView() {
    const html = previousHomeView();
    const launch = `<button class="search-launch" data-tool="context-crypto"><span>🔐</span><div><b>源码里有 AES / SM4？自动找 key / IV / 密文</b><small>只在参数明确时解密，成功后继续接自动试解链</small></div><em>开始 →</em></button>`;
    const marker = '</section>';
    return html.includes(marker) ? html.replace(marker, `${launch}${marker}`) : `${launch}${html}`;
  };

  commonView = function contextCryptoCommonView() {
    return `${previousCommonView()}<button class="search-launch" data-tool="context-crypto"><span>🔐</span><div><b>上下文强加密试解</b><small>AES / SM4 · key / IV / nonce / mode / tag / ciphertext 自动关联</small></div><em>打开 →</em></button>`;
  };

  function candidateCard(item, index) {
    const flag = item.flags?.[0];
    const title = flag || item.magic || item.cipher || '解密候选';
    const nested = item.nestedPath?.length ? `<small>后续：${esc(item.nestedPath.join(' → '))}</small>` : '';
    const artifact = item.artifact ? `<button class="button" data-context-crypto-artifact="${index}">导出 ${esc(item.magic || '解密文件')}</button>` : '';
    return `<div class="finding ${flag ? 'high' : item.magic ? 'medium' : 'info'}"><span>${flag ? 'FLAG' : esc(item.mode || 'crypto')}</span><div><b>${esc(title)}</b><small>${esc(item.cipher || '')} · key ${esc(item.keyEncoding || '—')} ${item.keyBytes || 0}B · ciphertext ${esc(item.ciphertextEncoding || '—')}</small><pre>${esc(item.preview || item.hexPreview || '')}</pre>${nested}${artifact}</div></div>`;
  }

  renderResult = function contextCryptoRenderResult(tool, result) {
    if (tool !== 'context-crypto') return previousRenderResult(tool, result);
    const ctx = result.context || {};
    const candidates = result.bestCandidates || [];
    const missing = ctx.missing?.length ? `<p class="notice"><b>缺少参数：</b>${esc(ctx.missing.join(', '))}</p>` : '';
    const found = result.foundFlag ? `<div class="error-box" style="border-color:#46654f;background:#14241a;color:#64d99a"><b>发现 Flag 候选</b><br>${esc(result.foundFlag)}</div>` : '';
    return `${found}
      <div class="result-stats"><div><b>${esc((ctx.algorithms || []).join('/') || '—')}</b><span>算法</span></div><div><b>${esc((ctx.modes || []).join('/') || '—')}</b><span>模式</span></div><div><b>${ctx.keys?.length || 0}</b><span>Key 候选</span></div><div><b>${result.tried || 0}</b><span>实际尝试</span></div></div>
      ${missing}<p class="notice"><b>下一步：</b>${esc(result.bestAction || '')}</p>
      ${candidates.length ? candidates.map(candidateCard).join('') : '<div class="result-empty">当前没有可展示的有效解密候选。</div>'}`;
  };

  document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-context-crypto-artifact]');
    if (!button) return;
    const artifact = state.toolResult?.bestCandidates?.[Number(button.dataset.contextCryptoArtifact)]?.artifact;
    if (!artifact) return;
    button.disabled = true;
    try {
      const saved = await window.newcyber.saveArtifact(artifact);
      if (saved?.filePath) toast(`已导出 ${artifact.name}`);
    } catch (error) {
      toast(error?.message || '导出失败', true);
    } finally {
      button.disabled = false;
    }
  });

  render();
})();
