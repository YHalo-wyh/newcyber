(() => {
  TOOL_META['auto-decode'] = {
    domain: 'common',
    title: '可疑数据自动试解',
    placeholder: '把可疑字符串直接粘进来，例如 Base64 / Hex / XOR 后的数据…',
    label: '可疑数据'
  };

  const previousHomeView = homeView;
  const previousCommonView = commonView;
  const previousRenderResult = renderResult;

  homeView = function autoDecodeHomeView() {
    const html = previousHomeView();
    const launch = `<button class="search-launch auto-decode-launch" data-tool="auto-decode"><span>↻</span><div><b>拿到一段可疑数据？自动试解</b><small>Hex / Base64 / URL / ROT / XOR / gzip 等高收益链，优先找 Flag 和文件头</small></div><em>开始 →</em></button>`;
    const marker = '</section>';
    return html.includes(marker) ? html.replace(marker, `${launch}${marker}`) : `${launch}${html}`;
  };

  commonView = function autoDecodeCommonView() {
    return `${previousCommonView()}<button class="search-launch auto-decode-launch" data-tool="auto-decode"><span>↻</span><div><b>可疑数据自动试解</b><small>不用自己逐个尝试常见编码、ROT、单字节 XOR 和压缩层</small></div><em>打开 →</em></button>`;
  };

  function candidateCard(candidate, index) {
    const path = candidate.path?.length ? candidate.path.join(' → ') : '原始输入';
    const flag = candidate.flags?.[0] || null;
    const badge = flag ? 'FLAG' : candidate.magic || `score ${candidate.score}`;
    const button = candidate.artifact
      ? `<button class="button" data-auto-decode-artifact="${index}">导出 ${esc(candidate.magic || '文件')} 候选</button>`
      : '';
    return `<div class="finding ${flag ? 'high' : 'medium'}"><span>${esc(badge)}</span><div><b>${esc(path)}</b><small>${candidate.size} bytes · printable ${Math.round((candidate.printableRatio || 0) * 100)}%</small><pre>${esc(flag || candidate.preview || candidate.hexPreview || '')}</pre>${button}</div></div>`;
  }

  renderResult = function autoDecodeRenderResult(tool, result) {
    if (tool !== 'auto-decode') return previousRenderResult(tool, result);
    const best = result.bestCandidates || [];
    const found = result.foundFlag
      ? `<div class="error-box" style="border-color:#46654f;background:#14241a;color:#64d99a"><b>发现 Flag 候选</b><br>${esc(result.foundFlag)}</div>`
      : '';
    return `${found}
      <div class="result-stats"><div><b>${result.triedCandidates || 0}</b><span>尝试候选</span></div><div><b>${result.maxDepth || 0}</b><span>最大层数</span></div><div><b>${result.flagHits?.length || 0}</b><span>Flag 命中</span></div></div>
      <p class="notice"><b>下一步：</b>${esc(result.bestAction || '')}</p>
      ${best.length ? best.slice(0, 10).map(candidateCard).join('') : '<div class="result-empty">没有找到高质量候选。</div>'}
      <p class="notice">${esc(result.note || '')}</p>`;
  };

  document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-auto-decode-artifact]');
    if (!button) return;
    const index = Number(button.dataset.autoDecodeArtifact);
    const artifact = state.toolResult?.bestCandidates?.[index]?.artifact;
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
