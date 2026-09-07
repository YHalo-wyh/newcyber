(() => {
  TOOL_META['auto-decode'] = {
    domain: 'common',
    title: '可疑数据自动试解',
    placeholder: '把可疑字符串直接粘进来，例如 Base64 / Hex / XOR 后的数据…',
    label: '可疑数据'
  };

  const previousHomeView = homeView;
  const previousCommonView = commonView;
  const previousToolView = toolView;
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

  toolView = function autoDecodeToolView(tool) {
    const html = previousToolView(tool);
    if (tool === 'auto-decode' || !state.toolResult) return html;
    const marker = '<button class="text-button" data-action="copy-result">复制</button>';
    const replacement = `<span style="display:flex;gap:8px"><button class="text-button" data-action="auto-decode-result">试解可疑结果</button>${marker}</span>`;
    return html.includes(marker) ? html.replace(marker, replacement) : html;
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

  function looksEncoded(value) {
    const text = String(value || '').trim();
    if (text.length < 8 || text.length > 4096) return false;
    return /^(?:0x)?[0-9a-f]{16,}$/i.test(text)
      || /^[A-Za-z0-9+/]{12,}={0,2}$/.test(text)
      || /^[A-Za-z0-9_-]{16,}={0,2}$/.test(text)
      || /(?:%[0-9a-f]{2}){4,}/i.test(text)
      || /(?:\\x[0-9a-f]{2}){4,}/i.test(text)
      || /^(?:[01]{8}[\s,_-]?){4,}$/i.test(text)
      || /^(?:\d{1,3}[\s,;:]+){5,}\d{1,3}$/.test(text);
  }

  function findSuspiciousValue(value, depth = 0) {
    if (depth > 5 || value == null) return null;
    if (typeof value === 'string') return looksEncoded(value) ? value.trim() : null;
    if (Array.isArray(value)) {
      for (const item of value.slice(0, 80)) {
        const found = findSuspiciousValue(item, depth + 1);
        if (found) return found;
      }
      return null;
    }
    if (typeof value === 'object') {
      const preferred = ['output', 'utf8', 'payload', 'data', 'hex', 'evidence', 'preview', 'sourcePreview'];
      const entries = Object.entries(value);
      entries.sort(([a], [b]) => preferred.indexOf(b) - preferred.indexOf(a));
      for (const [, item] of entries.slice(0, 100)) {
        const found = findSuspiciousValue(item, depth + 1);
        if (found) return found;
      }
    }
    return null;
  }

  async function runDecodeValue(value) {
    state.view = 'common';
    state.tool = 'auto-decode';
    state.toolError = null;
    try {
      state.toolResult = await window.newcyber.runTool('auto-decode', { input: value });
    } catch (error) {
      state.toolResult = null;
      state.toolError = error?.message || String(error);
    }
    render();
    const input = document.querySelector('#tool-input');
    if (input) input.value = value;
  }

  document.addEventListener('click', async (event) => {
    const decodeButton = event.target.closest('[data-action="auto-decode-result"]');
    if (decodeButton) {
      const selected = window.getSelection?.().toString().trim() || '';
      const value = selected || findSuspiciousValue(state.toolResult);
      if (!value) {
        toast('没有自动找到明显的编码串；可以选中可疑文本后再点一次。', true);
        return;
      }
      decodeButton.disabled = true;
      await runDecodeValue(value);
      return;
    }

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
