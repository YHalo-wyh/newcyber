(() => {
  const PANEL_ID = 'investigation-panel';
  const OPEN_KEY = 'newcyber.investigationOpen';
  const REVIEW_PREFIX = 'newcyber.investigationReview:';
  const baseRender = render;

  function workspaceKey() {
    return state.workspace?.workspacePath || state.workspace?.workspaceName || 'workspace';
  }

  function readJson(key, fallback = {}) {
    try {
      const value = JSON.parse(localStorage.getItem(key));
      return value == null ? fallback : value;
    } catch (_) { return fallback; }
  }

  function reviewState() {
    return readJson(`${REVIEW_PREFIX}${workspaceKey()}`, {});
  }

  function setReview(nodeId, status) {
    const current = reviewState();
    if (!status || status === 'pending') delete current[nodeId];
    else current[nodeId] = status;
    try { localStorage.setItem(`${REVIEW_PREFIX}${workspaceKey()}`, JSON.stringify(current)); } catch (_) {}
    enhanceInvestigation();
  }

  function storedOpen() {
    try { return localStorage.getItem(OPEN_KEY) !== '0'; } catch (_) { return true; }
  }

  function setOpen(open) {
    document.body.classList.toggle('investigation-open', open);
    try { localStorage.setItem(OPEN_KEY, open ? '1' : '0'); } catch (_) {}
  }

  function graph() {
    return state.workspace?.investigation || null;
  }

  function resolveArtifact(ref) {
    const file = (state.workspace?.files || []).find((item) => item.path === ref?.sourceFile);
    if (!file) return null;
    if (ref.source === 'uds') return file.metadata?.pcapng?.can?.udsProgramming?.transfers?.[ref.index]?.artifact || null;
    if (ref.source === 'mavftp') {
      const ftp = file.metadata?.lowAltitude?.ftpReassembly || file.metadata?.mavlink?.ftpReassembly;
      return ftp?.files?.[ref.index]?.artifact || null;
    }
    if (ref.source === 'auto-decode') return file.metadata?.autoDecode?.candidates?.[ref.index]?.artifact || null;
    if (ref.source === 'context-crypto') return file.metadata?.contextCrypto?.bestCandidates?.[ref.index]?.artifact || null;
    return null;
  }

  function reviewLabel(status) {
    if (status === 'confirmed') return '已验证';
    if (status === 'dismissed') return '已排除';
    return '待验证';
  }

  function reviewClass(status) {
    if (status === 'confirmed') return 'confirmed';
    if (status === 'dismissed') return 'dismissed';
    return 'pending';
  }

  function evidenceBlock(label, value) {
    if (!value) return '';
    return `<div class="investigation-detail-row"><span>${esc(label)}</span><p>${esc(value)}</p></div>`;
  }

  function findingCard(node, review) {
    const status = review[node.id] || 'pending';
    return `<details class="investigation-finding ${esc(node.severity || 'info')} ${reviewClass(status)}" data-investigation-node="${esc(node.id)}">
      <summary>
        <span class="investigation-severity">${esc(node.severity || 'info')}</span>
        <span class="investigation-finding-title"><strong>${esc(node.title)}</strong><small>${esc(node.file || 'workspace')}${node.line ? ` · L${Number(node.line)}` : ''}</small></span>
        <em>${reviewLabel(status)}</em>
      </summary>
      <div class="investigation-detail">
        ${evidenceBlock('Evidence', node.evidence)}
        ${evidenceBlock('Meaning', node.meaning)}
        ${evidenceBlock('Prerequisite', node.prerequisite)}
        ${evidenceBlock('Exploitability', node.exploitability)}
        ${evidenceBlock('Fix', node.fix)}
        ${evidenceBlock('Regression', node.regression)}
        ${evidenceBlock('Next', node.nextAction)}
        <div class="investigation-actions-row">
          ${node.recommendedTool ? `<button class="button primary" data-investigation-tool="${esc(node.recommendedTool)}">打开推荐工具</button>` : ''}
          ${node.file ? `<button class="button" data-investigation-file="${esc(node.file)}">定位文件</button>` : ''}
          <button class="text-button" data-investigation-copy="${esc(node.id)}">复制证据</button>
        </div>
        <div class="investigation-review-row"><span>人工复核</span><button data-review-status="pending" data-review-node="${esc(node.id)}" class="${status === 'pending' ? 'active' : ''}">待定</button><button data-review-status="confirmed" data-review-node="${esc(node.id)}" class="${status === 'confirmed' ? 'active' : ''}">确认</button><button data-review-status="dismissed" data-review-node="${esc(node.id)}" class="${status === 'dismissed' ? 'active' : ''}">排除</button></div>
      </div>
    </details>`;
  }

  function actionCard(item, index) {
    return `<div class="investigation-next-item ${esc(item.severity || 'info')}">
      <b>${index + 1}</b><div><strong>${esc(item.title)}</strong><p>${esc(item.text)}</p><div class="investigation-actions-row">
        ${item.tool ? `<button class="text-button" data-investigation-tool="${esc(item.tool)}">打开工具</button>` : ''}
        ${item.file ? `<button class="text-button" data-investigation-file="${esc(item.file)}">查看来源</button>` : ''}
        ${item.artifactId ? `<button class="text-button" data-investigation-artifact="${esc(item.artifactId)}">导出产物</button>` : ''}
      </div></div>
    </div>`;
  }

  function panelHtml(data) {
    const review = reviewState();
    const confirmedByAnalyst = Object.values(review).filter((x) => x === 'confirmed').length;
    const dismissedByAnalyst = Object.values(review).filter((x) => x === 'dismissed').length;
    return `<aside id="${PANEL_ID}" class="investigation-panel" aria-label="Investigation Panel">
      <div class="investigation-head"><div><span>INVESTIGATION</span><strong>${esc(state.workspace?.workspaceName || '赛题')}</strong></div><button data-investigation-close aria-label="收起 Investigation Panel">×</button></div>
      <div class="investigation-summary">
        <div><b>${data.summary?.high || 0}</b><span>High</span></div>
        <div><b>${data.summary?.confirmed || 0}</b><span>证据确认</span></div>
        <div><b>${confirmedByAnalyst}</b><span>人工确认</span></div>
        <div><b>${data.summary?.artifacts || 0}</b><span>Artifact</span></div>
      </div>
      ${dismissedByAnalyst ? `<p class="investigation-review-note">已人工排除 ${dismissedByAnalyst} 条；这里只影响本机复核状态，不修改分析器原始结论。</p>` : ''}
      <section class="investigation-section"><div class="investigation-section-title"><b>下一步</b><span>${data.nextActions?.length || 0}</span></div>${(data.nextActions || []).length ? `<div class="investigation-next-list">${data.nextActions.map(actionCard).join('')}</div>` : '<div class="investigation-empty">当前没有高价值动作，先确认主要附件和题目入口。</div>'}</section>
      <section class="investigation-section"><div class="investigation-section-title"><b>证据队列</b><span>${data.focus?.length || 0}</span></div>${(data.focus || []).length ? `<div class="investigation-findings">${data.focus.map((node) => findingCard(node, review)).join('')}</div>` : '<div class="investigation-empty">暂未形成结构化 finding。</div>'}</section>
      ${(data.artifacts || []).length ? `<section class="investigation-section"><div class="investigation-section-title"><b>产物</b><span>${data.artifacts.length}</span></div><div class="investigation-artifacts">${data.artifacts.slice(0, 10).map((item) => `<button data-investigation-artifact="${esc(item.id)}"><span>${esc(item.kind)}</span><strong>${esc(item.name || 'artifact')}</strong><small>${fmtBytes(item.size || 0)} · ${esc((item.sha256 || '').slice(0, 12))}</small></button>`).join('')}</div></section>` : ''}
    </aside>`;
  }

  function ensureToggle(data) {
    const actions = document.querySelector('.top-actions');
    if (!actions || actions.querySelector('.investigation-toggle')) return;
    const button = document.createElement('button');
    button.className = 'investigation-toggle';
    button.dataset.investigationToggle = '1';
    button.innerHTML = `<span>调查</span><b>${data.summary?.high || 0}</b>`;
    button.title = '打开 Investigation Panel';
    actions.prepend(button);
  }

  function enhanceInvestigation() {
    document.getElementById(PANEL_ID)?.remove();
    document.querySelector('.investigation-toggle')?.remove();
    const data = graph();
    if (!state.workspace || !data) {
      document.body.classList.remove('investigation-open');
      return;
    }
    document.body.insertAdjacentHTML('beforeend', panelHtml(data));
    ensureToggle(data);
    setOpen(storedOpen());
  }

  render = function investigationRender(...args) {
    const result = baseRender(...args);
    enhanceInvestigation();
    return result;
  };

  document.addEventListener('click', async (event) => {
    if (event.target.closest('[data-investigation-toggle]')) {
      setOpen(!document.body.classList.contains('investigation-open'));
      return;
    }
    if (event.target.closest('[data-investigation-close]')) {
      setOpen(false);
      return;
    }
    const toolButton = event.target.closest('[data-investigation-tool]');
    if (toolButton) {
      const tool = toolButton.dataset.investigationTool;
      if (TOOL_META?.[tool]) openTool(tool);
      else toast(`推荐工具 ${tool} 当前未注册`, true);
      return;
    }
    const fileButton = event.target.closest('[data-investigation-file]');
    if (fileButton) {
      state.fileFilter = fileButton.dataset.investigationFile || '';
      navigate('workspace');
      requestAnimationFrame(() => document.querySelector('#file-filter')?.focus());
      return;
    }
    const reviewButton = event.target.closest('[data-review-node]');
    if (reviewButton) {
      setReview(reviewButton.dataset.reviewNode, reviewButton.dataset.reviewStatus || 'pending');
      return;
    }
    const copyButton = event.target.closest('[data-investigation-copy]');
    if (copyButton) {
      const node = graph()?.focus?.find((item) => item.id === copyButton.dataset.investigationCopy);
      if (!node) return;
      const content = [
        `Finding: ${node.title}`,
        `Severity: ${node.severity}`,
        `File: ${node.file || 'workspace'}${node.line ? `:${node.line}` : ''}`,
        `Evidence: ${node.evidence || '—'}`,
        `Prerequisite: ${node.prerequisite || '—'}`,
        `Exploitability: ${node.exploitability || '—'}`,
        `Next: ${node.nextAction || '—'}`,
        `Fix: ${node.fix || '—'}`,
        `Regression: ${node.regression || '—'}`
      ].join('\n');
      await navigator.clipboard.writeText(content);
      toast('证据链已复制');
      return;
    }
    const artifactButton = event.target.closest('[data-investigation-artifact]');
    if (artifactButton) {
      const ref = graph()?.artifacts?.find((item) => item.id === artifactButton.dataset.investigationArtifact);
      const artifact = resolveArtifact(ref);
      if (!artifact) return toast('未找到可导出的完整产物', true);
      artifactButton.disabled = true;
      try {
        const saved = await window.newcyber.saveArtifact(artifact);
        if (saved?.filePath) toast(`已导出 ${artifact.name || 'artifact'}`);
      } catch (error) {
        toast(error?.message || '导出失败', true);
      } finally {
        artifactButton.disabled = false;
      }
    }
  });

  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key.toLowerCase() === 'i' && state.workspace) {
      event.preventDefault();
      setOpen(!document.body.classList.contains('investigation-open'));
    }
  });

  enhanceInvestigation();
})();
