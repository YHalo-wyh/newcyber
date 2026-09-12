(() => {
  const previousRenderResult = renderResult;
  const previousKnowledgeView = knowledgeView;
  const previousShell = shell;
  const previousToolView = toolView;

  function list(items, empty = '—') {
    if (!items?.length) return `<span>${empty}</span>`;
    return `<ul>${items.map((item) => `<li>${esc(item)}</li>`).join('')}</ul>`;
  }

  function knowledgeCard(item) {
    const tags = (item.tags || []).slice(0, 8).map((tag) => `<span class="surface on">${esc(tag)}</span>`).join('');
    return `<article class="panel" style="margin-bottom:12px">
      <div class="result-title"><div><span class="kicker">${esc(item.domain)} · ${esc(item.id)}</span><br><b>${esc(item.title || item.term)}</b></div><span>${Number(item.score || 0)}</span></div>
      <p>${esc(item.summary || item.text || '')}</p>
      <div class="surface-row">${tags}</div>
      <details>
        <summary>验证路径与比赛动作</summary>
        <div class="result-sub"><b>触发证据</b>${list(item.evidence)}</div>
        <div class="result-sub"><b>成立前提</b>${list(item.prerequisites)}</div>
        <div class="result-sub"><b>验证方法</b>${list(item.verify)}</div>
        <div class="result-sub"><b>常见误判</b>${list(item.falsePositives)}</div>
        <div class="result-sub"><b>下一步动作</b>${list(item.actions)}</div>
        <div class="result-sub"><b>泛化变异族</b>${list(item.mutations)}</div>
      </details>
    </article>`;
  }

  renderResult = function structuredKnowledgeRender(tool, result) {
    if (tool !== 'knowledge-search') return previousRenderResult(tool, result);
    const results = result.results || [];
    const stats = result.stats || {};
    const trackStats = Object.entries(stats.tracks || {}).map(([track, count]) => `${track}:${count}`).join(' · ');
    const header = `<div class="result-stats"><div><b>${stats.total || results.length}</b><span>Playbooks</span></div><div><b>${results.length}</b><span>命中</span></div></div>${trackStats ? `<p class="notice">${esc(trackStats)}</p>` : ''}`;
    return `${header}${results.length ? results.map(knowledgeCard).join('') : '<div class="result-empty">没有直接命中。尝试输入协议、漏洞原语、opcode、API 或攻击面关键词。</div>'}`;
  };

  knowledgeView = function structuredKnowledgeView() {
    const base = previousKnowledgeView();
    return base
      .replace('离线速查', 'AI 安全知识库')
      .replace('为断网赛场准备。收录 AI 安全速查条目：提示词注入、模型加载反序列化等，后续持续扩充。', '按 AI 安全能力族组织速查知识；条目包含触发证据、成立前提、误判边界和下一步验证。')
      .replace('搜索离线知识库', '搜索 AI 安全 Playbook')
      .replace('Prompt Injection / torch.load', 'Prompt Injection / torch.load / RAG 工具调用');
  };

  shell = function professionalShell(content) {
    return previousShell(content)
      .replace('OFFLINE FINALS KIT', 'CTF ANALYSIS WORKBENCH')
      .replace('Offline Ready', 'Workbench Ready')
      .replace('核心工具不依赖网络', 'Deterministic analysis pipeline');
  };

  toolView = function professionalToolView(tool) {
    return previousToolView(tool).replace('只在本机处理输入', 'Evidence-driven analysis');
  };

  render();
})();
