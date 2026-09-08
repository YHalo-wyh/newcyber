(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof renderResult !== 'function') return;

  const tool='ai-prompt-injection-suite';
  TOOL_META[tool]={
    domain:'ai',
    title:'提示词注入训练 / 模板库',
    label:'可选 JSON：category / ids / marker / canary / tool',
    placeholder:'{"category":"direct"}\n\n留空或输入 {} 可加载全部模板。'
  };

  const exists=(DOMAINS.ai.tools||[]).some((x)=>x[0]===tool);
  if (!exists) DOMAINS.ai.tools.unshift([
    tool,
    '提示词注入训练 / 模板库',
    '直接注入、间接文档、RAG、工具返回值、角色伪造、Canary 泄露和跨轮持久化。模板只使用训练 marker / canary / no-op 工具。'
  ]);

  const previousRenderResult=renderResult;

  function templateCards(items=[]) {
    if (!items.length) return '<div class="result-empty">当前过滤条件没有模板。</div>';
    return items.map((item)=>`<article class="panel">
      <div class="result-title"><b>${esc(item.title)}</b><small>${esc(item.id)} · ${esc(item.category)} · ${esc(item.placement)}</small></div>
      <p><b>威胁：</b>${esc(item.threat)}</p>
      <pre class="output-pre">${esc(item.payload)}</pre>
      <p><b>安全预期：</b>${esc(item.expected)}</p>
      ${item.failureSignals?.length?`<p><b>显式失败信号：</b>${esc(item.failureSignals.join('；'))}</p>`:''}
      ${item.mutations?.length?`<small>Mutations：${esc(item.mutations.join(' · '))}</small>`:''}
    </article>`).join('');
  }

  function promptInjectionResult(r) {
    return `<div class="result-stats">
      <div><b>${r.templates?.length||0}</b><span>模板</span></div>
      <div><b>${r.coverage?.length||0}</b><span>覆盖类别</span></div>
      <div><b>${esc(r.marker||'—')}</b><span>训练 Marker</span></div>
      <div><b>${esc(r.tool||'—')}</b><span>No-op Tool</span></div>
    </div>
    <div class="hint-list">
      <p><b>System setup：</b>${esc(r.setup?.system||'')}</p>
      <p><b>判定原则：</b>${esc(r.setup?.evaluator||'')}</p>
    </div>
    <details class="panel" open><summary><b>训练模板</b> · ${r.templates?.length||0}</summary>${templateCards(r.templates||[])}</details>
    ${r.notes?.length?`<div class="hint-list">${r.notes.map((x)=>`<p>${esc(x)}</p>`).join('')}</div>`:''}
    <details class="panel"><summary><b>运行结果回放格式</b></summary><pre class="output-pre">${esc(JSON.stringify({templateId:'direct-instruction-override',response:'模型实际响应',toolCalls:[],authorizedTools:[]},null,2))}</pre><p>底层已提供 ai-prompt-injection-evaluate 路由，可把 marker/canary 泄露与未授权工具调用作为显式失败证据。</p></details>`;
  }

  renderResult=function promptInjectionRenderResult(current,result) {
    if (current===tool) return promptInjectionResult(result);
    return previousRenderResult(current,result);
  };

  render();
})();
