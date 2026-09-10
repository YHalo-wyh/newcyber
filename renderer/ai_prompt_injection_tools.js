(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof renderResult !== 'function') return;

  const tool='ai-prompt-injection-suite';
  TOOL_META[tool]={
    domain:'ai',
    title:'提示词攻击基础模板库',
    label:'可选 JSON：category / ids / marker / canary / tool',
    placeholder:'{}\n\nNewCyber 默认为比赛原生：留空或输入 {} 加载全部基础模板；可按 category / ids 缩小范围。Workspace Autopilot 会在这些模板上继续生成 mutation probes。'
  };

  const exists=(DOMAINS.ai.tools||[]).some((x)=>x[0]===tool);
  if (!exists) DOMAINS.ai.tools.unshift([
    tool,
    '提示词攻击基础模板库',
    '直接覆盖、角色伪造、格式劫持、间接文档、RAG、工具返回值、隐藏上下文与跨轮触发；默认全部用于比赛。'
  ]);

  const previousRenderResult=renderResult;

  function templateCards(items=[]) {
    if (!items.length) return '<div class="result-empty">当前过滤条件没有模板。</div>';
    return items.map((item)=>`<article class="panel">
      <div class="result-title"><b>${esc(item.title)}</b><small>${esc(item.id)} · ${esc(item.category)} · ${esc(item.placement)}</small></div>
      <p><b>攻击面：</b>${esc(item.threat)}</p>
      <pre class="output-pre">${esc(item.payload)}</pre>
      <p><b>预期边界：</b>${esc(item.expected)}</p>
      ${item.failureSignals?.length?`<p><b>成功/失败判据：</b>${esc(item.failureSignals.join('；'))}</p>`:''}
      ${item.mutations?.length?`<small>Mutation seeds：${esc(item.mutations.join(' · '))}</small>`:''}
    </article>`).join('');
  }

  function promptInjectionResult(r) {
    return `<div class="result-stats">
      <div><b>${r.templates?.length||0}</b><span>基础模板</span></div>
      <div><b>${r.coverage?.length||0}</b><span>攻击类别</span></div>
      <div><b>${esc(r.marker||'—')}</b><span>Marker</span></div>
      <div><b>COMPETITION</b><span>默认工作流</span></div>
    </div>
    <div class="hint-list">
      <p><b>默认策略：</b>所有基础模板都属于比赛候选池；Workspace Autopilot 会自动按题面排序并扩展 mutation probes。</p>
      <p><b>System setup：</b>${esc(r.setup?.system||'')}</p>
      <p><b>判定原则：</b>${esc(r.setup?.evaluator||'')}</p>
    </div>
    <details class="panel" open><summary><b>基础攻击模板</b> · ${r.templates?.length||0}</summary>${templateCards(r.templates||[])}</details>
    ${r.notes?.length?`<div class="hint-list">${r.notes.map((x)=>`<p>${esc(String(x).replace(/competition=true[^。]*。?/g,''))}</p>`).join('')}</div>`:''}
    <details class="panel"><summary><b>运行结果回放格式</b></summary><pre class="output-pre">${esc(JSON.stringify({templateId:'direct-instruction-override',response:'模型实际响应',toolCalls:[],authorizedTools:[]},null,2))}</pre><p>底层 ai-prompt-injection-evaluate 会把 marker/canary 泄露与未授权工具调用作为显式证据；没有命中不代表安全。</p></details>`;
  }

  renderResult=function promptInjectionRenderResult(current,result) {
    if (current===tool) return promptInjectionResult(result);
    return previousRenderResult(current,result);
  };

  render();
})();
