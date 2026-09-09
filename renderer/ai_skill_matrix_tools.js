(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof renderResult !== 'function') return;

  const TOOL='ai-skill-matrix';
  const title='AI 一阶段五方向矩阵 / 一键诊断';
  const desc='按最新赛题说明收束为：提示词工程与大模型安全、对抗样本、模型隐私与数据泄露、模型后门与数据投毒、AI 基础设施与供应链安全。';
  const placeholder=`{
  "source": "# LLM/RAG/Agent 或模型加载源码",
  "promptRun": {"templateId":"direct-instruction-override","response":"...","toolCalls":[],"authorizedTools":[]},
  "adversarialBatch": {"samples":[],"epsilon":0.03,"norm":"linf","clip":[0,1]},
  "privacy": {"rows":[]},
  "extraction": {"rows":[],"holdoutFidelity":0.0},
  "inversion": {"rows":[]},
  "dataset": "text,label\\nnormal,0\\nrare_trigger sample,1",
  "poisoning": {"rows":[]},
  "backdoor": {"targetLabel":1,"rows":[]},
  "supplyChain": "model = torch.load(path, weights_only=False)"
}

也可以直接粘贴单个 JSON / CSV / 源码，矩阵会先做类型路由。`;

  TOOL_META[TOOL]={ domain:'ai',title,label:'五方向赛题证据 / JSON Bundle / CSV / 源码',placeholder };
  if (!(DOMAINS.ai.tools||[]).some((x)=>x[0]===TOOL)) DOMAINS.ai.tools.unshift([TOOL,title,desc]);

  const previousRenderResult=renderResult;

  function statusMeta(status) {
    return ({
      evidence:['EVIDENCE','已有证据','high'],
      candidate:['CANDIDATE','候选','medium'],
      'no-explicit-finding':['NO EXPLICIT FINDING','未见显式 finding','info'],
      'data-needed':['DATA NEEDED','数据不足','info']
    })[status] || [String(status||'UNKNOWN').toUpperCase(),String(status||'unknown'),'info'];
  }

  function value(v) {
    if (v===null || v===undefined || v==='') return '—';
    if (typeof v==='number') return Number.isInteger(v)?String(v):Number(v).toPrecision(5);
    if (typeof v==='object') return JSON.stringify(v);
    return String(v);
  }

  function findingsBlock(findings=[]) {
    if (!findings.length) return '<p class="notice">当前方向没有形成显式 finding。</p>';
    return findings.slice(0,10).map((f)=>`<div class="finding ${esc(f.severity||'info')}"><span>${esc(f.severity||'info')}</span><div><b>${esc(f.title||f.id||'finding')}</b><small>${esc(f.id||'')}${f.analyzer?` · ${esc(f.analyzer)}`:''}</small><p>${esc(f.meaning||f.message||'')}</p>${f.evidence!==undefined?`<pre>${esc(typeof f.evidence==='string'?f.evidence:JSON.stringify(f.evidence,null,2))}</pre>`:''}</div></div>`).join('');
  }

  function metricTable(metrics={}) {
    const rows=Object.entries(metrics).filter(([,v])=>v!==undefined && v!==null && v!=='');
    if (!rows.length) return '';
    return table(['指标','值'],rows.map(([k,v])=>[k,value(v)]));
  }

  function subskillsBlock(items=[]) {
    if (!items.length) return '';
    return `<div class="hint-list">${items.map((item)=>`<p><b>${esc(item.id)}</b> · ${esc(statusMeta(item.status)[1])} · confidence=${esc(item.confidence||'—')}</p>`).join('')}</div>`;
  }

  function skillCard(skill,index) {
    const [code,label]=statusMeta(skill.status);
    return `<article class="panel">
      <div class="result-title"><div><span class="kicker">0${index+1} · ${esc(code)}</span><b>${esc(skill.title)}</b><small>一阶段考察方向</small></div><span class="surface ${skill.status==='evidence'?'on':''}">${esc(label)}</span></div>
      <p class="notice"><b>下一步：</b>${esc(skill.nextAction||skill.dataHint||'')}</p>
      ${subskillsBlock(skill.subskills||[])}
      ${metricTable(skill.metrics||{})}
      ${findingsBlock(skill.findings||[])}
      ${skill.errors?.length?`<details><summary>解析提示</summary><pre class="mini-pre">${esc(skill.errors.join('\n'))}</pre></details>`:''}
      <details><summary>推荐工具</summary><p>${(skill.tools||[]).map((x)=>`<code>${esc(x)}</code>`).join(' · ')}</p></details>
    </article>`;
  }

  function matrixResult(r) {
    const s=r.summary||{},routing=r.inputRouting||{};
    return `<div class="result-stats">
        <div><b>${r.officialCoverage||0}</b><span>官方一阶段方向</span></div>
        <div><b>${s.evidence||0}</b><span>已有证据</span></div>
        <div><b>${s.candidate||0}</b><span>候选</span></div>
        <div><b>${s['data-needed']||0}</b><span>数据不足</span></div>
      </div>
      <p class="notice"><b>输入路由：</b>${esc((routing.providedSlots||[]).join(', ')||'未识别专用槽位')} ${routing.detections?.length?`· 自动识别 ${esc(routing.detections.join(', '))}`:''}</p>
      <div class="hint-list"><p><b>当前一级结构：</b>${esc((r.officialDirections||[]).join(' / '))}</p><p>对抗样本支持整批预算与成功率；隐私方向显示 AUC、TPR@0.1FPR、membership advantage、holdout fidelity 与 reconstruction；供应链单独检查模型加载与 artifact provenance。</p><p>NO EXPLICIT FINDING 不是安全证明。</p></div>
      ${(r.skills||[]).map(skillCard).join('')}
      ${r.nextQueue?.length?`<details class="panel" open><summary><b>下一步队列</b> · ${r.nextQueue.length}</summary>${table(['优先级','方向','状态','下一步'],r.nextQueue.map((x,i)=>[i+1,x.title,statusMeta(x.status)[1],x.nextAction]))}</details>`:''}`;
  }

  renderResult=function aiSkillMatrixRenderResult(tool,result) {
    if (tool===TOOL) return matrixResult(result);
    return previousRenderResult(tool,result);
  };

  render();
})();
