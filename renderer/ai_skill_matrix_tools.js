(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof renderResult !== 'function') return;

  const TOOL='ai-skill-matrix';
  const title='AI 安全六考点矩阵 / 一键诊断';
  const desc='把 Prompt Injection、对抗样本、数据投毒、模型窃取、模型逆向、后门攻击收成一张证据矩阵；自动区分已有证据、候选、未见显式 finding 与数据不足。';
  const placeholder=`{
  "source": "# 可选：LLM/RAG/Agent 源码",
  "promptRun": {"templateId":"direct-instruction-override","response":"...","toolCalls":[],"authorizedTools":[]},
  "adversarial": {"original":[0,0],"adversarial":[0.01,0],"epsilon":0.03,"norm":"linf","trueLabel":0,"predictedAdversarial":1},
  "dataset": "text,label\\nnormal,0\\nrare_trigger sample,1",
  "poisoning": {"rows":[]},
  "extraction": {"rows":[],"holdoutFidelity":0.0},
  "inversion": {"rows":[]},
  "backdoor": {"targetLabel":1,"rows":[]}
}

也可以直接粘贴单个 JSON / CSV / 源码，矩阵会先做类型路由。`;

  TOOL_META[TOOL]={ domain:'ai',title,label:'赛题证据 / JSON Bundle / CSV / 源码',placeholder };
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
    if (!findings.length) return '<p class="notice">当前这一考点没有形成显式 finding。</p>';
    return findings.slice(0,8).map((f)=>`<div class="finding ${esc(f.severity||'info')}"><span>${esc(f.severity||'info')}</span><div><b>${esc(f.title||f.id||'finding')}</b><small>${esc(f.id||'')}${f.analyzer?` · ${esc(f.analyzer)}`:''}</small><p>${esc(f.meaning||f.message||'')}</p>${f.evidence!==undefined?`<pre>${esc(typeof f.evidence==='string'?f.evidence:JSON.stringify(f.evidence,null,2))}</pre>`:''}</div></div>`).join('');
  }

  function metricTable(metrics={}) {
    const rows=Object.entries(metrics).filter(([,v])=>v!==undefined && v!==null && v!=='');
    if (!rows.length) return '';
    return table(['指标','值'],rows.map(([k,v])=>[k,value(v)]));
  }

  function skillCard(skill) {
    const [code,label,severity]=statusMeta(skill.status);
    return `<article class="panel">
      <div class="result-title"><div><span class="kicker">${esc(code)}</span><b>${esc(skill.title)}</b><small>官方考点：${esc(skill.trainingPoint||skill.title)}</small></div><span class="surface ${skill.status==='evidence'?'on':''}">${esc(label)}</span></div>
      <p class="notice"><b>下一步：</b>${esc(skill.nextAction||skill.dataHint||'')}</p>
      ${metricTable(skill.metrics||{})}
      ${findingsBlock(skill.findings||[])}
      ${skill.errors?.length?`<details><summary>解析提示</summary><pre class="mini-pre">${esc(skill.errors.join('\n'))}</pre></details>`:''}
      <details><summary>推荐工具</summary><p>${(skill.tools||[]).map((x)=>`<code>${esc(x)}</code>`).join(' · ')}</p></details>
    </article>`;
  }

  function matrixResult(r) {
    const s=r.summary||{};
    const routing=r.inputRouting||{};
    return `<div class="result-stats">
        <div><b>${s.evidence||0}</b><span>已有证据</span></div>
        <div><b>${s.candidate||0}</b><span>候选</span></div>
        <div><b>${s['no-explicit-finding']||0}</b><span>未见显式 finding</span></div>
        <div><b>${s['data-needed']||0}</b><span>数据不足</span></div>
      </div>
      <p class="notice"><b>输入路由：</b>${esc((routing.providedSlots||[]).join(', ')||'未识别专用槽位')} ${routing.detections?.length?`· 自动识别 ${esc(routing.detections.join(', '))}`:''}</p>
      <div class="hint-list"><p><b>矩阵原则：</b>no-explicit-finding 不是“安全”；它只代表当前材料没有形成显式失败证据。</p><p>模型窃取看独立 holdout fidelity，模型逆向看 reconstruction，后门优先看 trigger 与 neutral/control 对照。</p></div>
      ${(r.skills||[]).map(skillCard).join('')}
      ${r.nextQueue?.length?`<details class="panel" open><summary><b>下一步队列</b> · ${r.nextQueue.length}</summary>${table(['优先级','考点','状态','下一步'],r.nextQueue.map((x,i)=>[i+1,x.title,statusMeta(x.status)[1],x.nextAction]))}</details>`:''}`;
  }

  renderResult=function aiSkillMatrixRenderResult(tool,result) {
    if (tool===TOOL) return matrixResult(result);
    return previousRenderResult(tool,result);
  };

  render();
})();
