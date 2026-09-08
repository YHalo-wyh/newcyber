(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof renderResult !== 'function') return;

  const tools=[
    ['ai-poisoning-impact','数据投毒影响验证','对显式 clean/poison 样本、标签翻转、目标标签集中度和 baseline/suspect 指标差异做证据评估。'],
    ['ai-backdoor-behavior','后门行为验证','比较 clean / triggered / control 预测，计算 Clean Accuracy、ASR、Flip Rate 与对照特异性。']
  ];

  TOOL_META['ai-poisoning-impact']={
    domain:'ai',title:'数据投毒影响验证',label:'CSV/JSON：is_poison / label / original_label；可附 baseline / suspect metrics',
    placeholder:'{"rows":[{"is_poison":false,"label":0,"original_label":0},{"is_poison":true,"label":1,"original_label":0,"target_label":1,"trigger_id":"candidate-A"}],"baseline":{"accuracy":0.94},"suspect":{"accuracy":0.82}}'
  };
  TOOL_META['ai-backdoor-behavior']={
    domain:'ai',title:'后门行为验证',label:'CSV/JSON：true_label / clean_pred / triggered_pred / target_label / control_pred',
    placeholder:'{"targetLabel":1,"rows":[{"true_label":0,"clean_pred":0,"triggered_pred":1,"control_pred":0},{"true_label":2,"clean_pred":2,"triggered_pred":1,"control_pred":2}]}'
  };

  const existing=new Set((DOMAINS.ai.tools||[]).map((x)=>x[0]));
  for (const row of tools) if (!existing.has(row[0])) DOMAINS.ai.tools.push(row);

  const previousRenderResult=renderResult;

  function num(value,digits=4) {
    return value===null || value===undefined || !Number.isFinite(Number(value)) ? '—' : Number(value).toFixed(digits);
  }

  function findingCards(findings=[]) {
    if (!findings.length) return '<div class="result-empty">当前数据不足以形成显式高价值 finding。</div>';
    return findings.map((f)=>`<div class="finding ${esc(f.severity||'info')}"><span>${esc(f.severity||'info')}</span><div><b>${esc(f.title||f.id)}</b><small>${esc(f.id||'')}</small><p>${esc(f.meaning||'')}</p>${f.evidence?`<pre>${esc(typeof f.evidence==='string'?f.evidence:JSON.stringify(f.evidence,null,2))}</pre>`:''}</div></div>`).join('');
  }

  function poisoningResult(r) {
    const m=r.marked||{};
    const flip=r.labelFlip||{};
    return `<div class="result-stats">
      <div><b>${esc(r.verdict||'unknown')}</b><span>结论</span></div>
      <div><b>${r.rows||0}</b><span>样本</span></div>
      <div><b>${m.poison||0}</b><span>Poison 标记</span></div>
      <div><b>${num(r.contaminationRate)}</b><span>污染率</span></div>
    </div>
    ${typeof table==='function'?table(['指标','值'],[
      ['Clean 标记',m.clean??0],['Unknown',m.unknown??0],['标签可比较',flip.comparable??0],['标签翻转',flip.flips??0],['Label-flip rate',num(flip.rate)],['目标集中度',r.targetConcentration?`${esc(r.targetConcentration.label)} / ${num(r.targetConcentration.ratio)}`:'—'],['Top trigger',r.topTrigger?`${esc(r.topTrigger.trigger)} (${r.topTrigger.support})`:'—']
    ]):''}
    ${Object.keys(r.metrics?.deltas||{}).length?`<details class="panel" open><summary><b>Baseline → Suspect 指标差异</b></summary><pre class="mini-pre">${esc(JSON.stringify(r.metrics,null,2))}</pre></details>`:''}
    ${findingCards(r.findings||[])}
    ${r.nextActions?.length?`<div class="hint-list">${r.nextActions.map((x)=>`<p>${esc(x)}</p>`).join('')}</div>`:''}`;
  }

  function backdoorResult(r) {
    const m=r.metrics||{};
    return `<div class="result-stats">
      <div><b>${esc(r.verdict||'unknown')}</b><span>结论</span></div>
      <div><b>${esc(r.targetLabel??'—')}</b><span>Target</span></div>
      <div><b>${num(m.targetASR)}</b><span>Target ASR</span></div>
      <div><b>${num(m.flipRate)}</b><span>Flip Rate</span></div>
    </div>
    ${typeof table==='function'?table(['指标','值'],[
      ['Clean Accuracy',num(m.cleanAccuracy)],['Triggered Accuracy',num(m.triggeredAccuracy)],['Accuracy Drop',num(m.accuracyDrop)],['Target ASR',num(m.targetASR)],['Control Target Rate',num(m.controlTargetRate)],['Trigger Specificity',num(m.triggerSpecificity)],['Paired',r.paired??0],['Top transition',r.topTransition?`${esc(r.topTransition.transition)} / ${num(r.topTransition.ratio)}`:'—']
    ]):''}
    ${r.topTransition?`<p class="notice"><b>预测迁移：</b>${esc(r.topTransition.transition)} · support=${r.topTransition.support} · ratio=${num(r.topTransition.ratio)}</p>`:''}
    ${findingCards(r.findings||[])}
    ${r.nextActions?.length?`<div class="hint-list">${r.nextActions.map((x)=>`<p>${esc(x)}</p>`).join('')}</div>`:''}`;
  }

  renderResult=function poisonBackdoorRenderResult(tool,result) {
    if (tool==='ai-poisoning-impact') return poisoningResult(result);
    if (tool==='ai-backdoor-behavior') return backdoorResult(result);
    return previousRenderResult(tool,result);
  };

  render();
})();
