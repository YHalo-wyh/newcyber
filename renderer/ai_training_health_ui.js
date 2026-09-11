(() => {
  if (typeof toolView !== 'function') return;

  const TOOL='ai-skill-matrix';
  const previousToolView=toolView;
  const TRACKS={
    'prompt-llm-security':['prompt-llm-security'],
    'adversarial-example':['adversarial-example'],
    'privacy-leakage':['privacy-leakage','model-extraction'],
    'backdoor-poisoning':['backdoor-poisoning','dataset-pipeline-security'],
    'infra-supply-chain':['infra-supply-chain']
  };
  const TITLES={
    'prompt-llm-security':'提示词 / Agent',
    'adversarial-example':'对抗样本',
    'privacy-leakage':'隐私 / 提取',
    'backdoor-poisoning':'后门 / 数据链路',
    'infra-supply-chain':'基础设施 / 供应链'
  };
  const GAP_LABELS={
    'add-provenance-backed-cases':'补公开来源样本',
    'add-distinct-families':'补不同攻击 family',
    'add-cross-event-evidence':'补跨赛事证据',
    'upgrade-provenance-quality':'提升来源可信度',
    'reduce-duplicate-case-inflation':'降低重复样本膨胀',
    'build-cross-event-holdout':'建立跨赛事 holdout'
  };
  const READINESS={
    ready:{label:'可评估',tone:'good',rank:2},
    developing:{label:'建设中',tone:'warn',rank:1},
    seed:{label:'种子',tone:'gap',rank:0}
  };

  let curriculumResult=null;
  let curriculumBusy=false;
  let curriculumError='';

  function h(value){
    if (typeof esc==='function') return esc(String(value??''));
    return String(value??'').replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function byDirection(rows=[]){ return new Map((rows||[]).map((row)=>[row.direction,row])); }

  function aggregateDirection(direction){
    const tracks=TRACKS[direction]||[direction];
    const quality=byDirection(curriculumResult?.quality?.byDirection);
    const holdout=byDirection(curriculumResult?.holdout?.byDirection);
    const qs=tracks.map((id)=>quality.get(id)).filter(Boolean);
    const hs=tracks.map((id)=>holdout.get(id)).filter(Boolean);
    const readiness=qs.length?qs.reduce((worst,row)=>READINESS[row.readiness]?.rank<(READINESS[worst]?.rank??99)?row.readiness:worst,qs[0].readiness):'seed';
    const raw=qs.reduce((sum,row)=>sum+(row.rawCases||0),0);
    const effective=qs.reduce((sum,row)=>sum+(row.effectiveCases||0),0);
    const weakestEvents=qs.length?Math.min(...qs.map((row)=>row.uniqueEvents||0)):0;
    const weakestFamilies=qs.length?Math.min(...qs.map((row)=>row.uniqueFamilies||0)):0;
    const cleanPlans=hs.reduce((sum,row)=>sum+(row.summary?.cleanPlans||0),0);
    const unseenPlans=hs.reduce((sum,row)=>sum+(row.summary?.unseenFamilyPlans||0),0);
    const mismatch=tracks.some((id)=>quality.get(id)?.crossEventHoldoutReady && !holdout.get(id)?.eligible);
    const recommendations=[...new Set(qs.flatMap((row)=>row.recommendations||[]))];
    const nextGap=recommendations[0]||null;
    return {direction,tracks,readiness,raw,effective,weakestEvents,weakestFamilies,cleanPlans,unseenPlans,mismatch,nextGap};
  }

  function healthSummary(){
    const quality=curriculumResult?.quality?.summary||{};
    const holdout=curriculumResult?.holdout?.summary||{};
    const score=Number(quality.overallScore||0);
    return `<div class="stage1-health-summary">
      <div><span>QUALITY</span><b>${(score*100).toFixed(0)}%</b></div>
      <div><span>READY</span><b>${quality.ready||0}/${quality.directions||7}</b></div>
      <div><span>HOLDOUT</span><b>${holdout.eligibleDirections||0}/${holdout.directions||7}</b></div>
      <div><span>UNSEEN</span><b>${holdout.unseenFamilyPlans||0}</b></div>
    </div>`;
  }

  function directionRows(){
    return Object.keys(TRACKS).map((direction)=>{
      const row=aggregateDirection(direction);
      const meta=READINESS[row.readiness]||READINESS.seed;
      const gap=row.nextGap?GAP_LABELS[row.nextGap]||row.nextGap:'当前结构门禁已满足';
      return `<div class="stage1-health-row">
        <div class="stage1-health-row-main"><span>${h(TITLES[direction]||direction)}</span><small>${h(row.tracks.join(' + '))}</small></div>
        <div class="stage1-health-metrics"><b>${row.effective.toFixed(1)}<i>/${row.raw}</i></b><small>有效/原始 · 弱项 E${row.weakestEvents} F${row.weakestFamilies} · H${row.cleanPlans} U${row.unseenPlans}</small></div>
        <em class="stage1-health-badge ${meta.tone}">${h(meta.label)}</em>
        <p class="stage1-health-gap ${row.mismatch?'mismatch':''}">${row.mismatch?'门禁与实际 holdout 不一致 · ':''}${h(gap)}</p>
      </div>`;
    }).join('');
  }

  function healthPanel(){
    const button=curriculumBusy?'加载中':'刷新';
    if (!curriculumResult) {
      return `<section class="stage1-health-panel">
        <div class="stage1-health-head"><div><span>TRAINING HEALTH</span><b>训练覆盖健康度</b></div><button class="button ghost" data-training-health ${curriculumBusy?'disabled':''}>${curriculumBusy?'加载中':'加载'}</button></div>
        ${curriculumError?`<p class="stage1-training-error">${h(curriculumError)}</p>`:''}
        <div class="stage1-health-empty"><b>不是看样本数量，而是看能不能跨赛事评估。</b><p>读取 Batch95 quality + Batch96 holdout，显示有效样本、赛事 / family 弱项、clean holdout 和 unseen-family 压力测试。</p></div>
      </section>`;
    }
    return `<section class="stage1-health-panel">
      <div class="stage1-health-head"><div><span>TRAINING HEALTH</span><b>训练覆盖健康度</b></div><button class="button ghost" data-training-health ${curriculumBusy?'disabled':''}>${button}</button></div>
      ${healthSummary()}
      <div class="stage1-health-table">${directionRows()}</div>
      <div class="stage1-health-legend"><span>有效/原始</span><span>E/F = 最弱子轨赛事 / family</span><span>H = clean holdout</span><span>U = unseen-family</span></div>
    </section>`;
  }

  function injectHealth(html){
    if (typeof html!=='string'||!html.includes('stage1-training-pane')) return html;
    const marker='<div class="stage1-training-note">';
    if (!html.includes(marker)) return html;
    return html.replace(marker,`${healthPanel()}${marker}`);
  }

  toolView=function batch97TrainingHealthToolView(tool){
    const html=previousToolView(tool);
    return tool===TOOL?injectHealth(html):html;
  };

  document.addEventListener('click',async(event)=>{
    const button=event.target.closest('[data-training-health]');
    if (!button || state.tool!==TOOL || curriculumBusy) return;
    const input=document.querySelector('#tool-input')?.value||'';
    curriculumBusy=true;curriculumError='';render();state.tool=TOOL;
    try { curriculumResult=await window.newcyber.runTool('ai-training-curriculum',{}); }
    catch(error){ curriculumResult=null;curriculumError=error?.message||String(error); }
    finally {
      curriculumBusy=false;render();state.tool=TOOL;
      const next=document.querySelector('#tool-input');if(next)next.value=input;
    }
  });
})();