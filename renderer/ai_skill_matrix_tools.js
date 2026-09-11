(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function' || typeof renderResult !== 'function') return;

  const TOOL='ai-skill-matrix';
  const DIRECTIONS=[
    ['prompt-llm-security','01','提示词工程与大模型安全','PROMPT / AGENT'],
    ['adversarial-example','02','对抗样本攻击','ADVERSARIAL'],
    ['privacy-leakage','03','模型隐私与数据泄露','PRIVACY'],
    ['backdoor-poisoning','04','模型后门与数据投毒','BACKDOOR'],
    ['infra-supply-chain','05','AI 基础设施与供应链安全','AI INFRA']
  ];
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
}`;

  TOOL_META[TOOL]={domain:'ai',title:'AI Stage-One Bench',label:'五方向赛题证据 / JSON Bundle / CSV / 源码',placeholder};
  if (!(DOMAINS.ai.tools||[]).some((x)=>x[0]===TOOL)) DOMAINS.ai.tools.unshift([TOOL,'AI Stage-One Bench','按最新一阶段五方向做统一诊断、训练回归和能力缺口分析。']);

  const previousToolView=toolView;
  const previousRenderResult=renderResult;
  let activeDirection='prompt-llm-security';
  let trainingResult=null;
  let trainingBusy=false;
  let trainingError='';
  let ichunqiuResult=null;
  let ichunqiuBusy=false;
  let ichunqiuError='';
  let oldDriverResult=null;
  let oldDriverBusy=false;
  let oldDriverError='';

  function statusMeta(status) {
    return ({
      evidence:['EVIDENCE','已有证据','good'],
      candidate:['CANDIDATE','候选','warn'],
      'no-explicit-finding':['NO FINDING','未见显式 finding','quiet'],
      'data-needed':['DATA NEEDED','数据不足','gap']
    })[status] || [String(status||'UNKNOWN').toUpperCase(),String(status||'unknown'),'quiet'];
  }

  function formatValue(v) {
    if (v===null || v===undefined || v==='') return '—';
    if (typeof v==='number') {
      if (Number.isInteger(v)) return String(v);
      if (Math.abs(v)<=1.000001) return `${(v*100).toFixed(2)}%`;
      return Number(v).toPrecision(5);
    }
    if (typeof v==='boolean') return v?'YES':'NO';
    if (typeof v==='object') return JSON.stringify(v);
    return String(v);
  }

  function skillMap(result=state.toolResult) {
    return new Map((result?.skills||[]).map((skill)=>[skill.id,skill]));
  }

  function directionRail(result=state.toolResult) {
    const map=skillMap(result);
    return DIRECTIONS.map(([id,no,title,code])=>{
      const skill=map.get(id);
      const [status,,tone]=statusMeta(skill?.status||'data-needed');
      return `<button class="stage1-dir-row ${activeDirection===id?'active':''}" data-stage1-dir="${id}">
        <span class="stage1-dir-no">${no}</span><span class="stage1-dir-main"><b>${esc(title)}</b><small>${code}</small></span><i class="stage1-status-dot ${tone}" title="${esc(status)}"></i>
      </button>`;
    }).join('');
  }

  function findingsBlock(findings=[]) {
    if (!findings.length) return '<p class="stage1-empty-line">当前方向没有形成显式 finding。</p>';
    return `<div class="stage1-findings">${findings.slice(0,12).map((f)=>`<div class="stage1-finding ${esc(f.severity||'info')}">
      <span>${esc(String(f.severity||'info').toUpperCase())}</span><div><b>${esc(f.title||f.id||'finding')}</b><small>${esc(f.id||'')}${f.analyzer?` · ${esc(f.analyzer)}`:''}</small><p>${esc(f.meaning||f.message||'')}</p>${f.evidence!==undefined?`<pre>${esc(typeof f.evidence==='string'?f.evidence:JSON.stringify(f.evidence,null,2))}</pre>`:''}</div>
    </div>`).join('')}</div>`;
  }

  function metricsBlock(metrics={}) {
    const rows=Object.entries(metrics).filter(([,v])=>v!==undefined&&v!==null&&v!=='');
    if (!rows.length) return '<p class="stage1-empty-line">暂无可量化指标。</p>';
    return `<div class="stage1-metric-grid">${rows.slice(0,12).map(([key,value])=>`<div><span>${esc(key)}</span><b>${esc(formatValue(value))}</b></div>`).join('')}</div>`;
  }

  function selectedSkill(result) {
    const map=skillMap(result);
    return map.get(activeDirection)||map.get(DIRECTIONS[0][0])||null;
  }

  function analysisPanel(result) {
    if (!result) return `<div class="stage1-empty-analysis"><span>WAITING FOR EVIDENCE</span><b>把题目交给自动解题，或在这里粘贴五方向证据。</b><p>NewCyber 会先做类型路由，再只调用有输入证据的分析器。没有证据的方向保持 DATA NEEDED，不会为了覆盖率乱跑模板。</p></div>`;
    const skill=selectedSkill(result);
    if (!skill) return '<div class="stage1-empty-analysis">未找到方向结果。</div>';
    const [code,label,tone]=statusMeta(skill.status);
    const sub=(skill.subskills||[]).map((item)=>`<span>${esc(item.id)} · ${esc(statusMeta(item.status)[1])}</span>`).join('');
    return `<section class="stage1-analysis-view">
      <header class="stage1-analysis-head"><div><span>${esc(code)}</span><h2>${esc(skill.title)}</h2><p>${esc(skill.trainingPoint||'一阶段考察方向')}</p></div><b class="stage1-state ${tone}">${esc(label)}</b></header>
      <div class="stage1-next"><span>NEXT ACTION</span><p>${esc(skill.nextAction||skill.dataHint||'')}</p></div>
      ${sub?`<div class="stage1-subskills">${sub}</div>`:''}
      <div class="stage1-section-title"><b>COMPETITION METRICS</b><span>${Object.keys(skill.metrics||{}).length} signals</span></div>
      ${metricsBlock(skill.metrics||{})}
      <div class="stage1-section-title"><b>EVIDENCE</b><span>${skill.findings?.length||0} findings</span></div>
      ${findingsBlock(skill.findings||[])}
      ${skill.errors?.length?`<details class="stage1-details"><summary>解析提示</summary><pre>${esc(skill.errors.join('\n'))}</pre></details>`:''}
      <div class="stage1-tool-line"><span>TOOLS</span><p>${(skill.tools||[]).map((x)=>`<code>${esc(x)}</code>`).join(' · ')}</p></div>
    </section>`;
  }

  function summaryStrip(result) {
    const summary=result?.summary||{};
    const covered=(result?.skills||[]).filter((x)=>x.status!=='data-needed').length;
    return `<div class="stage1-score-strip">
      <div><span>DIRECTIONS</span><b>${result?.officialCoverage||5}/5</b></div>
      <div><span>INPUT COVERAGE</span><b>${covered}/5</b></div>
      <div><span>EVIDENCE</span><b>${summary.evidence||0}</b></div>
      <div><span>CANDIDATE</span><b>${summary.candidate||0}</b></div>
      <div><span>DATA GAP</span><b>${summary['data-needed']||5-covered}</b></div>
    </div>`;
  }

  function ichunqiuRows() {
    if (!ichunqiuResult?.results?.length) return [];
    const grouped=new Map();
    for (const item of ichunqiuResult.results) {
      const current=grouped.get(item.challenge)||{challenge:item.challenge,total:0,pass:0};
      current.total+=1;
      if (item.status==='pass') current.pass+=1;
      grouped.set(item.challenge,current);
    }
    return [...grouped.values()];
  }

  function promptDomesticReplay() {
    const cq=ichunqiuResult?.summary;
    const cqOverall=cq?`${cq.pass}/${cq.total}`:'—';
    const rows=ichunqiuRows();
    return `<div class="stage1-pane-title"><div><span>DOMESTIC CTF REPLAY</span><b>i春秋赛题族</b></div><button class="button ghost" data-ichunqiu-regression ${ichunqiuBusy?'disabled':''}>${ichunqiuBusy?'RUNNING':'RUN 12'}</button></div>
      <div class="stage1-training-overall"><span>2025 春秋杯冬季赛</span><b>${cqOverall}</b><small>${cq?`${cq.challenges} challenges · ${cq.families} families · ${cq.controls} negative controls`:'越狱的翻译官 / 健忘的客服 / 窥探内心 / 幻觉诱导'}</small></div>
      ${ichunqiuError?`<p class="stage1-training-error">${esc(ichunqiuError)}</p>`:''}
      <div class="stage1-training-list">${rows.length?rows.map((row)=>`<div><span>${esc(row.challenge)}</span><b>${row.pass}/${row.total}</b><i class="stage1-status-dot ${row.pass===row.total?'good':'gap'}"></i></div>`).join(''):`<div><span>公开 WP → 攻击家族 → 训练 canary/judge</span><b>READY</b><i class="stage1-status-dot quiet"></i></div>`}</div>`;
  }

  function adversarialDomesticReplay() {
    const summary=oldDriverResult?.summary;
    const overall=summary?`${summary.pass}/${summary.total}`:'—';
    const replay=oldDriverResult?.replay;
    const groupCount=replay?.groups?.length||0;
    const setCount=replay?.candidateSets?.length||0;
    return `<div class="stage1-pane-title"><div><span>DOMESTIC CTF REPLAY</span><b>old_driver 赛式排名</b></div><button class="button ghost" data-old-driver-regression ${oldDriverBusy?'disabled':''}>${oldDriverBusy?'RUNNING':'RUN 8'}</button></div>
      <div class="stage1-training-overall"><span>2021 春秋杯新年欢乐赛</span><b>${overall}</b><small>${summary?`${groupCount} hint groups · ${setCount} candidate sets`:'Top-2 pair / margin / runner-up / beam / verifier'}</small></div>
      ${oldDriverError?`<p class="stage1-training-error">${esc(oldDriverError)}</p>`:''}
      <div class="stage1-training-list">${oldDriverResult?.checks?.length?oldDriverResult.checks.map((row)=>`<div><span>${esc(row.id)}</span><b>${row.status==='pass'?'PASS':'MISS'}</b><i class="stage1-status-dot ${row.status==='pass'?'good':'gap'}"></i></div>`).join(''):`<div><span>公开 WP → 合成 logits → 候选排序 → hash verifier</span><b>READY</b><i class="stage1-status-dot quiet"></i></div>`}</div>`;
  }

  function domesticReplayPanel() {
    if (activeDirection==='prompt-llm-security') return promptDomesticReplay();
    if (activeDirection==='adversarial-example') return adversarialDomesticReplay();
    return `<div class="stage1-pane-title"><div><span>DOMESTIC CTF REPLAY</span><b>待锁定赛题</b></div><small>${esc(activeDirection)}</small></div>
      <div class="stage1-training-overall"><span>PROVENANCE FIRST</span><b>—</b><small>没有足够公开附件 / WP / verifier 证据时，不为了数量伪造国内赛题回归。</small></div>`;
  }

  function trainingPanel() {
    const rows=trainingResult?.directions||[];
    const overall=trainingResult?`${trainingResult.pass}/${trainingResult.caseCount}`:'—';
    return `<aside class="stage1-training-pane">
      <div class="stage1-pane-title"><div><span>PUBLIC CORPUS</span><b>训练回归</b></div><button class="button ghost" data-stage1-regression ${trainingBusy?'disabled':''}>${trainingBusy?'RUNNING':'RUN 100+'}</button></div>
      <div class="stage1-training-overall"><span>DETERMINISTIC CASES</span><b>${overall}</b><small>${trainingResult?`pass rate ${(trainingResult.passRate*100).toFixed(1)}%`:'HackAPrompt / AgentDojo / RobustBench / MICO / TrojAI / BackdoorBench / ModelScan 等公开样本族'}</small></div>
      ${trainingError?`<p class="stage1-training-error">${esc(trainingError)}</p>`:''}
      <div class="stage1-training-list">${rows.length?rows.map((row)=>`<div><span>${esc(row.title||row.id)}</span><b>${row.pass}/${row.total}</b><i class="stage1-status-dot ${row.passRate>=.9?'good':row.passRate>=.7?'warn':'gap'}"></i></div>`).join(''):DIRECTIONS.map(([,no,title])=>`<div><span>${no} · ${esc(title)}</span><b>READY</b><i class="stage1-status-dot quiet"></i></div>`).join('')}</div>
      ${domesticReplayPanel()}
      <div class="stage1-training-note"><span>TRAINING PRINCIPLE</span><p>公开题面 / benchmark 只提炼结构与 verifier，不复制答案。国内赛题保留真实判定结构，但训练样本使用合成 canary、logits、编号和 judge 证据，避免答案库式过拟合。</p></div>
    </aside>`;
  }

  function toolPage() {
    const result=state.toolResult;
    const routing=result?.inputRouting;
    const resultHtml=state.toolError?`<div class="error-box">${esc(state.toolError)}</div>`:analysisPanel(result);
    return `<div class="page-head tool-head stage1-bench-head"><div><span class="kicker">AI STAGE-ONE BENCH · OFFLINE</span><h1>一阶段五方向评测台</h1><p>参考统一跑分平台的信息结构：一份题目证据进入后，按五个官方方向自动路由、量化、回归；默认解题仍从 Challenge Session 进入。</p></div><div class="stage1-head-actions"><button class="button ghost" data-view="workspace">自动解题</button><button class="button ghost" data-view="ai">返回 AI</button></div></div>
      <div class="stage1-bench-shell">
        ${summaryStrip(result)}
        <div class="stage1-input-band"><div><span>CHALLENGE EVIDENCE</span><small>${routing?`route: ${(routing.providedSlots||routing.detections||[]).join(' / ')||'generic'}`:'JSON Bundle / CSV / transcript / source'}</small></div><textarea id="tool-input" spellcheck="false" placeholder="${esc(placeholder)}"></textarea><button class="button primary" data-action="run-tool">运行五方向诊断</button></div>
        <div class="stage1-bench-grid">
          <aside class="stage1-direction-pane"><div class="stage1-pane-title"><div><span>CAPABILITY MAP</span><b>五方向</b></div><small>STAGE 1</small></div>${directionRail(result)}</aside>
          <main class="stage1-analysis-pane"><div id="tool-result">${resultHtml}</div></main>
          ${trainingPanel()}
        </div>
        <footer class="stage1-bench-footer"><span>NO EXPLICIT FINDING ≠ SAFE</span><p>候选、证据和 verified 结论严格分层；训练覆盖率只代表回归语料能被当前分析器正确处理，不代表真实赛题自动解题率。</p></footer>
      </div>`;
  }

  toolView=function stage1BenchToolView(tool){
    if (tool===TOOL) return toolPage();
    return previousToolView(tool);
  };
  renderResult=function stage1BenchRenderResult(tool,result){
    if (tool===TOOL) return analysisPanel(result);
    return previousRenderResult(tool,result);
  };

  document.addEventListener('click',async(event)=>{
    const dir=event.target.closest('[data-stage1-dir]');
    if (dir && state.tool===TOOL) {
      activeDirection=dir.dataset.stage1Dir;
      const input=document.querySelector('#tool-input')?.value||'';
      render(); state.tool=TOOL;
      const next=document.querySelector('#tool-input'); if(next)next.value=input;
      return;
    }

    const ichunqiu=event.target.closest('[data-ichunqiu-regression]');
    if (ichunqiu && state.tool===TOOL && !ichunqiuBusy) {
      const input=document.querySelector('#tool-input')?.value||'';
      ichunqiuBusy=true;ichunqiuError='';render();state.tool=TOOL;
      try { ichunqiuResult=await window.newcyber.runTool('ai-ichunqiu-training-regression',{}); }
      catch(error){ ichunqiuResult=null;ichunqiuError=error?.message||String(error); }
      finally { ichunqiuBusy=false;render();state.tool=TOOL;const next=document.querySelector('#tool-input');if(next)next.value=input; }
      return;
    }

    const oldDriver=event.target.closest('[data-old-driver-regression]');
    if (oldDriver && state.tool===TOOL && !oldDriverBusy) {
      const input=document.querySelector('#tool-input')?.value||'';
      oldDriverBusy=true;oldDriverError='';render();state.tool=TOOL;
      try { oldDriverResult=await window.newcyber.runTool('ai-old-driver-training-regression',{}); }
      catch(error){ oldDriverResult=null;oldDriverError=error?.message||String(error); }
      finally { oldDriverBusy=false;render();state.tool=TOOL;const next=document.querySelector('#tool-input');if(next)next.value=input; }
      return;
    }

    const regression=event.target.closest('[data-stage1-regression]');
    if (!regression || state.tool!==TOOL || trainingBusy) return;
    const input=document.querySelector('#tool-input')?.value||'';
    trainingBusy=true;trainingError='';render();state.tool=TOOL;
    try { trainingResult=await window.newcyber.runTool('ai-stage1-training-regression',{options:{variantsPerSeed:4}}); }
    catch(error){ trainingResult=null;trainingError=error?.message||String(error); }
    finally { trainingBusy=false;render();state.tool=TOOL;const next=document.querySelector('#tool-input');if(next)next.value=input; }
  });

  render();
})();
