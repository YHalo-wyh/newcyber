(() => {
  if (typeof DOMAINS==='undefined'||typeof TOOL_META==='undefined'||typeof toolView!=='function'||typeof renderResult!=='function') return;

  const TOOL='ai-real-ctf-regression';
  const CASES=[
    ['Hackergame 2023','🪐 小型大语言模型星球','LLM / TARGET OUTPUT','PARTIAL'],
    ['2025 CISCN / 长城杯','欺诈猎手的后门陷阱','TABULAR BACKDOOR','PARTIAL'],
    ['2025 CISCN / 长城杯','The Silent Heist','ISOLATION FOREST','PARTIAL'],
    ['2025 CISCN 总决赛','what-is-model','GRAY-BOX MODEL','PARTIAL'],
    ['2026 蓝桥杯决赛','prompt_audit','RAG / PROMPT','PARTIAL'],
    ['2026 软件系统安全赛','CIFAR-10','IMAGE BACKDOOR','PARTIAL'],
    ['2026 软件系统安全赛','Fake Emotion','NPY / SAMPLE','GAP'],
    ['第五届湾区杯决赛','Blind','ASR → SHELL','FULL']
  ];

  TOOL_META[TOOL]={domain:'ai',title:'国内 AI CTF 真题回归',label:'公开真题最小复现 / 能力缺口',placeholder:''};
  if(!(DOMAINS.ai.tools||[]).some((row)=>row[0]===TOOL))DOMAINS.ai.tools.unshift([TOOL,'国内 AI CTF 真题回归','用公开题面/官方题解提炼最小复现，验证识别能力并暴露 PARTIAL / GAP。']);

  const previousToolView=toolView;
  const previousRenderResult=renderResult;

  function statusClass(value=''){return String(value).toLowerCase().replace(/[^a-z]+/g,'-');}

  function catalogRows(){
    return CASES.map(([event,challenge,kind,coverage],index)=>`<div class="real-ctf-row">
      <span>${String(index+1).padStart(2,'0')}</span>
      <div><strong>${esc(challenge)}</strong><small>${esc(event)}</small></div>
      <em>${esc(kind)}</em><b class="coverage-${statusClass(coverage)}">${coverage}</b>
    </div>`).join('');
  }

  function emptyResult(){
    return `<div class="real-ctf-empty"><span>AI / REAL CORPUS</span><strong>8 个公开真题样本待回归</strong><p>运行后同时显示“是否识别到证据模式”和“当前覆盖程度”。PASS 不代表自动解出原题。</p></div>`;
  }

  function toolPage(){
    const resultHtml=state.toolError?`<div class="error-box">${esc(state.toolError)}</div>`:state.toolResult?renderResult(TOOL,state.toolResult):emptyResult();
    return `<div class="page-head tool-head real-ctf-head"><div><span class="kicker">AI · REAL CHALLENGE REGRESSION</span><h1>国内 AI CTF 真题回归</h1><p>公开题面 / 官方题解 → 最小复现 → NewCyber 实际分析结果。缺口直接保留，不做虚假全绿。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="real-ctf-workbench">
        <article class="panel real-ctf-catalog"><div class="result-title"><div><b>公开真题集</b><small>8 CASES · 国内赛事优先</small></div></div><div class="real-ctf-list">${catalogRows()}</div><div class="real-ctf-source-note">公开来源：USTC Hackergame · CTF-Archives · 公开赛事题解。未公开附件细节不会被补写进 fixture。</div></article>
        <article class="panel real-ctf-results"><div class="result-title"><b>回归结果</b><button class="button primary" data-action="run-tool">运行全部</button></div><textarea id="tool-input" class="real-ctf-hidden-input" aria-hidden="true"></textarea><div id="tool-result">${resultHtml}</div></article>
      </div>`;
  }

  function regressionResult(result){
    const s=result.summary||{};
    const rows=(result.results||[]).map((item)=>`<article class="real-ctf-result-row ${esc(statusClass(item.status))}">
      <div class="real-ctf-result-status"><span>${esc(String(item.status||'unknown').toUpperCase())}</span><b>${esc(String(item.coverage||'unknown').toUpperCase())}</b></div>
      <div class="real-ctf-result-main"><strong>${esc(item.challenge||item.id)}</strong><small>${esc(item.event||'')} · ${esc(item.kind||'')}</small><p>${esc(item.evidence||'')}</p><em>${esc(item.limitation||'')}</em></div>
      <div class="real-ctf-result-tool"><span>${esc(item.tool||'—')}</span><small>${esc(item.provenance||'')}</small></div>
    </article>`).join('');
    return `<div class="real-ctf-summary"><div><span>RECOGNIZED</span><b>${s.recognitionPass||0}/${s.total||0}</b></div><div><span>FULL</span><b>${s.coverageFull||0}</b></div><div><span>PARTIAL</span><b>${s.coveragePartial||0}</b></div><div><span>GAP</span><b>${s.coverageGap||0}</b></div></div>
      <div class="real-ctf-result-list">${rows}</div><p class="notice">${esc(result.note||'')}</p>`;
  }

  toolView=function realCtfToolView(tool){if(tool===TOOL)return toolPage();return previousToolView(tool);};
  renderResult=function realCtfRenderResult(tool,result){if(tool===TOOL)return regressionResult(result||{});return previousRenderResult(tool,result);};
  render();
})();
