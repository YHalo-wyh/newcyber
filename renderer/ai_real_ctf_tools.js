(() => {
  if (typeof DOMAINS==='undefined'||typeof TOOL_META==='undefined'||typeof toolView!=='function'||typeof renderResult!=='function') return;

  const TOOL='ai-real-ctf-regression';
  const CASES=[
    ['Hackergame 2023','🪐 小型大语言模型星球','LLM / TARGET OUTPUT','PARTIAL'],
    ['SUCTF 2026','SU_easyLLM','LLM → SHA256 → AES','PARTIAL'],
    ['2025 CISCN / 长城杯','欺诈猎手的后门陷阱','TABULAR BACKDOOR','PARTIAL'],
    ['2025 CISCN / 长城杯','easy_poison','TEXT POISONING','PARTIAL'],
    ['2025 CISCN / 长城杯','The Silent Heist','ISOLATION FOREST','PARTIAL'],
    ['2025 CISCN 总决赛','what-is-model','GRAY-BOX MODEL','PARTIAL'],
    ['2026 蓝桥杯决赛','prompt_audit','RAG / PROMPT','PARTIAL'],
    ['2026 软件系统安全赛','CIFAR-10','IMAGE BACKDOOR','PARTIAL'],
    ['2026 软件系统安全赛','Fake Emotion','NPY / SAMPLE','PARTIAL'],
    ['第五届湾区杯决赛','耄耋','AIGC / FFT','PARTIAL'],
    ['第五届湾区杯决赛','Blind','ASR → SHELL','FULL']
  ];

  TOOL_META[TOOL]={domain:'ai',title:'国内 AI CTF 真题回归',label:'Recognized → Candidate → Verified',placeholder:''};
  if(!(DOMAINS.ai.tools||[]).some((row)=>row[0]===TOOL))DOMAINS.ai.tools.unshift([TOOL,'国内 AI CTF 真题回归','公开真题最小复现，按 Recognized → Candidate → Verified 分层评估能力。']);

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
    return `<div class="real-ctf-empty"><span>AI / REAL CORPUS</span><strong>${CASES.length} 个公开真题样本待回归</strong><p>结果分三层：Recognized 只代表识别核心证据；Candidate 必须产出具体候选；Verified 还要完成 oracle / 确定性验证。Batch48 会额外显示哪些题已经有可执行 verifier。</p></div>`;
  }

  function toolPage(){
    const resultHtml=state.toolError?`<div class="error-box">${esc(state.toolError)}</div>`:state.toolResult?renderResult(TOOL,state.toolResult):emptyResult();
    return `<div class="page-head tool-head real-ctf-head"><div><span class="kicker">AI · REAL CHALLENGE MATURITY</span><h1>国内 AI CTF 真题回归</h1><p>公开题面 / 官方源码 / 公开题解 → 最小复现 → Recognized → Candidate → Verified。Batch48 开始把 Candidate 接到真正的 verifier，不会把“识别到漏洞模式”包装成“已经做出题”。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="real-ctf-workbench">
        <article class="panel real-ctf-catalog"><div class="result-title"><div><b>公开真题集</b><small>${CASES.length} CASES · 国内赛事优先</small></div></div><div class="real-ctf-list">${catalogRows()}</div><div class="real-ctf-source-note">公开来源：USTC Hackergame · SUCTF 官方仓库 · CTF-Archives · 公开赛事题解。未公开附件细节不会被补写进 fixture。</div></article>
        <article class="panel real-ctf-results"><div class="result-title"><b>成熟度回归</b><button class="button primary" data-action="run-tool">运行全部</button></div><textarea id="tool-input" class="real-ctf-hidden-input" aria-hidden="true"></textarea><div id="tool-result">${resultHtml}</div></article>
      </div>`;
  }

  function verifierButton(item){
    const tool=item.verifierAvailable || item.candidateObject?.verifier;
    if(!tool)return '';
    return `<button class="text-button" data-tool="${esc(tool)}">验证 →</button>`;
  }

  function regressionResult(result){
    const s=result.summary||{};
    const rows=(result.results||[]).map((item)=>`<article class="real-ctf-result-row ${esc(statusClass(item.status))}">
      <div class="real-ctf-result-status"><span>${esc(String(item.maturityStage||'unrecognized').toUpperCase())}</span><b>${esc(String(item.coverage||'unknown').toUpperCase())}</b></div>
      <div class="real-ctf-result-main"><strong>${esc(item.challenge||item.id)}</strong><small>${esc(item.event||'')} · ${esc(item.kind||'')}</small><p>${esc(item.candidateEvidence||item.evidence||'')}</p>${item.candidateObject?.candidateId?`<code>${esc(item.candidateObject.candidateId)}</code>`:''}<em>${esc(item.limitation||'')}</em></div>
      <div class="real-ctf-result-tool"><span>${esc(item.tool||'—')}</span><small>${esc(item.provenance||'')}</small>${verifierButton(item)}</div>
    </article>`).join('');
    return `<div class="real-ctf-summary"><div><span>RECOGNIZED</span><b>${s.recognitionPass||0}/${s.total||0}</b></div><div><span>CANDIDATE</span><b>${s.candidatePass||0}/${s.total||0}</b></div><div><span>VERIFIED</span><b>${s.verifiedPass||0}/${s.total||0}</b></div><div><span>VERIFIER</span><b>${s.verifierAvailable||0}/${s.total||0}</b></div><div><span>FULL</span><b>${s.coverageFull||0}</b></div><div><span>PARTIAL</span><b>${s.coveragePartial||0}</b></div></div>
      <div class="real-ctf-result-list">${rows}</div><p class="notice">${esc(result.note||'')}</p>`;
  }

  toolView=function realCtfToolView(tool){if(tool===TOOL)return toolPage();return previousToolView(tool);};
  renderResult=function realCtfRenderResult(tool,result){if(tool===TOOL)return regressionResult(result||{});return previousRenderResult(tool,result);};
  render();
})();
