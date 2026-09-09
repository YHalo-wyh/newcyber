(() => {
  if(typeof workspaceView!=='function'||typeof homeView!=='function'||typeof esc!=='function')return;

  const STATE_TEXT={done:'DONE',partial:'PARTIAL',blocked:'BLOCKED',ready:'READY',skipped:'SKIPPED'};
  const STATUS_TEXT={solved:'SOLVED',candidate:'CANDIDATE','needs-input':'NEED INPUT',handoff:'AI HANDOFF',empty:'EMPTY'};
  const PHASE_TEXT={ingest:'INGEST',triage:'TRIAGE',solve:'SOLVE',derive:'DERIVE',correlate:'CORRELATE',verify:'VERIFY',handoff:'HANDOFF'};

  function getSession(){return state.workspace?.challengeSession||null;}
  function sourceKind(){return state.workspace?.challengeInput?.kind||getSession()?.source?.kind||'directory';}
  function isFileSession(){return sourceKind()==='file-session';}
  function challengeName(){return state.workspace?.challengeInput?.displayName||state.workspace?.workspaceName||'Challenge Session';}
  function fmtCount(value){return Number(value)||0;}
  function pipelineOf(s){
    if(s?.solverPipeline?.nodes?.length)return s.solverPipeline;
    const legacy=s?.solverLedger||[];
    return {activeNodeId:null,summary:{total:legacy.length,done:legacy.filter((x)=>x.status==='solved'||x.status==='done'||x.status==='ran').length,partial:legacy.filter((x)=>x.status==='partial').length,blocked:legacy.filter((x)=>x.status==='gap'||x.status==='blocked').length,ready:0,skipped:0},nodes:legacy.map((item,index)=>({id:item.id||`legacy-${index}`,title:item.title,phase:'solve',state:item.status==='gap'?'blocked':item.status==='partial'?'partial':item.status==='solved'?'done':'done',detail:item.detail||'',evidence:item.hits?[`${item.hits} hit(s)`]:[]}))};
  }

  function resultLine(s){
    if(s?.result?.value){
      const verified=s.status==='solved';
      return `<div class="cs40-result-line ${verified?'verified':'candidate'}"><span class="cs40-result-label">${verified?'VERIFIED RESULT':'FLAG CANDIDATE'}</span><code>${esc(s.result.value)}</code><small>${esc(s.result.source||s.result.file||'workspace')}</small><button class="button ${verified?'primary':'ghost'}" data-session-copy-result="${esc(s.result.value)}">复制</button></div>`;
    }
    if(s?.status==='handoff')return `<div class="cs40-result-line neutral"><span class="cs40-result-label">DETERMINISTIC EXHAUSTED</span><strong>现有确定性链没有形成可提交结果</strong><small>右侧已准备本地 AI 接管上下文。</small></div>`;
    return '';
  }

  function inlineFacts(s){
    const facts=s?.facts||[];
    const summary=pipelineOf(s).summary||{};
    const items=[
      ['FILES',s?.stats?.files||0],['DONE',summary.done||0],['PARTIAL',summary.partial||0],['BLOCKED',summary.blocked||0],['ARTIFACTS',s?.stats?.recoveredArtifacts||0]
    ];
    for(const fact of facts.slice(0,3))items.push([fact.label,fact.value]);
    return `<div class="cs40-metrics">${items.map(([label,value])=>`<span><b>${esc(label)}</b><strong title="${esc(String(value))}">${esc(String(value))}</strong></span>`).join('')}</div>`;
  }

  function fileTree(s){
    const files=s?.inventory||[];
    if(!files.length)return '<div class="cs40-empty-note">暂无附件</div>';
    return `<div class="cs40-file-tree">${files.slice(0,48).map((file,index)=>`<button class="cs40-file-row" type="button" title="${esc(file.path)}"><span class="cs40-tree-branch">${index===files.length-1?'└':'├'}─</span><span class="cs40-file-kind">${esc((file.type||'FILE').slice(0,8))}</span><span class="cs40-file-name">${esc(file.path)}</span><small>${fmtBytes(file.size||0)}${file.findingCount?` · ${file.findingCount}`:''}</small></button>`).join('')}</div>`;
  }

  function pipelineTimeline(s){
    const pipeline=pipelineOf(s);const nodes=pipeline.nodes||[];
    if(!nodes.length)return '<div class="cs40-empty-note">还没有 solver 执行记录。</div>';
    return `<div class="cs40-timeline">${nodes.map((item,index)=>{
      const stateName=['done','partial','blocked','ready','skipped'].includes(item.state)?item.state:'ready';
      const active=pipeline.activeNodeId===item.id;
      const evidence=(item.evidence||[]).slice(0,3);
      return `<div class="cs40-step ${stateName} ${active?'active':''}">
        <div class="cs40-rail"><span class="cs40-dot"></span>${index<nodes.length-1?'<i></i>':''}</div>
        <div class="cs40-step-main"><div class="cs40-step-top"><span class="cs40-phase">${esc(PHASE_TEXT[item.phase]||String(item.phase||'STEP').toUpperCase())}</span><strong>${esc(item.title)}</strong><em>${esc(STATE_TEXT[stateName]||stateName.toUpperCase())}</em></div>${item.detail?`<p>${esc(item.detail)}</p>`:''}${evidence.length?`<div class="cs40-evidence-chips">${evidence.map((x)=>`<span>${esc(x)}</span>`).join('')}</div>`:''}</div>
      </div>`;
    }).join('')}</div>`;
  }

  function needInspector(s){
    const need=s?.primaryNeed;
    if(!need)return `<section class="cs40-inspector-section"><header><span>NEXT INPUT</span><b>当前无需补充材料</b></header><p>先让现有确定性链跑完；不会为了增加命中率而无依据套模板。</p></section>`;
    const accepts=(need.accepts||[]).slice(0,8);
    return `<section class="cs40-inspector-section priority"><header><span>MINIMUM GAP</span><b>${esc(need.title)}</b></header><p>${esc(need.why||need.detail||'补齐后继续当前 Session。')}</p>${need.detail?`<small>${esc(need.detail)}</small>`:''}${accepts.length?`<dl class="cs40-accepts"><dt>可补充</dt>${accepts.map((x)=>`<dd>${esc(x)}</dd>`).join('')}</dl>`:''}<div class="cs40-inspector-actions">${isFileSession()&&['file','file-or-context'].includes(need.kind)?'<button class="button primary" data-session-add-files>补充文件并继续</button>':''}${!isFileSession()?'<button class="button ghost" data-action="rescan-workspace">补好目录后重扫</button>':''}<button class="button ghost" data-session-copy-need>复制需求</button></div>${isFileSession()?'<div class="cs40-mini-drop" data-session-add-drop>拖补充附件到这里</div>':''}</section>`;
  }

  function handoffInspector(s){
    if(!s?.aiHandoff?.ready)return'';
    return `<section class="cs40-inspector-section"><header><span>LOCAL AI HANDOFF</span><b>上下文已经整理好</b></header><p>题型、附件、执行过的模板、候选、失败路径和最小缺口都已合并，直接交给本地模型继续。</p><button class="button ghost wide" data-session-copy-handoff>复制完整接管包</button></section>`;
  }

  function sessionInspector(s){
    return `<section class="cs40-inspector-section compact"><header><span>SESSION</span><b>${isFileSession()?'ISOLATED FILE SESSION':'DIRECTORY SESSION'}</b></header><dl class="cs40-kv"><dt>Input</dt><dd>${fmtCount(s?.stats?.files)} files</dd><dt>High</dt><dd>${fmtCount(s?.stats?.highFindings)}</dd><dt>Recovered</dt><dd>${fmtCount(s?.stats?.recoveredArtifacts)}</dd><dt>Mode</dt><dd>Offline / read-only</dd></dl><button class="button ghost wide" data-action="export-report">导出完整报告</button></section>`;
  }

  function toolFallbacks(s){
    const tools=s?.toolFallbacks||[];
    if(!tools.length)return'';
    return `<section class="cs40-inspector-section"><header><span>MANUAL VERIFY</span><b>专业复核入口</b></header><div class="cs40-tool-links">${tools.slice(0,6).map((item)=>`<button data-tool="${esc(item.tool)}"><span>${esc(item.title||item.tool)}</span><small>${esc(item.detail||'自动链之后再人工复核')}</small><em>→</em></button>`).join('')}</div></section>`;
  }

  function evidenceDock(a,s){
    const files=s?.inventory||[];
    const severity={high:4,medium:3,low:2,info:1};
    const findings=[...(a.findings||[])].sort((x,y)=>(severity[y.severity]||0)-(severity[x.severity]||0)).slice(0,24);
    return `<details class="cs40-dock"><summary><span>EVIDENCE DOCK</span><b>${findings.length} priority findings</b><small>${files.length} files</small><em>展开 / 收起</em></summary><div class="cs40-dock-body"><div class="cs40-findings"><header>FINDINGS</header>${findings.map((item)=>`<div class="cs40-finding-row ${esc(item.severity||'info')}"><span>${esc(String(item.severity||'info').toUpperCase())}</span><div><strong>${esc(item.title||item.id||'Finding')}</strong><small>${esc(item.file||'workspace')}${item.line?`:${item.line}`:''}</small><p>${esc(String(item.evidence||item.detail||'').slice(0,520))}</p></div></div>`).join('')||'<div class="cs40-empty-note">暂无 Finding</div>'}</div><div class="cs40-artifact-list"><header>RECOVERED / FILES</header>${files.slice(0,32).map((file)=>`<div><span>${esc(file.type||'FILE')}</span><strong>${esc(file.path)}</strong><small>${fmtBytes(file.size||0)}</small></div>`).join('')||'<div class="cs40-empty-note">暂无附件</div>'}</div></div></details>`;
  }

  function emptyView(){
    return `<div class="cs40-empty">
      <div class="cs40-empty-command"><span>NEW CHALLENGE</span><h1>把题目附件丢进来</h1><p>从附件识别开始，自动路由现有确定性分析器；能闭环就给验证结果，缺东西只报最小缺口，最后再交给本地 AI。</p><div><button class="button primary" data-session-open-file>打开题目文件</button><button class="button ghost" data-action="choose-workspace">打开完整目录</button></div><small>也可以直接拖入一个或多个附件。单文件使用隔离 Session。</small></div>
      <div class="cs40-empty-flow"><span><b>01</b><strong>INGEST</strong><small>识别附件与题型</small></span><i>→</i><span><b>02</b><strong>SOLVE</strong><small>自动套可证明适用的模板</small></span><i>→</i><span><b>03</b><strong>VERIFY</strong><small>候选不冒充结果</small></span><i>→</i><span><b>04</b><strong>HANDOFF</strong><small>最小缺口 / Local AI</small></span></div>
      <div class="cs40-drop-plane" data-session-drop tabindex="0"><span>DROP CHALLENGE FILES HERE</span><small>不会执行不可信附件，也不会默认联网。</small></div>
    </div>`;
  }

  homeView=function batch40Home(){return state.workspace?workspaceView():emptyView();};

  workspaceView=function batch40Workspace(){
    if(!state.workspace)return emptyView();
    const a=state.workspace;const s=getSession()||{status:'handoff',headline:'分析已完成',inventory:[],stats:{},facts:[],toolFallbacks:[]};
    const status=STATUS_TEXT[s.status]||'ANALYSIS';
    const rescan=isFileSession()?'<button class="button ghost" data-session-rescan>重跑自动链</button>':'<button class="button ghost" data-action="rescan-workspace">重跑自动链</button>';
    return `<div class="cs40-workspace">
      <header class="cs40-head"><div><span>AUTO SOLVE / CHALLENGE SESSION</span><h1>${esc(challengeName())}</h1><p>${esc(s.headline||'自动分析已完成')}</p></div><div class="cs40-head-actions"><strong class="cs40-status ${esc(s.status||'handoff')}">${esc(status)}</strong>${isFileSession()?'<button class="button ghost" data-session-add-files>补充附件</button>':''}${rescan}</div></header>
      ${resultLine(s)}
      ${inlineFacts(s)}
      <div class="cs40-desk">
        <aside class="cs40-tree-pane"><header><span>INPUT TREE</span><b>附件 / 对象</b></header>${fileTree(s)}</aside>
        <main class="cs40-solver-pane"><header><div><span>SOLVER TIMELINE</span><b>Evidence-driven pipeline</b></div><small>${pipelineOf(s).summary?.total||0} nodes</small></header>${pipelineTimeline(s)}</main>
        <aside class="cs40-inspector"><div class="cs40-inspector-title"><span>CONTEXT INSPECTOR</span><b>当前下一步</b></div>${needInspector(s)}${handoffInspector(s)}${toolFallbacks(s)}${sessionInspector(s)}</aside>
      </div>
      ${evidenceDock(a,s)}
    </div>`;
  };

  render();
})();
