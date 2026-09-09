(() => {
  if(typeof render!=='function'||typeof shell!=='function'||typeof workspaceView!=='function'||typeof homeView!=='function')return;

  let evidenceOpen=false;
  let busy=false;

  const STATUS_LABEL={solved:'SOLVED',candidate:'CANDIDATE','needs-input':'NEED INPUT',handoff:'AI HANDOFF',empty:'EMPTY'};
  const STATUS_TEXT={
    solved:'已验证结果',candidate:'候选待验证','needs-input':'缺少材料',handoff:'确定性链已跑完',empty:'等待题目'
  };

  function session(){return state.workspace?.challengeSession||null;}
  function sourceKind(){return state.workspace?.challengeInput?.kind||session()?.source?.kind||'directory';}
  function challengeName(){
    return state.workspace?.challengeInput?.displayName||state.workspace?.workspaceName||'Challenge Session';
  }
  function isFileSession(){return sourceKind()==='file-session';}
  function statusClass(value){return ['solved','candidate','needs-input','handoff','empty'].includes(value)?value:'handoff';}

  function sessionNavButton(){
    const active=!state.tool&&(state.view==='workspace'||state.view==='home');
    return `<button class="nav-item challenge-primary-nav ${active?'active':''}" data-session-return><span>▶</span><b>自动解题</b>${state.workspace?`<small>${esc(challengeName())}</small>`:'<small>丢题目直接分析</small>'}</button>`;
  }

  shell=function challengeShell(content){
    const toolTitle=state.tool?(TOOL_META[state.tool]?.title||state.tool):null;
    const pageTitle=toolTitle||((state.view==='workspace'||state.view==='home')?'Challenge Session':(DOMAINS[state.view]?.title||({common:'通用工具',knowledge:'离线速查'}[state.view]||'工具库')));
    return `<div class="shell challenge-shell">
      <aside class="sidebar challenge-sidebar">
        <button class="brand" data-view="home"><span class="brand-mark">N</span><span><strong>NewCyber</strong><small>AUTO SOLVE WORKBENCH</small></span></button>
        <div class="nav-section challenge-main-nav"><b>解题</b>${sessionNavButton()}</div>
        <div class="nav-section challenge-tools-nav"><b>手工复核工具</b>
          ${navButton('vehicle','车联网','V')}
          ${navButton('lowalt','低空 / UAV','U')}
          ${navButton('ai','AI 安全','A')}
          ${navButton('web3','Web3','B')}
          ${navButton('common','通用工具','C')}
          ${navButton('knowledge','离线速查','K')}
        </div>
        <div class="sidebar-status"><span class="dot"></span><div><strong>Offline First</strong><small>自动链默认不联网、不执行不可信附件</small></div></div>
      </aside>
      <main>
        <header class="topbar challenge-topbar"><div><span>NewCyber</span><b>/</b><strong>${esc(pageTitle)}</strong>${state.workspace&&!state.tool?`<em class="challenge-top-status ${statusClass(session()?.status)}">${esc(STATUS_TEXT[session()?.status]||'分析中')}</em>`:''}</div><div class="top-actions">${state.tool&&state.workspace?'<button class="button ghost" data-session-return>返回解题任务</button>':''}<button class="button ghost" data-session-open-file>打开题目文件</button><button class="button primary" data-action="choose-workspace">打开完整目录</button></div></header>
        <section class="content challenge-content">${content}</section>
      </main>
    </div><div id="toast"></div>`;
  };

  function emptyWorkflow(){
    return `<div class="challenge-empty-layout">
      <section class="challenge-drop" data-session-drop tabindex="0">
        <div class="challenge-drop-icon">＋</div>
        <div><span class="challenge-kicker">CHALLENGE SESSION</span><h1>把题目文件丢进来</h1><p>NewCyber 会自己识别题型、套确定性模板、递归分析新产物，尽量直接跑到可验证结果。</p></div>
        <div class="challenge-drop-actions"><button class="button primary" data-session-open-file>打开题目文件</button><button class="button ghost" data-action="choose-workspace">打开完整赛题目录</button></div>
        <small>支持拖放单个或多个附件。单文件会进入隔离 Session，不会扫描同目录无关文件。</small>
      </section>
      <section class="challenge-flow-preview">
        <article><b>01</b><strong>自动识别</strong><p>文件类型、赛道、协议、模型、二进制、源码与附件关系。</p></article>
        <article><b>02</b><strong>自动套模板</strong><p>解码、密码链、模型算术、侧信道、流量、固件、逆向关系等能跑的先全部跑。</p></article>
        <article><b>03</b><strong>只给一个结论</strong><p>能解直接给结果；缺材料只告诉你最小缺口；全失败就生成本地 AI 接管包。</p></article>
      </section>
    </div>`;
  }

  homeView=function challengeHomeView(){
    if(state.workspace)return workspaceView();
    return emptyWorkflow();
  };

  function resultPanel(s){
    if(s?.result?.value){
      const verified=s.status==='solved';
      return `<section class="challenge-result ${verified?'verified':'candidate'}"><div><span>${verified?'VERIFIED RESULT':'FLAG CANDIDATE'}</span><code>${esc(s.result.value)}</code><small>${esc(s.result.source||s.result.file||'workspace')}</small></div><button class="button ${verified?'primary':'ghost'}" data-session-copy-result="${esc(s.result.value)}">复制结果</button></section>`;
    }
    if(s?.status==='handoff')return `<section class="challenge-result neutral"><div><span>DETERMINISTIC EXHAUSTED</span><strong>现有确定性模板没有形成可提交结果</strong><small>下面已经整理好本地 AI 接管上下文，不需要你自己重新拼信息。</small></div></section>`;
    return '';
  }

  function solverLedger(s){
    const items=s?.solverLedger||[];
    if(!items.length)return '<div class="challenge-empty-small">当前还没有可记录的专项模板执行。</div>';
    return `<div class="challenge-ledger">${items.slice(0,18).map((item,index)=>`<article class="${esc(item.status||'ran')}"><span>${String(index+1).padStart(2,'0')}</span><div><strong>${esc(item.title)}</strong><small>${esc(item.detail||'已执行')}</small></div><em>${esc(String(item.status||'ran').toUpperCase())}</em></article>`).join('')}</div>`;
  }

  function needsPanel(s){
    const need=s?.primaryNeed;
    if(!need)return `<section class="challenge-side-card"><header><span>NEXT INPUT</span><b>暂时不需要你补材料</b></header><p>NewCyber 会先把能自动处理的步骤跑完。</p></section>`;
    const accepts=(need.accepts||[]).map((x)=>`<span>${esc(x)}</span>`).join('');
    const addButton=isFileSession()&&['file','file-or-context'].includes(need.kind)?'<button class="button primary" data-session-add-files>补充文件并继续解</button>':'';
    const rescanButton=!isFileSession()?'<button class="button ghost" data-action="rescan-workspace">目录补好后重新扫描</button>':'';
    return `<section class="challenge-side-card need"><header><span>还缺这一项</span><b>${esc(need.title)}</b></header><p>${esc(need.why||need.detail||'补齐后继续当前 Session。')}</p>${need.detail?`<small>${esc(need.detail)}</small>`:''}${accepts?`<div class="challenge-accepts">${accepts}</div>`:''}<div class="challenge-side-actions">${addButton}${rescanButton}<button class="button ghost" data-session-copy-need>复制需求</button></div>${isFileSession()?'<div class="challenge-mini-drop" data-session-add-drop>也可以把补充附件直接拖到这里</div>':''}</section>`;
  }

  function handoffPanel(s){
    if(!s?.aiHandoff?.ready)return '';
    return `<section class="challenge-side-card handoff"><header><span>LOCAL AI HANDOFF</span><b>本地 AI 接管包已生成</b></header><p>包含题型判断、附件清单、已跑模板、关键 Finding、候选结果、失败路径和缺口。直接复制给本地模型继续分析。</p><button class="button primary" data-session-copy-handoff>复制完整接管包</button></section>`;
  }

  function factsRow(s){
    const facts=s?.facts||[];
    if(!facts.length)return'';
    return `<div class="challenge-facts">${facts.map((item)=>`<article><span>${esc(item.label)}</span><strong title="${esc(item.value)}">${esc(item.value)}</strong>${item.detail?`<small>${esc(item.detail)}</small>`:''}</article>`).join('')}</div>`;
  }

  function evidenceArea(a,s){
    const files=s?.inventory||[];
    const findings=[...(a.findings||[])].sort((x,y)=>({high:4,medium:3,low:2,info:1}[y.severity]||0)-({high:4,medium:3,low:2,info:1}[x.severity]||0)).slice(0,16);
    return `<section class="challenge-evidence ${evidenceOpen?'open':''}"><button class="challenge-evidence-toggle" data-session-toggle-evidence><span><b>证据与附件</b><small>${files.length} files · ${findings.length} priority findings</small></span><em>${evidenceOpen?'收起':'展开'}</em></button>${evidenceOpen?`<div class="challenge-evidence-grid"><div><h3>附件</h3><div class="challenge-file-list">${files.slice(0,30).map((file)=>`<article><span>${esc(file.type||'FILE')}</span><div><strong>${esc(file.path)}</strong><small>${fmtBytes(file.size||0)}${file.findingCount?` · ${file.findingCount} findings`:''}</small></div></article>`).join('')||'<p>无附件</p>'}</div></div><div><h3>关键 Finding</h3><div class="challenge-finding-list">${findings.map((item)=>`<article class="${esc(item.severity||'info')}"><span>${esc(item.severity||'info')}</span><div><strong>${esc(item.title||item.id||'Finding')}</strong><small>${esc(item.file||'workspace')}${item.line?`:${item.line}`:''}</small><p>${esc(String(item.evidence||item.detail||'').slice(0,420))}</p></div></article>`).join('')||'<p>暂无 Finding</p>'}</div></div></div>`:''}</section>`;
  }

  function manualFallbacks(s){
    const tools=s?.toolFallbacks||[];
    if(!tools.length)return'';
    return `<details class="challenge-manual"><summary>手工复核 / 专业工具（自动链之后再用）</summary><div>${tools.map((item)=>`<article><div><strong>${esc(item.title||'专业工具')}</strong><small>${esc(item.detail||'')}</small></div><button class="button ghost" data-tool="${esc(item.tool)}">打开</button></article>`).join('')}</div></details>`;
  }

  workspaceView=function challengeWorkspaceView(){
    if(!state.workspace)return emptyWorkflow();
    const a=state.workspace;const s=session()||{status:'handoff',headline:'分析已完成',solverLedger:[],inventory:[],stats:{}};
    const status=statusClass(s.status);
    const rescan=isFileSession()?'<button class="button ghost" data-session-rescan>重新跑完整自动链</button>':'<button class="button ghost" data-action="rescan-workspace">重新跑完整自动链</button>';
    return `<div class="challenge-session-workspace">
      <header class="challenge-session-head"><div><span class="challenge-kicker">AUTO SOLVE · CHALLENGE SESSION</span><h1>${esc(challengeName())}</h1><p>${esc(s.headline||'自动分析已完成')}</p></div><div class="challenge-head-actions"><span class="challenge-status ${status}">${esc(STATUS_LABEL[s.status]||'ANALYSIS')}</span>${isFileSession()?'<button class="button ghost" data-session-add-files>补充附件</button>':''}${rescan}</div></header>
      ${resultPanel(s)}
      ${factsRow(s)}
      <div class="challenge-session-grid">
        <main class="challenge-solve-main"><section class="challenge-main-card"><header><div><span>SOLVER GRAPH</span><b>NewCyber 已自动套用的模板</b></div><em>${s.stats?.templatesRun||0} templates</em></header>${solverLedger(s)}</section>${evidenceArea(a,s)}${manualFallbacks(s)}</main>
        <aside class="challenge-solve-side">${needsPanel(s)}${handoffPanel(s)}<section class="challenge-side-card compact"><header><span>SESSION</span><b>${isFileSession()?'隔离文件任务':'完整目录任务'}</b></header><div class="challenge-session-stats"><span><b>${s.stats?.files||0}</b> 文件</span><span><b>${s.stats?.highFindings||0}</b> High</span><span><b>${s.stats?.recoveredArtifacts||0}</b> 产物</span></div><button class="button ghost" data-action="export-report">导出完整报告</button></section></aside>
      </div>
    </div>`;
  };

  async function setBusy(value,message){
    busy=value;
    document.body.classList.toggle('challenge-busy',value);
    if(message)toast(message);
    try{await window.newcyber.setTaskProgress?.(value?'indeterminate':'none');}catch{}
  }

  async function acceptAnalysis(promise,label='正在自动求解…'){
    if(busy)return;
    await setBusy(true,label);
    try{
      const analysis=await promise;
      if(!analysis)return;
      state.workspace=analysis;state.view='workspace';state.tool=null;state.toolResult=null;state.toolError=null;evidenceOpen=false;
      render();
      toast(`自动链完成：${analysis.challengeSession?.stats?.templatesRun||0} 个模板`);
    }catch(error){toast(error?.message||'Challenge Session 分析失败',true);}finally{await setBusy(false);}
  }

  document.addEventListener('click',async(event)=>{
    const target=event.target.closest?.('[data-session-open-file],[data-session-return],[data-session-add-files],[data-session-rescan],[data-session-copy-handoff],[data-session-copy-result],[data-session-copy-need],[data-session-toggle-evidence]');
    if(!target)return;
    if(target.hasAttribute('data-session-open-file')){await acceptAnalysis(window.newcyber.chooseChallengeFiles(),'正在读取题目并自动求解…');return;}
    if(target.hasAttribute('data-session-return')){state.tool=null;state.toolResult=null;state.toolError=null;state.view=state.workspace?'workspace':'home';render();return;}
    if(target.hasAttribute('data-session-add-files')){
      if(!state.workspace||!isFileSession())return toast('完整目录模式请把补充文件放进赛题目录后重新扫描',true);
      await acceptAnalysis(window.newcyber.addChallengeFiles(state.workspace.workspacePath),'正在加入补充材料并继续求解…');return;
    }
    if(target.hasAttribute('data-session-rescan')){
      if(!state.workspace||!isFileSession())return;
      await acceptAnalysis(window.newcyber.rescanChallenge(state.workspace.workspacePath),'正在重新执行全部自动模板…');return;
    }
    if(target.hasAttribute('data-session-copy-handoff')){
      const value=session()?.aiHandoff?.markdown||'';if(!value)return;
      try{await navigator.clipboard.writeText(value);toast('本地 AI 接管包已复制');}catch{toast('复制失败',true);}return;
    }
    if(target.hasAttribute('data-session-copy-result')){
      try{await navigator.clipboard.writeText(target.dataset.sessionCopyResult||'');toast('结果已复制');}catch{toast('复制失败',true);}return;
    }
    if(target.hasAttribute('data-session-copy-need')){
      const need=session()?.primaryNeed;if(!need)return;
      const value=[`还缺：${need.title}`,need.why,need.detail,(need.accepts||[]).length?`可提供：${need.accepts.join(' / ')}`:''].filter(Boolean).join('\n');
      try{await navigator.clipboard.writeText(value);toast('缺口说明已复制');}catch{toast('复制失败',true);}return;
    }
    if(target.hasAttribute('data-session-toggle-evidence')){evidenceOpen=!evidenceOpen;render();}
  });

  document.addEventListener('dragover',(event)=>{
    if(event.target.closest?.('[data-session-drop],[data-session-add-drop]')){event.preventDefault();event.dataTransfer.dropEffect='copy';}
  });
  document.addEventListener('drop',async(event)=>{
    const start=event.target.closest?.('[data-session-drop]');
    const add=event.target.closest?.('[data-session-add-drop]');
    if(!start&&!add)return;
    event.preventDefault();
    const files=event.dataTransfer?.files;if(!files?.length)return;
    if(add){
      if(!state.workspace||!isFileSession())return toast('完整目录模式请把文件加入原目录后重新扫描',true);
      await acceptAnalysis(window.newcyber.addDroppedChallengeFiles(state.workspace.workspacePath,files),'正在加入拖入附件并继续求解…');
    }else await acceptAnalysis(window.newcyber.analyzeDroppedChallenge(files),'正在分析拖入题目并自动求解…');
  });

  render();
})();