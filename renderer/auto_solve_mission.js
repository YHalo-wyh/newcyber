(() => {
  if (typeof workspaceView !== 'function' || typeof homeView !== 'function') return;
  const previousWorkspaceView=workspaceView;
  const previousHomeView=homeView;

  const STATUS_LABEL={solved:'SOLVED',candidate:'CANDIDATE',blocked:'BLOCKED',empty:'EMPTY',review:'REVIEW'};
  const STAGE_LABEL={ok:'DONE',gap:'GAP',partial:'PARTIAL',pending:'WAIT'};

  function actionButtons(mission){
    const action=mission?.primaryAction||{};
    let primary='';
    if(action.kind==='copy-flag') primary=`<button class="button primary" data-auto-solve-copy="${esc(action.value||mission?.result?.value||'')}">复制 Flag</button>`;
    else if(action.kind==='verify-flag') primary=`<button class="button primary" data-auto-solve-copy-candidate="${esc(action.value||mission?.result?.value||'')}">复制候选</button>`;
    else if(action.kind==='tool'&&action.tool) primary=`<button class="button primary" data-tool="${esc(action.tool)}">${esc(action.title||'打开对应工具')}</button>`;
    else primary='<button class="button primary" data-auto-solve-rerun>继续自动求解</button>';
    const rerun=action.kind==='rerun'?'':`<button class="button ghost" data-auto-solve-rerun>重新自动求解</button>`;
    return `<div class="auto-solve-actions">${primary}${rerun}</div>`;
  }

  function resultRow(mission){
    const result=mission?.result;
    if(!result?.value)return'';
    const verified=mission.status==='solved';
    return `<div class="auto-solve-result ${verified?'verified':''}"><span>${verified?'VERIFIED RESULT':'FLAG CANDIDATE'}</span><code>${esc(result.value)}</code><button class="text-button" data-auto-solve-copy${verified?'':'-candidate'}="${esc(result.value)}">复制</button></div>`;
  }

  function stages(mission){
    return `<div class="auto-solve-stages">${(mission.stages||[]).map((item)=>`<article class="auto-solve-stage ${esc(item.status||'pending')}"><b>${esc(item.title)}</b><p>${esc(item.detail||'')}</p><em>${esc(STAGE_LABEL[item.status]||item.status||'WAIT')}</em></article>`).join('')}</div>`;
  }

  function facts(mission){
    if(!(mission.facts||[]).length)return'<p class="notice">当前还没有形成可以合并的高价值事实。</p>';
    return `<div class="auto-solve-facts">${mission.facts.map((item)=>`<div class="auto-solve-fact"><span>${esc(item.label)}</span><div><b title="${esc(item.value)}">${esc(item.value)}</b>${item.detail?`<small title="${esc(item.detail)}">${esc(item.detail)}</small>`:''}</div></div>`).join('')}</div>`;
  }

  function missionPanel(mission){
    if(!mission)return'';
    const progress=mission.progress||{completed:0,total:5};
    const progressStep=Math.max(0,Math.min(5,Number(progress.completed)||0));
    const action=mission.primaryAction||{};
    return `<section class="panel auto-solve-mission ${esc(mission.status||'review')}">
      <div class="auto-solve-head"><div><span class="auto-solve-kicker">AUTO SOLVE · ONE RESULT / ONE NEXT STEP</span><h2>${esc(mission.headline||'自动求解')}</h2><p>${esc(mission.explanation||'')}</p></div><span class="auto-solve-status">${esc(STATUS_LABEL[mission.status]||String(mission.status||'REVIEW').toUpperCase())}</span></div>
      <div class="auto-solve-progress"><i class="p${progressStep}"></i></div>
      ${resultRow(mission)}
      <div class="auto-solve-grid"><section class="auto-solve-section"><header><b>自动求解阶段</b><span>${progress.completed||0} / ${progress.total||5}</span></header>${stages(mission)}</section><section class="auto-solve-section"><header><b>NewCyber 已替你整合</b><span>只保留高价值事实</span></header>${facts(mission)}</section></div>
      <div class="auto-solve-next"><div><span>唯一下一步</span><b>${esc(action.title||'继续自动求解')}</b><p>${esc(action.detail||'能自动完成的步骤会继续自动跑；只有明确 capability gap 才要求打开专业工具。')}</p></div>${actionButtons(mission)}</div>
    </section>`;
  }

  workspaceView=function autoSolveWorkspaceView(...args){
    const html=previousWorkspaceView(...args);
    if(!state.workspace?.autoSolve)return html;
    return `${missionPanel(state.workspace.autoSolve)}${html}`;
  };

  homeView=function autoSolveHomeView(...args){
    return String(previousHomeView(...args))
      .replace(/一键自动分析/g,'一键自动求解')
      .replace(/自动把重复劳动跑完/g,'自动整合证据，尽量直接跑到 Flag')
      .replace(/选择赛题目录，开始分析/g,'选择赛题目录，一键自动求解');
  };

  document.addEventListener('click',async(event)=>{
    const rerun=event.target.closest('[data-auto-solve-rerun]');
    if(rerun){
      const root=state.workspace?.workspacePath;
      if(!root)return toast('当前没有赛题目录',true);
      rerun.disabled=true;
      try{toast('正在重新执行完整自动求解链…');await chooseWorkspace(root);}catch(error){toast(error?.message||'自动求解失败',true);}finally{rerun.disabled=false;}
      return;
    }
    const copy=event.target.closest('[data-auto-solve-copy]');
    if(copy){
      const value=copy.dataset.autoSolveCopy||'';
      try{await navigator.clipboard.writeText(value);toast('已复制 verified Flag');}catch{toast('复制失败',true);}
      return;
    }
    const candidate=event.target.closest('[data-auto-solve-copy-candidate]');
    if(candidate){
      const value=candidate.dataset.autoSolveCopyCandidate||'';
      try{await navigator.clipboard.writeText(value);toast('已复制候选；它还没有被严格验证');}catch{toast('复制失败',true);}
    }
  });

  render();
})();