(() => {
  if (typeof TOOL_META === 'undefined' || typeof DOMAINS === 'undefined' || typeof toolView !== 'function' || typeof domainView !== 'function') return;

  const SWARM='lowalt-swarm-coordination';
  const FLOW='lowalt-cross-boundary-flow';
  const previousToolView=toolView;
  const previousDomainView=domainView;
  let swarmInput='';
  let flowInput='';
  let swarmResult=null;
  let flowResult=null;
  let swarmBusy=false;
  let flowBusy=false;
  let swarmError='';
  let flowError='';

  TOOL_META[SWARM]={domain:'lowalt',title:'蜂群协同工作台',placeholder:'',label:'成员 / Leader / 任务 / 序列 / 时间'};
  TOOL_META[FLOW]={domain:'lowalt',title:'跨边界攻击链',placeholder:'',label:'APP → GCS → FC → PHYSICAL'};
  if (!DOMAINS.lowalt.tools.some((row)=>row[0]===SWARM)) DOMAINS.lowalt.tools.unshift([SWARM,'蜂群协同工作台','重建成员、角色、任务和消息新鲜度，只在可复核冲突时生成 candidate。']);
  if (!DOMAINS.lowalt.tools.some((row)=>row[0]===FLOW)) DOMAINS.lowalt.tools.unshift([FLOW,'APP → GCS → FC 攻击链','按 trace / request / order / task / mission / route 关联业务入口、地面站、飞控和飞行结果。']);

  const SWARM_SAMPLE=[
    'type=LEADER src=uav-01 role=leader term=7 seq=40 auth=signed addr=10.0.0.11 session=K1',
    'type=TASK_ASSIGN src=uav-01 dst=uav-02 role=leader task=T-88 seq=41 auth=signed route=R-A',
    'type=TASK_ASSIGN src=uav-02 dst=uav-03 role=follower task=T-88 seq=8 auth=none route=R-B',
    'type=TASK_ASSIGN src=uav-02 dst=uav-03 role=follower task=T-88 seq=8 auth=none route=R-B',
    'type=TIME_SYNC src=uav-03 offset_ms=5300'
  ].join('\n');

  const FLOW_SAMPLE=[
    'stage=APP trace=TX-42 order=ORD-137 action=PATCH auth=idor status=200 actor=merchant-7',
    'stage=GCS trace=TX-42 task=TASK-9 mission=M-77 action=dispatch status=accepted actor=dispatcher',
    'stage=FC trace=TX-42 mission=M-77 msg=MISSION_ITEM_INT auth=unsigned status=accepted sysid=1',
    'stage=PHYSICAL trace=TX-42 mission=M-77 event=flight_log state=mission_changed vehicle=uav-01'
  ].join('\n');

  function workspaceSummary(){
    const ws=state.workspace;
    if(!ws) return '';
    const lines=[`workspace=${ws.workspaceName||ws.workspacePath||'current'}`];
    for(const file of (ws.files||[]).slice(0,180)){
      const label=file.relativePath||file.path||file.name||'file';
      lines.push(`[file] ${label}`);
      for(const finding of [...(file.findings||[]),...(file.metadata?.findings||[])].slice(0,12)){
        if(typeof finding==='string') lines.push(finding);
        else if(finding) lines.push(`${finding.title||finding.id||''} ${finding.evidence||finding.message||finding.summary||''}`.trim());
      }
      const meta=file.metadata||{};
      if(meta.mavlink) lines.push(`[FC] MAVLink ${label} ${JSON.stringify({parsedFrames:meta.mavlink.parsedFrames,hits:meta.mavlink.hits?.slice?.(0,4)})}`);
      if(meta.wifi) lines.push(`[GCS] WiFi ${label} networks=${meta.wifi.networks?.length||0}`);
      if(meta.flightLog) lines.push(`[PHYSICAL] flight_log ${label} ${JSON.stringify(meta.flightLog).slice(0,1600)}`);
      if(meta.firmware) lines.push(`[FC] firmware ${label}`);
      if(meta.regulatory) lines.push(`[APP] api ${label} ${JSON.stringify(meta.regulatory).slice(0,1200)}`);
    }
    for(const focus of (ws.investigation?.focus||[]).slice(0,40)) lines.push(`[focus] ${focus.title||focus.label||focus.id||''} ${focus.evidence||focus.reason||''}`.trim());
    return lines.join('\n').slice(0,480000);
  }

  function shell(title,kicker,sub,body){
    return `<div class="page-head tool-head b30-head"><div><span class="kicker">${kicker}</span><h1>${title}</h1><p>${sub}</p></div><button class="button ghost" data-view="lowalt">返回</button></div>${body}`;
  }

  function inputConsole(kind,value,busy){
    const swarm=kind==='swarm';
    return `<article class="panel b30-console"><header><b>${swarm?'EVENT TAPE':'EVIDENCE TRACE'}</b><span>JSONL / key=value / workspace evidence</span></header><div class="b30-console-actions"><button class="button" data-b30-action="workspace" data-b30-kind="${kind}" ${state.workspace?'':'disabled'}>载入当前赛题</button><button class="button" data-b30-action="sample" data-b30-kind="${kind}">演示格式</button><button class="button primary" data-b30-action="run" data-b30-kind="${kind}" ${busy?'disabled':''}>${busy?'分析中…':'分析'}</button></div><textarea data-b30-input="${kind}" spellcheck="false" placeholder="${swarm?'例如：type=TASK_ASSIGN src=uav-01 role=leader task=T1 seq=12 auth=signed':'例如：stage=APP trace=X1 order=O1 auth=idor status=200'}">${esc(value)}</textarea><footer>${swarm?'只重建成员、角色、任务和新鲜度证据；地址变化或重传不会单独判漏洞。':'没有共享关联标识就不连边；四层同时出现也不会自动拼成攻击链。'}</footer></article>`;
  }

  function badge(text,kind='idle'){return `<span class="b30-badge ${kind}">${esc(text)}</span>`;}

  function swarmStats(result){
    const s=result?.summary||{};
    return `<div class="b30-stats"><div><b>${s.members||0}</b><span>MEMBERS</span></div><div><b>${s.leaders||0}</b><span>LEADERS</span></div><div><b>${s.tasks||0}</b><span>TASKS</span></div><div><b>${s.candidates||0}</b><span>CANDIDATES</span></div></div>`;
  }

  function memberTable(result){
    const rows=result?.members||[];
    if(!rows.length) return '<div class="b30-empty">没有成员身份/节点证据。</div>';
    return `<div class="b30-table"><div class="head"><span>MEMBER</span><span>ROLE</span><span>ADDR / SESSION</span><span>EVENTS</span></div>${rows.slice(0,40).map((row)=>`<div><b>${esc(row.id)}</b><span>${esc((row.roles||[]).join(', ')||'unknown')}</span><span class="mono">${esc((row.addresses||[]).join(', ')||'-')}<small>${esc((row.sessions||[]).join(', ')||'')}</small></span><span>${row.events||0}</span></div>`).join('')}</div>`;
  }

  function topology(result){
    const edges=result?.topology?.edges||[];
    if(!edges.length) return '<div class="b30-empty">没有 src → dst 关系可重建。</div>';
    return `<div class="b30-edge-list">${edges.slice(0,32).map((edge)=>`<div><b>${esc(edge.from)}</b><i>→</i><b>${esc(edge.to)}</b><span>${esc((edge.types||[]).join(' / '))}</span><small>${edge.count} msg${(edge.tasks||[]).length?` · task ${esc(edge.tasks.join(','))}`:''}</small></div>`).join('')}</div>`;
  }

  function findings(result){
    const rows=result?.findings||[];
    if(!rows.length) return '<div class="b30-empty"><b>NO CONFLICT CANDIDATE</b><p>当前证据没有形成可复核的身份 / 角色 / 任务 / 序列 / 时间冲突。</p></div>';
    return `<div class="b30-findings">${rows.slice(0,30).map((row)=>`<article><header>${badge(row.severity||'candidate',row.severity==='high'?'bad':'warn')}<b>${esc(row.title)}</b></header><p>${esc(row.why||'')}</p>${(row.evidence||[]).slice(0,4).map((x)=>`<code>${esc(x)}</code>`).join('')}<footer>${esc(row.nextCheck||'')}</footer></article>`).join('')}</div>`;
  }

  function swarmPanel(){
    if(swarmError) return `<div class="error-box">${esc(swarmError)}</div>`;
    if(!swarmResult) return '<div class="b30-empty"><b>WAITING FOR SWARM EVIDENCE</b><p>推荐把成员发现、Leader 选举、任务分配、广播消息、seq/term 和时间同步记录放进 Event Tape。</p></div>';
    return `${swarmStats(swarmResult)}<div class="b30-swarm-board"><section><header><b>MEMBER REGISTRY</b><span>${swarmResult.members?.length||0}</span></header>${memberTable(swarmResult)}</section><section><header><b>COORDINATION GRAPH</b><span>${swarmResult.topology?.edges?.length||0} edges</span></header>${topology(swarmResult)}</section><section class="wide"><header><b>CONFLICT / REPLAY CANDIDATES</b><span>candidate-only</span></header>${findings(swarmResult)}</section></div>`;
  }

  function swarmView(){
    return shell('蜂群协同工作台','LOW ALTITUDE · SWARM COORDINATION','重建 MEMBER → LEADER → TASK → FORMATION/PEER 的证据关系，不按关键词直接判漏洞。',`<div class="b30-workbench">${inputConsole('swarm',swarmInput,swarmBusy)}<article class="panel b30-result"><header><b>SWARM STATE</b><span>DETERMINISTIC</span></header>${swarmPanel()}</article></div>`);
  }

  function stageRail(result){
    const labels={APP:'业务系统 / API',GCS:'地面站 / 调度桥',FC:'飞控 / MAVLink',PHYSICAL:'飞行状态 / 日志'};
    const rows=result?.stages||['APP','GCS','FC','PHYSICAL'].map((id)=>({id,evidence:[]}));
    return `<div class="b30-stage-rail">${rows.map((row,index)=>`<div class="${row.evidence?.length?'observed':'idle'}"><span>${esc(row.id)}</span><b>${esc(labels[row.id]||row.id)}</b><small>${row.evidence?.length||0} evidence</small></div>${index<rows.length-1?'<i>→</i>':''}`).join('')}</div>`;
  }

  function pathList(result){
    const rows=result?.paths||[];
    if(!rows.length) return '<div class="b30-empty"><b>UNLINKED EVIDENCE</b><p>当前没有至少跨两层且共享关联标识的证据。不要手工把同时出现的 APP / GCS / FC 现象硬拼成攻击链。</p></div>';
    return `<div class="b30-paths">${rows.slice(0,16).map((path)=>`<article><header><b>${esc(path.correlation)}</b><span>${esc(path.coverage)} · score ${path.score}</span></header><div class="b30-path-lane">${path.stages.map((stage)=>`<span>${esc(stage)}</span>`).join('<i>→</i>')}</div>${path.events.slice(0,6).map((event)=>`<code><b>${esc(event.stage)}</b>${esc(event.raw)}</code>`).join('')}</article>`).join('')}</div>`;
  }

  function flowFindings(result){
    const rows=result?.findings||[];
    if(!rows.length) return '<div class="b30-empty">没有形成“授权弱点 / 控制接受 / 飞行影响”候选链。</div>';
    return `<div class="b30-flow-findings">${rows.slice(0,20).map((row)=>`<article><header>${badge(row.severity||'candidate','bad')}<b>${esc(row.title)}</b></header><p>${esc(row.why||'')}</p><small>${esc(row.nextCheck||'')}</small></article>`).join('')}</div>`;
  }

  function flowPanel(){
    if(flowError) return `<div class="error-box">${esc(flowError)}</div>`;
    if(!flowResult) return '<div class="b30-empty"><b>WAITING FOR CORRELATED EVIDENCE</b><p>优先保留 trace/request/order/task/mission/route 等关联字段，以及 APP 请求、GCS 调度、FC ACK、飞行日志时间点。</p></div>';
    return `${stageRail(flowResult)}<div class="b30-flow-grid"><section><header><b>LINKED PATHS</b><span>${flowResult.summary?.linkedPaths||0}</span></header>${pathList(flowResult)}</section><section><header><b>CANDIDATE IMPACT</b><span>${flowResult.summary?.candidates||0}</span></header>${flowFindings(flowResult)}${flowResult.gaps?.length?`<div class="b30-gaps"><b>EVIDENCE GAPS</b>${flowResult.gaps.slice(0,10).map((x)=>`<p>${esc(x)}</p>`).join('')}</div>`:''}</section></div>`;
  }

  function flowView(){
    return shell('APP → GCS → FC 跨边界攻击链','LOW ALTITUDE · CROSS-BOUNDARY FLOW','把业务入口、调度桥、飞控消息和飞行结果按同一关联标识串起来；没有关联证据就保持断链。',`<div class="b30-workbench flow">${inputConsole('flow',flowInput,flowBusy)}<article class="panel b30-result"><header><b>CROSS-BOUNDARY GRAPH</b><span>STRICT CORRELATION</span></header>${flowPanel()}</article></div>`);
  }

  toolView=function batch30ToolView(tool){
    if(tool===SWARM) return swarmView();
    if(tool===FLOW) return flowView();
    return previousToolView(tool);
  };

  domainView=function batch30DomainView(id){
    const html=previousDomainView(id);
    if(id!=='lowalt'||/data-b30-entry/.test(html)) return html;
    const entry=`<section class="b30-domain-entry" data-b30-entry><button data-tool="${SWARM}"><span>SWARM</span><b>蜂群协同</b><small>成员 / Leader / Task / Replay</small></button><i>+</i><button data-tool="${FLOW}"><span>BOUNDARY</span><b>业务 → 飞控</b><small>APP / GCS / FC / Flight State</small></button></section>`;
    return `${entry}${html}`;
  };

  async function runKind(kind){
    const tool=kind==='swarm'?SWARM:FLOW;
    const text=kind==='swarm'?swarmInput:flowInput;
    if(kind==='swarm'){swarmBusy=true;swarmError='';}else{flowBusy=true;flowError='';}
    state.tool=tool; render(); state.tool=tool;
    try{
      const result=await window.newcyber.runTool(tool,{input:{text}});
      if(kind==='swarm') swarmResult=result; else flowResult=result;
    }catch(error){
      if(kind==='swarm'){swarmResult=null;swarmError=error?.message||String(error);}else{flowResult=null;flowError=error?.message||String(error);}
    }finally{
      if(kind==='swarm') swarmBusy=false; else flowBusy=false;
      state.tool=tool; render(); state.tool=tool;
    }
  }

  document.addEventListener('input',(event)=>{
    const kind=event.target?.dataset?.b30Input;
    if(kind==='swarm') swarmInput=event.target.value;
    if(kind==='flow') flowInput=event.target.value;
  });

  document.addEventListener('click',(event)=>{
    const button=event.target?.closest?.('[data-b30-action]');
    if(!button) return;
    const kind=button.dataset.b30Kind;
    const action=button.dataset.b30Action;
    if(kind!=='swarm'&&kind!=='flow') return;
    if(action==='workspace'){
      const text=workspaceSummary();
      if(kind==='swarm') swarmInput=text; else flowInput=text;
      runKind(kind); return;
    }
    if(action==='sample'){
      if(kind==='swarm') swarmInput=SWARM_SAMPLE; else flowInput=FLOW_SAMPLE;
      state.tool=kind==='swarm'?SWARM:FLOW; render(); return;
    }
    if(action==='run') runKind(kind);
  });

  render();
})();
