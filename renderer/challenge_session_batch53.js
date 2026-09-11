(() => {
  if(typeof workspaceView!=='function'||typeof esc!=='function')return;

  const previousWorkspaceView=workspaceView;

  function stageState(kind,value){
    if(kind==='archive')return Number(value?.archiveCount||0)>0?'done':(value?.kind==='file-session'?'idle':'skip');
    if(kind==='recover')return Number(value?.files||0)>0?'done':(Number(value?.passes||0)>0?'done':'idle');
    if(kind==='preprocess')return value?.status==='ready'?'done':value?.status==='conflict'?'gap':value?.status==='partial'?'partial':value?.status==='not-detected'?'idle':'idle';
    if(kind==='onnx')return ['verified','ranked'].includes(value?.status)?'done':value?.status==='gap'?'gap':value?.status==='not-applicable'?'idle':'idle';
    if(kind==='detect')return value?.status==='evaluated'?'done':value?.status==='partial'?'partial':value?.status==='gap'?'gap':'idle';
    if(kind==='verifier')return value?.status==='verified'?'done':['contracts-found','ranked','partial'].includes(value?.status)?'partial':value?.status==='gap'?'gap':'idle';
    return'idle';
  }

  function pipelineStrip(a){
    const input=a?.challengeInput||{};
    const recovered=a?.recoveredArtifacts||a?.challengeSession?.recoveredArtifacts||{};
    const preprocess=a?.aiPreprocessingManifest||a?.challengeSession?.aiPreprocessingManifest||{};
    const onnx=a?.onnxContestAutopilot||a?.challengeSession?.onnxContestAutopilot||{};
    const detection=a?.aiDetectionAutopilot||a?.challengeSession?.aiDetectionAutopilot||{};
    const contest=a?.aiContestAutopilot||a?.challengeSession?.aiContestAutopilot||{};
    const staticVerifier=a?.verifierContractAutopilot||a?.challengeSession?.verifierContractAutopilot||{};
    const verifier=staticVerifier.status&&staticVerifier.status!=='not-applicable'?staticVerifier:contest;
    let verifierDetail=verifier.status||'未触发';
    if(staticVerifier.status==='verified')verifierDetail='静态 checker/verifier 已闭环';
    else if(staticVerifier.status==='contracts-found')verifierDetail=`${staticVerifier.summary?.contracts||0} contract · 等待候选命中`;
    else if(contest.status==='verified')verifierDetail='赛题 verifier 精确命中';
    else if(contest.status==='ranked')verifierDetail='候选已排名，等待 verifier';
    const stages=[
      ['ARCHIVE','安全展开',stageState('archive',input),input.archiveCount?`${input.archiveCount} archive · ${input.expandedFileCount||0} files`:'原始附件直接分析'],
      ['RECOVER','递归产物',stageState('recover',recovered),recovered.files?`${recovered.files} recovered · ${recovered.passes||0} pass`:'固定点复扫待命'],
      ['PREPROCESS','预处理证据',stageState('preprocess',preprocess),preprocess.status&&preprocess.status!=='not-detected'?`${preprocess.status} · ${preprocess.evidence?.length||0} evidence`:'未检测到图像预处理链'],
      ['ONNX','本地模型推理',stageState('onnx',onnx),onnx.status?`${onnx.status} · ${onnx.runs||0} runs`:'未触发'],
      ['DETECT','结果自动复算',stageState('detect',detection),detection.summary?.evaluations?`${detection.summary.evaluations} eval · ${detection.summary.gaps||0} gap`:detection.status||'未触发'],
      ['VERIFY','题目判定闭环',stageState('verifier',verifier),verifierDetail]
    ];
    const active=stages.some((item)=>item[2]!=='idle'&&item[2]!=='skip')||input.archiveCount||input.kind==='file-session';
    if(!active)return'';
    return `<section class="cs53-pipeline"><header><div><span>DROP-TO-RESULT PIPELINE</span><b>压缩包自动解题链</b></div><small>只执行受控解析器 / 本地 ONNX / 结构化 scorer / 静态 verifier；不运行赛题脚本</small></header><div class="cs53-stages">${stages.map(([code,title,status,detail],index)=>`<article class="${esc(status)}"><i>${String(index+1).padStart(2,'0')}</i><div><span>${esc(code)}</span><b>${esc(title)}</b><small>${esc(detail)}</small></div><em>${status==='done'?'DONE':status==='gap'?'GAP':status==='partial'?'PARTIAL':status==='skip'?'SKIP':'IDLE'}</em></article>`).join('')}</div></section>`;
  }

  workspaceView=function batch53Workspace(){
    let html=previousWorkspaceView();
    const a=state.workspace;
    if(!a)return html;
    if(a.challengeSession?.result?.kind&&a.challengeSession.result.kind!=='flag')html=html.replace('FLAG CANDIDATE','RESULT CANDIDATE');
    const strip=pipelineStrip(a);if(!strip)return html;
    const marker='<div class="challenge-session-workspace">';
    return html.includes(marker)?html.replace(marker,`${marker}${strip}`):`${strip}${html}`;
  };

  render();
})();