(() => {
  if(typeof workspaceView!=='function'||typeof esc!=='function')return;
  const previousWorkspaceView=workspaceView;

  function row(d,index,primary){
    const blockers=(d.blockers||[]).join(' · ')||'none';
    return `<div class="cs55-closure-row ${d.id===primary?'primary':''}">
      <b>${index+1}</b><span>${esc(d.title)}</span><code>${Number(d.stepsToFlag)||0} STEP${Number(d.stepsToFlag)===1?'':'S'} · ${esc(String(d.closureStage||'search').toUpperCase())}</code><small>${esc(d.nextBestAction||'')}</small><em>${esc(blockers)}</em>
    </div>`;
  }

  function fullProbeText(fullProbe){
    if(!fullProbe)return'full-probe pending';
    if(!fullProbe.executed)return`full-probe ${fullProbe.actual?'actual':'pending'} · not executed`;
    const done=Number(fullProbe.fullScanSucceededRows??fullProbe.fullScanRows)||0;
    const target=Number(fullProbe.targetRows)||0;
    const mode=fullProbe.actual?'actual':fullProbe.estimated?'estimated':'unknown';
    const expanded=Number(fullProbe.fullProbeExpandedRows)||0;
    const changed=Number(fullProbe.top1ChangedRows)||0;
    return `full-probe ${mode} ${done}/${target} · expanded ${expanded} · top1 Δ ${changed}`;
  }

  function verifiedRecoveryText(sca){
    const value=sca?.verifiedRecovery;if(!value)return'';
    const tokens=Number(value.tokens)||0;
    const min=Number(value.minCosine),mean=Number(value.meanCosine),threshold=Number(value.threshold);
    const fmt=(x)=>Number.isFinite(x)?x.toFixed(6):'n/a';
    return `VERIFIED RECOVERY · ${tokens} tokens · cos min ${fmt(min)} · mean ${fmt(mean)} · gate ${fmt(threshold)} · recovered text hidden`;
  }

  function feedbackLine(feedback){
    if(!feedback)return'';
    const action=feedback.pauseForVerifier?'STOP / VERIFY':feedback.status==='hold'?'HOLD':feedback.status==='adaptive-ready'?'ADAPT':'OBSERVE';
    const classes=Object.entries(feedback.classificationCounts||{}).map(([key,value])=>`${key}:${Number(value)||0}`).join(' · ')||'no trusted response';
    return `<div class="cs55-feedback ${feedback.pauseForVerifier?'pause':''}">
      <strong>REPLAY FEEDBACK</strong><span>${esc(action)} · ${esc(feedback.dominantClass||feedback.status||'pending')}</span><code>${esc(classes)}</code><small>${Number(feedback.trustedMatched)||0} trusted · next ${Number(feedback.nextContractCount)||0} · budget ${Number(feedback.globalBudget?.attempted)||0}/${Number(feedback.globalBudget?.max)||32}</small><em>${esc(feedback.nextBestAction||'')}</em>
    </div>`;
  }

  function strip(c,replay,sca,feedback){
    if(!c)return'';
    const primary=(c.directions||[]).find((x)=>x.id===c.primaryDirection)||c.directions?.[0];
    const route=sca?.qualityRoute;const contract=replay?.contracts?.[0];const recovery=verifiedRecoveryText(sca);
    return `<details class="cs55-closure" open>
      <summary><span>AI FLAG CLOSURE</span><b>${esc(c.closed?'VERIFIED / CLOSED':primary?.title||'自动判定中')}</b><code>${Number(c.minStepsToFlag)||0} steps to flag</code><small>${Number(replay?.contractCount)||0} replay contracts${feedback?.nextContractCount?` · ${Number(feedback.nextContractCount)} adaptive`:''}</small><em>${esc(feedback?.pauseForVerifier?'LOCAL VERIFY FIRST':route?`SCA ${route.selectedEngine}`:'AI-ONLY SPRINT')}</em></summary>
      <div class="cs55-closure-list">${(c.directions||[]).map((d,i)=>row(d,i,c.primaryDirection)).join('')}</div>
      ${route?`<div class="cs55-route"><strong>SCA QUALITY ROUTE</strong><span>${esc(route.engine||'batch55')} → ${esc(route.selectedEngine||'unknown')}</span><code>${esc(route.feature?`${route.feature.rawDim??'?'}→${route.feature.effectiveDim??'?'} · ${route.feature.windowFunction||'window'}`:'feature pending')}</code><small>${esc(fullProbeText(route.fullProbe))}</small></div>`:''}
      ${recovery?`<div class="cs55-route"><strong>VERIFIED RECOVERY</strong><span>${esc(recovery)}</span><code>ANSWER EXTRACTION ONLY</code><small>正文默认隐藏；仅在明确提交时查看 SCA 结果</small></div>`:''}
      ${feedbackLine(feedback)}
      ${contract?`<div class="cs55-replay"><strong>AUTHORIZED REPLAY</strong><span>${esc(contract.probeId||contract.direction||'contract')}</span><code>${esc(contract.contractId||'')}</code><small>显式授权后执行 · 命中 candidate/leak/tool-call 即停并本地验证</small></div>`:''}
    </details>`;
  }

  workspaceView=function batch55Workspace(){
    let html=previousWorkspaceView();
    const workspace=state.workspace||{};
    const c=workspace.aiFlagClosure||workspace.challengeSession?.aiFlagClosure;
    const replay=workspace.aiRemoteReplay||workspace.challengeSession?.aiRemoteReplay;
    const feedback=workspace.aiReplayFeedback||workspace.challengeSession?.aiReplayFeedback;
    const sca=workspace.scaAutopilot?.result||null;
    const s=strip(c,replay,sca,feedback);if(!s)return html;
    if(html.includes('<div class="cs40-desk">'))return html.replace('<div class="cs40-desk">',`${s}<div class="cs40-desk">`);
    return `${s}${html}`;
  };
  render();
})();