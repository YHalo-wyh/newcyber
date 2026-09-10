(() => {
  if(typeof workspaceView!=='function'||typeof esc!=='function')return;
  const previousWorkspaceView=workspaceView;

  function row(d,index,primary){
    const blockers=(d.blockers||[]).join(' · ')||'none';
    return `<div class="cs55-closure-row ${d.id===primary?'primary':''}">
      <b>${index+1}</b><span>${esc(d.title)}</span><code>${Number(d.stepsToFlag)||0} STEP${Number(d.stepsToFlag)===1?'':'S'} · ${esc(String(d.closureStage||'search').toUpperCase())}</code><small>${esc(d.nextBestAction||'')}</small><em>${esc(blockers)}</em>
    </div>`;
  }

  function strip(c,replay,sca){
    if(!c)return'';
    const primary=(c.directions||[]).find((x)=>x.id===c.primaryDirection)||c.directions?.[0];
    const route=sca?.qualityRoute;const contract=replay?.contracts?.[0];
    return `<details class="cs55-closure" open>
      <summary><span>AI FLAG CLOSURE</span><b>${esc(c.closed?'VERIFIED / CLOSED':primary?.title||'自动判定中')}</b><code>${Number(c.minStepsToFlag)||0} steps to flag</code><small>${Number(replay?.contractCount)||0} replay contracts</small><em>${esc(route?`SCA ${route.selectedEngine}`:'AI-ONLY SPRINT')}</em></summary>
      <div class="cs55-closure-list">${(c.directions||[]).map((d,i)=>row(d,i,c.primaryDirection)).join('')}</div>
      ${route?`<div class="cs55-route"><strong>SCA QUALITY ROUTE</strong><span>${esc(route.engine||'batch55')} → ${esc(route.selectedEngine||'unknown')}</span><code>${esc(route.feature?`${route.feature.rawDim??'?'}→${route.feature.effectiveDim??'?'} · ${route.feature.windowFunction||'window'}`:'feature pending')}</code><small>${route.fullProbe?.executed?`full-probe ${Number(route.fullProbe.fullScanRows)||0}/${Number(route.fullProbe.targetRows)||0}`:'full-probe pending'}</small></div>`:''}
      ${contract?`<div class="cs55-replay"><strong>AUTHORIZED REPLAY</strong><span>${esc(contract.probeId||contract.direction||'contract')}</span><code>${esc(contract.contractId||'')}</code><small>显式授权后执行 · 命中 flag 即停止</small></div>`:''}
    </details>`;
  }

  workspaceView=function batch55Workspace(){
    let html=previousWorkspaceView();
    const workspace=state.workspace||{};
    const c=workspace.aiFlagClosure||workspace.challengeSession?.aiFlagClosure;
    const replay=workspace.aiRemoteReplay||workspace.challengeSession?.aiRemoteReplay;
    const sca=workspace.scaAutopilot?.result||null;
    const s=strip(c,replay,sca);if(!s)return html;
    if(html.includes('<div class="cs40-desk">'))return html.replace('<div class="cs40-desk">',`${s}<div class="cs40-desk">`);
    return `${s}${html}`;
  };
  render();
})();
