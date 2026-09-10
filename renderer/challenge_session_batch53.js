(() => {
  if(typeof workspaceView!=='function'||typeof esc!=='function')return;

  const previousWorkspaceView=workspaceView;

  function handoffRows(handoff){
    const attempts=handoff?.attempts||[];
    const contracts=handoff?.contracts||[];
    const rows=[];
    for(const item of attempts.slice(0,12)){
      const chain=(item.transitions||[]).map((x)=>String(x).toUpperCase()).join(' → ');
      rows.push(`<div class="cs53-observation-row ${esc(item.status||'rejected')}"><span>${esc(item.verifier||'verifier')}</span><strong>${esc(item.candidateId||'candidate')}</strong><code>${esc(chain)}</code><small>${esc(item.observationFile||item.verdict||'captured')}</small></div>`);
    }
    if(!rows.length){
      for(const item of contracts.filter((x)=>x.status!=='verified').slice(0,8)){
        const state=String(item.status||'waiting').toUpperCase();
        rows.push(`<div class="cs53-observation-row ${esc(item.status||'waiting')}"><span>${esc(item.verifier||'verifier')}</span><strong>${esc(item.candidateId||'candidate')}</strong><code>${esc(`${state} → OBSERVATION`)}</code><small>${esc(item.captureHint||item.missing?.join(', ')||'waiting for sidecar')}</small></div>`);
      }
    }
    return rows.length?`<div class="cs53-observation-rows">${rows.join('')}</div>`:'<div class="cs53-observation-empty">当前 Workspace 没有可交接的 Candidate observation contract。</div>';
  }

  function observationStrip(handoff){
    if(!handoff)return'';
    const summary=handoff.summary||{};
    if(!(summary.contracts||summary.captured||summary.unmatched))return'';
    return `<details class="cs53-observation" open>
      <summary><span>OBSERVATION HANDOFF</span><b>${Number(summary.contracts)||0} contracts · ${Number(summary.captured)||0} captured · ${Number(summary.verified)||0} verified</b><small>${Number(summary.waiting)||0} waiting · ${Number(summary.rejected)||0} rejected</small><em>SIDECAR-ONLY / NO MODEL EXEC / NO REMOTE</em></summary>
      ${handoffRows(handoff)}
    </details>`;
  }

  workspaceView=function batch53Workspace(){
    let html=previousWorkspaceView();
    const handoff=state.workspace?.observationHandoff||state.workspace?.challengeSession?.observationHandoff;
    const strip=observationStrip(handoff);
    if(!strip)return html;
    if(html.includes('<div class="cs40-desk">'))return html.replace('<div class="cs40-desk">',`${strip}<div class="cs40-desk">`);
    return `${strip}${html}`;
  };

  render();
})();
