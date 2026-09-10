(() => {
  if(typeof workspaceView!=='function'||typeof esc!=='function')return;
  const previousWorkspaceView=workspaceView;

  function row(d,index,primary){
    const tools=(d.localTools||[]).slice(0,4).join(' · ');
    return `<div class="cs54-dir-row ${d.id===primary?'primary':''}"><b>${index+1}</b><span>${esc(d.title)}</span><code>${esc(String(d.confidence||'background').toUpperCase())} · score=${Number(d.score)||0}</code><small>${esc(tools)}</small></div>`;
  }
  function strip(a){
    if(!a)return'';
    const primary=(a.directions||[]).find((x)=>x.id===a.primaryDirection)||a.directions?.[0];
    const remote=primary?.remoteTemplates?.[0];
    return `<details class="cs54-autopilot" open>
      <summary><span>AI FIVE-DIRECTION AUTOPILOT</span><b>${esc(primary?.title||'自动判定中')}</b><small>${Number(a.promptPlan?.templateCount)||0} templates → ${Number(a.promptPlan?.probeCount)||0} prompt probes</small><em>COMPETITION-NATIVE / FLAG-CLOSURE</em></summary>
      <div class="cs54-dir-list">${(a.directions||[]).map((d,i)=>row(d,i,a.primaryDirection)).join('')}</div>
      ${remote?`<div class="cs54-remote"><strong>靶机建议模板</strong><span>${esc(remote.title)}</span><code>${esc(remote.template)}</code><small>建议执行 / 不自动发包</small></div>`:''}
    </details>`;
  }
  workspaceView=function batch54Workspace(){
    let html=previousWorkspaceView();
    const a=state.workspace?.aiCompetitionAutopilot||state.workspace?.challengeSession?.aiCompetitionAutopilot;
    const s=strip(a);if(!s)return html;
    if(html.includes('<div class="cs40-desk">'))return html.replace('<div class="cs40-desk">',`${s}<div class="cs40-desk">`);
    return `${s}${html}`;
  };
  render();
})();
