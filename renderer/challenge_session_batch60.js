(() => {
  if(typeof workspaceView!=='function'||typeof esc!=='function')return;
  const previousWorkspaceView=workspaceView;

  function modelCard(auto){
    if(!auto||auto.status==='not-applicable')return'';
    const status=String(auto.status||'gap').toUpperCase();
    const selection=auto.modelSelection||null;
    const verifier=auto.verifier||null;
    const index=auto.candidateIndex||null;
    const plan=auto.inputPlan||null;
    const bindings=auto.inputBindings||null;
    const scoreSpace=auto.scoreSpace||null;
    const gap=auto.gap||null;
    const reasons=(selection?.reasons||[]).slice(0,4).map((x)=>`<span>${esc(x)}</span>`).join('');
    const alternatives=(selection?.alternatives||[]).slice(0,3).map((x)=>`<small>${esc(x.path||'model')} · score ${esc(String(x.score??'-'))}</small>`).join('');
    const verifierText=verifier?`${String(verifier.status||'unknown').toUpperCase()} · ${verifier.specs?.length||0} recipes · ${verifier.matches?.length||0} matches`:'not detected';
    const aux=plan?.auxiliaryInputNames||[];
    const inputText=plan?`${plan.primaryInputName||'primary'} + ${aux.length} aux`:(bindings?.names?.length?`${bindings.names.length} explicit binding(s)`:'single/unknown');
    const inputEvidence=plan?.evidence?.length?plan.evidence.map((x)=>`${x.name}←${x.file}`).slice(0,3).join(' · '):(bindings?.status?`bindings ${bindings.status}`:'input contract pending');
    const classCount=scoreSpace?.mapping?.completeClassCount;
    const scoreText=scoreSpace?`${String(scoreSpace.status||'unknown').toUpperCase()} · ${classCount||scoreSpace.mapping?.classes||'?'} classes`:'not normalized';
    return `<section class="cs60-autopilot ${esc(String(auto.status||'gap'))}">
      <header><div><span>AI MODEL AUTOPILOT</span><b>${esc(status)}</b></div><em>${esc(String(auto.mode||'unknown'))}</em></header>
      <div class="cs60-grid">
        <article><span>MODEL</span><strong>${esc(auto.model||gap?.code||'unresolved')}</strong><small>${selection?`${esc(selection.method||'selection')} · score ${esc(String(selection.score??'-'))}`:'等待模型证据'}</small></article>
        <article><span>INPUT PLAN</span><strong>${esc(inputText)}</strong><small>${esc(inputEvidence)}</small></article>
        <article><span>INFERENCE</span><strong>${esc(String(auto.runs||0))} candidates</strong><small>${index?`${esc(String(index.candidateMappings||0))} manifest labels · ${esc(String(index.classMappings||0))} class maps`:'candidate index unavailable'}</small></article>
        <article><span>LABEL SPACE</span><strong>${esc(scoreText)}</strong><small>${scoreSpace?.mapping?.mode?esc(scoreSpace.mapping.mode):'evidence mapping pending'}</small></article>
        <article><span>VERIFIER</span><strong>${esc(verifierText)}</strong><small>${verifier?.matches?.[0]?.spec?.file?esc(verifier.matches[0].spec.file):(gap?esc(gap.detail||gap.code):'evidence-driven only')}</small></article>
      </div>
      ${reasons?`<div class="cs60-reasons">${reasons}</div>`:''}${alternatives?`<div class="cs60-alt">${alternatives}</div>`:''}
      ${gap?`<div class="cs60-gap"><b>${esc(gap.code||'GAP')}</b><span>${esc(gap.detail||'自动链在证据不足处停止，没有猜测。')}</span></div>`:''}
    </section>`;
  }

  workspaceView=function batch60Workspace(){
    const html=previousWorkspaceView();
    const auto=state.workspace?.onnxContestAutopilot||state.workspace?.challengeSession?.onnxContestAutopilot;
    const card=modelCard(auto);if(!card)return html;
    if(html.includes('<div class="challenge-session-grid">'))return html.replace('<div class="challenge-session-grid">',`${card}<div class="challenge-session-grid">`);
    return `${card}${html}`;
  };
  render();
})();
