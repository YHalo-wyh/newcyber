(() => {
  if(typeof workspaceView!=='function'||typeof render!=='function')return;
  const previousWorkspaceView=workspaceView;

  function escapeHtml(value){
    if(typeof esc==='function')return esc(String(value??''));
    return String(value??'').replace(/[&<>"']/g,(ch)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  }
  function artifactOf(){
    const workspace=state.workspace||{};const session=workspace.challengeSession||{};
    return session.submissionArtifact||session.result?.artifact||workspace.submissionArtifact?.artifact||workspace.submissionAutopilot?.result?.artifact||null;
  }
  function resultPanel(artifact){
    const session=state.workspace?.challengeSession||{};const verified=Boolean(artifact.verified||session.status==='solved');
    const sha=String(artifact.sha256||'');const bytes=Number(artifact.bytes)||0;
    return `<section class="challenge-result ${verified?'verified':'candidate'} challenge-artifact-result">
      <div class="challenge-artifact-main"><span>${verified?'VERIFIED SUBMISSION':'SUBMISSION CANDIDATE'}</span><code>${escapeHtml(artifact.filename||artifact.path||'submission')}</code><small>${escapeHtml(artifact.path||'')} · ${escapeHtml(artifact.format||'txt')} · ${bytes.toLocaleString()} bytes${sha?` · sha256 ${escapeHtml(sha.slice(0,20))}…`:''}</small></div>
      <div class="challenge-artifact-actions"><button class="button ${verified?'primary':'ghost'}" data-session-reveal-artifact>在文件夹中显示</button><button class="button ghost" data-session-copy-artifact>复制路径</button><button class="button ghost" data-session-copy-submission>复制提交内容</button></div>
    </section>`;
  }

  workspaceView=function batch89Workspace(){
    const html=previousWorkspaceView();const artifact=artifactOf();if(!artifact)return html;
    const panel=resultPanel(artifact);
    const resultRe=/<section class="challenge-result\b[\s\S]*?<\/section>/;
    if(resultRe.test(html))return html.replace(resultRe,panel);
    return html.replace(/(<header class="challenge-session-head"[\s\S]*?<\/header>)/,`$1${panel}`);
  };

  document.addEventListener('click',async(event)=>{
    const target=event.target.closest?.('[data-session-reveal-artifact],[data-session-copy-artifact],[data-session-copy-submission]');if(!target)return;
    const artifact=artifactOf();if(!artifact)return;
    if(target.hasAttribute('data-session-copy-artifact')){
      await navigator.clipboard.writeText(String(artifact.absolutePath||artifact.path||''));
      if(typeof toast==='function')toast('已复制提交文件路径');return;
    }
    if(target.hasAttribute('data-session-copy-submission')){
      const payload=state.workspace?.challengeSession?.result?.payload??state.workspace?.submissionAutopilot?.result?.payload??'';
      await navigator.clipboard.writeText(String(payload));
      if(typeof toast==='function')toast('已复制提交内容');return;
    }
    if(target.hasAttribute('data-session-reveal-artifact')){
      const root=state.workspace?.challengeInput?.stagedRoot||state.workspace?.workspacePath||'';
      const relative=artifact.path||'';
      const ok=await window.newcyber.revealArtifact?.(root,relative);
      if(typeof toast==='function')toast(ok?'已在文件夹中定位提交文件':'无法定位提交文件',!ok);
    }
  });
  render();
})();
