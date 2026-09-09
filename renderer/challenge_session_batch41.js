(() => {
  if(typeof workspaceView!=='function'||typeof esc!=='function')return;

  const previousWorkspaceView=workspaceView;

  function fmtBytes41(value){
    const n=Number(value)||0;
    if(n>=1024*1024)return `${(n/1024/1024).toFixed(n>=10*1024*1024?0:1)} MB`;
    if(n>=1024)return `${(n/1024).toFixed(n>=10*1024?0:1)} KB`;
    return `${n} B`;
  }

  function transactionRows(execution){
    const attempts=execution?.attempts||[];
    if(!attempts.length)return '<div class="cs41-exec-empty">本轮没有 READY 节点需要 Executor 接管。</div>';
    return `<div class="cs41-exec-rows">${attempts.slice(0,12).map((item)=>{
      const transitions=(item.transitions||[]).map((x)=>String(x).toUpperCase()).join(' → ');
      const output=Object.entries(item.outputs||{}).slice(0,4).map(([key,value])=>`${key}=${value}`).join(' · ');
      return `<div class="cs41-exec-row ${esc(item.status||'done')}"><span class="cs41-adapter">${esc(item.adapter||item.nodeId||'adapter')}</span><strong>${esc(item.file||'workspace')}</strong><code>${esc(transitions)}</code><small>${esc(item.error||output||item.detail||'completed')}</small></div>`;
    }).join('')}</div>`;
  }

  function executionStrip(execution){
    if(!execution||execution.enabled===false)return'';
    const summary=execution.summary||{};
    if(!(execution.attempts||[]).length)return'';
    return `<details class="cs41-executor" open>
      <summary><span>AUTO EXECUTOR</span><b>${Number(summary.done)||0} done · ${Number(summary.blocked)||0} blocked</b><small>${fmtBytes41(summary.bytesRead||0)} read</small><em>READY-only / offline</em></summary>
      ${transactionRows(execution)}
    </details>`;
  }

  workspaceView=function batch41Workspace(){
    let html=previousWorkspaceView();
    const execution=state.workspace?.solverExecution||state.workspace?.challengeSession?.solverExecution;
    const strip=executionStrip(execution);
    if(!strip)return html;
    if(html.includes('<div class="cs40-desk">'))return html.replace('<div class="cs40-desk">',`${strip}<div class="cs40-desk">`);
    return `${strip}${html}`;
  };

  render();
})();