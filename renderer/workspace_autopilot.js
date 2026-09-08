(() => {
  const previousHomeView=homeView;
  const previousWorkspaceView=workspaceView;
  let autopilotArtifacts=[];

  function cleanLegacyLabels(html='') {
    return String(html)
      .replace(/COMPETITION MODE/g,'AUTO WORKFLOW')
      .replace(/比赛模式/g,'自动分析')
      .replace(/默认比赛模式/g,'默认自动工作流')
      .replace(/我想自己选专业工具/g,'专业工具与手动复核');
  }

  function autoHomeView() {
    const html=cleanLegacyLabels(previousHomeView());
    return html
      .replace('选择赛题目录，开始分析','选择赛题目录，一键自动分析')
      .replace('把题目丢进来，<em>先告诉你下一步做什么。</em>','把题目丢进来，<em>自动把重复劳动跑完。</em>')
      .replace('NewCyber 先做离线分析，再把最值得追的线索压缩成 1～3 个动作。','NewCyber 默认直接跑离线扫描、赛道识别、专项审计、产物恢复和优先级排序，再把需要人工处理的部分压缩到最短链路。');
  }

  function actionHtml(item,index) {
    const exportButton=Number.isInteger(item.artifactIndex)
      ? `<button class="button primary" data-autopilot-artifact="${item.artifactIndex}">直接导出</button>`:'';
    const toolButton=item.tool
      ? `<button class="button primary" data-tool="${esc(item.tool)}">打开对应工具</button>`:'';
    return `<div class="competition-step ${esc(item.level||'normal')}"><b>${index+1}</b><div><strong>${esc(item.title||'下一步')}</strong><p>${esc(item.detail||'')}</p><div class="run-row">${exportButton}${toolButton}</div></div></div>`;
  }

  function autopilotPanel(analysis) {
    const a=analysis.autopilot;
    if (!a) return '';
    autopilotArtifacts=(a.artifacts||[]).map((x)=>x.artifact).filter(Boolean);
    const checks=(a.automaticChecks||[]).slice(0,8);
    const track=a.track?.title||'暂未锁定';
    return `<section class="panel next-actions autopilot-panel">
      <div class="result-title"><div><b>一键自动分析已完成</b><p>不是额外模式：打开赛题目录后默认就走这条工作流，能自动跑的先全部跑完。</p></div><span>${a.summary?.automaticCheckKinds||0} 类检查 · ${a.summary?.automaticCheckHits||0} 次命中</span></div>
      <div class="simple-score-row">
        <article class="simple-result"><span>自动识别方向</span><strong>${esc(track)}</strong><small>${a.track?`score ${a.track.score}`:'结合题目说明继续判断'}</small></article>
        <article class="simple-result"><span>高危线索</span><strong>${a.summary?.highFindings||0}</strong><small>已按优先级排序</small></article>
        <article class="simple-result"><span>Flag 候选</span><strong>${a.summary?.flagCandidates||0}</strong><small>只需人工核对来源</small></article>
        <article class="simple-result"><span>可导出产物</span><strong>${a.summary?.exportableArtifacts||0}</strong><small>固件 / FTP / 自动解码 / 图传</small></article>
      </div>
      <div class="step-list">${(a.actions||[]).map(actionHtml).join('')}</div>
      ${checks.length?`<div class="hint-list"><p><b>已经自动跑过：</b> ${checks.map((x)=>`${esc(x.title)} ×${x.hits}`).join(' · ')}</p></div>`:''}
    </section>`;
  }

  function autoWorkspaceView() {
    const base=cleanLegacyLabels(previousWorkspaceView());
    if (!state.workspace) return base;
    return `${autopilotPanel(state.workspace)}${base}`;
  }

  document.addEventListener('click',async(event)=>{
    const button=event.target.closest('[data-autopilot-artifact]');
    if (!button) return;
    const artifact=autopilotArtifacts[Number(button.dataset.autopilotArtifact)];
    if (!artifact) return toast('当前没有可直接导出的完整产物',true);
    button.disabled=true;
    try {
      const saved=await window.newcyber.saveArtifact(artifact);
      if (saved?.filePath) toast(`已导出 ${artifact.name||'产物'}`);
    } catch (error) {
      toast(error?.message||'导出失败',true);
    } finally {
      button.disabled=false;
    }
  });

  homeView=autoHomeView;
  workspaceView=autoWorkspaceView;
  render();
})();
